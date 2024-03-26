// A utility to generate sboms with syft

package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/Transmitt0r/daggerverse/syft/command"
)

const (
	defaultVersion          = "1.0.1"
	defaultImage            = "anchore/syft"
	defaultTemplatePath     = "template.templ"
	defaultContainerTarPath = "container.tar"
	defaultDirectoryPath    = "scan"
	defaultOutputDirectory  = "out"
)

var (
	ErrReadTemplateName     = errors.New("unable to read template name")
	ErrTemplateMissing      = errors.New("template file is missing")
	ErrTemplateOutputNotSet = errors.New("template output format has been set but not template file is provided")
)

type Syft struct {
	// Container with syft installed
	Container *Container
	// +private
	OutputFormats []OutputFormat
}

// Create a new syft instance
func New(
	// base container to use
	// +optional
	container *Container,
	// version to use, ignored if container is provided
	// +optional
	version string,
) *Syft {
	s := &Syft{}
	if version == "" {
		version = defaultVersion
	}
	if container == nil {
		image := fmt.Sprintf("%s:v%s", defaultImage, version)
		fmt.Println(image)
		container = dag.Container().From(image)
	}
	s.Container = container
	return s
}

// Add a output format to syft
func (s *Syft) WithOutputFormat(
	// format of the output, e.g. spdx, syft-table, syft-json
	format string,
	// output filename, e.g. syft.json
	file string,
) *Syft {
	if s.OutputFormats == nil {
		s.OutputFormats = []OutputFormat{}
	}
	s.OutputFormats = append(s.OutputFormats, OutputFormat{
		Format: format,
		Output: file,
	})
	return s
}

type OutputFormat struct {
	Format string
	Output string
}

// Scans a directory and generates an sbom
func (s *Syft) ScanDirectory(
	ctx context.Context,
	// directory for which the SBOM should be generated
	directory *Directory,
	//+optional
	exclude []string,
	// squashed or all-layers
	// +optional
	scope string,
	// e.g. linux/arm64
	// +optional
	platform string,
	// +optional
	sourceName string,
	// +optional
	sourceVersion string,
	// +optional
	selectCatalogers []string,
	// +optional
	template *File,
) (*Directory, error) {
	s.Container = s.Container.WithMountedDirectory(defaultDirectoryPath, directory)
	return s.scan(ctx, defaultDirectoryPath, exclude, scope, platform, sourceName, sourceVersion, selectCatalogers, template)
}

// Scans a container and generates an sbom
func (s *Syft) ScanContainer(
	ctx context.Context,
	// container for which the SBOM should be generated
	container *Container,
	//+optional
	exclude []string,
	// squashed or all-layers
	// +optional
	scope string,
	// e.g. linux/arm64
	// +optional
	platform string,
	// +optional
	sourceName string,
	// +optional
	sourceVersion string,
	// +optional
	selectCatalogers []string,
	// +optional
	template *File,
) (*Directory, error) {
	s.Container = s.Container.WithFile(defaultContainerTarPath, container.AsTarball())
	return s.scan(ctx, defaultContainerTarPath, exclude, scope, platform, sourceName, sourceVersion, selectCatalogers, template)
}

func (s *Syft) scan(
	ctx context.Context,
	// path for which the SBOM should be generated
	scanPath string,
	//+optional
	exclude []string,
	// squashed or all-layers
	// +optional
	scope string,
	// e.g. linux/arm64
	// +optional
	platform string,
	// +optional
	sourceName string,
	// +optional
	sourceVersion string,
	// +optional
	selectCatalogers []string,
	// +optional
	template *File,
) (*Directory, error) {
	if err := checkTemplate(s.OutputFormats, template); err != nil {
		return nil, err
	}
	scanner := s.Container
	cmdOpts := Opts{
		scanPath:         scanPath,
		outputFormat:     formatOutputFormat(defaultOutputDirectory, s.OutputFormats),
		exclude:          exclude,
		scope:            scope,
		platform:         platform,
		sourceName:       sourceName,
		sourceVersion:    sourceVersion,
		selectCatalogers: selectCatalogers,
	}
	if template != nil {
		templatePath, err := template.Name(ctx)
		if err != nil {
			return nil, err
		}
		scanner = s.Container.WithFile(templatePath, template)
		cmdOpts.templatePath = templatePath
	}
	cmd := generateCommand(cmdOpts)
	return scanner.WithExec(cmd).Directory(defaultOutputDirectory), nil
}

func formatOutputFormat(outDir string, outputFormats []OutputFormat) []string {
	newOutputFormat := make([]string, len(outputFormats))
	for i, out := range outputFormats {
		newOutputFormat[i] = fmt.Sprintf("%s=%s/%s", out.Format, outDir, out.Output)
	}
	return newOutputFormat
}

type Opts struct {
	scanPath         string
	exclude          []string
	scope            string
	platform         string
	sourceName       string
	sourceVersion    string
	selectCatalogers []string
	templatePath     string
	outputFormat     []string
}

func generateCommand(opts Opts) []string {
	cmd := command.NewCommand("scan").
		AddFlag("output", opts.outputFormat...).
		AddFlag("exclude", opts.exclude...).
		AddFlag("scope", opts.scope).
		AddFlag("platform", opts.platform).
		AddFlag("source-name", opts.sourceName).
		AddFlag("source-version", opts.sourceVersion).
		AddFlag("select-catalogers", opts.selectCatalogers...).
		AddFlag("template", opts.templatePath).
		AddCommand(opts.scanPath)

	return cmd.String()
}

func outputFormatContains(format []OutputFormat, name string) bool {
	for _, f := range format {
		if f.Format == name {
			return true
		}
	}
	return false
}

func checkTemplate(outputFormats []OutputFormat, template *File) error {
	if outputFormatContains(outputFormats, "template") && template == nil {
		return ErrTemplateMissing
	}
	if template != nil && !outputFormatContains(outputFormats, "template") {
		return ErrTemplateOutputNotSet
	}
	return nil
}
