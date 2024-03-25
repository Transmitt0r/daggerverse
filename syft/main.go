// A utility to generate sboms with syft

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

const (
	defaultVersion          = "1.0.1"
	defaultImage            = "anchore/syft"
	defaultTemplatePath     = "template.templ"
	defaultContainerTarPath = "container.tar"
)

var (
	ErrReadTemplateName     = errors.New("unable to read template name")
	ErrTemplateMissing      = errors.New("template file is missing")
	ErrTemplateOutputNotSet = errors.New("template output format has been set but not template file is provided")
)

type Syft struct {
	Container *Container
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

// Scans a container and generates an sbom
func (s *Syft) Scan(
	ctx context.Context,
	// container for which the SBOM should be generated
	container *Container,
	// +optional
	basePath string,
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
	// output formats to generate
	// +optional
	// +default=["syft-json"]
	outputFormat ...string,

) ([]*File, error) {
	if slices.Contains(outputFormat, "template") && template == nil {
		return nil, ErrTemplateMissing
	}
	if template != nil && !slices.Contains(outputFormat, "template") {
		return nil, ErrTemplateOutputNotSet
	}
	scanner := s.Container.WithFile(defaultContainerTarPath, container.AsTarball())

	cmdOpts := Opts{
		outputFormat:     formatOutputFormat(outputFormat),
		basePath:         basePath,
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
		scanner = scanner.WithFile(templatePath, template)
		cmdOpts.templatePath = templatePath
	}

	cmd := GenerateCommand(cmdOpts)
	scanner = scanner.WithExec(cmd)

	outfiles := []*File{}

	for _, out := range outputFormat {
		outfiles = append(outfiles, scanner.File(out))
	}

	return outfiles, nil
}

func formatOutputFormat(outputFormats []string) []string {
	newOutputFormat := make([]string, len(outputFormats))
	for i, out := range outputFormats {
		newOutputFormat[i] = fmt.Sprintf("%s=%s", out, out)
	}
	return newOutputFormat
}
