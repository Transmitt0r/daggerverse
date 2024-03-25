// A utility to generate sboms with syft

package main

import (
	"errors"
	"fmt"
	"slices"
)

const (
	defaultVersion = "1.0.1"
	defaultImage   = "anchore/syft"
)

var (
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
	scanner := s.Container.WithFile("container.tar", container.AsTarball())

	command := []string{"scan", "--from", "oci-archive", "container.tar"}
	for _, out := range outputFormat {
		command = append(command, "-o", fmt.Sprintf("%s=%s", out, out))
	}

	if basePath != "" {
		command = append(command, "--base-path", basePath)
	}

	for _, ex := range exclude {
		command = append(command, "--exclude", ex)
	}

	if scope != "" {
		command = append(command, "--scope", scope)
	}

	if platform != "" {
		command = append(command, "--platform", platform)
	}

	if sourceName != "" {
		command = append(command, "--source-name", sourceName)
	}

	if sourceVersion != "" {
		command = append(command, "--source-version", sourceVersion)
	}

	for _, cataloger := range selectCatalogers {
		command = append(command, "--select-catalogers", cataloger)
	}

	if template != nil {
		scanner = scanner.WithFile("template", template)
		command = append(command, "--template", "template")
	}

	scanner = scanner.WithExec(command)

	outfiles := []*File{}

	for _, out := range outputFormat {
		outfiles = append(outfiles, scanner.File(out))
	}

	return outfiles, nil
}
