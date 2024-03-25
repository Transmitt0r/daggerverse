// A utility to generate sboms with syft

package main

import (
	"fmt"
)

const (
	defaultVersion = "1.0.1"
	defaultImage   = "anchore/syft"
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
func (s *Syft) Scan(container *Container, outputFormat ...string) []*File {
	command := []string{"scan", "--from", "oci-archive", "container.tar"}
	for _, out := range outputFormat {
		command = append(command, "-o", fmt.Sprintf("%s=%s", out, out))
	}

	scanner := s.Container.
		WithFile("container.tar", container.AsTarball()).
		WithExec(command)

	outfiles := []*File{}

	for _, out := range outputFormat {
		outfiles = append(outfiles, scanner.File(out))
	}

	return outfiles
}
