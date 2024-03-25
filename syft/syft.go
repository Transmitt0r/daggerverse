package main

type Opts struct {
	containerPath    string
	basePath         string
	exclude          []string
	scope            string
	platform         string
	sourceName       string
	sourceVersion    string
	selectCatalogers []string
	templatePath     string
	outputFormat     []string
}

func GenerateCommand(opts Opts) []string {
	cmd := NewCommand("scan").
		AddFlag("from", "oci-archive").
		AddFlag("output", opts.outputFormat...).
		AddFlag("base-path", opts.basePath).
		AddFlag("exclude", opts.exclude...).
		AddFlag("scope", opts.scope).
		AddFlag("platform", opts.platform).
		AddFlag("source-name", opts.sourceName).
		AddFlag("source-version", opts.sourceVersion).
		AddFlag("select-catalogers", opts.selectCatalogers...).
		AddFlag("template", opts.templatePath).
		AddCommand(opts.containerPath)

	return cmd
}
