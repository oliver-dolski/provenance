package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
	"github.com/oliver-dolski/provenance/internal/manifest"
	"github.com/oliver-dolski/provenance/internal/osv"
	"github.com/oliver-dolski/provenance/internal/report"
	"github.com/oliver-dolski/provenance/internal/risk"
	"github.com/oliver-dolski/provenance/internal/sbom"
)

// lookupTimeout bounds the whole vulnerability lookup. A scan that hangs on a
// slow network is worse than one that says it could not finish.
const lookupTimeout = 2 * time.Minute

// vulnerabilityLookup is the vulnerability database call, replaced in tests.
var vulnerabilityLookup = func(ctx context.Context, components []component.Component) (osv.Result, error) {
	return osv.NewClient("provenance/"+version).Check(ctx, components)
}

// scan reads the project, checks it, and reports what was found.
func scan(opts options, stdout, stderr io.Writer) (int, error) {
	set, problems, err := manifest.Scan(opts.Path)
	if err != nil {
		return exitError, err
	}
	components := set.All()

	files, _ := manifest.Discover(opts.Path)
	result := report.Report{
		Tool:       "provenance",
		Version:    version,
		Path:       opts.Path,
		Sources:    sourceNames(files),
		Components: components,
		Findings:   risk.Check(components),
		Unreadable: problemNames(problems),
		KnownNames: map[string]int{
			string(component.NPM):  risk.PopularNameCount(component.NPM),
			string(component.PyPI): risk.PopularNameCount(component.PyPI),
		},
	}

	if !opts.Offline && len(components) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
		defer cancel()

		lookup, err := vulnerabilityLookup(ctx, components)
		if err != nil {
			// A report that silently holds no vulnerabilities because the
			// database was unreachable is the one outcome worth failing for.
			return exitError, fmt.Errorf("vulnerability lookup failed (use -offline to scan without it): %w", err)
		}
		result.VulnerabilitySource = "OSV"
		result.Queried = lookup.Checked
		result.Unchecked = lookup.Skipped
		result.Warnings = append(result.Warnings, lookup.Warnings...)
		result.Findings = append(result.Findings, lookup.Findings...)
	}
	// The two sets of findings were each ordered on their own; combining them
	// needs one pass so the report reads most severe first.
	finding.Sort(result.Findings)

	// The report is for a person or a pipeline; the SBOM is a document for
	// another tool. Whichever of them is sent to standard output has it to
	// itself, so it can be piped without prose or a second document mixed in.
	reportOut := stdout
	if opts.SBOMPath == "-" {
		reportOut = stderr
	}

	if opts.SBOMPath != "" {
		if err := writeSBOM(opts, components, stdout); err != nil {
			return exitError, err
		}
		result.SBOMPath = opts.SBOMPath
	}

	if err := render(opts, result, reportOut); err != nil {
		return exitError, err
	}
	return exitCodeFor(opts, result), nil
}

// render writes the report in the requested format.
func render(opts options, result report.Report, w io.Writer) error {
	if opts.Format == formatJSON {
		return report.JSON(w, result)
	}
	return report.Text(w, result)
}

// exitCodeFor decides what the process reports to its caller. Findings only
// change the exit code when the caller asked for that with -fail-on, so that
// adding this tool to a pipeline does not break the pipeline by surprise.
func exitCodeFor(opts options, result report.Report) int {
	if !opts.FailOnSet {
		return exitOK
	}
	for _, f := range result.Findings {
		if f.Severity >= opts.FailOn {
			return exitFindings
		}
	}
	return exitOK
}

// writeSBOM writes the CycloneDX document to the requested destination.
func writeSBOM(opts options, components []component.Component, stdout io.Writer) error {
	sbomOpts := sbom.Options{
		ProjectName: projectName(opts.Path),
		ToolVersion: version,
		Timestamp:   time.Now(),
	}

	if opts.SBOMPath == "-" {
		return sbom.Write(stdout, components, sbomOpts)
	}

	file, err := os.Create(opts.SBOMPath)
	if err != nil {
		return fmt.Errorf("writing SBOM: %w", err)
	}
	if err := sbom.Write(file, components, sbomOpts); err != nil {
		file.Close()
		return fmt.Errorf("writing SBOM: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("writing SBOM: %w", err)
	}
	return nil
}

// sourceNames lists the dependency files that were read.
func sourceNames(files []manifest.File) []string {
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Rel)
	}
	return names
}

// problemNames lists the files that could not be parsed.
func problemNames(problems []manifest.Problem) []string {
	if len(problems) == 0 {
		return nil
	}
	names := make([]string, 0, len(problems))
	for _, p := range problems {
		names = append(names, p.Error())
	}
	return names
}

// projectName names the scanned project after its directory, which is the only
// name available before any manifest is trusted to state one.
func projectName(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Base(path)
	}
	return filepath.Base(abs)
}
