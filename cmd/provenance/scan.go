package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/manifest"
	"github.com/oliver-dolski/provenance/internal/sbom"
)

// scan reads the project and reports what it found.
func scan(opts options, stdout, stderr io.Writer) error {
	set, problems, err := manifest.Scan(opts.Path)
	if err != nil {
		return err
	}
	components := set.All()

	// The summary is a report for a person and the SBOM is a document for a
	// machine. When the SBOM goes to standard output, the summary steps aside
	// so the document can be piped without being corrupted by prose.
	summaryOut := stdout
	if opts.SBOMPath == "-" {
		summaryOut = stderr
	}

	if opts.SBOMPath != "" {
		if err := writeSBOM(opts, components, stdout); err != nil {
			return err
		}
	}

	printSummary(summaryOut, opts, components, problems)
	return nil
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

// printSummary states what was scanned and what was found.
func printSummary(w io.Writer, opts options, components []component.Component, problems []manifest.Problem) {
	byEcosystem := map[component.Ecosystem]int{}
	var direct, unpinned, dev int
	for _, c := range components {
		byEcosystem[c.Ecosystem]++
		if c.Direct {
			direct++
		}
		if !c.Pinned() {
			unpinned++
		}
		if c.Dev {
			dev++
		}
	}

	fmt.Fprintf(w, "provenance %s\n", version)
	fmt.Fprintf(w, "scanned %s\n\n", opts.Path)

	fmt.Fprintf(w, "components  %d", len(components))
	if len(byEcosystem) > 0 {
		fmt.Fprintf(w, " (%s)", ecosystemBreakdown(byEcosystem))
	}
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  direct    %d\n", direct)
	fmt.Fprintf(w, "  indirect  %d\n", len(components)-direct)
	fmt.Fprintf(w, "  dev only  %d\n", dev)
	// An unpinned dependency is the one count here that is already a finding:
	// the next release of that package enters the build without review.
	fmt.Fprintf(w, "  unpinned  %d\n", unpinned)

	if opts.SBOMPath != "" && opts.SBOMPath != "-" {
		fmt.Fprintf(w, "\nSBOM written to %s (CycloneDX %s)\n", opts.SBOMPath, sbom.SpecVersion)
	}

	if len(problems) > 0 {
		// Said out loud, because a file the scanner could not read is a hole in
		// everything above it.
		fmt.Fprintf(w, "\nnot read (%d):\n", len(problems))
		for _, p := range problems {
			fmt.Fprintf(w, "  %s\n", p)
		}
	}

	if len(components) == 0 && len(problems) == 0 {
		fmt.Fprintf(w, "\nNo dependency manifests or lockfiles found under this path.\n")
	}
}

// ecosystemBreakdown renders the per-ecosystem counts in a stable order.
func ecosystemBreakdown(counts map[component.Ecosystem]int) string {
	// The same order the components are listed in, so the two agree.
	order := []component.Ecosystem{component.NPM, component.PyPI}
	out := ""
	for _, eco := range order {
		count, ok := counts[eco]
		if !ok {
			continue
		}
		if out != "" {
			out += ", "
		}
		out += fmt.Sprintf("%s %d", eco, count)
	}
	return out
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
