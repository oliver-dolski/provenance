package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
	"github.com/oliver-dolski/provenance/internal/guidance"
)

// textWidth is where wrapped prose is broken. Eighty columns is the width a
// terminal is still expected to have, and a report that wraps badly is a report
// nobody reads to the end.
const textWidth = 78

// labelWidth aligns the left column of the summary.
const labelWidth = 12

// Text writes the report for a person reading a terminal.
func Text(w io.Writer, r Report) error {
	out := &writer{w: w}

	out.printf("%s %s\n", r.Tool, r.Version)
	out.printf("%-*s%s\n", labelWidth, "scanned", r.Path)
	if len(r.Sources) > 0 {
		out.printf("%-*s%s\n", labelWidth, "read", strings.Join(r.Sources, ", "))
	}

	writeComponents(out, r)
	writeCoverage(out, r)
	writeFindings(out, r)

	if r.SBOMPath != "" {
		out.printf("\n%-*s%s\n", labelWidth, "sbom", r.SBOMPath)
		for _, line := range wrap(guidance.ForSBOM().String(), textWidth-labelWidth) {
			out.printf("%-*s%s\n", labelWidth, "", line)
		}
	}
	if len(r.Unreadable) > 0 {
		out.printf("\nnot read (%d):\n", len(r.Unreadable))
		for _, file := range r.Unreadable {
			out.printf("  %s\n", file)
		}
	}
	if len(r.Warnings) > 0 {
		out.printf("\nwarnings (%d):\n", len(r.Warnings))
		for _, warning := range r.Warnings {
			out.printf("  %s\n", warning)
		}
	}
	return out.err
}

// writeComponents prints what the project pulls in.
func writeComponents(out *writer, r Report) {
	counts := map[component.Ecosystem]int{}
	var direct, dev, unpinned int
	for _, c := range r.Components {
		counts[c.Ecosystem]++
		if c.Direct {
			direct++
		}
		if c.Dev {
			dev++
		}
		if !c.Pinned() {
			unpinned++
		}
	}

	out.printf("\n%-*s%d", labelWidth, "components", len(r.Components))
	if breakdown := ecosystems(counts); breakdown != "" {
		out.printf("  (%s)", breakdown)
	}
	out.printf("\n")
	if len(r.Components) == 0 {
		out.printf("%-*sno dependency manifests or lockfiles found under this path\n", labelWidth, "")
		return
	}
	out.printf("%-*s%d direct, %d indirect, %d dev only, %d unpinned\n",
		labelWidth, "", direct, len(r.Components)-direct, dev, unpinned)
}

// writeCoverage states what the scan did and did not ask.
func writeCoverage(out *writer, r Report) {
	if len(r.Components) == 0 {
		return
	}

	out.printf("\n%-*s", labelWidth, "checked")
	if r.VulnerabilitySource == "" {
		out.printf("no vulnerability database was queried\n")
	} else {
		out.printf("%d of %d components against %s\n", r.Queried, len(r.Components), r.VulnerabilitySource)
	}
	if len(r.Unchecked) > 0 {
		out.printf("%-*s%d with no resolved version could not be checked\n", labelWidth, "", len(r.Unchecked))
	}
	if len(r.KnownNames) > 0 {
		out.printf("%-*snames compared against %s\n", labelWidth, "", knownNames(r.KnownNames))
	}
}

// writeFindings prints the findings, most severe first.
func writeFindings(out *writer, r Report) {
	out.printf("\n%-*s%d", labelWidth, "findings", len(r.Findings))
	if len(r.Findings) > 0 {
		out.printf("  (%s)", severities(finding.CountBySeverity(r.Findings)))
	}
	out.printf("\n")

	for _, f := range r.Findings {
		out.printf("\n  %-8s %s\n", strings.ToUpper(f.Severity.String()), componentLabel(f.Component))
		for _, line := range wrap(string(f.Kind)+" - "+f.Title, textWidth-11) {
			out.printf("           %s\n", line)
		}

		if origin := findingOrigin(f); origin != "" {
			out.printf("           %s\n", origin)
		}
		if f.FixedIn != "" {
			out.printf("           fixed in %s\n", f.FixedIn)
		}
		for _, line := range wrap(f.Detail, textWidth-11) {
			out.printf("           %s\n", line)
		}
		for _, ref := range f.References {
			out.printf("           %s\n", ref)
		}
		for _, ref := range guidance.For(f.Kind) {
			for _, line := range wrap(ref.String(), textWidth-11) {
				out.printf("           %s\n", line)
			}
		}
	}
}

// componentLabel names the component a finding is about.
func componentLabel(c component.Component) string {
	label := c.Name
	if c.Version != "" {
		label += " " + c.Version
	}
	if c.Source != "" {
		label += "  (" + c.Source + ")"
	}
	return label
}

// findingOrigin names the database a claim comes from, so an advisory someone
// else published is not read as this tool's own judgement. A finding this
// scanner raised itself carries no identifier and needs no such line: the whole
// report is this tool speaking.
func findingOrigin(f finding.Finding) string {
	if f.ID == "" {
		return ""
	}
	origin := strings.TrimSpace(f.Source + " " + f.ID)
	if len(f.Aliases) > 0 {
		origin += " (" + strings.Join(f.Aliases, ", ") + ")"
	}
	return origin
}

// ecosystems renders per-ecosystem counts in a fixed order.
func ecosystems(counts map[component.Ecosystem]int) string {
	order := []component.Ecosystem{component.NPM, component.PyPI}
	var parts []string
	for _, eco := range order {
		if count, ok := counts[eco]; ok {
			parts = append(parts, fmt.Sprintf("%s %d", eco, count))
		}
	}
	return strings.Join(parts, ", ")
}

// severities renders the finding counts from most to least severe.
func severities(counts map[finding.Severity]int) string {
	order := []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Unknown}
	var parts []string
	for _, severity := range order {
		if count, ok := counts[severity]; ok && count > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", count, severity))
		}
	}
	return strings.Join(parts, ", ")
}

// knownNames states how wide the typosquatting comparison was, so the check is
// not read as covering a whole registry.
func knownNames(counts map[string]int) string {
	names := make([]string, 0, len(counts))
	for eco := range counts {
		names = append(names, eco)
	}
	// Ecosystem names are spelled as their registries spell them, so a plain
	// byte sort would put every capitalized name ahead of every lowercase one.
	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})

	parts := make([]string, 0, len(names))
	for _, eco := range names {
		parts = append(parts, fmt.Sprintf("%d known %s packages", counts[eco], eco))
	}
	return strings.Join(parts, " and ")
}

// wrap breaks text into lines at word boundaries.
func wrap(text string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	if width < 20 {
		width = 20
	}

	var lines []string
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > width {
			lines = append(lines, line)
			line = word
			continue
		}
		line += " " + word
	}
	return append(lines, line)
}

// writer keeps the first write error instead of checking every call site.
type writer struct {
	w   io.Writer
	err error
}

func (w *writer) printf(format string, args ...any) {
	if w.err != nil {
		return
	}
	_, w.err = fmt.Fprintf(w.w, format, args...)
}
