// Package report renders a scan for its two audiences: a person reading a
// terminal, and a program consuming the result in a pipeline. Both get the same
// facts, including what the scan did not cover.
package report

import (
	"encoding/json"
	"io"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
	"github.com/oliver-dolski/provenance/internal/guidance"
)

// Report is everything one scan established.
type Report struct {
	// Tool and Version identify what produced the report, because a finding is
	// only as good as the version of the rules that raised it.
	Tool    string
	Version string

	// Path is the scanned project.
	Path string
	// Sources are the dependency files that were read, relative to Path.
	Sources []string

	Components []component.Component
	Findings   []finding.Finding

	// VulnerabilitySource names the database that was queried, or is empty when
	// the lookup did not run.
	VulnerabilitySource string
	// Queried is how many components were checked against that database.
	Queried int
	// Unchecked are components the database could not be asked about, because
	// no version was resolved for them.
	Unchecked []component.Component

	// Unreadable are dependency files that were found but could not be parsed.
	Unreadable []string
	// Warnings are everything else that went wrong without stopping the scan.
	Warnings []string

	// SBOMPath is where the bill of materials was written, if anywhere.
	SBOMPath string
	// KnownNames is how many package names each typosquatting check compared
	// against, keyed by ecosystem.
	KnownNames map[string]int
}

// Coverage reports whether the scan answered everything it set out to. A report
// that is not complete is still useful, as long as it does not read as if it
// were.
func (r Report) Complete() bool {
	return len(r.Unreadable) == 0 && len(r.Warnings) == 0 && len(r.Unchecked) == 0 &&
		(r.VulnerabilitySource != "" || len(r.Components) == 0)
}

// The JSON shapes. They are declared here rather than reusing the internal
// models, so that a change to an internal field does not silently change the
// documented output of the tool.

type jsonReport struct {
	Tool       string          `json:"tool"`
	Version    string          `json:"version"`
	Path       string          `json:"path"`
	Sources    []string        `json:"sources"`
	Summary    jsonSummary     `json:"summary"`
	Components []jsonComponent `json:"components"`
	Findings   []jsonFinding   `json:"findings"`
	Coverage   jsonCoverage    `json:"coverage"`
}

type jsonSummary struct {
	Components int            `json:"components"`
	Direct     int            `json:"direct"`
	Dev        int            `json:"dev"`
	Unpinned   int            `json:"unpinned"`
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"findings_by_severity"`
}

type jsonComponent struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Ecosystem  string `json:"ecosystem"`
	PURL       string `json:"purl"`
	Direct     bool   `json:"direct"`
	Dev        bool   `json:"dev"`
	Pinned     bool   `json:"pinned"`
	Constraint string `json:"constraint,omitempty"`
	Resolved   string `json:"resolved,omitempty"`
	Source     string `json:"source"`
}

type jsonFinding struct {
	Kind       string         `json:"kind"`
	Severity   string         `json:"severity"`
	Title      string         `json:"title"`
	Detail     string         `json:"detail,omitempty"`
	Component  jsonComponent  `json:"component"`
	FixedIn    string         `json:"fixed_in,omitempty"`
	Source     string         `json:"source"`
	ID         string         `json:"id,omitempty"`
	Aliases    []string       `json:"aliases,omitempty"`
	References []string       `json:"references,omitempty"`
	Guidance   []jsonGuidance `json:"guidance,omitempty"`
}

type jsonGuidance struct {
	Framework string `json:"framework"`
	Clause    string `json:"clause"`
	Statement string `json:"statement"`
	URL       string `json:"url"`
}

// jsonCoverage states the limits of the scan next to its results, so a consumer
// can tell an empty finding list from an unanswered question.
type jsonCoverage struct {
	Complete            bool            `json:"complete"`
	VulnerabilitySource string          `json:"vulnerability_source,omitempty"`
	ComponentsQueried   int             `json:"components_queried"`
	Unchecked           []jsonComponent `json:"unchecked,omitempty"`
	UnreadableFiles     []string        `json:"unreadable_files,omitempty"`
	Warnings            []string        `json:"warnings,omitempty"`
	KnownNamesCompared  map[string]int  `json:"known_names_compared,omitempty"`
}

// JSON writes the report as a single JSON document.
func JSON(w io.Writer, r Report) error {
	out := jsonReport{
		Tool:       r.Tool,
		Version:    r.Version,
		Path:       r.Path,
		Sources:    nonNil(r.Sources),
		Summary:    summarize(r),
		Components: make([]jsonComponent, 0, len(r.Components)),
		Findings:   make([]jsonFinding, 0, len(r.Findings)),
		Coverage: jsonCoverage{
			Complete:            r.Complete(),
			VulnerabilitySource: r.VulnerabilitySource,
			ComponentsQueried:   r.Queried,
			Unchecked:           convertComponents(r.Unchecked),
			UnreadableFiles:     r.Unreadable,
			Warnings:            r.Warnings,
			KnownNamesCompared:  r.KnownNames,
		},
	}
	for _, c := range r.Components {
		out.Components = append(out.Components, convertComponent(c))
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, convertFinding(f))
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(out)
}

// summarize counts what the report holds.
func summarize(r Report) jsonSummary {
	summary := jsonSummary{
		Components: len(r.Components),
		Findings:   len(r.Findings),
		BySeverity: map[string]int{},
	}
	for _, c := range r.Components {
		if c.Direct {
			summary.Direct++
		}
		if c.Dev {
			summary.Dev++
		}
		if !c.Pinned() {
			summary.Unpinned++
		}
	}
	for severity, count := range finding.CountBySeverity(r.Findings) {
		summary.BySeverity[severity.String()] = count
	}
	return summary
}

func convertComponent(c component.Component) jsonComponent {
	return jsonComponent{
		Name:       c.Name,
		Version:    c.Version,
		Ecosystem:  string(c.Ecosystem),
		PURL:       c.PURL(),
		Direct:     c.Direct,
		Dev:        c.Dev,
		Pinned:     c.Pinned(),
		Constraint: c.Constraint,
		Resolved:   c.Resolved,
		Source:     c.Source,
	}
}

func convertComponents(components []component.Component) []jsonComponent {
	if len(components) == 0 {
		return nil
	}
	out := make([]jsonComponent, 0, len(components))
	for _, c := range components {
		out = append(out, convertComponent(c))
	}
	return out
}

func convertFinding(f finding.Finding) jsonFinding {
	out := jsonFinding{
		Kind:       string(f.Kind),
		Severity:   f.Severity.String(),
		Title:      f.Title,
		Detail:     f.Detail,
		Component:  convertComponent(f.Component),
		FixedIn:    f.FixedIn,
		Source:     f.Source,
		ID:         f.ID,
		Aliases:    f.Aliases,
		References: f.References,
	}
	for _, ref := range guidance.For(f.Kind) {
		out.Guidance = append(out.Guidance, jsonGuidance{
			Framework: ref.Framework,
			Clause:    ref.Clause,
			Statement: ref.Statement,
			URL:       ref.URL,
		})
	}
	return out
}

// nonNil keeps an empty list out of the JSON as [] rather than null, which is
// friendlier to consumers that iterate without checking.
func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
