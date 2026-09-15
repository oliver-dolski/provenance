// Package finding defines what the scanner reports. Every finding states the
// component it is about, why it was raised and where that reasoning comes from,
// so a reviewer can judge it instead of taking the tool's word.
package finding

import (
	"sort"
	"strings"

	"github.com/oliver-dolski/provenance/internal/component"
)

// Severity ranks how much attention a finding deserves. Unknown is its own
// rank rather than a default to Low: a vulnerability nobody has scored is not
// the same as one scored as minor.
type Severity int

const (
	Unknown Severity = iota
	Low
	Medium
	High
	Critical
)

// severityNames maps each severity to the word used in output and on the
// command line.
var severityNames = map[Severity]string{
	Unknown:  "unknown",
	Low:      "low",
	Medium:   "medium",
	High:     "high",
	Critical: "critical",
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "unknown"
}

// ParseSeverity reads a severity word, as a command-line flag or a
// vulnerability database states it.
func ParseSeverity(value string) (Severity, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	// Some databases use "moderate" where the CVSS bands say "medium".
	if normalized == "moderate" {
		normalized = "medium"
	}
	for severity, name := range severityNames {
		if name == normalized {
			return severity, true
		}
	}
	return Unknown, false
}

// FromCVSSScore maps a CVSS base score onto the qualitative bands defined by
// the CVSS specification.
func FromCVSSScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	default:
		return Unknown
	}
}

// Kind is what sort of problem a finding describes. It decides the guidance
// attached to it and lets a reader filter the report.
type Kind string

const (
	// KindVulnerability is a published vulnerability affecting the component.
	KindVulnerability Kind = "vulnerability"
	// KindUnpinned is a dependency that is not fixed to one version.
	KindUnpinned Kind = "unpinned"
	// KindPrivateSource is a component fetched from somewhere other than the
	// ecosystem's public registry.
	KindPrivateSource Kind = "private-source"
	// KindTyposquat is a name close enough to a widely used package to be
	// worth a second look.
	KindTyposquat Kind = "typosquat"
	// KindMissingIntegrity is a locked component with no integrity hash, so
	// nothing detects the artifact being swapped.
	KindMissingIntegrity Kind = "missing-integrity"
)

// Finding is one reported problem.
type Finding struct {
	Kind      Kind
	Severity  Severity
	Component component.Component

	// Title is the one-line statement of the problem.
	Title string
	// Detail says why this was raised, in terms of what was actually read.
	Detail string
	// FixedIn names the version that resolves it, when one is known.
	FixedIn string

	// Source is where the claim comes from - a vulnerability database, or this
	// scanner's own check. A reviewer weighs a finding by its source.
	Source string
	// ID is the identifier in that source, such as an OSV or GHSA identifier.
	ID string
	// Aliases are the same issue's identifiers elsewhere, usually a CVE.
	Aliases []string
	// References are links supporting the finding.
	References []string
}

// Sort orders findings by severity first and then by component, so the report
// reads top down and two scans of the same project produce the same order.
func Sort(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		an := a.Component.Ecosystem.NormalizeName(a.Component.Name)
		bn := b.Component.Ecosystem.NormalizeName(b.Component.Name)
		if an != bn {
			return an < bn
		}
		if a.Component.Version != b.Component.Version {
			return a.Component.Version < b.Component.Version
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.ID < b.ID
	})
}

// CountBySeverity tallies findings for the summary line.
func CountBySeverity(findings []Finding) map[Severity]int {
	counts := make(map[Severity]int, len(severityNames))
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// Highest returns the most severe finding's severity, or Unknown when there
// are none.
func Highest(findings []Finding) Severity {
	highest := Unknown
	for _, f := range findings {
		if f.Severity > highest {
			highest = f.Severity
		}
	}
	return highest
}
