package osv

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
)

// The request and response shapes of the OSV API. Only the fields this scanner
// acts on are declared; the rest of a record is left unread rather than
// half-understood.

type batchRequest struct {
	Queries []query `json:"queries"`
}

type query struct {
	Version string       `json:"version,omitempty"`
	Package queryPackage `json:"package"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

type batchResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

// vulnerability is one OSV record.
type vulnerability struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Summary          string          `json:"summary"`
	Details          string          `json:"details"`
	Withdrawn        string          `json:"withdrawn"`
	Severity         []severityEntry `json:"severity"`
	Affected         []affected      `json:"affected"`
	References       []reference     `json:"references"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type severityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type affected struct {
	Package          queryPackage    `json:"package"`
	Ranges           []versionRange  `json:"ranges"`
	Versions         []string        `json:"versions"`
	Severity         []severityEntry `json:"severity"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

type versionRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

type reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// maxDetailLength caps how much of an advisory's prose is quoted. The full text
// is a page of markdown; the finding carries the first part of it and a link to
// the rest, so a terminal report stays readable.
const maxDetailLength = 280

// toFinding turns an advisory into a finding about one component.
func (v vulnerability) toFinding(comp component.Component) finding.Finding {
	f := finding.Finding{
		Kind:       finding.KindVulnerability,
		Severity:   v.severity(comp),
		Component:  comp,
		Title:      v.title(comp),
		Detail:     summarize(v.Details),
		FixedIn:    v.fixedIn(comp),
		Source:     "OSV",
		ID:         v.ID,
		Aliases:    v.Aliases,
		References: v.referenceURLs(),
	}
	if f.Detail == "" {
		f.Detail = strings.TrimSpace(v.Summary)
	}
	return f
}

// title states the advisory in one line.
func (v vulnerability) title(comp component.Component) string {
	summary := strings.TrimSpace(v.Summary)
	if summary == "" {
		return fmt.Sprintf("%s affects %s %s", v.ID, comp.Name, comp.Version)
	}
	return summary
}

// severity ranks the advisory. A CVSS vector is scored rather than trusted to
// come with a number, and the qualitative word a database attached is only used
// when no vector is published.
func (v vulnerability) severity(comp component.Component) finding.Severity {
	entries := append([]severityEntry{}, v.Severity...)
	for _, a := range v.Affected {
		if a.matches(comp) {
			entries = append(entries, a.Severity...)
		}
	}

	highest := finding.Unknown
	for _, entry := range entries {
		if !strings.EqualFold(entry.Type, "CVSS_V3") {
			// CVSS v2 and v4 vectors are scored by formulas this tool does not
			// implement. Using the v3 arithmetic on them would produce a
			// confident wrong answer.
			continue
		}
		score, ok := scoreCVSS(entry.Score)
		if !ok {
			continue
		}
		if s := finding.FromCVSSScore(score); s > highest {
			highest = s
		}
	}
	if highest != finding.Unknown {
		return highest
	}

	// No usable vector: fall back to the word the database recorded.
	for _, raw := range []json.RawMessage{v.DatabaseSpecific, v.affectedDatabaseSpecific(comp)} {
		if s, ok := severityFromDatabaseSpecific(raw); ok {
			return s
		}
	}
	return finding.Unknown
}

// affectedDatabaseSpecific returns the database-specific block of the affected
// entry for this component, if there is one.
func (v vulnerability) affectedDatabaseSpecific(comp component.Component) json.RawMessage {
	for _, a := range v.Affected {
		if a.matches(comp) && len(a.DatabaseSpecific) > 0 {
			return a.DatabaseSpecific
		}
	}
	return nil
}

// severityFromDatabaseSpecific reads the qualitative severity some databases
// record outside the standard fields, as GitHub advisories do.
func severityFromDatabaseSpecific(raw json.RawMessage) (finding.Severity, bool) {
	if len(raw) == 0 {
		return finding.Unknown, false
	}
	var block struct {
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(raw, &block); err != nil {
		return finding.Unknown, false
	}
	return finding.ParseSeverity(block.Severity)
}

// fixedIn lists the versions that carry the fix. Several can apply when a
// project maintains more than one release line, and picking one of them would
// mean comparing versions by rules that differ per ecosystem - so all of them
// are stated and the reviewer picks the line they are on.
func (v vulnerability) fixedIn(comp component.Component) string {
	seen := map[string]bool{}
	var versions []string
	for _, a := range v.Affected {
		if !a.matches(comp) {
			continue
		}
		for _, r := range a.Ranges {
			for _, event := range r.Events {
				fixed := event["fixed"]
				if fixed == "" || seen[fixed] {
					continue
				}
				seen[fixed] = true
				versions = append(versions, fixed)
			}
		}
	}
	sort.Strings(versions)
	return strings.Join(versions, ", ")
}

// referenceURLs returns the most useful links, advisories first.
func (v vulnerability) referenceURLs() []string {
	const maxReferences = 3
	priority := map[string]int{"ADVISORY": 0, "FIX": 1, "REPORT": 2, "WEB": 3}
	rank := func(t string) int {
		if p, ok := priority[strings.ToUpper(t)]; ok {
			return p
		}
		return len(priority)
	}

	ordered := append([]reference{}, v.References...)
	sort.SliceStable(ordered, func(i, j int) bool { return rank(ordered[i].Type) < rank(ordered[j].Type) })

	var urls []string
	for _, r := range ordered {
		if r.URL == "" {
			continue
		}
		urls = append(urls, r.URL)
		if len(urls) == maxReferences {
			break
		}
	}
	return urls
}

// matches reports whether an affected entry is about this component. OSV states
// package names in each ecosystem's own normalized form, which is what the
// component model already applies.
func (a affected) matches(comp component.Component) bool {
	if !strings.EqualFold(a.Package.Ecosystem, string(comp.Ecosystem)) {
		return false
	}
	return comp.Ecosystem.NormalizeName(a.Package.Name) == comp.Ecosystem.NormalizeName(comp.Name)
}

// summarize shortens advisory prose to something a terminal report can carry,
// cutting at a word boundary rather than mid-word.
func summarize(details string) string {
	text := strings.TrimSpace(details)
	if text == "" {
		return ""
	}
	// Advisories are written in markdown; the first paragraph is the summary.
	if idx := strings.Index(text, "\n\n"); idx > 0 {
		text = text[:idx]
	}
	text = strings.Join(strings.Fields(text), " ")
	if len(text) <= maxDetailLength {
		return text
	}
	cut := strings.LastIndex(text[:maxDetailLength], " ")
	if cut < maxDetailLength/2 {
		cut = maxDetailLength
	}
	return strings.TrimSpace(text[:cut]) + "..."
}
