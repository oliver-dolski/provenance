package osv

import (
	"sort"

	"github.com/oliver-dolski/provenance/internal/finding"
)

// dedupe folds advisories that describe the same issue into one finding.
//
// OSV aggregates several databases, and the same vulnerability commonly arrives
// as two or three records: a GitHub advisory, an ecosystem-specific one, and a
// CVE. Each names the others in its aliases. Reported as they arrive, four
// packages can produce twenty-seven findings for fourteen problems, and the
// reader loses the ability to count what they are facing.
//
// Records are grouped per component by the transitive closure of their
// identifiers, and each group is reported once, under the record that carries
// the most usable information.
func dedupe(findings []finding.Finding) []finding.Finding {
	type group struct {
		component string
		ids       map[string]bool
		best      finding.Finding
	}

	var groups []*group
	for _, f := range findings {
		ids := identifiers(f)
		key := f.Component.Key()

		// Every group that shares an identifier with this finding describes the
		// same issue, so they collapse together with it.
		var target *group
		kept := groups[:0]
		for _, g := range groups {
			if g.component != key || !intersects(g.ids, ids) {
				kept = append(kept, g)
				continue
			}
			if target == nil {
				target = g
				kept = append(kept, g)
				continue
			}
			for id := range g.ids {
				target.ids[id] = true
			}
			target.best = merge(target.best, g.best)
		}
		groups = kept

		if target == nil {
			groups = append(groups, &group{component: key, ids: ids, best: f})
			continue
		}
		for id := range ids {
			target.ids[id] = true
		}
		target.best = merge(target.best, f)
	}

	out := make([]finding.Finding, 0, len(groups))
	for _, g := range groups {
		best := g.best
		best.Aliases = otherIdentifiers(g.ids, best.ID)
		out = append(out, best)
	}
	return out
}

// identifiers is everything an advisory calls itself and its aliases.
func identifiers(f finding.Finding) map[string]bool {
	ids := make(map[string]bool, len(f.Aliases)+1)
	if f.ID != "" {
		ids[f.ID] = true
	}
	for _, alias := range f.Aliases {
		if alias != "" {
			ids[alias] = true
		}
	}
	return ids
}

// intersects reports whether two identifier sets name anything in common.
func intersects(a, b map[string]bool) bool {
	// Walking the smaller set keeps this cheap on advisories with long alias
	// lists.
	if len(b) < len(a) {
		a, b = b, a
	}
	for id := range a {
		if b[id] {
			return true
		}
	}
	return false
}

// otherIdentifiers lists the group's identifiers apart from the reported one,
// so nothing that was folded in becomes unfindable.
func otherIdentifiers(ids map[string]bool, reported string) []string {
	others := make([]string, 0, len(ids))
	for id := range ids {
		if id != reported {
			others = append(others, id)
		}
	}
	if len(others) == 0 {
		return nil
	}
	// Sorted, which also puts CVE identifiers first, and makes the output the
	// same on every run.
	sort.Strings(others)
	return others
}

// merge picks which of two records for the same issue to report, and fills what
// the winner does not carry from the other. A record with no severity is
// usually a mirror of one that has it; taking the fuller record means the
// reader sees the fix version and the links, not the sparsest copy.
func merge(a, b finding.Finding) finding.Finding {
	winner, loser := a, b
	if prefer(b, a) {
		winner, loser = b, a
	}

	if winner.Detail == "" {
		winner.Detail = loser.Detail
	}
	if winner.FixedIn == "" {
		winner.FixedIn = loser.FixedIn
	}
	if len(winner.References) == 0 {
		winner.References = loser.References
	}
	if winner.Severity == finding.Unknown {
		winner.Severity = loser.Severity
	}
	return winner
}

// prefer reports whether candidate should be reported instead of current.
func prefer(candidate, current finding.Finding) bool {
	if candidate.Severity != current.Severity {
		return candidate.Severity > current.Severity
	}
	if c, o := completeness(candidate), completeness(current); c != o {
		return c > o
	}
	// Nothing separates them on content, so the identifier decides and the
	// report reads the same on every run.
	return candidate.ID < current.ID
}

// completeness scores how much of an advisory a record actually carries.
func completeness(f finding.Finding) int {
	score := 0
	if f.Detail != "" {
		score++
	}
	if f.FixedIn != "" {
		score++
	}
	if len(f.References) > 0 {
		score++
	}
	return score
}
