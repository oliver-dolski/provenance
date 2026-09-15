// Package component defines the normalized dependency model. Every manifest
// parser produces components in this shape, and every consumer - the SBOM
// writer, the vulnerability lookup, the risk checks - reads them in this shape.
// Keeping one model in the middle means a new ecosystem only needs a parser.
package component

import (
	"fmt"
	"sort"
	"strings"
)

// Ecosystem identifies the package registry a component comes from. The values
// match the ecosystem names used by OSV, so they can be sent to the API as-is.
type Ecosystem string

const (
	NPM  Ecosystem = "npm"
	PyPI Ecosystem = "PyPI"
)

// purlType returns the package URL type for the ecosystem, which is spelled
// differently from the OSV name.
func (e Ecosystem) purlType() string {
	switch e {
	case NPM:
		return "npm"
	case PyPI:
		return "pypi"
	default:
		return strings.ToLower(string(e))
	}
}

// NormalizeName applies the ecosystem's own name-comparison rules. PyPI treats
// runs of "-", "_" and "." as equivalent and is case-insensitive (PEP 503), so
// "Flask_Login" and "flask-login" are the same project. npm names are already
// lowercase by registry rule and are left untouched.
func (e Ecosystem) NormalizeName(name string) string {
	if e != PyPI {
		return name
	}
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		b.WriteRune(r)
		lastDash = false
	}
	return strings.Trim(b.String(), "-")
}

// Component is one dependency of the scanned project.
type Component struct {
	Name      string
	Ecosystem Ecosystem

	// Version is the exact resolved version. It is empty when the manifest only
	// states a range and no lockfile pins it down.
	Version string

	// Constraint is the raw version expression as written in the manifest
	// ("^1.2.3", ">=2.0"). It is kept verbatim so a finding can quote it.
	Constraint string

	// Direct marks a dependency the project declares itself, as opposed to one
	// pulled in by another dependency.
	Direct bool

	// Dev marks a dependency needed only to develop or test the project.
	Dev bool

	// Resolved is the URL the lockfile recorded for the package, when present.
	// A host other than the ecosystem's public registry is worth a look.
	Resolved string

	// Integrity is the lockfile's content hash for the package, when present.
	Integrity string

	// Source is the manifest the component was read from, relative to the scan
	// root, so every finding can point at a file the reviewer can open.
	Source string
}

// PURL returns the package URL for the component. Version is omitted when it is
// not known, which keeps the identifier honest rather than inventing a version.
func (c Component) PURL() string {
	name := c.Ecosystem.NormalizeName(c.Name)
	// npm scopes ("@scope/name") keep their slash: it is a namespace separator
	// in a package URL, not a character to escape.
	purl := fmt.Sprintf("pkg:%s/%s", c.Ecosystem.purlType(), name)
	if c.Version != "" {
		purl += "@" + c.Version
	}
	return purl
}

// Pinned reports whether the component is fixed to a single version. An
// unpinned dependency makes a build unreproducible and lets a later release of
// that package enter the project without review.
func (c Component) Pinned() bool {
	return c.Version != ""
}

// Key identifies a component for deduplication: the same package at the same
// version, however many manifests mention it, is one component.
func (c Component) Key() string {
	return string(c.Ecosystem) + "|" + c.Ecosystem.NormalizeName(c.Name) + "|" + c.Version
}

// Set collects components, merging duplicates instead of listing a package
// twice because two manifests both declared it.
type Set struct {
	order []string
	byKey map[string]*Component
}

// NewSet returns an empty Set.
func NewSet() *Set {
	return &Set{byKey: make(map[string]*Component)}
}

// Add stores a component, merging it into an existing entry with the same key.
// Merging keeps the stronger claim: a direct dependency stays direct, a runtime
// dependency is not downgraded to dev, and known lockfile detail is not lost.
func (s *Set) Add(c Component) {
	key := c.Key()
	existing, ok := s.byKey[key]
	if !ok {
		copied := c
		s.byKey[key] = &copied
		s.order = append(s.order, key)
		return
	}
	if c.Direct {
		existing.Direct = true
	}
	// Dev is only true when every sighting agrees it is dev-only.
	if !c.Dev {
		existing.Dev = false
	}
	if existing.Constraint == "" {
		existing.Constraint = c.Constraint
	}
	if existing.Resolved == "" {
		existing.Resolved = c.Resolved
	}
	if existing.Integrity == "" {
		existing.Integrity = c.Integrity
	}
	if existing.Source != c.Source && !strings.Contains(existing.Source, c.Source) {
		existing.Source += ", " + c.Source
	}
}

// Len returns the number of distinct components.
func (s *Set) Len() int { return len(s.byKey) }

// All returns the components sorted by ecosystem, then name, then version, so
// that two scans of an unchanged project produce byte-identical output.
func (s *Set) All() []Component {
	out := make([]Component, 0, len(s.byKey))
	for _, key := range s.order {
		out = append(out, *s.byKey[key])
	}
	Sort(out)
	return out
}

// Sort orders components deterministically.
func Sort(cs []Component) {
	sort.Slice(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		// Ecosystem names are compared case-insensitively: "npm" and "PyPI" are
		// spelled as OSV spells them, and raw byte order would put every
		// capitalized ecosystem ahead of every lowercase one.
		ae := strings.ToLower(string(a.Ecosystem))
		be := strings.ToLower(string(b.Ecosystem))
		if ae != be {
			return ae < be
		}
		an := a.Ecosystem.NormalizeName(a.Name)
		bn := b.Ecosystem.NormalizeName(b.Name)
		if an != bn {
			return an < bn
		}
		return a.Version < b.Version
	})
}
