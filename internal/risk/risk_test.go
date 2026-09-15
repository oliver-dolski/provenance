package risk

import (
	"strings"
	"testing"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
)

// findingsFor runs the checks over one component and indexes them by kind.
func findingsFor(c component.Component) map[finding.Kind]finding.Finding {
	byKind := make(map[finding.Kind]finding.Finding)
	for _, f := range Check([]component.Component{c}) {
		byKind[f.Kind] = f
	}
	return byKind
}

func TestUnpinnedDependencyIsReported(t *testing.T) {
	got := findingsFor(component.Component{
		Name:       "requests",
		Ecosystem:  component.PyPI,
		Constraint: ">=2.31.0",
		Direct:     true,
		Source:     "requirements.txt",
	})

	f, ok := got[finding.KindUnpinned]
	if !ok {
		t.Fatal("an unpinned direct dependency was not reported")
	}
	if f.Severity != finding.Medium {
		t.Errorf("Severity = %s, want medium for a direct runtime dependency", f.Severity)
	}
	if !strings.Contains(f.Detail, ">=2.31.0") || !strings.Contains(f.Detail, "requirements.txt") {
		t.Errorf("Detail = %q, want the constraint and the file it was read from", f.Detail)
	}
}

func TestUnpinnedDevDependencyRanksLower(t *testing.T) {
	got := findingsFor(component.Component{
		Name: "jest", Ecosystem: component.NPM, Constraint: "^29.0.0", Direct: true, Dev: true,
	})
	if got[finding.KindUnpinned].Severity != finding.Low {
		t.Errorf("Severity = %s, want low: a test dependency does not ship", got[finding.KindUnpinned].Severity)
	}
}

func TestPinnedDependencyIsNotReported(t *testing.T) {
	got := findingsFor(component.Component{
		Name: "lodash", Ecosystem: component.NPM, Version: "4.17.21",
		Resolved:  "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
		Integrity: "sha512-abc",
	})
	if len(got) != 0 {
		t.Errorf("a pinned package from the public registry produced findings: %v", got)
	}
}

func TestUnscopedPrivatePackageRanksHigher(t *testing.T) {
	got := findingsFor(component.Component{
		Name: "internal-auth", Ecosystem: component.NPM, Version: "1.0.0",
		Resolved:  "https://npm.internal.example.com/internal-auth/-/internal-auth-1.0.0.tgz",
		Integrity: "sha512-abc",
		Source:    "package-lock.json",
	})

	f, ok := got[finding.KindPrivateSource]
	if !ok {
		t.Fatal("a package from a private registry was not reported")
	}
	if f.Severity != finding.High {
		t.Errorf("Severity = %s, want high: an unscoped name can be claimed on the public registry", f.Severity)
	}
	if !strings.Contains(f.Title, "npm.internal.example.com") {
		t.Errorf("Title = %q, want the host it is fetched from", f.Title)
	}
}

func TestScopedPrivatePackageRanksLower(t *testing.T) {
	got := findingsFor(component.Component{
		Name: "@acme/ui", Ecosystem: component.NPM, Version: "1.0.0",
		Resolved:  "https://npm.internal.example.com/@acme/ui/-/ui-1.0.0.tgz",
		Integrity: "sha512-abc",
	})
	if got[finding.KindPrivateSource].Severity != finding.Medium {
		t.Errorf("Severity = %s, want medium: the scope is owned on the public registry too",
			got[finding.KindPrivateSource].Severity)
	}
}

func TestPrivateIndexIsReportedForPyPI(t *testing.T) {
	got := findingsFor(component.Component{
		Name: "internal-lib", Ecosystem: component.PyPI, Version: "0.4.1",
		Resolved: "https://pypi.internal.example.com/simple",
		Source:   "poetry.lock",
	})
	if _, ok := got[finding.KindPrivateSource]; !ok {
		t.Fatal("a package from a private index was not reported")
	}
}

func TestLocalPathIsNotAPrivateRegistry(t *testing.T) {
	got := findingsFor(component.Component{
		Name: "shared", Ecosystem: component.NPM, Version: "1.0.0", Resolved: "packages/shared",
	})
	if _, ok := got[finding.KindPrivateSource]; ok {
		t.Error("a path inside the repository was reported as a private registry")
	}
	if _, ok := got[finding.KindMissingIntegrity]; ok {
		t.Error("local source was reported as missing an integrity hash")
	}
}

func TestMissingIntegrityIsReported(t *testing.T) {
	got := findingsFor(component.Component{
		Name: "lodash", Ecosystem: component.NPM, Version: "4.17.21",
		Resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
		Source:   "package-lock.json",
	})
	f, ok := got[finding.KindMissingIntegrity]
	if !ok {
		t.Fatal("a locked package without a hash was not reported")
	}
	if f.Severity != finding.Low {
		t.Errorf("Severity = %s, want low", f.Severity)
	}
}

func TestTyposquatIsReported(t *testing.T) {
	got := findingsFor(component.Component{
		Name: "loadsh", Ecosystem: component.NPM, Version: "1.0.0", Source: "package.json",
	})
	f, ok := got[finding.KindTyposquat]
	if !ok {
		t.Fatal("a name one transposition away from lodash was not reported")
	}
	if !strings.Contains(f.Title, "lodash") {
		t.Errorf("Title = %q, want the package it resembles", f.Title)
	}
}

func TestPopularPackageIsNotItsOwnTyposquat(t *testing.T) {
	for _, c := range []component.Component{
		{Name: "lodash", Ecosystem: component.NPM, Version: "4.17.21"},
		{Name: "Flask", Ecosystem: component.PyPI, Version: "3.0.0"},
	} {
		if _, ok := findingsFor(c)[finding.KindTyposquat]; ok {
			t.Errorf("%s was reported as an imitation of itself", c.Name)
		}
	}
}

func TestScopedNamesAreNotComparedForTyposquatting(t *testing.T) {
	got := findingsFor(component.Component{
		Name: "@types/loadsh", Ecosystem: component.NPM, Version: "1.0.0",
	})
	if _, ok := got[finding.KindTyposquat]; ok {
		t.Error("a scoped name was compared: the scope owner decides what it serves")
	}
}

func TestIsOneTypoApart(t *testing.T) {
	near := [][2]string{
		{"loadsh", "lodash"},    // two characters swapped
		{"lodahs", "lodash"},    // swapped at the end
		{"lodas", "lodash"},     // one character deleted
		{"lodashh", "lodash"},   // one character inserted
		{"ledash", "lodash"},    // one character substituted
		{"reqests", "requests"}, // a dropped letter mid-word
		{"djanga", "django"},
	}
	for _, pair := range near {
		if !isOneTypoApart(pair[0], pair[1]) {
			t.Errorf("isOneTypoApart(%q, %q) = false, want true", pair[0], pair[1])
		}
	}

	far := [][2]string{
		{"lodash", "lodash"},              // the same name is not a typo of itself
		{"lodash", "lodash.merge"},        // a longer name in the same family
		{"requests", "requests-oauthlib"}, // likewise
		{"numpy", "scipy"},                // three substitutions
		{"sass", "sax"},                   // shorter, but not by one deletion
		{"jest", "test"},                  // one substitution, but see the caller
	}
	for _, pair := range far[:len(far)-1] {
		if isOneTypoApart(pair[0], pair[1]) {
			t.Errorf("isOneTypoApart(%q, %q) = true, want false", pair[0], pair[1])
		}
	}
	// The last pair is one substitution apart and the function says so. What
	// keeps it out of the report is that "test" is not on the bundled list.
	if !isOneTypoApart("jest", "test") {
		t.Error(`isOneTypoApart("jest", "test") = false: this function only measures distance`)
	}
}

func TestPopularNameCountIsStated(t *testing.T) {
	// The report tells the reader how wide the comparison was, so a count of
	// zero would be a silently useless check.
	for _, eco := range []component.Ecosystem{component.NPM, component.PyPI} {
		if PopularNameCount(eco) < 50 {
			t.Errorf("%s list holds %d names, want a list worth comparing against", eco, PopularNameCount(eco))
		}
	}
}

func TestFindingsAreSortedBySeverity(t *testing.T) {
	findings := Check([]component.Component{
		{Name: "requests", Ecosystem: component.PyPI, Constraint: ">=2.0", Direct: true},
		{Name: "internal-auth", Ecosystem: component.NPM, Version: "1.0.0",
			Resolved: "https://npm.internal.example.com/internal-auth.tgz", Integrity: "sha512-abc"},
	})
	if len(findings) < 2 {
		t.Fatalf("got %d findings, want at least 2", len(findings))
	}
	if findings[0].Severity < findings[1].Severity {
		t.Error("findings are not ordered most severe first")
	}
}
