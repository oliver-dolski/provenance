package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oliver-dolski/provenance/internal/component"
)

// scanSample parses the committed sample project and indexes it by package name.
func scanSample(t *testing.T) map[string]component.Component {
	t.Helper()
	set, problems, err := Scan(filepath.Join("testdata", "sample"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	byName := make(map[string]component.Component)
	for _, c := range set.All() {
		byName[c.Name] = c
	}
	return byName
}

func TestDiscoverFindsDependencyFiles(t *testing.T) {
	files, err := Discover(filepath.Join("testdata", "sample"))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	want := map[string]Kind{
		"package-lock.json":     KindNPMLock,
		"poetry.lock":           KindPoetryLock,
		"package.json":          KindNPMManifest,
		"requirements.txt":      KindRequirements,
		"requirements/base.txt": KindRequirements,
	}
	if len(files) != len(want) {
		t.Fatalf("found %d files, want %d: %v", len(files), len(want), files)
	}
	for _, f := range files {
		kind, ok := want[f.Rel]
		if !ok {
			t.Errorf("unexpected file %q", f.Rel)
			continue
		}
		if kind != f.Kind {
			t.Errorf("%s classified as %s, want %s", f.Rel, f.Kind, kind)
		}
	}
	// Lockfiles must be parsed before manifests, so that declarations annotate
	// resolved components instead of duplicating them.
	for i, f := range files {
		if !f.Kind.resolvesVersions() {
			continue
		}
		for j := 0; j < i; j++ {
			if !files[j].Kind.resolvesVersions() {
				t.Fatalf("%s (declaration) sorted before lockfile %s", files[j].Rel, f.Rel)
			}
		}
	}
}

func TestDiscoverSkipsInstalledPackages(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"dependencies":{"express":"^4.0.0"}}`)
	mustWrite(t, filepath.Join(root, "node_modules", "express", "package.json"), `{"dependencies":{"ms":"2.0.0"}}`)
	mustWrite(t, filepath.Join(root, ".venv", "requirements.txt"), `flask==3.0.0`)
	mustWrite(t, filepath.Join(root, ".git", "package.json"), `{}`)

	files, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(files) != 1 || files[0].Rel != "package.json" {
		t.Fatalf("found %v, want only the project's own package.json", files)
	}
}

func TestScanResolvesVersionsAndDirectness(t *testing.T) {
	byName := scanSample(t)

	cases := []struct {
		name       string
		version    string
		direct     bool
		dev        bool
		constraint string
	}{
		{name: "express", version: "4.18.2", direct: true, constraint: "^4.18.2"},
		{name: "lodash", version: "4.17.21", direct: true, constraint: "4.17.21"},
		{name: "ms", version: "2.0.0", direct: false},
		{name: "jest", version: "29.7.0", direct: true, dev: true, constraint: "^29.7.0"},
		{name: "click", version: "8.1.7"},
		{name: "pytest", version: "8.0.0", dev: true},
		{name: "Flask", version: "3.0.0", direct: true, constraint: "==3.0.0"},
		{name: "certifi", version: "2024.2.2", direct: true, constraint: "==2024.2.2"},
	}
	for _, tc := range cases {
		got, ok := byName[tc.name]
		if !ok {
			t.Errorf("%s not found", tc.name)
			continue
		}
		if got.Version != tc.version {
			t.Errorf("%s version = %q, want %q", tc.name, got.Version, tc.version)
		}
		if got.Direct != tc.direct {
			t.Errorf("%s direct = %v, want %v", tc.name, got.Direct, tc.direct)
		}
		if got.Dev != tc.dev {
			t.Errorf("%s dev = %v, want %v", tc.name, got.Dev, tc.dev)
		}
		if tc.constraint != "" && got.Constraint != tc.constraint {
			t.Errorf("%s constraint = %q, want %q", tc.name, got.Constraint, tc.constraint)
		}
	}
}

func TestScanKeepsUnpinnedDependencies(t *testing.T) {
	byName := scanSample(t)

	for _, name := range []string{"requests", "urllib3"} {
		got, ok := byName[name]
		if !ok {
			t.Fatalf("%s not found: an unpinned dependency is a finding, not something to drop", name)
		}
		if got.Pinned() {
			t.Errorf("%s reported as pinned (version %q)", name, got.Version)
		}
		if got.Constraint == "" {
			t.Errorf("%s has no constraint recorded, so a finding could not quote it", name)
		}
	}
}

func TestScanReadsIncludedRequirements(t *testing.T) {
	byName := scanSample(t)
	got, ok := byName["certifi"]
	if !ok {
		t.Fatal("certifi not found: the -r include was not followed")
	}
	if got.Source != "requirements/base.txt" {
		t.Errorf("certifi source = %q, want the included file it was declared in", got.Source)
	}
}

func TestScanRecordsNonPublicSources(t *testing.T) {
	byName := scanSample(t)

	npmPkg, ok := byName["@internal/ui-kit"]
	if !ok {
		t.Fatal("@internal/ui-kit not found")
	}
	if npmPkg.Resolved != "https://npm.internal.example.com/@internal/ui-kit/-/ui-kit-2.3.0.tgz" {
		t.Errorf("@internal/ui-kit resolved = %q, want the private registry URL", npmPkg.Resolved)
	}

	pyPkg, ok := byName["internal-lib"]
	if !ok {
		t.Fatal("internal-lib not found")
	}
	if pyPkg.Resolved != "https://pypi.internal.example.com/simple" {
		t.Errorf("internal-lib resolved = %q, want the private index from [package.source]", pyPkg.Resolved)
	}
}

func TestScanSkipsWorkspaceLinks(t *testing.T) {
	byName := scanSample(t)
	if _, ok := byName["@sample/shared"]; ok {
		t.Error("@sample/shared reported as a component: it is local source, not a registry package")
	}
}

func TestScanNormalizesPyPINames(t *testing.T) {
	byName := scanSample(t)
	got, ok := byName["zope.interface"]
	if !ok {
		t.Fatal("zope.interface not found")
	}
	if got.Version != "6.1" {
		t.Errorf("version = %q, want 6.1: spaces around == are legal", got.Version)
	}
	if got.PURL() != "pkg:pypi/zope-interface@6.1" {
		t.Errorf("PURL = %q, want the PEP 503 normalized form", got.PURL())
	}
}

func TestScanReportsUnreadableFileAndContinues(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package.json"), `{"dependencies":{"express":"^4.0.0"}}`)
	mustWrite(t, filepath.Join(root, "broken", "package.json"), `{"dependencies": `)

	set, problems, err := Scan(root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(problems) != 1 || problems[0].File != "broken/package.json" {
		t.Fatalf("problems = %v, want exactly the malformed file", problems)
	}
	if set.Len() != 1 {
		t.Errorf("Len = %d, want the readable manifest still parsed", set.Len())
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
