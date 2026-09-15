package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/oliver-dolski/provenance/internal/component"
)

func testOptions() Options {
	return Options{
		ProjectName:  "sample-app",
		ToolVersion:  "1.2.3",
		Timestamp:    time.Date(2026, 9, 15, 10, 30, 0, 0, time.UTC),
		SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000",
	}
}

func TestBuildDocumentShape(t *testing.T) {
	bom, err := Build(nil, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != SpecVersion {
		t.Errorf("format = %q %q, want CycloneDX %s", bom.BOMFormat, bom.SpecVersion, SpecVersion)
	}
	if bom.Version != 1 {
		t.Errorf("Version = %d, want 1", bom.Version)
	}
	if bom.Metadata.Timestamp != "2026-09-15T10:30:00Z" {
		t.Errorf("Timestamp = %q, want RFC 3339 in UTC", bom.Metadata.Timestamp)
	}
	if len(bom.Metadata.Tools.Components) != 1 || bom.Metadata.Tools.Components[0].Version != "1.2.3" {
		t.Errorf("tool metadata = %+v, want this scanner and its version", bom.Metadata.Tools.Components)
	}
	if bom.Metadata.Component == nil || bom.Metadata.Component.Name != "sample-app" {
		t.Errorf("metadata component = %+v, want the scanned project", bom.Metadata.Component)
	}
}

func TestBuildConvertsComponent(t *testing.T) {
	in := []component.Component{{
		Name:       "lodash",
		Ecosystem:  component.NPM,
		Version:    "4.17.21",
		Direct:     true,
		Constraint: "^4.17.0",
		Source:     "package-lock.json",
	}}
	bom, err := Build(in, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := bom.Components[0]
	if got.Type != "library" || got.Name != "lodash" || got.Version != "4.17.21" {
		t.Errorf("component = %+v, want the library lodash 4.17.21", got)
	}
	if got.PURL != "pkg:npm/lodash@4.17.21" || got.BOMRef != got.PURL {
		t.Errorf("purl = %q, bom-ref = %q, want both to be the package URL", got.PURL, got.BOMRef)
	}
	if got.Scope != "required" {
		t.Errorf("Scope = %q, want required for a runtime dependency", got.Scope)
	}
	want := map[string]string{
		"provenance:source":     "package-lock.json",
		"provenance:direct":     "true",
		"provenance:constraint": "^4.17.0",
	}
	for _, p := range got.Properties {
		if expected, ok := want[p.Name]; ok {
			if p.Value != expected {
				t.Errorf("%s = %q, want %q", p.Name, p.Value, expected)
			}
			delete(want, p.Name)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing properties: %v", want)
	}
}

func TestBuildMarksDevDependencyOptional(t *testing.T) {
	bom, err := Build([]component.Component{{
		Name: "jest", Ecosystem: component.NPM, Version: "29.7.0", Dev: true,
	}}, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if bom.Components[0].Scope != "optional" {
		t.Errorf("Scope = %q, want optional: a test dependency does not ship", bom.Components[0].Scope)
	}
}

func TestBuildFlagsUnpinnedComponent(t *testing.T) {
	bom, err := Build([]component.Component{{
		Name: "requests", Ecosystem: component.PyPI, Constraint: ">=2.31.0",
	}}, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := bom.Components[0]
	if got.Version != "" {
		t.Errorf("Version = %q, want empty: no version was resolved", got.Version)
	}
	var pinned string
	for _, p := range got.Properties {
		if p.Name == "provenance:pinned" {
			pinned = p.Value
		}
	}
	if pinned != "false" {
		t.Error("an unpinned component must say so: a missing version field is easy to read past")
	}
}

func TestBuildKeepsBOMRefsUnique(t *testing.T) {
	bom, err := Build([]component.Component{
		{Name: "requests", Ecosystem: component.PyPI, Constraint: ">=2.31.0", Source: "a.txt"},
		{Name: "requests", Ecosystem: component.PyPI, Constraint: "<3", Source: "b.txt"},
	}, testOptions())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if bom.Components[0].BOMRef == bom.Components[1].BOMRef {
		t.Fatalf("both components use bom-ref %q, which makes the document invalid", bom.Components[0].BOMRef)
	}
}

func TestConvertHash(t *testing.T) {
	// "sha512-" followed by base64; CycloneDX states hashes in hex.
	got, ok := convertHash("sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
	if !ok {
		t.Fatal("a valid integrity string was rejected")
	}
	if got.Alg != "SHA-256" {
		t.Errorf("Alg = %q, want SHA-256", got.Alg)
	}
	if got.Content != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("Content = %q, want the hex form of the empty-string digest", got.Content)
	}

	for _, bad := range []string{"", "not-an-integrity", "md5-abc", "sha512-not base64!!"} {
		if _, ok := convertHash(bad); ok {
			t.Errorf("convertHash(%q) accepted an unusable value", bad)
		}
	}
}

func TestWriteProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	in := []component.Component{{Name: "flask", Ecosystem: component.PyPI, Version: "3.0.0", Source: "requirements.txt"}}
	if err := Write(&buf, in, testOptions()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if !strings.Contains(buf.String(), "\n  \"bomFormat\"") {
		t.Error("output is not indented, and an SBOM is read by people as well as parsers")
	}
}

func TestWriteIsDeterministic(t *testing.T) {
	in := []component.Component{
		{Name: "flask", Ecosystem: component.PyPI, Version: "3.0.0"},
		{Name: "lodash", Ecosystem: component.NPM, Version: "4.17.21"},
	}
	var first, second bytes.Buffer
	if err := Write(&first, in, testOptions()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := Write(&second, in, testOptions()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if first.String() != second.String() {
		t.Error("two runs over the same input differ, so the SBOM cannot be diffed between scans")
	}
}

func TestSerialNumberIsAUUIDURN(t *testing.T) {
	serial, err := newSerialNumber()
	if err != nil {
		t.Fatalf("newSerialNumber: %v", err)
	}
	if !strings.HasPrefix(serial, "urn:uuid:") || len(serial) != len("urn:uuid:")+36 {
		t.Fatalf("serial = %q, want a UUID URN", serial)
	}
	if serial[23] != '4' {
		t.Errorf("serial = %q, want version 4", serial)
	}

	other, err := newSerialNumber()
	if err != nil {
		t.Fatalf("newSerialNumber: %v", err)
	}
	if serial == other {
		t.Error("two documents got the same serial number")
	}
}
