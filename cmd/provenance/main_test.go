package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oliver-dolski/provenance/internal/attest"
	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
	"github.com/oliver-dolski/provenance/internal/osv"
)

// TestMain makes the vulnerability lookup fail loudly by default, so a test
// that forgets to stub it cannot quietly reach the public OSV API.
func TestMain(m *testing.M) {
	vulnerabilityLookup = func(context.Context, []component.Component) (osv.Result, error) {
		return osv.Result{}, errors.New("no vulnerability lookup was stubbed for this test")
	}
	// The provenance check reaches a registry too. It defaults to finding
	// nothing rather than to failing, because most tests are not about it.
	provenanceLookup = func(context.Context, []component.Component) (attest.Result, error) {
		return attest.Result{}, nil
	}
	os.Exit(m.Run())
}

// stubProvenance replaces the build provenance check for one test.
func stubProvenance(t *testing.T, result attest.Result, err error) {
	t.Helper()
	original := provenanceLookup
	provenanceLookup = func(context.Context, []component.Component) (attest.Result, error) {
		return result, err
	}
	t.Cleanup(func() { provenanceLookup = original })
}

// verifiedProvenance is a stand-in for a checked build statement.
func verifiedProvenance() component.Provenance {
	return component.Provenance{
		SourceRepo:   "https://github.com/pallets/flask",
		SourceCommit: "1f3d8b6e1f3d8b6e1f3d8b6e1f3d8b6e1f3d8b6e",
		Workflow:     ".github/workflows/release.yml@refs/heads/main",
		Builder:      "https://github.com/actions/runner/github-hosted",
		Issuer:       "https://token.actions.githubusercontent.com",
		SignedAt:     time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	}
}

// stubLookup replaces the vulnerability lookup for one test.
func stubLookup(t *testing.T, result osv.Result, err error) {
	t.Helper()
	original := vulnerabilityLookup
	vulnerabilityLookup = func(_ context.Context, components []component.Component) (osv.Result, error) {
		if err != nil {
			return osv.Result{}, err
		}
		stubbed := result
		stubbed.Checked = len(components)
		return stubbed, nil
	}
	t.Cleanup(func() { vulnerabilityLookup = original })
}

// sampleProject writes a small project and returns its path.
func sampleProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write(t, filepath.Join(root, "package.json"), `{
	  "dependencies": {"express": "^4.18.2"},
	  "devDependencies": {"jest": "^29.7.0"}
	}`)
	write(t, filepath.Join(root, "requirements.txt"), "flask==3.0.0\nrequests>=2.31.0\n")
	return root
}

// criticalFinding is a stand-in for an advisory from the database.
func criticalFinding() finding.Finding {
	return finding.Finding{
		Kind:      finding.KindVulnerability,
		Severity:  finding.Critical,
		Component: component.Component{Name: "flask", Ecosystem: component.PyPI, Version: "3.0.0", Source: "requirements.txt"},
		Title:     "Prototype pollution in flask",
		Source:    "OSV",
		ID:        "GHSA-test-test-test",
		Aliases:   []string{"CVE-2026-0001"},
		FixedIn:   "3.0.1",
	}
}

func TestRunScansProject(t *testing.T) {
	stubLookup(t, osv.Result{}, nil)

	var stdout, stderr bytes.Buffer
	code := run([]string{sampleProject(t)}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"components  4",
		"4 direct, 0 indirect, 1 dev only, 3 unpinned",
		"against OSV",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestRunReportsOfflineChecksWithoutTheDatabase(t *testing.T) {
	// The default stub fails, so this passing at all proves no lookup was made.
	var stdout, stderr bytes.Buffer
	code := run([]string{"-offline", sampleProject(t)}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "no vulnerability database was queried") {
		t.Errorf("report does not say the lookup was skipped:\n%s", out)
	}
	if !strings.Contains(out, "unpinned") {
		t.Errorf("offline checks did not run:\n%s", out)
	}
}

func TestRunFailsWhenTheDatabaseIsUnreachable(t *testing.T) {
	stubLookup(t, osv.Result{}, errors.New("connection refused"))

	var stdout, stderr bytes.Buffer
	code := run([]string{sampleProject(t)}, &stdout, &stderr)

	if code != exitError {
		t.Fatalf("exit = %d, want %d: an unreachable database must not read as a clean scan", code, exitError)
	}
	if !strings.Contains(stderr.String(), "-offline") {
		t.Errorf("error does not point at the flag that scans without the lookup:\n%s", stderr.String())
	}
}

func TestRunReportsFindingsFromTheDatabase(t *testing.T) {
	stubLookup(t, osv.Result{Findings: []finding.Finding{criticalFinding()}}, nil)

	var stdout, stderr bytes.Buffer
	if code := run([]string{sampleProject(t)}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"CRITICAL",
		"OSV GHSA-test-test-test (CVE-2026-0001)",
		"fixed in 3.0.1",
		"CRA Regulation (EU) 2024/2847",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	// The most severe finding comes first, ahead of the unpinned dependencies.
	if strings.Index(out, "CRITICAL") > strings.Index(out, "MEDIUM") {
		t.Error("findings are not ordered most severe first")
	}
}

func TestRunExitCodeOnlyChangesWhenAsked(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{name: "not asked", args: nil, want: exitOK},
		{name: "threshold above the findings", args: []string{"-fail-on", "critical"}, want: exitOK},
		{name: "threshold at the findings", args: []string{"-fail-on", "medium"}, want: exitFindings},
		{name: "threshold below the findings", args: []string{"-fail-on", "low"}, want: exitFindings},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(append([]string{"-offline"}, tc.args...), sampleProject(t))
			if code := run(args, &stdout, &stderr); code != tc.want {
				t.Errorf("exit = %d, want %d\n%s", code, tc.want, stdout.String())
			}
		})
	}
}

func TestRunWritesJSONReport(t *testing.T) {
	stubLookup(t, osv.Result{Findings: []finding.Finding{criticalFinding()}}, nil)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-format", "json", sampleProject(t)}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	var decoded struct {
		Tool    string `json:"tool"`
		Summary struct {
			Components int            `json:"components"`
			BySeverity map[string]int `json:"findings_by_severity"`
		} `json:"summary"`
		Findings []struct {
			Kind     string `json:"kind"`
			Severity string `json:"severity"`
			Guidance []struct {
				Framework string `json:"framework"`
			} `json:"guidance"`
		} `json:"findings"`
		Coverage struct {
			VulnerabilitySource string `json:"vulnerability_source"`
			Complete            bool   `json:"complete"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout.String())
	}
	if decoded.Tool != "provenance" || decoded.Summary.Components != 4 {
		t.Errorf("report = %+v, want this tool and the four components", decoded)
	}
	if decoded.Summary.BySeverity["critical"] != 1 {
		t.Errorf("severity counts = %v, want one critical", decoded.Summary.BySeverity)
	}
	if decoded.Coverage.VulnerabilitySource != "OSV" {
		t.Errorf("coverage source = %q, want the database that was queried", decoded.Coverage.VulnerabilitySource)
	}
	if len(decoded.Findings) == 0 || len(decoded.Findings[0].Guidance) == 0 {
		t.Error("findings carry no guidance, so a reader has to map them to obligations by hand")
	}
}

func TestRunStatesAnIncompleteScan(t *testing.T) {
	unchecked := component.Component{Name: "requests", Ecosystem: component.PyPI, Constraint: ">=2.31.0"}
	stubLookup(t, osv.Result{Skipped: []component.Component{unchecked}}, nil)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-format", "json", sampleProject(t)}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}

	var decoded struct {
		Coverage struct {
			Complete  bool `json:"complete"`
			Unchecked []struct {
				Name string `json:"name"`
			} `json:"unchecked"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Coverage.Complete {
		t.Error("a scan that could not check every component reported itself as complete")
	}
	if len(decoded.Coverage.Unchecked) != 1 || decoded.Coverage.Unchecked[0].Name != "requests" {
		t.Errorf("unchecked = %+v, want the component that has no version", decoded.Coverage.Unchecked)
	}
}

func TestRunReportsVerifiedProvenance(t *testing.T) {
	stubLookup(t, osv.Result{}, nil)

	root := sampleProject(t)
	// The key has to match the component the scan builds from the manifest,
	// which is what ties a verified statement to a line in a lockfile.
	flask := component.Component{Name: "flask", Ecosystem: component.PyPI, Version: "3.0.0"}
	stubProvenance(t, attest.Result{
		Verified: map[string]component.Provenance{flask.Key(): verifiedProvenance()},
		Checked:  3,
		Absent:   2,
	}, nil)

	var stdout, stderr bytes.Buffer
	if code := run([]string{root}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	out := stdout.String()
	for _, want := range []string{
		"1 of 3 components carry verified build provenance",
		"2 publish none",
		"flask 3.0.0 built from",
		// Shortened to the length people quote, and the line may wrap before
		// it, so the repository and revision are looked for on their own.
		"https://github.com/pallets/flask@1f3d8b6e1f3d",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "1f3d8b6e1f3d8b6e") {
		t.Error("the full revision is printed where a short one is enough")
	}
}

func TestRunRecordsProvenanceInTheSBOM(t *testing.T) {
	stubLookup(t, osv.Result{}, nil)
	flask := component.Component{Name: "flask", Ecosystem: component.PyPI, Version: "3.0.0"}
	stubProvenance(t, attest.Result{
		Verified: map[string]component.Provenance{flask.Key(): verifiedProvenance()},
		Checked:  1,
	}, nil)

	target := filepath.Join(t.TempDir(), "sbom.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-sbom", target, sampleProject(t)}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading SBOM: %v", err)
	}
	var bom struct {
		Components []struct {
			Name               string `json:"name"`
			ExternalReferences []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"externalReferences"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("SBOM is not valid JSON: %v", err)
	}

	var checked bool
	for _, c := range bom.Components {
		if c.Name != "flask" {
			continue
		}
		checked = true
		var attested string
		for _, p := range c.Properties {
			if p.Name == "provenance:attestation" {
				attested = p.Value
			}
		}
		if attested != "verified" {
			t.Errorf("flask carries provenance:attestation = %q, want verified", attested)
		}
		if len(c.ExternalReferences) == 0 || c.ExternalReferences[0].Type != "vcs" {
			t.Errorf("flask has no source reference: %+v", c.ExternalReferences)
		}
	}
	if !checked {
		t.Fatal("flask is missing from the SBOM")
	}
}

func TestRunSkipsProvenanceWhenTurnedOff(t *testing.T) {
	stubLookup(t, osv.Result{}, nil)
	provenanceLookup = func(context.Context, []component.Component) (attest.Result, error) {
		t.Error("provenance was checked although -attest=false was given")
		return attest.Result{}, nil
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-attest=false", sampleProject(t)}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if strings.Contains(stdout.String(), "build provenance") {
		t.Errorf("report mentions provenance although the check did not run:\n%s", stdout.String())
	}
}

func TestRunTreatsAFailedProvenanceLookupAsAGap(t *testing.T) {
	stubLookup(t, osv.Result{}, nil)
	stubProvenance(t, attest.Result{}, errors.New("registry unreachable"))

	var stdout, stderr bytes.Buffer
	code := run([]string{sampleProject(t)}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, want %d: the rest of the scan still holds", code, exitOK)
	}
	if !strings.Contains(stdout.String(), "registry unreachable") {
		t.Errorf("report does not state that provenance could not be checked:\n%s", stdout.String())
	}
}

func TestRunWithoutPathIsAUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Errorf("no usage shown for a command line with no path:\n%s", stderr.String())
	}
}

func TestRunRejectsConflictingOutputs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-format", "json", "-sbom", "-", sampleProject(t)}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d: two documents cannot share stdout", code, exitUsage)
	}
}

func TestRunRejectsUnknownSeverity(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-fail-on", "severe", sampleProject(t)}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("exit = %d, want %d", code, exitUsage)
	}
}

func TestRunRejectsMissingPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-offline", filepath.Join(t.TempDir(), "absent")}, &stdout, &stderr)
	if code != exitError {
		t.Fatalf("exit = %d, want %d for a path that does not exist", code, exitError)
	}
	if !strings.Contains(stderr.String(), "provenance:") {
		t.Errorf("error not reported on stderr:\n%s", stderr.String())
	}
}

func TestRunPrintsVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-version"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stderr.String(), version) {
		t.Errorf("version %q not printed:\n%s", version, stderr.String())
	}
}

func TestRunWritesSBOMFile(t *testing.T) {
	root := sampleProject(t)
	target := filepath.Join(t.TempDir(), "sbom.json")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline", "-sbom", target, root}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading SBOM: %v", err)
	}
	var bom struct {
		BOMFormat  string           `json:"bomFormat"`
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("SBOM is not valid JSON: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" || len(bom.Components) != 4 {
		t.Errorf("SBOM has format %q and %d components, want CycloneDX and 4", bom.BOMFormat, len(bom.Components))
	}
	if !strings.Contains(stdout.String(), "sbom") {
		t.Errorf("report does not say where the SBOM went:\n%s", stdout.String())
	}
}

func TestRunKeepsStdoutCleanWhenSBOMGoesThere(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline", "-sbom", "-", sampleProject(t)}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	var bom map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatalf("stdout is not a usable SBOM, so it cannot be piped: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "components") {
		t.Errorf("report did not move to stderr:\n%s", stderr.String())
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
