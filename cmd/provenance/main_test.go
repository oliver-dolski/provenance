package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestRunScansProject(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{sampleProject(t)}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"components  4 (npm 2, PyPI 2)", "unpinned  3", "dev only  1"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
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

func TestRunRejectsMissingPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{filepath.Join(t.TempDir(), "absent")}, &stdout, &stderr)
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
	if code := run([]string{"-sbom", target, root}, &stdout, &stderr); code != exitOK {
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
	if !strings.Contains(stdout.String(), "SBOM written to") {
		t.Errorf("summary does not say where the SBOM went:\n%s", stdout.String())
	}
}

func TestRunKeepsStdoutCleanWhenSBOMGoesThere(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-sbom", "-", sampleProject(t)}, &stdout, &stderr); code != exitOK {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}

	var bom map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &bom); err != nil {
		t.Fatalf("stdout is not a usable SBOM, so it cannot be piped: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "components") {
		t.Errorf("summary did not move to stderr:\n%s", stderr.String())
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
