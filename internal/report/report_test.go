package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
)

func sampleReport() Report {
	lodash := component.Component{
		Name: "lodash", Ecosystem: component.NPM, Version: "4.17.11",
		Direct: true, Source: "package-lock.json",
	}
	requests := component.Component{
		Name: "requests", Ecosystem: component.PyPI, Constraint: ">=2.31.0",
		Direct: true, Source: "requirements.txt",
	}
	return Report{
		Tool:       "provenance",
		Version:    "1.0.0",
		Path:       "/projects/app",
		Sources:    []string{"package-lock.json", "requirements.txt"},
		Components: []component.Component{lodash, requests},
		Findings: []finding.Finding{
			{
				Kind: finding.KindVulnerability, Severity: finding.Critical, Component: lodash,
				Title: "Prototype pollution in lodash", Detail: "Versions before 4.17.12 are affected.",
				FixedIn: "4.17.12", Source: "OSV", ID: "GHSA-jf85-cpcp-j695",
				Aliases: []string{"CVE-2019-10744"}, References: []string{"https://example.com/advisory"},
			},
			{
				Kind: finding.KindUnpinned, Severity: finding.Medium, Component: requests,
				Title: "requests is not pinned to a version", Source: "provenance",
			},
		},
		VulnerabilitySource: "OSV",
		Queried:             1,
		Unchecked:           []component.Component{requests},
		KnownNames:          map[string]int{"npm": 125, "PyPI": 119},
	}
}

func TestTextStatesWhatWasScannedAndFound(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, sampleReport()); err != nil {
		t.Fatalf("Text: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"provenance 1.0.0",
		"/projects/app",
		"package-lock.json, requirements.txt",
		"components  2",
		"1 of 2 components against OSV",
		"1 with no resolved version could not be checked",
		"125 known npm packages",
		"findings    2",
		"CRITICAL",
		"vulnerability - Prototype pollution in lodash",
		"OSV GHSA-jf85-cpcp-j695 (CVE-2019-10744)",
		"fixed in 4.17.12",
		"https://example.com/advisory",
		"CRA Regulation (EU) 2024/2847",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

func TestTextDoesNotLabelItsOwnFindingsWithAnIdentifier(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, sampleReport()); err != nil {
		t.Fatalf("Text: %v", err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.TrimSpace(line) == "provenance" {
			t.Error("a finding is labelled with the tool's own name on a line of its own, which says nothing")
		}
	}
}

func TestTextWrapsToATerminalWidth(t *testing.T) {
	var buf bytes.Buffer
	report := sampleReport()
	report.Findings[1].Detail = strings.Repeat("a long explanation of why this matters ", 12)
	if err := Text(&buf, report); err != nil {
		t.Fatalf("Text: %v", err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		// The scanned path is printed whole: breaking a path would make it
		// unusable, and it is the one line worth the overflow.
		if strings.Contains(line, "/projects/app") {
			continue
		}
		if len(line) > textWidth+2 {
			t.Errorf("line of %d characters does not fit a terminal:\n%s", len(line), line)
		}
	}
}

func TestTextSaysWhenNothingWasFound(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, Report{Tool: "provenance", Version: "1.0.0", Path: "/empty"}); err != nil {
		t.Fatalf("Text: %v", err)
	}
	if !strings.Contains(buf.String(), "no dependency manifests or lockfiles found") {
		t.Errorf("an empty scan reads as a clean scan:\n%s", buf.String())
	}
}

func TestJSONCarriesFindingsCoverageAndGuidance(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sampleReport()); err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var decoded jsonReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded.Summary.Components != 2 || decoded.Summary.Unpinned != 1 || decoded.Summary.Direct != 2 {
		t.Errorf("summary = %+v, want two components, both direct, one unpinned", decoded.Summary)
	}
	if decoded.Summary.BySeverity["critical"] != 1 || decoded.Summary.BySeverity["medium"] != 1 {
		t.Errorf("severity counts = %v, want one critical and one medium", decoded.Summary.BySeverity)
	}
	if len(decoded.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(decoded.Findings))
	}
	if decoded.Findings[0].Guidance == nil {
		t.Error("the vulnerability finding carries no guidance")
	}
	if decoded.Coverage.Complete {
		t.Error("a scan with an unchecked component reported itself complete")
	}
	if len(decoded.Coverage.Unchecked) != 1 {
		t.Errorf("coverage lists %d unchecked components, want 1", len(decoded.Coverage.Unchecked))
	}
	if decoded.Components[1].Pinned {
		t.Error("a component with only a constraint is reported as pinned")
	}
}

func TestJSONUsesEmptyListsRatherThanNull(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, Report{Tool: "provenance", Version: "1.0.0"}); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	for _, field := range []string{`"sources": []`, `"components": []`, `"findings": []`} {
		if !strings.Contains(buf.String(), field) {
			t.Errorf("output does not carry %s, so a consumer has to handle null:\n%s", field, buf.String())
		}
	}
}

func TestCompleteRequiresEveryQuestionAnswered(t *testing.T) {
	full := Report{
		Components:          []component.Component{{Name: "lodash", Ecosystem: component.NPM, Version: "4.17.21"}},
		VulnerabilitySource: "OSV",
		Queried:             1,
	}
	if !full.Complete() {
		t.Error("a scan that read every file and queried every component is not reported complete")
	}

	for name, incomplete := range map[string]Report{
		"unreadable file":     {Unreadable: []string{"broken/package.json"}},
		"warning":             {Warnings: []string{"advisory could not be read"}},
		"unchecked component": {Unchecked: []component.Component{{Name: "requests"}}},
		"lookup skipped": {
			Components: []component.Component{{Name: "lodash", Ecosystem: component.NPM, Version: "4.17.21"}},
		},
	} {
		if incomplete.Complete() {
			t.Errorf("a scan with a %s reported itself complete", name)
		}
	}
}
