package finding

import (
	"testing"

	"github.com/oliver-dolski/provenance/internal/component"
)

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"critical": Critical,
		"HIGH":     High,
		" medium ": Medium,
		"moderate": Medium, // some databases use this word for the same band
		"low":      Low,
		"unknown":  Unknown,
	}
	for input, want := range cases {
		got, ok := ParseSeverity(input)
		if !ok {
			t.Errorf("ParseSeverity(%q) was not recognized", input)
			continue
		}
		if got != want {
			t.Errorf("ParseSeverity(%q) = %s, want %s", input, got, want)
		}
	}

	if _, ok := ParseSeverity("severe"); ok {
		t.Error(`ParseSeverity("severe") was accepted, and a typo in a flag should not become a silent default`)
	}
}

func TestFromCVSSScore(t *testing.T) {
	// The qualitative bands of the CVSS specification.
	cases := []struct {
		score float64
		want  Severity
	}{
		{10.0, Critical},
		{9.0, Critical},
		{8.9, High},
		{7.0, High},
		{6.9, Medium},
		{4.0, Medium},
		{3.9, Low},
		{0.1, Low},
		{0.0, Unknown},
	}
	for _, tc := range cases {
		if got := FromCVSSScore(tc.score); got != tc.want {
			t.Errorf("FromCVSSScore(%.1f) = %s, want %s", tc.score, got, tc.want)
		}
	}
}

func TestUnknownIsNotTheLowestRank(t *testing.T) {
	// An unscored vulnerability is not the same as one scored as minor, but a
	// threshold of "low" must still not be met by it.
	if Unknown >= Low {
		t.Error("an unknown severity ranks at or above low, so -fail-on low would trip on unscored findings")
	}
}

func TestSortOrdersBySeverityThenComponent(t *testing.T) {
	findings := []Finding{
		{Severity: Low, Component: component.Component{Name: "zod", Ecosystem: component.NPM}},
		{Severity: Critical, Component: component.Component{Name: "flask", Ecosystem: component.PyPI}},
		{Severity: Low, Component: component.Component{Name: "axios", Ecosystem: component.NPM}},
		{Severity: High, Component: component.Component{Name: "lodash", Ecosystem: component.NPM}},
	}
	Sort(findings)

	want := []string{"flask", "lodash", "axios", "zod"}
	for i, name := range want {
		if findings[i].Component.Name != name {
			t.Fatalf("position %d is %q, want %q", i, findings[i].Component.Name, name)
		}
	}
}

func TestSortIsStableAcrossRuns(t *testing.T) {
	build := func() []Finding {
		return []Finding{
			{Severity: Medium, Kind: KindUnpinned, Component: component.Component{Name: "requests", Ecosystem: component.PyPI}},
			{Severity: Medium, Kind: KindTyposquat, Component: component.Component{Name: "requests", Ecosystem: component.PyPI}},
			{Severity: Medium, Kind: KindPrivateSource, Component: component.Component{Name: "requests", Ecosystem: component.PyPI}},
		}
	}
	first, second := build(), build()
	Sort(first)
	Sort(second)
	for i := range first {
		if first[i].Kind != second[i].Kind {
			t.Fatalf("two sorts of the same findings differ at position %d: %s and %s", i, first[i].Kind, second[i].Kind)
		}
	}
}

func TestCountBySeverityAndHighest(t *testing.T) {
	findings := []Finding{
		{Severity: Low}, {Severity: Low}, {Severity: High},
	}
	counts := CountBySeverity(findings)
	if counts[Low] != 2 || counts[High] != 1 {
		t.Errorf("counts = %v, want two low and one high", counts)
	}
	if got := Highest(findings); got != High {
		t.Errorf("Highest = %s, want high", got)
	}
	if got := Highest(nil); got != Unknown {
		t.Errorf("Highest of nothing = %s, want unknown", got)
	}
}
