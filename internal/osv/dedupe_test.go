package osv

import (
	"testing"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
)

func flask() component.Component {
	return component.Component{Name: "flask", Ecosystem: component.PyPI, Version: "0.12.2"}
}

func TestDedupeFoldsAliasedRecords(t *testing.T) {
	// How OSV actually answers: a GitHub advisory and an ecosystem record for
	// one issue, each naming the other.
	github := finding.Finding{
		Kind: finding.KindVulnerability, Severity: finding.High, Component: flask(),
		Title: "Denial of service in Flask", Detail: "Incorrect encoding of JSON data.",
		FixedIn: "0.12.3", Source: "OSV", ID: "GHSA-562c-5r94-xh97",
		Aliases:    []string{"CVE-2018-1000656", "PYSEC-2018-66"},
		References: []string{"https://example.com/advisory"},
	}
	ecosystem := finding.Finding{
		Kind: finding.KindVulnerability, Severity: finding.Unknown, Component: flask(),
		Title: "Flask denial of service", Source: "OSV", ID: "PYSEC-2018-66",
		Aliases: []string{"CVE-2018-1000656", "GHSA-562c-5r94-xh97"},
	}

	got := dedupe([]finding.Finding{github, ecosystem})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: both records describe one issue", len(got))
	}
	if got[0].ID != "GHSA-562c-5r94-xh97" {
		t.Errorf("reported %q, want the record that carries the severity and the fix", got[0].ID)
	}
	if got[0].Severity != finding.High {
		t.Errorf("Severity = %s, want the scored record's severity", got[0].Severity)
	}
	want := []string{"CVE-2018-1000656", "PYSEC-2018-66"}
	if len(got[0].Aliases) != len(want) {
		t.Fatalf("Aliases = %v, want every folded identifier kept", got[0].Aliases)
	}
	for i, alias := range want {
		if got[0].Aliases[i] != alias {
			t.Errorf("Aliases[%d] = %q, want %q", i, got[0].Aliases[i], alias)
		}
	}
}

func TestDedupeJoinsRecordsThroughASharedAlias(t *testing.T) {
	// Two advisories that do not name each other, but share a CVE, are the same
	// issue and have to end up in the same group.
	first := finding.Finding{
		Component: flask(), ID: "GHSA-aaaa-aaaa-aaaa", Severity: finding.Medium,
		Aliases: []string{"CVE-2021-0001"},
	}
	second := finding.Finding{
		Component: flask(), ID: "GHSA-bbbb-bbbb-bbbb", Severity: finding.Medium,
		Aliases: []string{"CVE-2021-0001"},
	}
	third := finding.Finding{
		Component: flask(), ID: "PYSEC-2021-1", Severity: finding.Medium,
		Aliases: []string{"GHSA-bbbb-bbbb-bbbb"},
	}

	got := dedupe([]finding.Finding{first, second, third})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: the three records are linked through shared identifiers", len(got))
	}
	if len(got[0].Aliases) != 3 {
		t.Errorf("Aliases = %v, want the other three identifiers", got[0].Aliases)
	}
}

func TestDedupeFillsGapsFromTheFoldedRecord(t *testing.T) {
	scored := finding.Finding{
		Component: flask(), ID: "GHSA-aaaa-aaaa-aaaa", Severity: finding.High,
		Aliases: []string{"CVE-2021-0001"},
	}
	detailed := finding.Finding{
		Component: flask(), ID: "PYSEC-2021-1", Severity: finding.Unknown,
		Aliases: []string{"CVE-2021-0001"}, Detail: "The full story.",
		FixedIn: "1.0.1", References: []string{"https://example.com/advisory"},
	}

	got := dedupe([]finding.Finding{scored, detailed})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Severity != finding.High {
		t.Errorf("Severity = %s, want the one record that was scored", got[0].Severity)
	}
	if got[0].FixedIn != "1.0.1" || got[0].Detail == "" || len(got[0].References) == 0 {
		t.Errorf("finding = %+v, want the detail of the record it folded in", got[0])
	}
}

func TestDedupeKeepsSeparateIssuesApart(t *testing.T) {
	got := dedupe([]finding.Finding{
		{Component: flask(), ID: "GHSA-aaaa-aaaa-aaaa", Aliases: []string{"CVE-2021-0001"}},
		{Component: flask(), ID: "GHSA-bbbb-bbbb-bbbb", Aliases: []string{"CVE-2022-0002"}},
	})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: these are different vulnerabilities", len(got))
	}
}

func TestDedupeKeepsComponentsApart(t *testing.T) {
	other := flask()
	other.Version = "0.12.3"

	got := dedupe([]finding.Finding{
		{Component: flask(), ID: "GHSA-aaaa-aaaa-aaaa", Aliases: []string{"CVE-2021-0001"}},
		{Component: other, ID: "GHSA-aaaa-aaaa-aaaa", Aliases: []string{"CVE-2021-0001"}},
	})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: the same advisory affects two installed versions", len(got))
	}
}

func TestDedupeIsDeterministic(t *testing.T) {
	// Two records with nothing to separate them must still produce the same
	// report on every run.
	build := func() []finding.Finding {
		return []finding.Finding{
			{Component: flask(), ID: "GHSA-bbbb-bbbb-bbbb", Aliases: []string{"CVE-2021-0001"}, Severity: finding.Medium},
			{Component: flask(), ID: "GHSA-aaaa-aaaa-aaaa", Aliases: []string{"CVE-2021-0001"}, Severity: finding.Medium},
		}
	}
	first := dedupe(build())
	second := dedupe(build())
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("got %d and %d findings, want 1 each", len(first), len(second))
	}
	if first[0].ID != second[0].ID {
		t.Errorf("two runs reported %q and %q", first[0].ID, second[0].ID)
	}
}
