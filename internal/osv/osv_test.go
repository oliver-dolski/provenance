package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
)

// fakeOSV serves the two endpoints the client uses, from advisories given per
// test, and records what it was asked.
type fakeOSV struct {
	// vulnsFor maps "ecosystem|name|version" to advisory identifiers.
	vulnsFor map[string][]string
	// records maps an identifier to the advisory served for it.
	records map[string]string
	// missing are identifiers whose details fail to load.
	missing map[string]bool

	mu       sync.Mutex
	queries  []query
	detailed []string
}

func (f *fakeOSV) start(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	client := NewClient("provenance-test")
	client.BaseURL = server.URL
	return client
}

func (f *fakeOSV) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/querybatch" {
		var request batchRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		response := batchResponse{Results: make([]batchResult, len(request.Queries))}
		for i, q := range request.Queries {
			f.mu.Lock()
			f.queries = append(f.queries, q)
			f.mu.Unlock()
			for _, id := range f.vulnsFor[q.Package.Ecosystem+"|"+q.Package.Name+"|"+q.Version] {
				response.Results[i].Vulns = append(response.Results[i].Vulns, struct {
					ID string `json:"id"`
				}{ID: id})
			}
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
	f.mu.Lock()
	f.detailed = append(f.detailed, id)
	f.mu.Unlock()
	if f.missing[id] {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	record, ok := f.records[id]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write([]byte(record))
}

func lodash() component.Component {
	return component.Component{Name: "lodash", Ecosystem: component.NPM, Version: "4.17.11", Source: "package-lock.json"}
}

const lodashAdvisory = `{
  "id": "GHSA-jf85-cpcp-j695",
  "aliases": ["CVE-2019-10744"],
  "summary": "Prototype Pollution in lodash",
  "details": "Versions of lodash before 4.17.12 are vulnerable to prototype pollution.\n\nThe function defaultsDeep could be tricked into adding properties to Object.prototype.",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{
    "package": {"ecosystem": "npm", "name": "lodash"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]
  }],
  "references": [
    {"type": "WEB", "url": "https://example.com/blog"},
    {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-jf85-cpcp-j695"}
  ]
}`

func TestCheckReportsAdvisory(t *testing.T) {
	fake := &fakeOSV{
		vulnsFor: map[string][]string{"npm|lodash|4.17.11": {"GHSA-jf85-cpcp-j695"}},
		records:  map[string]string{"GHSA-jf85-cpcp-j695": lodashAdvisory},
	}
	client := fake.start(t)

	result, err := client.Check(context.Background(), []component.Component{lodash()})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}

	got := result.Findings[0]
	if got.Kind != finding.KindVulnerability || got.ID != "GHSA-jf85-cpcp-j695" {
		t.Errorf("finding = %+v, want the advisory for lodash", got)
	}
	if got.Severity != finding.Critical {
		t.Errorf("Severity = %s, want critical: the vector scores 9.8", got.Severity)
	}
	if got.FixedIn != "4.17.12" {
		t.Errorf("FixedIn = %q, want 4.17.12", got.FixedIn)
	}
	if len(got.Aliases) != 1 || got.Aliases[0] != "CVE-2019-10744" {
		t.Errorf("Aliases = %v, want the CVE", got.Aliases)
	}
	if got.Source != "OSV" {
		t.Errorf("Source = %q, want the database the claim came from", got.Source)
	}
	if len(got.References) == 0 || !strings.Contains(got.References[0], "advisories") {
		t.Errorf("References = %v, want the advisory link first", got.References)
	}
	if strings.Contains(got.Detail, "defaultsDeep") {
		t.Errorf("Detail = %q, want only the first paragraph", got.Detail)
	}
}

func TestCheckQueriesNormalizedNames(t *testing.T) {
	fake := &fakeOSV{vulnsFor: map[string][]string{}}
	client := fake.start(t)

	_, err := client.Check(context.Background(), []component.Component{
		{Name: "Flask_Login", Ecosystem: component.PyPI, Version: "0.6.3"},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(fake.queries) != 1 {
		t.Fatalf("sent %d queries, want 1", len(fake.queries))
	}
	got := fake.queries[0]
	if got.Package.Name != "flask-login" || got.Package.Ecosystem != "PyPI" || got.Version != "0.6.3" {
		t.Errorf("query = %+v, want the PEP 503 name and the OSV ecosystem spelling", got)
	}
}

func TestCheckSkipsComponentsWithoutVersion(t *testing.T) {
	fake := &fakeOSV{vulnsFor: map[string][]string{}}
	client := fake.start(t)

	result, err := client.Check(context.Background(), []component.Component{
		{Name: "requests", Ecosystem: component.PyPI, Constraint: ">=2.31.0"},
		lodash(),
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Checked != 1 {
		t.Errorf("Checked = %d, want 1", result.Checked)
	}
	if len(result.Skipped) != 1 || result.Skipped[0].Name != "requests" {
		t.Fatalf("Skipped = %v, want the unpinned component named", result.Skipped)
	}
	if len(fake.queries) != 1 {
		t.Errorf("sent %d queries, want only the component that has a version", len(fake.queries))
	}
}

func TestCheckSplitsLargeScansIntoBatches(t *testing.T) {
	original := batchSize
	batchSize = 2
	t.Cleanup(func() { batchSize = original })

	fake := &fakeOSV{
		vulnsFor: map[string][]string{"npm|pkg-4|1.0.0": {"GHSA-jf85-cpcp-j695"}},
		records:  map[string]string{"GHSA-jf85-cpcp-j695": lodashAdvisory},
	}
	client := fake.start(t)

	var components []component.Component
	for i := 0; i < 5; i++ {
		components = append(components, component.Component{
			Name:      "pkg-" + string(rune('0'+i)),
			Ecosystem: component.NPM,
			Version:   "1.0.0",
		})
	}

	result, err := client.Check(context.Background(), components)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(fake.queries) != 5 {
		t.Errorf("sent %d queries across batches, want 5", len(fake.queries))
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}
	// The advisory belongs to the fifth component, which is in the third batch:
	// an off-by-one in batching would attach it to the wrong package.
	if result.Findings[0].Component.Name != "pkg-4" {
		t.Errorf("finding attached to %q, want pkg-4", result.Findings[0].Component.Name)
	}
}

func TestCheckSkipsWithdrawnAdvisories(t *testing.T) {
	fake := &fakeOSV{
		vulnsFor: map[string][]string{"npm|lodash|4.17.11": {"GHSA-withdrawn"}},
		records: map[string]string{"GHSA-withdrawn": `{
		  "id": "GHSA-withdrawn",
		  "summary": "Retracted advisory",
		  "withdrawn": "2024-01-01T00:00:00Z"
		}`},
	}
	client := fake.start(t)

	result, err := client.Check(context.Background(), []component.Component{lodash()})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("got %d findings, want none: the publisher retracted the advisory", len(result.Findings))
	}
}

func TestCheckFallsBackToDatabaseSeverity(t *testing.T) {
	fake := &fakeOSV{
		vulnsFor: map[string][]string{"npm|lodash|4.17.11": {"GHSA-word-only"}},
		records: map[string]string{"GHSA-word-only": `{
		  "id": "GHSA-word-only",
		  "summary": "Denial of service",
		  "database_specific": {"severity": "MODERATE"}
		}`},
	}
	client := fake.start(t)

	result, err := client.Check(context.Background(), []component.Component{lodash()})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Findings[0].Severity != finding.Medium {
		t.Errorf("Severity = %s, want medium from the database's own word", result.Findings[0].Severity)
	}
}

func TestCheckIgnoresUnscoreableVectors(t *testing.T) {
	fake := &fakeOSV{
		vulnsFor: map[string][]string{"npm|lodash|4.17.11": {"GHSA-v4-only"}},
		records: map[string]string{"GHSA-v4-only": `{
		  "id": "GHSA-v4-only",
		  "summary": "Scored with a version this tool does not compute",
		  "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]
		}`},
	}
	client := fake.start(t)

	result, err := client.Check(context.Background(), []component.Component{lodash()})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Findings[0].Severity != finding.Unknown {
		t.Errorf("Severity = %s, want unknown rather than a number computed with the wrong formulas", result.Findings[0].Severity)
	}
}

func TestCheckReportsAdvisoryItCouldNotRead(t *testing.T) {
	fake := &fakeOSV{
		vulnsFor: map[string][]string{"npm|lodash|4.17.11": {"GHSA-unreadable"}},
		missing:  map[string]bool{"GHSA-unreadable": true},
	}
	client := fake.start(t)

	result, err := client.Check(context.Background(), []component.Component{lodash()})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "GHSA-unreadable" {
		t.Fatalf("findings = %+v, want the advisory reported by identifier", result.Findings)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "GHSA-unreadable") {
		t.Errorf("Warnings = %v, want the failed retrieval stated", result.Warnings)
	}
}

func TestCheckFailsLoudlyWhenTheAPIIsUnusable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	client := NewClient("provenance-test")
	client.BaseURL = server.URL

	// A scan that silently reports no vulnerabilities because the lookup failed
	// is worse than one that fails.
	if _, err := client.Check(context.Background(), []component.Component{lodash()}); err == nil {
		t.Fatal("Check returned no error although the database was unreachable")
	}
}

func TestCheckFetchesEachAdvisoryOnce(t *testing.T) {
	fake := &fakeOSV{
		vulnsFor: map[string][]string{
			"npm|lodash|4.17.11": {"GHSA-jf85-cpcp-j695"},
			"npm|lodash|4.17.10": {"GHSA-jf85-cpcp-j695"},
		},
		records: map[string]string{"GHSA-jf85-cpcp-j695": lodashAdvisory},
	}
	client := fake.start(t)

	older := lodash()
	older.Version = "4.17.10"
	result, err := client.Check(context.Background(), []component.Component{lodash(), older})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Errorf("got %d findings, want one per affected component", len(result.Findings))
	}
	if len(fake.detailed) != 1 {
		t.Errorf("fetched the advisory %d times, want once", len(fake.detailed))
	}
}
