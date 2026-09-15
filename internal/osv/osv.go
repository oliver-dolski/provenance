// Package osv looks up known vulnerabilities for scanned components in the OSV
// database. OSV aggregates the advisory feeds of the ecosystems this scanner
// reads, it is free to query, and every record it returns carries its own
// identifier and references - so a finding can be traced back to a published
// advisory rather than to this tool.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
)

// DefaultBaseURL is the public OSV API.
const DefaultBaseURL = "https://api.osv.dev"

// batchSize bounds one querybatch request. The API accepts up to a thousand
// queries; staying below that leaves room for proxies that cap request bodies.
// It is a variable so that a test can force several batches without building a
// project with a thousand dependencies.
var batchSize = 500

// detailWorkers bounds concurrent requests for advisory details. The API is a
// free public service, and scanning a large project should not look like an
// attempt to hammer it.
const detailWorkers = 8

// Client queries the OSV API.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	UserAgent string
}

// NewClient returns a client for the public OSV API.
func NewClient(userAgent string) *Client {
	return &Client{
		BaseURL:   DefaultBaseURL,
		HTTP:      &http.Client{Timeout: 30 * time.Second},
		UserAgent: userAgent,
	}
}

// Result is what a lookup produced, including what it could not cover.
type Result struct {
	Findings []finding.Finding

	// Checked is how many components were actually queried.
	Checked int

	// Skipped lists components with no resolved version. They cannot be matched
	// against version ranges, and listing every advisory ever published for the
	// package would bury the ones that apply.
	Skipped []component.Component

	// Warnings are advisories that could not be fully retrieved. The finding is
	// still reported, with less detail, rather than dropped.
	Warnings []string
}

// Check looks up every component that has a resolved version.
func (c *Client) Check(ctx context.Context, components []component.Component) (Result, error) {
	var result Result

	queryable := make([]component.Component, 0, len(components))
	for _, comp := range components {
		if comp.Version == "" {
			result.Skipped = append(result.Skipped, comp)
			continue
		}
		queryable = append(queryable, comp)
	}
	result.Checked = len(queryable)
	if len(queryable) == 0 {
		return result, nil
	}

	idsPerComponent, err := c.queryBatch(ctx, queryable)
	if err != nil {
		return Result{}, err
	}

	unique := map[string]bool{}
	for _, ids := range idsPerComponent {
		for _, id := range ids {
			unique[id] = true
		}
	}
	details, warnings := c.fetchDetails(ctx, unique)
	result.Warnings = warnings

	for i, ids := range idsPerComponent {
		for _, id := range ids {
			vuln, ok := details[id]
			if !ok {
				// The advisory exists but could not be read. Reporting the
				// identifier alone is still actionable; dropping it is not.
				result.Findings = append(result.Findings, finding.Finding{
					Kind:      finding.KindVulnerability,
					Severity:  finding.Unknown,
					Component: queryable[i],
					Title:     fmt.Sprintf("%s affects %s %s", id, queryable[i].Name, queryable[i].Version),
					Detail:    "OSV reported this advisory for the component, but its record could not be retrieved.",
					Source:    "OSV",
					ID:        id,
				})
				continue
			}
			if vuln.Withdrawn != "" {
				// A withdrawn advisory was retracted by its publisher.
				continue
			}
			result.Findings = append(result.Findings, vuln.toFinding(queryable[i]))
		}
	}

	finding.Sort(result.Findings)
	return result, nil
}

// queryBatch asks OSV which advisories apply to each component, returning the
// identifiers per component in the order the components were given.
func (c *Client) queryBatch(ctx context.Context, components []component.Component) ([][]string, error) {
	ids := make([][]string, len(components))

	for start := 0; start < len(components); start += batchSize {
		end := start + batchSize
		if end > len(components) {
			end = len(components)
		}
		chunk := components[start:end]

		request := batchRequest{Queries: make([]query, len(chunk))}
		for i, comp := range chunk {
			request.Queries[i] = query{
				Version: comp.Version,
				Package: queryPackage{
					Name:      comp.Ecosystem.NormalizeName(comp.Name),
					Ecosystem: string(comp.Ecosystem),
				},
			}
		}

		var response batchResponse
		if err := c.post(ctx, "/v1/querybatch", request, &response); err != nil {
			return nil, err
		}
		if len(response.Results) != len(chunk) {
			return nil, fmt.Errorf("osv: asked about %d components, got %d results", len(chunk), len(response.Results))
		}
		for i, r := range response.Results {
			for _, v := range r.Vulns {
				ids[start+i] = append(ids[start+i], v.ID)
			}
			sort.Strings(ids[start+i])
		}
	}
	return ids, nil
}

// fetchDetails retrieves the full record for each advisory identifier.
func (c *Client) fetchDetails(ctx context.Context, ids map[string]bool) (map[string]vulnerability, []string) {
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)

	var (
		mu       sync.Mutex
		details  = make(map[string]vulnerability, len(ordered))
		warnings []string
		wg       sync.WaitGroup
	)

	workers := detailWorkers
	if len(ordered) < workers {
		workers = len(ordered)
	}
	work := make(chan string)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				var vuln vulnerability
				err := c.get(ctx, "/v1/vulns/"+id, &vuln)

				mu.Lock()
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("%s: %v", id, err))
				} else {
					details[id] = vuln
				}
				mu.Unlock()
			}
		}()
	}

	for _, id := range ordered {
		select {
		case work <- id:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()

	sort.Strings(warnings)
	return details, warnings
}

// post sends a JSON request and decodes the JSON response.
func (c *Client) post(ctx context.Context, path string, payload, into any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("osv: encoding request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, into)
}

// get retrieves and decodes a JSON document.
func (c *Client) get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL()+path, nil)
	if err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	return c.do(req, into)
}

func (c *Client) do(req *http.Request, into any) error {
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("osv: %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// The start of the body usually says what was wrong; the rest is not
		// worth carrying into an error message.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("osv: %s: %s: %s", req.URL.Path, resp.Status, strings.TrimSpace(string(snippet)))
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("osv: %s: decoding response: %w", req.URL.Path, err)
	}
	return nil
}

func (c *Client) baseURL() string {
	if c.BaseURL == "" {
		return DefaultBaseURL
	}
	return strings.TrimSuffix(c.BaseURL, "/")
}
