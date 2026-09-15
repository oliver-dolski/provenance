package attest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
)

// DefaultRegistry is the public npm registry, which serves the attestations
// alongside the packages.
const DefaultRegistry = "https://registry.npmjs.org"

// workers bounds concurrent requests. One request per package is already a lot
// to ask of a free registry; asking for all of them at once is worse.
const workers = 8

// Client fetches and verifies publish attestations.
type Client struct {
	Registry  string
	HTTP      *http.Client
	UserAgent string
}

// NewClient returns a client for the public npm registry.
func NewClient(userAgent string) *Client {
	return &Client{
		Registry:  DefaultRegistry,
		HTTP:      &http.Client{Timeout: 30 * time.Second},
		UserAgent: userAgent,
	}
}

// Result is what checking a set of components established.
type Result struct {
	// Verified maps a component key to the provenance proven for it.
	Verified map[string]component.Provenance
	// Findings are attestations that exist and do not hold up.
	Findings []finding.Finding
	// Checked is how many components were asked about.
	Checked int
	// Absent is how many of those publish no attestation at all. Most packages
	// still do not, so this is a coverage number rather than a list of
	// problems.
	Absent int
	// Warnings are components whose attestation could not be retrieved.
	Warnings []string
}

// Check verifies the build provenance of every component that can have one.
func (c *Client) Check(ctx context.Context, components []component.Component) (Result, error) {
	subjects := make([]component.Component, 0, len(components))
	for _, comp := range components {
		if supported(comp) {
			subjects = append(subjects, comp)
		}
	}

	result := Result{Verified: map[string]component.Provenance{}, Checked: len(subjects)}
	if len(subjects) == 0 {
		return result, nil
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	work := make(chan component.Component)

	count := workers
	if len(subjects) < count {
		count = len(subjects)
	}
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for comp := range work {
				provenance, found, err := c.check(ctx, comp)

				mu.Lock()
				switch {
				case err != nil:
					var reported *finding.Finding
					reported, result.Warnings = classify(comp, err, result.Warnings)
					if reported != nil {
						result.Findings = append(result.Findings, *reported)
					}
				case !found:
					result.Absent++
				default:
					result.Verified[comp.Key()] = provenance
				}
				mu.Unlock()
			}
		}()
	}

	for _, comp := range subjects {
		select {
		case work <- comp:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()

	sort.Strings(result.Warnings)
	finding.Sort(result.Findings)
	return result, nil
}

// supported reports whether a component can have an attestation this tool
// knows how to fetch. Only npm publishes them today, and only for a package
// served by the public registry at a known version.
func supported(comp component.Component) bool {
	if comp.Ecosystem != component.NPM || comp.Version == "" {
		return false
	}
	if comp.Resolved == "" {
		// Declared but never resolved: there is no artifact to attest to.
		return false
	}
	parsed, err := url.Parse(comp.Resolved)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "registry.npmjs.org" || host == "registry.npmjs.com"
}

// verificationError marks a failure that is about the attestation itself
// rather than about reaching the registry. The difference decides whether the
// scan reports a finding or a gap in its own coverage.
type verificationError struct {
	err error
	// mismatch marks the worst case: the attestation is genuine, and it is
	// about a different file than the one the project installs.
	mismatch bool
}

func (e verificationError) Error() string { return e.err.Error() }

// classify turns an error into either a finding or a warning.
func classify(comp component.Component, err error, warnings []string) (*finding.Finding, []string) {
	var invalid verificationError
	if !errors.As(err, &invalid) {
		// The registry could not be asked. That is a hole in the scan's
		// coverage, not a claim about the package.
		return nil, append(warnings, fmt.Sprintf("%s %s: %v", comp.Name, comp.Version, err))
	}

	if invalid.mismatch {
		return &finding.Finding{
			Kind: finding.KindProvenanceMismatch,
			// A valid statement about a different artifact is the case this
			// whole check exists for: the build was attested, and what the
			// project installs is not what was attested.
			Severity:  finding.Critical,
			Component: comp,
			Title:     fmt.Sprintf("build provenance for %s %s covers a different artifact", comp.Name, comp.Version),
			Detail: fmt.Sprintf(
				"The provenance attestation verifies, but %v. The package this project installs is not the one the attestation was issued for.",
				invalid.err),
			Source: "provenance",
		}, warnings
	}

	return &finding.Finding{
		Kind: finding.KindProvenanceFailed,
		// An attestation that does not hold up is a stronger signal than one
		// that was never published: something produced a statement about this
		// artifact that does not survive checking.
		Severity:  finding.High,
		Component: comp,
		Title:     fmt.Sprintf("build provenance for %s %s does not verify", comp.Name, comp.Version),
		Detail: fmt.Sprintf(
			"The registry publishes a provenance attestation for this version and it fails verification: %v. Until that is explained, the artifact cannot be tied to the source it claims to come from.",
			invalid.err),
		Source: "provenance",
	}, warnings
}

// check fetches and verifies one component's attestation. The second return
// value reports whether an attestation exists at all.
func (c *Client) check(ctx context.Context, comp component.Component) (component.Provenance, bool, error) {
	response, found, err := c.fetch(ctx, comp)
	if err != nil || !found {
		return component.Provenance{}, false, err
	}

	for _, a := range response.Attestations {
		if a.PredicateType != slsaPredicateType {
			// The other attestation npm publishes only restates the package
			// name and says nothing about how it was built.
			continue
		}
		provenance, digests, err := verify(a.Bundle)
		if err != nil {
			return component.Provenance{}, true, verificationError{err: err}
		}
		if err := coversArtifact(digests, comp); err != nil {
			return component.Provenance{}, true, verificationError{err: err, mismatch: true}
		}
		return provenance, true, nil
	}
	return component.Provenance{}, false, nil
}

// coversArtifact checks that the verified statement is about the artifact this
// project actually installs. Everything up to here proves a statement is
// genuine; this is what proves it is about the right file.
func coversArtifact(digests map[string]string, comp component.Component) error {
	algorithm, digest, ok := comp.Digest()
	if !ok {
		// The lockfile records no hash, so there is nothing to compare. The
		// missing hash is reported by its own check.
		return nil
	}
	attested, stated := digests[algorithm]
	if !stated {
		return nil
	}
	if attested != digest {
		return fmt.Errorf(
			"the attestation covers a %s artifact with digest %s, but the lockfile pins %s",
			algorithm, short(attested), short(digest))
	}
	return nil
}

// short trims a digest to something a report line can carry.
func short(digest string) string {
	if len(digest) <= 16 {
		return digest
	}
	return digest[:16] + "..."
}

// fetch retrieves the attestations the registry publishes for a version.
func (c *Client) fetch(ctx context.Context, comp component.Component) (attestationsResponse, bool, error) {
	registry := c.Registry
	if registry == "" {
		registry = DefaultRegistry
	}
	// A scoped name keeps its slash: the registry addresses "@scope/name" as a
	// path, not as an escaped segment.
	endpoint := fmt.Sprintf("%s/-/npm/v1/attestations/%s@%s",
		strings.TrimSuffix(registry, "/"), comp.Name, url.PathEscape(comp.Version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return attestationsResponse{}, false, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return attestationsResponse{}, false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// The registry answers this way for a package that publishes no
		// attestation, which is still the common case.
		return attestationsResponse{}, false, nil
	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return attestationsResponse{}, false, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}

	var response attestationsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return attestationsResponse{}, false, fmt.Errorf("reading the attestation: %w", err)
	}
	if len(response.Attestations) == 0 {
		return attestationsResponse{}, false, nil
	}
	return response, true, nil
}
