package attest

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
)

// The fixture is the real attestation the npm registry serves for
// sigstore@3.0.0, captured on 2026-09-15. Using a real bundle is the point:
// a verifier tested only against material it generated itself proves that it
// agrees with its own encoder.
const (
	fixtureRepo   = "https://github.com/sigstore/sigstore-js"
	fixtureCommit = "3a57a741bfb9f7c3bca69b63e170fc28e9432e69"
	// The sha512 the statement covers, which is also what the npm lockfile
	// records as the package's integrity.
	fixtureDigest = "3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894489557531c70911000d87fe66d78"
)

func loadFixture(t *testing.T) attestationsResponse {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "sigstore-3.0.0.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var response attestationsResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return response
}

// provenanceBundle returns the SLSA attestation from the fixture.
func provenanceBundle(t *testing.T) bundle {
	t.Helper()
	for _, a := range loadFixture(t).Attestations {
		if a.PredicateType == slsaPredicateType {
			return a.Bundle
		}
	}
	t.Fatal("fixture carries no build provenance attestation")
	return bundle{}
}

// fixtureComponent is the component the fixture attests to, as a lockfile
// would record it.
func fixtureComponent(t *testing.T) component.Component {
	t.Helper()
	raw, err := hex.DecodeString(fixtureDigest)
	if err != nil {
		t.Fatalf("decoding fixture digest: %v", err)
	}
	return component.Component{
		Name:      "sigstore",
		Ecosystem: component.NPM,
		Version:   "3.0.0",
		Resolved:  "https://registry.npmjs.org/sigstore/-/sigstore-3.0.0.tgz",
		Integrity: "sha512-" + base64.StdEncoding.EncodeToString(raw),
		Source:    "package-lock.json",
	}
}

func TestVerifyRealAttestation(t *testing.T) {
	got, digests, err := verify(provenanceBundle(t))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if got.SourceRepo != fixtureRepo {
		t.Errorf("SourceRepo = %q, want %q", got.SourceRepo, fixtureRepo)
	}
	if got.SourceCommit != fixtureCommit {
		t.Errorf("SourceCommit = %q, want %q", got.SourceCommit, fixtureCommit)
	}
	if !strings.Contains(got.Workflow, "release.yml") {
		t.Errorf("Workflow = %q, want the workflow that published it", got.Workflow)
	}
	if !strings.Contains(got.Issuer, "githubusercontent.com") {
		t.Errorf("Issuer = %q, want the identity provider that authenticated the build", got.Issuer)
	}
	if digests["sha512"] != fixtureDigest {
		t.Errorf("attested sha512 = %q, want the artifact digest", digests["sha512"])
	}
	// The signing certificate was valid for ten minutes in October 2024. That
	// the check passes at all is the point: the time came from the
	// transparency log, not from the clock.
	if got.SignedAt.Year() != 2024 {
		t.Errorf("SignedAt = %s, want the moment the log recorded the signature", got.SignedAt)
	}
}

func TestVerifyRejectsTamperedStatement(t *testing.T) {
	b := provenanceBundle(t)

	// Rewrite the statement to claim a different source repository, as an
	// attacker publishing a package would want to.
	raw, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	tampered := strings.Replace(string(raw), "sigstore/sigstore-js", "attacker/evil-repo", 1)
	if tampered == string(raw) {
		t.Fatal("test did not change the statement")
	}
	b.DSSEEnvelope.Payload = base64.StdEncoding.EncodeToString([]byte(tampered))

	if _, _, err := verify(b); err == nil {
		t.Fatal("a rewritten statement verified")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	b := provenanceBundle(t)
	signature, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	signature[len(signature)-1] ^= 0xff
	b.DSSEEnvelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(signature)

	if _, _, err := verify(b); err == nil {
		t.Fatal("a corrupted signature verified")
	}
}

func TestVerifyRejectsForgedSigningTime(t *testing.T) {
	// Moving the signing time is how an expired or unrelated certificate would
	// be made to look current. The log's own signature covers that field.
	b := provenanceBundle(t)
	b.VerificationMaterial.TlogEntries[0].IntegratedTime = "1893456000"

	_, _, err := verify(b)
	if err == nil {
		t.Fatal("a rewritten signing time verified")
	}
	if !strings.Contains(err.Error(), "transparency log") {
		t.Errorf("error = %v, want it to name the check that caught this", err)
	}
}

func TestVerifyRejectsLogEntryForAnotherStatement(t *testing.T) {
	// A genuine, correctly signed log entry taken from a different artifact
	// must not vouch for this one.
	b := provenanceBundle(t)
	other := loadFixture(t).Attestations[0].Bundle
	b.VerificationMaterial.TlogEntries[0].CanonicalizedBody = other.VerificationMaterial.TlogEntries[0].CanonicalizedBody

	if _, _, err := verify(b); err == nil {
		t.Fatal("a log entry about a different statement was accepted")
	}
}

func TestVerifyRejectsBundleWithoutLogEntry(t *testing.T) {
	b := provenanceBundle(t)
	b.VerificationMaterial.TlogEntries = nil

	_, _, err := verify(b)
	if err == nil {
		t.Fatal("a bundle with nothing to date it verified")
	}
	if !strings.Contains(err.Error(), "when this was signed") {
		t.Errorf("error = %v, want it to say why the bundle cannot be judged", err)
	}
}

// serveFixture answers attestation requests with the captured bundle.
func serveFixture(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := NewClient("provenance-test")
	client.Registry = server.URL
	return client
}

func TestCheckVerifiesComponent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sigstore-3.0.0.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var requested string
	client := serveFixture(t, func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		w.Write(raw)
	})

	comp := fixtureComponent(t)
	result, err := client.Check(context.Background(), []component.Component{comp})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	if !strings.HasSuffix(requested, "/-/npm/v1/attestations/sigstore@3.0.0") {
		t.Errorf("asked for %q, want the attestations endpoint for this version", requested)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %+v, want none: the attestation verifies", result.Findings)
	}
	provenance, ok := result.Verified[comp.Key()]
	if !ok {
		t.Fatal("the component has no verified provenance recorded")
	}
	if provenance.SourceRepo != fixtureRepo {
		t.Errorf("SourceRepo = %q, want %q", provenance.SourceRepo, fixtureRepo)
	}
}

func TestCheckReportsAttestationForAnotherArtifact(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sigstore-3.0.0.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	client := serveFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write(raw) })

	// The lockfile pins a different tarball than the one the attestation
	// covers, which is what a swapped artifact looks like.
	comp := fixtureComponent(t)
	comp.Integrity = "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))

	result, err := client.Check(context.Background(), []component.Component{comp})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(result.Findings))
	}
	got := result.Findings[0]
	if got.Kind != finding.KindProvenanceMismatch || got.Severity != finding.Critical {
		t.Errorf("finding = %s at %s, want a critical provenance mismatch", got.Kind, got.Severity)
	}
	if len(result.Verified) != 0 {
		t.Error("a mismatched attestation was recorded as verified provenance")
	}
}

func TestCheckReportsFailedVerification(t *testing.T) {
	response := loadFixture(t)
	for i, a := range response.Attestations {
		if a.PredicateType != slsaPredicateType {
			continue
		}
		signature, err := base64.StdEncoding.DecodeString(a.Bundle.DSSEEnvelope.Signatures[0].Sig)
		if err != nil {
			t.Fatalf("decoding signature: %v", err)
		}
		signature[0] ^= 0xff
		response.Attestations[i].Bundle.DSSEEnvelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(signature)
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("encoding fixture: %v", err)
	}
	client := serveFixture(t, func(w http.ResponseWriter, r *http.Request) { w.Write(body) })

	result, err := client.Check(context.Background(), []component.Component{fixtureComponent(t)})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Kind != finding.KindProvenanceFailed {
		t.Fatalf("findings = %+v, want one failed-verification finding", result.Findings)
	}
	if result.Findings[0].Severity != finding.High {
		t.Errorf("Severity = %s, want high", result.Findings[0].Severity)
	}
}

func TestCheckCountsPackagesWithoutAttestation(t *testing.T) {
	// Most packages publish none. That is a coverage number, not a finding per
	// package, or a report of a real project would be nothing else.
	client := serveFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
	})

	result, err := client.Check(context.Background(), []component.Component{fixtureComponent(t)})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Absent != 1 || len(result.Findings) != 0 {
		t.Errorf("absent = %d, findings = %d, want 1 and 0", result.Absent, len(result.Findings))
	}
}

func TestCheckReportsUnreachableRegistryAsAGap(t *testing.T) {
	client := serveFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream is down", http.StatusBadGateway)
	})

	result, err := client.Check(context.Background(), []component.Component{fixtureComponent(t)})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Error("an unreachable registry was reported as a problem with the package")
	}
	if len(result.Warnings) != 1 {
		t.Errorf("warnings = %v, want the gap in coverage stated", result.Warnings)
	}
}

func TestCheckSkipsWhatCannotHaveAttestation(t *testing.T) {
	client := serveFixture(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("the registry was asked about a component that cannot have an npm attestation")
	})

	result, err := client.Check(context.Background(), []component.Component{
		{Name: "flask", Ecosystem: component.PyPI, Version: "3.0.0", Resolved: "https://pypi.org/simple"},
		{Name: "express", Ecosystem: component.NPM, Constraint: "^4.18.2"},
		{Name: "@acme/ui", Ecosystem: component.NPM, Version: "1.0.0", Resolved: "https://npm.internal.example.com/ui.tgz"},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if result.Checked != 0 {
		t.Errorf("Checked = %d, want 0", result.Checked)
	}
}
