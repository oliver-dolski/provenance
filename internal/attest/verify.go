package attest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oliver-dolski/provenance/internal/component"
)

// The trust roots. They are vendored rather than fetched, because a trust root
// downloaded at scan time is trusted on the strength of the connection that
// delivered it, which is the thing signatures exist to stop relying on.
//
// fulcio.pem came from https://fulcio.sigstore.dev/api/v1/rootCert and
// rekor.pub from https://rekor.sigstore.dev/api/v1/log/publicKey, both
// retrieved on 2026-09-15. Replacing them is a deliberate act, visible in the
// repository's history.

//go:embed roots/fulcio.pem
var fulcioRootsPEM []byte

//go:embed roots/rekor.pub
var rekorPublicKeyPEM []byte

// Fulcio records the identity it authenticated in certificate extensions.
// Only the issuer is read here: the repository, commit and workflow are taken
// from the signed statement itself, and the certificate is used to check that
// the statement agrees with the identity that signed it.
var (
	oidIssuerV1 = []int{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = []int{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

var (
	trustOnce  sync.Once
	trustErr   error
	fulcioRoot *x509.CertPool
	fulcioMid  *x509.CertPool
	rekorKey   *ecdsa.PublicKey
)

// loadTrustRoots parses the vendored roots once.
func loadTrustRoots() error {
	trustOnce.Do(func() {
		fulcioRoot = x509.NewCertPool()
		fulcioMid = x509.NewCertPool()

		rest := fulcioRootsPEM
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				trustErr = fmt.Errorf("parsing Fulcio roots: %w", err)
				return
			}
			// A self-issued certificate is the anchor; anything else is an
			// intermediate that has to chain up to it.
			if cert.Subject.String() == cert.Issuer.String() {
				fulcioRoot.AddCert(cert)
			} else {
				fulcioMid.AddCert(cert)
			}
		}

		block, _ := pem.Decode(rekorPublicKeyPEM)
		if block == nil {
			trustErr = fmt.Errorf("parsing transparency log key: not PEM")
			return
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			trustErr = fmt.Errorf("parsing transparency log key: %w", err)
			return
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			trustErr = fmt.Errorf("transparency log key is %T, want an ECDSA key", parsed)
			return
		}
		rekorKey = key
	})
	return trustErr
}

// verify checks a bundle end to end and returns what it establishes.
//
// The order matters. The signing certificate is valid for ten minutes, so the
// signing time has to come from somewhere other than the bundle's own claim
// before the certificate can be judged: the transparency log's signed entry
// timestamp provides it, and the log entry's payload hash ties that timestamp
// to this statement and no other.
func verify(b bundle) (component.Provenance, map[string]string, error) {
	if err := loadTrustRoots(); err != nil {
		return component.Provenance{}, nil, err
	}

	stmt, payload, err := decodeStatement(b.DSSEEnvelope)
	if err != nil {
		return component.Provenance{}, nil, err
	}

	signedAt, err := verifyLogEntry(b, payload)
	if err != nil {
		return component.Provenance{}, nil, err
	}

	leaf, err := verifyCertificate(b, signedAt)
	if err != nil {
		return component.Provenance{}, nil, err
	}

	if err := verifySignature(b.DSSEEnvelope, leaf); err != nil {
		return component.Provenance{}, nil, err
	}

	return buildProvenance(stmt, leaf, signedAt)
}

// verifyLogEntry checks the transparency log's signed entry timestamp and that
// the entry it covers is this statement.
func verifyLogEntry(b bundle, payload []byte) (time.Time, error) {
	if len(b.VerificationMaterial.TlogEntries) == 0 {
		return time.Time{}, fmt.Errorf("no transparency log entry: nothing vouches for when this was signed")
	}
	entry := b.VerificationMaterial.TlogEntries[0]

	integratedTime, err := strconv.ParseInt(entry.IntegratedTime, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("transparency log entry has no usable timestamp: %w", err)
	}
	logID, err := base64.StdEncoding.DecodeString(entry.LogID.KeyID)
	if err != nil {
		return time.Time{}, fmt.Errorf("transparency log entry has an unreadable log identifier: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(entry.InclusionPromise.SignedEntryTimestamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("transparency log entry has an unreadable timestamp signature: %w", err)
	}
	logIndex, err := strconv.ParseInt(entry.LogIndex, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("transparency log entry has no usable index: %w", err)
	}

	// The log signs this exact object. The field order is alphabetical and the
	// encoding has no whitespace, which is how the log canonicalizes it; any
	// other spelling produces a different hash and fails to verify.
	signed, err := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{
		Body:           entry.CanonicalizedBody,
		IntegratedTime: integratedTime,
		LogID:          hex.EncodeToString(logID),
		LogIndex:       logIndex,
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("rebuilding the transparency log entry: %w", err)
	}

	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(rekorKey, digest[:], signature) {
		return time.Time{}, fmt.Errorf("the transparency log's timestamp does not verify against its public key")
	}

	if err := verifyLogEntryCovers(entry, payload); err != nil {
		return time.Time{}, err
	}
	return time.Unix(integratedTime, 0).UTC(), nil
}

// verifyLogEntryCovers checks that the timestamped log entry is about this
// statement. Without it, a valid timestamp for some other entry could be
// pasted alongside any payload.
func verifyLogEntryCovers(entry tlogEntry, payload []byte) error {
	raw, err := base64.StdEncoding.DecodeString(entry.CanonicalizedBody)
	if err != nil {
		return fmt.Errorf("transparency log entry is unreadable: %w", err)
	}
	var body tlogBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return fmt.Errorf("parsing the transparency log entry: %w", err)
	}

	recorded := body.Spec.Content.PayloadHash
	if !strings.EqualFold(recorded.Algorithm, "sha256") {
		return fmt.Errorf("transparency log entry records a %q hash, which this tool does not check", recorded.Algorithm)
	}
	digest := sha256.Sum256(payload)
	if !strings.EqualFold(recorded.Value, hex.EncodeToString(digest[:])) {
		return fmt.Errorf("the transparency log entry is about a different statement than the one in this bundle")
	}
	return nil
}

// verifyCertificate checks that the signing certificate chains to Fulcio, as
// of the moment the signature was logged.
func verifyCertificate(b bundle, signedAt time.Time) (*x509.Certificate, error) {
	certificates := b.VerificationMaterial.X509CertificateChain.Certificates
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no signing certificate in the bundle")
	}

	parsed := make([]*x509.Certificate, 0, len(certificates))
	for _, c := range certificates {
		der, err := base64.StdEncoding.DecodeString(c.RawBytes)
		if err != nil {
			return nil, fmt.Errorf("decoding the signing certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing the signing certificate: %w", err)
		}
		parsed = append(parsed, cert)
	}

	leaf := parsed[0]
	intermediates := fulcioMid.Clone()
	for _, cert := range parsed[1:] {
		intermediates.AddCert(cert)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         fulcioRoot,
		Intermediates: intermediates,
		CurrentTime:   signedAt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return nil, fmt.Errorf("the signing certificate does not chain to a trusted root: %w", err)
	}
	return leaf, nil
}

// verifySignature checks the envelope signature against the certified key.
func verifySignature(envelope dsseEnvelope, leaf *x509.Certificate) error {
	if len(envelope.Signatures) == 0 {
		return fmt.Errorf("the statement carries no signature")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		return fmt.Errorf("decoding the signature: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("decoding the statement: %w", err)
	}

	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("the certificate carries a %T key, which this tool does not verify", leaf.PublicKey)
	}

	digest := sha256.Sum256(preAuthenticationEncoding(envelope.PayloadType, payload))
	if !ecdsa.VerifyASN1(key, digest[:], signature) {
		return fmt.Errorf("the statement's signature does not verify against the certified key")
	}
	return nil
}

// preAuthenticationEncoding builds the byte string a DSSE signature actually
// covers. Signing the payload directly would let the same signature be
// replayed under a different payload type, so the type and both lengths are
// bound into what is hashed.
func preAuthenticationEncoding(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	return append([]byte(prefix), payload...)
}

// buildProvenance reads the verified statement, after checking that it agrees
// with the identity that signed it.
func buildProvenance(stmt statement, leaf *x509.Certificate, signedAt time.Time) (component.Provenance, map[string]string, error) {
	if stmt.PredicateType != slsaPredicateType {
		return component.Provenance{}, nil, fmt.Errorf("statement describes %q, not build provenance", stmt.PredicateType)
	}

	workflow := stmt.Predicate.BuildDefinition.ExternalParameters.Workflow
	p := component.Provenance{
		SourceRepo: workflow.Repository,
		Builder:    stmt.Predicate.RunDetails.Builder.ID,
		Issuer:     certificateIssuer(leaf),
		SignedAt:   signedAt,
	}
	if workflow.Path != "" {
		p.Workflow = workflow.Path + "@" + workflow.Ref
	}
	for _, dependency := range stmt.Predicate.BuildDefinition.ResolvedDependencies {
		if commit := dependency.Digest["gitCommit"]; commit != "" {
			p.SourceCommit = commit
			break
		}
	}

	digests := map[string]string{}
	for _, subject := range stmt.Subject {
		for algorithm, value := range subject.Digest {
			digests[strings.ToLower(algorithm)] = strings.ToLower(value)
		}
	}
	if len(digests) == 0 {
		return component.Provenance{}, nil, fmt.Errorf("the statement names no artifact digest, so it cannot be tied to a package")
	}

	// The certificate says which workflow signed; the statement says which
	// repository was built. A statement about someone else's repository,
	// signed by this workflow, would otherwise pass every check above.
	if err := agreesWithSigner(p.SourceRepo, leaf); err != nil {
		return component.Provenance{}, nil, err
	}
	return p, digests, nil
}

// agreesWithSigner checks the statement's repository against the signing
// identity in the certificate.
func agreesWithSigner(repo string, leaf *x509.Certificate) error {
	if repo == "" || len(leaf.URIs) == 0 {
		// Nothing to compare. The statement is reported as it stands rather
		// than treated as disproved.
		return nil
	}
	identity := leaf.URIs[0].String()
	if !strings.HasPrefix(identity, strings.TrimSuffix(repo, "/")+"/") {
		return fmt.Errorf("the statement claims %s but was signed by %s", repo, identity)
	}
	return nil
}

// certificateIssuer reads the identity provider Fulcio authenticated against.
func certificateIssuer(leaf *x509.Certificate) string {
	for _, extension := range leaf.Extensions {
		switch {
		case extension.Id.Equal(oidIssuerV2):
			return derUTF8String(extension.Value)
		case extension.Id.Equal(oidIssuerV1):
			return string(extension.Value)
		}
	}
	return ""
}

// derUTF8String unwraps the DER string Fulcio's newer extensions carry. A
// value that is not one is returned as it stands rather than guessed at.
func derUTF8String(value []byte) string {
	const utf8StringTag = 0x0c
	if len(value) >= 2 && value[0] == utf8StringTag && int(value[1]) == len(value)-2 {
		return string(value[2:])
	}
	return string(value)
}
