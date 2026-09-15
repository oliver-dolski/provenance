// Package attest verifies where a package actually came from.
//
// A vulnerability scan answers "is there a known problem in this version". It
// says nothing about whether the artifact in the lockfile is the one the
// project's source produced. Build provenance answers that: npm publishes
// Sigstore bundles stating which repository, which commit and which workflow
// produced a tarball, signed by a short-lived certificate tied to the
// workflow's own identity.
//
// This package checks those statements rather than displaying them. A
// provenance claim nobody verified is a claim, and the difference between the
// two is the whole point of the exercise.
package attest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// attestationsResponse is what the npm registry returns for a package version.
type attestationsResponse struct {
	Attestations []attestation `json:"attestations"`
}

type attestation struct {
	PredicateType string `json:"predicateType"`
	Bundle        bundle `json:"bundle"`
}

// slsaPredicateType marks the attestation that states how the artifact was
// built. The other one npm publishes only restates the package name.
const slsaPredicateType = "https://slsa.dev/provenance/v1"

// bundle is a Sigstore bundle: the signed statement, the certificate that
// signed it, and the transparency log entry that timestamps it.
type bundle struct {
	MediaType            string               `json:"mediaType"`
	VerificationMaterial verificationMaterial `json:"verificationMaterial"`
	DSSEEnvelope         dsseEnvelope         `json:"dsseEnvelope"`
}

type verificationMaterial struct {
	X509CertificateChain certificateChain `json:"x509CertificateChain"`
	TlogEntries          []tlogEntry      `json:"tlogEntries"`
}

type certificateChain struct {
	Certificates []struct {
		RawBytes string `json:"rawBytes"`
	} `json:"certificates"`
}

// tlogEntry is the transparency log's record of the signature. Its signed
// entry timestamp is what makes the signing time trustworthy: the signing
// certificate is valid for ten minutes, so without a time that someone else
// vouches for, the bundle would be stating its own validity window.
type tlogEntry struct {
	LogIndex string `json:"logIndex"`
	LogID    struct {
		KeyID string `json:"keyId"`
	} `json:"logId"`
	IntegratedTime   string `json:"integratedTime"`
	InclusionPromise struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"inclusionPromise"`
	CanonicalizedBody string `json:"canonicalizedBody"`
}

// dsseEnvelope carries the statement and its signatures.
type dsseEnvelope struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
	Signatures  []struct {
		Sig string `json:"sig"`
	} `json:"signatures"`
}

// statement is the in-toto statement inside the envelope: what was built, and
// how.
type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate slsaPredicate `json:"predicate"`
}

// slsaPredicate is the part of the SLSA v1 provenance this tool reports.
type slsaPredicate struct {
	BuildDefinition struct {
		BuildType          string `json:"buildType"`
		ExternalParameters struct {
			Workflow struct {
				Ref        string `json:"ref"`
				Repository string `json:"repository"`
				Path       string `json:"path"`
			} `json:"workflow"`
		} `json:"externalParameters"`
		ResolvedDependencies []struct {
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"resolvedDependencies"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		Metadata struct {
			InvocationID string `json:"invocationId"`
		} `json:"metadata"`
	} `json:"runDetails"`
}

// tlogBody is the log entry's own record of what was signed. Its payload hash
// is what ties the timestamp to this statement rather than to some other entry
// the same key also signed.
type tlogBody struct {
	Spec struct {
		Content struct {
			PayloadHash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"payloadHash"`
		} `json:"content"`
	} `json:"spec"`
}

// decodeStatement reads the in-toto statement out of the envelope.
func decodeStatement(envelope dsseEnvelope) (statement, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return statement{}, nil, fmt.Errorf("decoding statement: %w", err)
	}
	var s statement
	if err := json.Unmarshal(raw, &s); err != nil {
		return statement{}, nil, fmt.Errorf("parsing statement: %w", err)
	}
	return s, raw, nil
}
