// Package sbom writes the scanned components as a CycloneDX bill of materials.
// The output is what a reviewer, an auditor or another tool consumes, so it
// follows the published schema rather than a shape convenient for this program.
package sbom

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oliver-dolski/provenance/internal/component"
)

// SpecVersion is the CycloneDX specification the output conforms to.
const SpecVersion = "1.6"

// BOM is a CycloneDX document.
type BOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

// Metadata describes how and when the document was produced, and what it
// describes. A consumer that cannot tell which tool made a BOM, from which
// inputs, cannot judge how much of the truth it contains.
type Metadata struct {
	Timestamp string     `json:"timestamp"`
	Tools     Tools      `json:"tools"`
	Component *Component `json:"component,omitempty"`
}

// Tools lists the tools involved in producing the document.
type Tools struct {
	Components []Component `json:"components"`
}

// Component is one entry in the bill of materials.
type Component struct {
	Type               string              `json:"type"`
	BOMRef             string              `json:"bom-ref,omitempty"`
	Name               string              `json:"name"`
	Version            string              `json:"version,omitempty"`
	PURL               string              `json:"purl,omitempty"`
	Scope              string              `json:"scope,omitempty"`
	Hashes             []Hash              `json:"hashes,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences,omitempty"`
	Properties         []Property          `json:"properties,omitempty"`
}

// ExternalReference points at something outside the document. It is how a
// component in the bill of materials is tied back to the source it was built
// from, for the packages where that has actually been proven.
type ExternalReference struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment,omitempty"`
}

// Hash is a content hash of the packaged component.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// Property carries information the CycloneDX schema has no field for. The
// namespace keeps these distinguishable from properties another tool wrote.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Options control the parts of the document that are not derived from the
// components themselves.
type Options struct {
	// ProjectName names the scanned project in the metadata.
	ProjectName string
	// ToolVersion is the version of this scanner.
	ToolVersion string
	// Timestamp is when the scan ran. Zero means now.
	Timestamp time.Time
	// SerialNumber identifies this document. Empty means a fresh random one,
	// which is what the specification asks for; tests set it to compare output.
	SerialNumber string
	// Provenance holds the build provenance proven for components, keyed by
	// component key. Only what was verified belongs here: an unverified claim
	// recorded in a bill of materials is worse than none, because the next
	// reader has no way to tell the two apart.
	Provenance map[string]component.Provenance
}

// Build assembles a CycloneDX document from the scanned components.
func Build(components []component.Component, opts Options) (BOM, error) {
	serial := opts.SerialNumber
	if serial == "" {
		generated, err := newSerialNumber()
		if err != nil {
			return BOM{}, err
		}
		serial = generated
	}
	timestamp := opts.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	bom := BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		SerialNumber: serial,
		// A first document is version 1. Later revisions of the same
		// serial number would increment it.
		Version: 1,
		Metadata: Metadata{
			Timestamp: timestamp.UTC().Format(time.RFC3339),
			Tools: Tools{Components: []Component{{
				Type:    "application",
				Name:    "provenance",
				Version: opts.ToolVersion,
			}}},
		},
		Components: make([]Component, 0, len(components)),
	}
	if opts.ProjectName != "" {
		bom.Metadata.Component = &Component{
			Type:   "application",
			Name:   opts.ProjectName,
			BOMRef: "root",
		}
	}

	used := make(map[string]int, len(components))
	for _, c := range components {
		bom.Components = append(bom.Components, convert(c, used, opts.Provenance[c.Key()]))
	}
	return bom, nil
}

// Write encodes the document as indented JSON. Indented, because an SBOM ends
// up in a repository and in review comments more often than in a parser.
func Write(w io.Writer, components []component.Component, opts Options) error {
	bom, err := Build(components, opts)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(bom)
}

// convert maps one scanned component onto a CycloneDX entry.
func convert(c component.Component, used map[string]int, provenance component.Provenance) Component {
	purl := c.PURL()
	out := Component{
		Type:    "library",
		BOMRef:  uniqueRef(purl, used),
		Name:    c.Name,
		Version: c.Version,
		PURL:    purl,
		// A dependency needed only to build or test the project is optional to
		// what ships; everything else is required.
		Scope: "required",
	}
	if c.Dev {
		out.Scope = "optional"
	}
	if h, ok := convertHash(c.Integrity); ok {
		out.Hashes = []Hash{h}
	}

	out.Properties = []Property{
		{Name: "provenance:source", Value: c.Source},
		{Name: "provenance:direct", Value: fmt.Sprintf("%t", c.Direct)},
	}
	if c.Constraint != "" {
		out.Properties = append(out.Properties, Property{Name: "provenance:constraint", Value: c.Constraint})
	}
	if !c.Pinned() {
		// Said plainly, because a version-less component is easy to read past.
		out.Properties = append(out.Properties, Property{Name: "provenance:pinned", Value: "false"})
	}
	if c.Resolved != "" {
		out.Properties = append(out.Properties, Property{Name: "provenance:resolved", Value: c.Resolved})
	}
	addProvenance(&out, provenance)
	return out
}

// addProvenance records a verified build statement on the component. The
// wording is deliberate: these fields say the statement was checked, not that
// the publisher made it.
func addProvenance(out *Component, p component.Provenance) {
	if p.SourceRepo == "" {
		return
	}
	out.Properties = append(out.Properties,
		Property{Name: "provenance:attestation", Value: "verified"},
		Property{Name: "provenance:source-repository", Value: p.SourceRepo},
	)
	if p.SourceCommit != "" {
		out.Properties = append(out.Properties, Property{Name: "provenance:source-commit", Value: p.SourceCommit})
	}
	if p.Workflow != "" {
		out.Properties = append(out.Properties, Property{Name: "provenance:build-workflow", Value: p.Workflow})
	}
	if !p.SignedAt.IsZero() {
		out.Properties = append(out.Properties, Property{Name: "provenance:attested-at", Value: p.SignedAt.UTC().Format(time.RFC3339)})
	}

	reference := ExternalReference{Type: "vcs", URL: p.SourceRepo}
	if p.SourceCommit != "" {
		reference.Comment = "built from commit " + p.SourceCommit
	}
	out.ExternalReferences = append(out.ExternalReferences, reference)
}

// uniqueRef keeps bom-ref unique. Two components can share a package URL when
// neither has a version, and a duplicate reference makes the document invalid.
func uniqueRef(purl string, used map[string]int) string {
	count := used[purl]
	used[purl] = count + 1
	if count == 0 {
		return purl
	}
	return fmt.Sprintf("%s#%d", purl, count+1)
}

// convertHash turns a Subresource Integrity string, as npm lockfiles record it,
// into a CycloneDX hash. CycloneDX states hashes in hex; npm states them in
// base64, so the value is converted rather than copied.
func convertHash(integrity string) (Hash, bool) {
	// An integrity field may list several hashes separated by whitespace; the
	// first one is enough to identify the artifact.
	integrity = strings.TrimSpace(integrity)
	if integrity == "" {
		return Hash{}, false
	}
	if idx := strings.IndexAny(integrity, " \t"); idx > 0 {
		integrity = integrity[:idx]
	}

	name, encoded, found := strings.Cut(integrity, "-")
	if !found {
		return Hash{}, false
	}
	var alg string
	switch strings.ToLower(name) {
	case "sha512":
		alg = "SHA-512"
	case "sha384":
		alg = "SHA-384"
	case "sha256":
		alg = "SHA-256"
	case "sha1":
		alg = "SHA-1"
	default:
		return Hash{}, false
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Hash{}, false
	}
	return Hash{Alg: alg, Content: hex.EncodeToString(raw)}, true
}

// newSerialNumber returns a random UUID URN, which is how CycloneDX identifies
// a document.
func newSerialNumber() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating serial number: %w", err)
	}
	// Version 4, variant 1, as RFC 4122 defines them.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
