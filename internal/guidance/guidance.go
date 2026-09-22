// Package guidance connects a finding to the obligation or practice it bears
// on. The point is not to claim compliance: it is to save the reader the step
// of working out why a scanner's output matters to the framework their
// organization is measured against.
//
// Each reference names its source document and quotes one requirement from it.
// Nothing here is legal advice, and a scanner cannot establish that a product
// conforms to a regulation - only that an obligation is engaged and someone
// should look.
package guidance

import "github.com/oliver-dolski/provenance/internal/finding"

// Reference is one framework requirement a finding relates to.
type Reference struct {
	// Framework is the short name of the source document.
	Framework string
	// Clause locates the requirement inside it.
	Clause string
	// Statement is what that requirement says, quoted rather than summarized,
	// so a reader can check it against the source instead of against this
	// tool's reading of it.
	Statement string
	// URL is where the source document can be read.
	URL string
}

// String renders the reference on one line.
func (r Reference) String() string {
	return r.Framework + " " + r.Clause + ": " + r.Statement
}

const craURL = "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"

// craSBOM is the obligation that makes a component inventory mandatory rather
// than good practice, for products in scope of the Cyber Resilience Act. The
// obligations of Annex I Part II apply from 11 December 2027.
var craSBOM = Reference{
	Framework: "CRA",
	Clause:    "Regulation (EU) 2024/2847, Annex I, Part II (1)",
	Statement: "identify and document vulnerabilities and components contained in products with digital elements, including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies of the products",
	URL:       craURL,
}

// craRemediate is the obligation to act on what the inventory reveals.
var craRemediate = Reference{
	Framework: "CRA",
	Clause:    "Regulation (EU) 2024/2847, Annex I, Part II (2)",
	Statement: "in relation to the risks posed to products with digital elements, address and remediate vulnerabilities without delay, including by providing security updates; where technically feasible, new security updates shall be provided separately from functionality updates",
	URL:       craURL,
}

// The SLSA threat model numbers the ways an artifact can stop being what its
// source says it is. Each reference below points at the specific threat, not
// at the page, so a reader lands on the paragraph the finding came from.

var slsaDependency = Reference{
	Framework: "SLSA",
	Clause:    "v1.0 threats (D) Use compromised dependency",
	Statement: "a dependency threat is a vector for an adversary to introduce behavior to an artifact through external software that the artifact requires to function",
	URL:       "https://slsa.dev/spec/v1.0/threats#d-use-compromised-dependency",
}

var slsaTyposquat = Reference{
	Framework: "SLSA",
	Clause:    "v1.0 threats (H) Use compromised package, typosquatting",
	Statement: "a package whose name resembles a widely used one is a way to have a consumer install something other than what they meant",
	URL:       "https://slsa.dev/spec/v1.0/threats#typosquatting",
}

var slsaRegistry = Reference{
	Framework: "SLSA",
	Clause:    "v1.0 threats (G) Compromise package registry",
	Statement: "an adversary modifies the package on the package registry using an administrative interface or through a compromise of the infrastructure",
	URL:       "https://slsa.dev/spec/v1.0/threats#g-compromise-package-registry",
}

// byKind maps each kind of finding to the requirements it engages.
var byKind = map[finding.Kind][]Reference{
	finding.KindVulnerability:    {craRemediate},
	finding.KindUnpinned:         {slsaDependency, craSBOM},
	finding.KindPrivateSource:    {slsaDependency},
	finding.KindTyposquat:        {slsaTyposquat},
	finding.KindMissingIntegrity: {slsaRegistry},
	// A published build statement that does not hold up, or that covers a
	// different file than the one being installed, is the registry-side threat
	// the statement exists to detect.
	finding.KindProvenanceFailed:   {slsaRegistry},
	finding.KindProvenanceMismatch: {slsaRegistry},
}

// For returns the references that apply to a kind of finding.
func For(kind finding.Kind) []Reference {
	return byKind[kind]
}

// ForSBOM returns the requirement an SBOM itself answers, for a report that
// produced one.
func ForSBOM() Reference {
	return craSBOM
}
