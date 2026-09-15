// Package guidance connects a finding to the obligation or practice it bears
// on. The point is not to claim compliance: it is to save the reader the step
// of working out why a scanner's output matters to the framework their
// organization is measured against.
//
// Each reference names its source document and quotes or paraphrases one
// requirement from it. Nothing here is legal advice, and a scanner cannot
// establish that a product conforms to a regulation - only that an obligation
// is engaged and someone should look.
package guidance

import "github.com/oliver-dolski/provenance/internal/finding"

// Reference is one framework requirement a finding relates to.
type Reference struct {
	// Framework is the short name of the source document.
	Framework string
	// Clause locates the requirement inside it.
	Clause string
	// Statement says what that requirement asks for.
	Statement string
	// URL is where the source document can be read.
	URL string
}

// String renders the reference on one line.
func (r Reference) String() string {
	return r.Framework + " " + r.Clause + ": " + r.Statement
}

const (
	craURL  = "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"
	slsaURL = "https://slsa.dev/spec/v1.0/threats"
)

// craSBOM is the obligation that makes a component inventory mandatory rather
// than good practice, for products in scope of the Cyber Resilience Act.
var craSBOM = Reference{
	Framework: "CRA",
	Clause:    "Regulation (EU) 2024/2847, Annex I, Part II (1)",
	Statement: "identify and document vulnerabilities and components, including a software bill of materials covering at least the top-level dependencies",
	URL:       craURL,
}

// craRemediate is the obligation to act on what the inventory reveals.
var craRemediate = Reference{
	Framework: "CRA",
	Clause:    "Regulation (EU) 2024/2847, Annex I, Part II (2)",
	Statement: "address and remediate vulnerabilities without delay, including by providing security updates",
	URL:       craURL,
}

// slsaDependency covers the threat of a build consuming a dependency that is
// not the one that was reviewed.
var slsaDependency = Reference{
	Framework: "SLSA",
	Clause:    "v1.0 supply chain threats, dependency threats",
	Statement: "a build that does not fix what it consumes can take in a package nobody reviewed",
	URL:       slsaURL,
}

// slsaArtifact covers the threat of the registry or the transport serving
// different bytes than the ones that were reviewed.
var slsaArtifact = Reference{
	Framework: "SLSA",
	Clause:    "v1.0 supply chain threats, package threats",
	Statement: "without a hash of the artifact, a modified package served for the same version is not detected",
	URL:       slsaURL,
}

// byKind maps each kind of finding to the requirements it engages.
var byKind = map[finding.Kind][]Reference{
	finding.KindVulnerability:    {craRemediate},
	finding.KindUnpinned:         {slsaDependency, craSBOM},
	finding.KindPrivateSource:    {slsaDependency},
	finding.KindTyposquat:        {slsaDependency},
	finding.KindMissingIntegrity: {slsaArtifact},
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
