// Package risk holds the supply-chain checks that need no network and no
// vulnerability database: what the manifests themselves already say about how a
// build can be influenced. A published vulnerability is a known problem in
// known code; these checks are about the ways unreviewed code gets in.
package risk

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/oliver-dolski/provenance/internal/component"
	"github.com/oliver-dolski/provenance/internal/finding"
)

// source names this scanner as the origin of a finding, as opposed to an
// advisory database. A reader weighs the two differently and should be able to
// tell them apart at a glance.
const source = "provenance"

// Check runs every offline supply-chain check over the scanned components.
func Check(components []component.Component) []finding.Finding {
	var findings []finding.Finding
	for _, c := range components {
		findings = append(findings, checkComponent(c)...)
	}
	finding.Sort(findings)
	return findings
}

// checkComponent applies each check to one component.
func checkComponent(c component.Component) []finding.Finding {
	var findings []finding.Finding
	for _, check := range []func(component.Component) (finding.Finding, bool){
		checkUnpinned,
		checkPrivateSource,
		checkTyposquat,
		checkMissingIntegrity,
	} {
		if f, ok := check(c); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

// checkUnpinned reports a dependency that is not fixed to one version. The
// build that passes review and the build that ships can then contain different
// code, and a compromised release of that package enters without anyone
// changing a file in the project.
func checkUnpinned(c component.Component) (finding.Finding, bool) {
	if c.Pinned() {
		return finding.Finding{}, false
	}

	// A dependency that ships is worth more attention than one used only to run
	// the tests, though neither is harmless: a build-time package executes on
	// the machine that builds the release.
	severity := finding.Low
	if c.Direct && !c.Dev {
		severity = finding.Medium
	}

	constraint := c.Constraint
	if constraint == "" {
		constraint = "no version stated"
	}
	return finding.Finding{
		Kind:      finding.KindUnpinned,
		Severity:  severity,
		Component: c,
		Title:     fmt.Sprintf("%s is not pinned to a version", c.Name),
		Detail: fmt.Sprintf(
			"%s declares %s as %q and no lockfile resolves it. Two builds of the same commit can install different code, and a new release of the package enters the project without a change to review.",
			c.Source, c.Name, constraint),
		Source: source,
	}, true
}

// publicRegistries are the hosts that serve each ecosystem's public packages.
var publicRegistries = map[component.Ecosystem]map[string]bool{
	component.NPM: {
		"registry.npmjs.org":   true,
		"registry.npmjs.com":   true,
		"registry.yarnpkg.com": true,
	},
	component.PyPI: {
		"pypi.org":               true,
		"pypi.python.org":        true,
		"files.pythonhosted.org": true,
	},
}

// checkPrivateSource reports a component fetched from somewhere other than the
// ecosystem's public registry. That is normal in an organization that runs its
// own registry, and it is also the precondition for dependency confusion: if
// the same name is published publicly with a higher version, a resolver that
// consults both indexes can prefer the public one, and the build installs a
// stranger's package under an internal name.
func checkPrivateSource(c component.Component) (finding.Finding, bool) {
	if c.Resolved == "" {
		return finding.Finding{}, false
	}
	parsed, err := url.Parse(c.Resolved)
	if err != nil || parsed.Host == "" {
		// A relative path points inside the repository, which is local source
		// rather than a fetch from anywhere.
		return finding.Finding{}, false
	}
	host := strings.ToLower(parsed.Hostname())
	if publicRegistries[c.Ecosystem][host] {
		return finding.Finding{}, false
	}

	// An npm scope is owned by whoever registered it publicly, which blocks the
	// simplest form of the attack. An unscoped internal name does not have that
	// protection: anyone can publish it on the public registry.
	severity := finding.Medium
	protection := ""
	if c.Ecosystem == component.NPM {
		if strings.HasPrefix(c.Name, "@") {
			protection = " The name is scoped, so the public registry will only serve it to whoever owns the scope."
		} else {
			severity = finding.High
			protection = " The name is unscoped, so anyone can publish it on the public registry under a higher version."
		}
	}

	return finding.Finding{
		Kind:      finding.KindPrivateSource,
		Severity:  severity,
		Component: c,
		Title:     fmt.Sprintf("%s is fetched from %s, not the public registry", c.Name, host),
		Detail: fmt.Sprintf(
			"%s resolves this package to %s.%s Confirm that the build cannot fall back to a public index for this name.",
			c.Source, c.Resolved, protection),
		Source:     source,
		References: []string{"https://slsa.dev/spec/v1.0/threats"},
	}, true
}

// checkTyposquat reports a name one edit away from a widely used package. The
// attack is to publish such a name and wait for a typo in someone's install
// command or manifest.
func checkTyposquat(c component.Component) (finding.Finding, bool) {
	name := c.Ecosystem.NormalizeName(c.Name)
	// A scoped npm name is served only to whoever owns the scope, so a
	// resemblance in the package part is not the same exposure.
	if strings.HasPrefix(name, "@") {
		return finding.Finding{}, false
	}

	target, ok := nearestPopular(c.Ecosystem, name)
	if !ok {
		return finding.Finding{}, false
	}
	return finding.Finding{
		Kind: finding.KindTyposquat,
		// A name similarity is a reason to look, not a finding of malice: an
		// unrelated project is allowed to be spelled almost like a popular one.
		Severity:  finding.Medium,
		Component: c,
		Title:     fmt.Sprintf("%s is one character away from %s", c.Name, target),
		Detail: fmt.Sprintf(
			"%s depends on %q, which differs by a single character from the widely used package %q. Confirm that the name in the manifest is the package that was meant.",
			c.Source, c.Name, target),
		Source: source,
	}, true
}

// checkMissingIntegrity reports a locked component with no content hash. The
// lockfile then fixes which version is installed but not which bytes, so a
// registry or proxy that serves different content for that version is not
// detected by the install.
func checkMissingIntegrity(c component.Component) (finding.Finding, bool) {
	// Only lockfile entries make this claim. A declaration in package.json or a
	// requirements line is not expected to carry a hash.
	if c.Resolved == "" || c.Integrity != "" {
		return finding.Finding{}, false
	}
	// A path inside the repository is local source, which no hash covers.
	if parsed, err := url.Parse(c.Resolved); err != nil || parsed.Host == "" {
		return finding.Finding{}, false
	}

	return finding.Finding{
		Kind:      finding.KindMissingIntegrity,
		Severity:  finding.Low,
		Component: c,
		Title:     fmt.Sprintf("%s %s is locked without an integrity hash", c.Name, c.Version),
		Detail: fmt.Sprintf(
			"%s records where %s comes from but no hash of what it contains, so an install cannot tell that the artifact served for this version is the one that was reviewed.",
			c.Source, c.Name),
		Source:     source,
		References: []string{"https://slsa.dev/spec/v1.0/threats"},
	}, true
}
