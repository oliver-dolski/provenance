package manifest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oliver-dolski/provenance/internal/component"
)

// npmLock covers both lockfile layouts. npm v7 and later write "packages",
// keyed by install path; npm v6 wrote a nested "dependencies" tree. Lockfile
// version 2 carries both for backward compatibility, and "packages" is the
// authoritative one there.
type npmLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
	Dependencies    map[string]npmLockDepV1   `json:"dependencies"`
}

type npmLockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Dev                  bool              `json:"dev"`
	DevOptional          bool              `json:"devOptional"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type npmLockDepV1 struct {
	Version      string                  `json:"version"`
	Resolved     string                  `json:"resolved"`
	Integrity    string                  `json:"integrity"`
	Dev          bool                    `json:"dev"`
	Dependencies map[string]npmLockDepV1 `json:"dependencies"`
}

// npmManifest is the part of package.json this scanner reads.
type npmManifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// parseNPMLock reads package-lock.json or npm-shrinkwrap.json.
func parseNPMLock(set *component.Set, data []byte, source string) error {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if len(lock.Packages) > 0 {
		parseNPMPackages(set, lock, source)
		return nil
	}
	if len(lock.Dependencies) > 0 {
		for name, dep := range lock.Dependencies {
			addNPMDepV1(set, name, dep, source)
		}
		return nil
	}
	// An empty lockfile is a valid lockfile for a project with no
	// dependencies. Only an unrecognized layout is worth reporting.
	if lock.LockfileVersion == 0 {
		return fmt.Errorf("not an npm lockfile: no lockfileVersion, packages or dependencies")
	}
	return nil
}

// parseNPMPackages reads the flat "packages" map of lockfile version 2 and 3.
func parseNPMPackages(set *component.Set, lock npmLock, source string) {
	root := lock.Packages[""]
	declared := make(map[string]string, len(root.Dependencies)+len(root.DevDependencies))
	for name, constraint := range root.Dependencies {
		declared[name] = constraint
	}
	for name, constraint := range root.DevDependencies {
		declared[name] = constraint
	}
	for name, constraint := range root.OptionalDependencies {
		declared[name] = constraint
	}

	for path, pkg := range lock.Packages {
		if path == "" {
			// The root entry describes the scanned project itself, not one of
			// its dependencies.
			continue
		}
		if pkg.Link {
			// A link points at a workspace inside this repository. It is local
			// source, not something pulled from a registry.
			continue
		}
		name := npmNameFromPath(path)
		if name == "" || pkg.Version == "" {
			continue
		}
		c := component.Component{
			Name:      name,
			Ecosystem: component.NPM,
			Version:   pkg.Version,
			Dev:       pkg.Dev || pkg.DevOptional,
			Resolved:  pkg.Resolved,
			Integrity: pkg.Integrity,
			Source:    source,
		}
		// A package installed at the top of node_modules and named in the
		// project's own dependencies is a direct dependency. Anything deeper
		// was pulled in by another package.
		if constraint, ok := declared[name]; ok && strings.Count(path, "node_modules/") == 1 {
			c.Direct = true
			c.Constraint = constraint
		}
		set.Add(c)
	}
}

// npmNameFromPath turns a lockfile install path into a package name:
// "node_modules/foo" and "node_modules/a/node_modules/@scope/foo" both name the
// package after the last "node_modules/" segment.
func npmNameFromPath(path string) string {
	const marker = "node_modules/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		// A path outside node_modules is a workspace package: local source.
		return ""
	}
	return path[idx+len(marker):]
}

// addNPMDepV1 walks the nested tree of a version 1 lockfile. Directness is left
// to package.json: the v1 layout hoists packages, so a top-level entry is not
// necessarily one the project declared.
func addNPMDepV1(set *component.Set, name string, dep npmLockDepV1, source string) {
	if dep.Version != "" {
		set.Add(component.Component{
			Name:      name,
			Ecosystem: component.NPM,
			Version:   dep.Version,
			Dev:       dep.Dev,
			Resolved:  dep.Resolved,
			Integrity: dep.Integrity,
			Source:    source,
		})
	}
	for nestedName, nested := range dep.Dependencies {
		addNPMDepV1(set, nestedName, nested, source)
	}
}

// parseNPMManifest reads package.json. It states what the project asked for,
// which is where an unpinned range becomes visible; the resolved version, if
// any, comes from the lockfile.
func parseNPMManifest(set *component.Set, data []byte, source string) error {
	var m npmManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	declare := func(deps map[string]string, dev bool) {
		for name, constraint := range deps {
			set.Declare(component.Component{
				Name:       name,
				Ecosystem:  component.NPM,
				Constraint: constraint,
				Direct:     true,
				Dev:        dev,
				Source:     source,
			})
		}
	}
	declare(m.Dependencies, false)
	declare(m.OptionalDependencies, false)
	declare(m.DevDependencies, true)
	return nil
}
