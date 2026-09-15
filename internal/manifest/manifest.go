// Package manifest finds a project's dependency manifests and lockfiles and
// parses them into normalized components. It only reads files: nothing here
// installs, resolves or executes anything from the scanned project.
package manifest

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/oliver-dolski/provenance/internal/component"
)

// Kind is the type of a dependency file, which decides both the parser used
// and how much the file can be trusted about versions.
type Kind string

const (
	// KindNPMLock is package-lock.json or npm-shrinkwrap.json: resolved
	// versions, registry URLs and integrity hashes.
	KindNPMLock Kind = "npm-lock"
	// KindNPMManifest is package.json: declared dependencies and ranges.
	KindNPMManifest Kind = "npm-manifest"
	// KindPoetryLock is poetry.lock: resolved versions.
	KindPoetryLock Kind = "poetry-lock"
	// KindRequirements is a pip requirements file: usually declarations, and
	// resolved versions only where the author pinned with "==".
	KindRequirements Kind = "pip-requirements"
)

// resolvesVersions reports whether a file states exact installed versions.
// Those files are parsed first so that declarations from manifests annotate
// resolved components instead of adding versionless duplicates.
func (k Kind) resolvesVersions() bool {
	return k == KindNPMLock || k == KindPoetryLock
}

// File is one dependency file found under the scan root.
type File struct {
	Kind Kind
	// Path is the location on disk, used to open the file.
	Path string
	// Rel is the path relative to the scan root with forward slashes. It is
	// what findings quote, so output is identical on every platform.
	Rel string
}

// Problem is a file that was found but could not be fully read. Scanning
// continues: a project with one unreadable manifest should still get an SBOM
// for the rest, as long as the gap is reported rather than hidden.
type Problem struct {
	File string
	Err  error
}

func (p Problem) Error() string { return p.File + ": " + p.Err.Error() }

// skippedDirs are directories that hold installed packages, build output or
// tooling state. Walking them would report the dependencies of dependencies as
// if the project declared them, and on a large project it is most of the walk.
var skippedDirs = map[string]bool{
	".git":             true,
	".hg":              true,
	".svn":             true,
	".tox":             true,
	".nox":             true,
	".venv":            true,
	"venv":             true,
	"env":              true,
	"node_modules":     true,
	"bower_components": true,
	"vendor":           true,
	"__pycache__":      true,
	"site-packages":    true,
	".mypy_cache":      true,
	".pytest_cache":    true,
	".gradle":          true,
	".idea":            true,
	".vscode":          true,
}

// classify maps a file to a parser, or returns false when the file is not a
// dependency file this scanner understands. The parent directory matters: pip
// projects commonly split their requirements into requirements/base.txt and
// requirements/dev.txt, whose names say nothing on their own.
func classify(name, parent string) (Kind, bool) {
	switch name {
	case "package-lock.json", "npm-shrinkwrap.json":
		return KindNPMLock, true
	case "package.json":
		return KindNPMManifest, true
	case "poetry.lock":
		return KindPoetryLock, true
	}
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".txt") {
		return "", false
	}
	// requirements.txt, requirements-dev.txt, requirements_test.txt.
	if strings.HasPrefix(lower, "requirements") {
		return KindRequirements, true
	}
	// Any .txt inside a requirements/ directory.
	if strings.ToLower(parent) == "requirements" {
		return KindRequirements, true
	}
	return "", false
}

// Discover walks the project tree and returns every dependency file it
// recognizes, in a stable order.
func Discover(root string) ([]File, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", root)
	}

	var files []File
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable subtree is not a reason to abandon the scan; it is
			// reported when the file itself is parsed, or simply skipped here.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != root && (skippedDirs[d.Name()] || strings.HasSuffix(d.Name(), ".egg-info")) {
				return fs.SkipDir
			}
			return nil
		}
		kind, ok := classify(d.Name(), filepath.Base(filepath.Dir(path)))
		if !ok {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		files = append(files, File{Kind: kind, Path: path, Rel: filepath.ToSlash(rel)})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(files, func(i, j int) bool {
		// Files that resolve versions come first, so later declarations
		// annotate them instead of duplicating them.
		ri, rj := files[i].Kind.resolvesVersions(), files[j].Kind.resolvesVersions()
		if ri != rj {
			return ri
		}
		return files[i].Rel < files[j].Rel
	})
	return files, nil
}

// Scan discovers and parses every dependency file under root. It returns the
// components found, the files that could not be read, and an error only when
// the root itself is unusable.
func Scan(root string) (*component.Set, []Problem, error) {
	files, err := Discover(root)
	if err != nil {
		return nil, nil, err
	}

	set := component.NewSet()
	var problems []Problem
	for _, f := range files {
		if err := parseInto(set, f); err != nil {
			problems = append(problems, Problem{File: f.Rel, Err: err})
		}
	}
	return set, problems, nil
}

// parseInto dispatches one file to its parser.
func parseInto(set *component.Set, f File) error {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return err
	}
	switch f.Kind {
	case KindNPMLock:
		return parseNPMLock(set, data, f.Rel)
	case KindNPMManifest:
		return parseNPMManifest(set, data, f.Rel)
	case KindPoetryLock:
		return parsePoetryLock(set, data, f.Rel)
	case KindRequirements:
		// The directory is needed to follow "-r other.txt" includes, and the
		// file itself is pre-marked as read so a self-include terminates.
		seen := map[string]bool{}
		if abs, err := filepath.Abs(f.Path); err == nil {
			seen[abs] = true
		}
		return parseRequirementsFile(set, data, f.Rel, filepath.Dir(f.Path), 0, seen)
	default:
		return fmt.Errorf("no parser for %s", f.Kind)
	}
}
