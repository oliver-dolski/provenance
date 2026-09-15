package manifest

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/oliver-dolski/provenance/internal/component"
)

// requirementLine splits "name[extras] specifier ; markers" into its parts. The
// name grammar follows PEP 508: a letter or digit first, then letters, digits,
// and the separators PEP 503 treats as equivalent.
var requirementLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$`)

// exactVersion matches a specifier that pins one version and nothing else.
// "==1.2.*" is deliberately excluded: a wildcard is a range.
var exactVersion = regexp.MustCompile(`^={2,3}\s*([^\s,*]+)$`)

// inlineComment matches a pip comment: a "#" at the start of a line or after
// whitespace. A "#" glued to a URL is a fragment, not a comment.
var inlineComment = regexp.MustCompile(`(^|\s)#.*$`)

// maxRequirementDepth bounds "-r other.txt" recursion. Requirements files are
// allowed to include each other, and a cycle would otherwise not terminate.
const maxRequirementDepth = 10

// parseRequirementsFile reads a pip requirements file. Such a file usually
// states declarations rather than a resolved set, so a version is only recorded
// when the author pinned it with "==". It carries the on-disk directory needed
// to follow "-r" includes, and the set of files already read so a cycle ends.
func parseRequirementsFile(set *component.Set, data []byte, source, dir string, depth int, seen map[string]bool) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var logical strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		// A trailing backslash continues the requirement on the next line.
		if trimmed := strings.TrimRight(line, " \t"); strings.HasSuffix(trimmed, `\`) {
			logical.WriteString(strings.TrimSuffix(trimmed, `\`))
			continue
		}
		logical.WriteString(line)
		parseRequirement(set, logical.String(), source, dir, depth, seen)
		logical.Reset()
	}
	if logical.Len() > 0 {
		parseRequirement(set, logical.String(), source, dir, depth, seen)
	}
	return scanner.Err()
}

// parseRequirement handles one logical line.
func parseRequirement(set *component.Set, line, source, dir string, depth int, seen map[string]bool) {
	line = strings.TrimSpace(inlineComment.ReplaceAllString(line, ""))
	if line == "" {
		return
	}

	if strings.HasPrefix(line, "-") {
		followInclude(set, line, source, dir, depth, seen)
		return
	}

	match := requirementLine.FindStringSubmatch(line)
	if match == nil {
		return
	}
	name := match[1]
	rest := strings.TrimSpace(match[3])

	// "--hash=" pins the artifact, not the version, and never changes which
	// package is meant.
	if idx := strings.Index(rest, "--hash"); idx >= 0 {
		rest = strings.TrimSpace(rest[:idx])
	}
	// Environment markers decide whether the requirement applies, not which
	// version it is.
	if idx := strings.Index(rest, ";"); idx >= 0 {
		rest = strings.TrimSpace(rest[:idx])
	}

	c := component.Component{
		Name:       name,
		Ecosystem:  component.PyPI,
		Constraint: rest,
		Direct:     true,
		Source:     source,
	}
	switch {
	case strings.HasPrefix(rest, "@"):
		// "name @ https://..." installs from a URL instead of the index. The
		// version is whatever that URL serves, so none is recorded.
		c.Resolved = strings.TrimSpace(strings.TrimPrefix(rest, "@"))
	default:
		if m := exactVersion.FindStringSubmatch(rest); m != nil {
			c.Version = m[1]
		}
	}
	set.Declare(c)
}

// followInclude handles the option lines of a requirements file. Only "-r"
// brings in more requirements; the rest either configure pip or point at local
// sources, neither of which is a component from a registry.
func followInclude(set *component.Set, line, source, dir string, depth int, seen map[string]bool) {
	fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == '=' })
	if len(fields) < 2 {
		return
	}
	if fields[0] != "-r" && fields[0] != "--requirement" {
		return
	}
	if dir == "" || depth >= maxRequirementDepth {
		return
	}

	target := filepath.Join(dir, filepath.FromSlash(fields[1]))
	abs, err := filepath.Abs(target)
	if err != nil || seen[abs] {
		return
	}
	seen[abs] = true

	data, err := os.ReadFile(target)
	if err != nil {
		return
	}
	rel := filepath.ToSlash(filepath.Join(filepath.Dir(source), fields[1]))
	parseRequirementsFile(set, data, rel, filepath.Dir(target), depth+1, seen)
}

// parsePoetryLock reads poetry.lock. Only the fields that identify a component
// are read, which keeps the scanner free of a TOML dependency - fitting, for a
// tool whose subject is dependencies it did not need to take.
func parsePoetryLock(set *component.Set, data []byte, source string) error {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var current component.Component
	var inPackage, inSource bool
	flush := func() {
		if inPackage && current.Name != "" {
			set.Add(current)
		}
		current = component.Component{}
		inPackage, inSource = false, false
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			switch {
			case line == "[[package]]":
				flush()
				inPackage = true
				current = component.Component{Ecosystem: component.PyPI, Source: source}
			case inPackage && line == "[package.source]":
				// Where poetry was told to fetch this package from, which is
				// worth keeping when it is not the public index.
				inSource = true
			case inPackage && strings.HasPrefix(line, "[package."):
				// Dependencies, extras and files of the current package: the
				// package's own fields have ended.
				inSource = false
			default:
				flush()
			}
			continue
		}
		if !inPackage {
			continue
		}

		key, value, ok := poetryField(line)
		if !ok {
			continue
		}
		switch {
		case inSource && key == "url":
			current.Resolved = value
		case inSource:
			// Other source fields (type, reference) do not identify the
			// component.
		case key == "name":
			current.Name = value
		case key == "version":
			current.Version = value
		case key == "category":
			// Poetry before 1.5 recorded the dependency group here.
			current.Dev = value == "dev"
		}
	}
	flush()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading poetry.lock: %w", err)
	}
	return nil
}

// poetryField splits a `key = "value"` line, returning the unquoted value.
func poetryField(line string) (key, value string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}
