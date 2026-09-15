package risk

import (
	_ "embed"
	"sort"
	"strings"
	"sync"

	"github.com/oliver-dolski/provenance/internal/component"
)

// The bundled name lists. They are a static snapshot of widely used packages,
// carried in the binary so the check works without a network call. A name that
// is not on a list is not thereby judged safe, and the report says so.

//go:embed data/npm-popular.txt
var npmPopularData string

//go:embed data/pypi-popular.txt
var pypiPopularData string

// minComparableLength is the shortest name compared against the lists. On very
// short names a single edit is most of the name, and unrelated packages such as
// "ms" and "mz" would be reported as look-alikes.
const minComparableLength = 4

var (
	popularOnce sync.Once
	popular     map[component.Ecosystem][]string
	popularSet  map[component.Ecosystem]map[string]bool
)

// loadPopular parses the bundled lists once.
func loadPopular() {
	popular = make(map[component.Ecosystem][]string, 2)
	popularSet = make(map[component.Ecosystem]map[string]bool, 2)

	for eco, data := range map[component.Ecosystem]string{
		component.NPM:  npmPopularData,
		component.PyPI: pypiPopularData,
	} {
		names := make([]string, 0, 128)
		set := make(map[string]bool, 128)
		for _, line := range strings.Split(data, "\n") {
			name := strings.TrimSpace(line)
			if name == "" || strings.HasPrefix(name, "#") {
				continue
			}
			name = eco.NormalizeName(name)
			if set[name] {
				continue
			}
			set[name] = true
			names = append(names, name)
		}
		sort.Strings(names)
		popular[eco] = names
		popularSet[eco] = set
	}
}

// PopularNameCount reports how many names the bundled list for an ecosystem
// holds, so a report can state the size of the comparison rather than implying
// it covers the registry.
func PopularNameCount(eco component.Ecosystem) int {
	popularOnce.Do(loadPopular)
	return len(popular[eco])
}

// nearestPopular returns a widely used package name that the given name is one
// typo away from. A name that is itself on the list matches nothing: it is the
// popular package, not an imitation of it.
func nearestPopular(eco component.Ecosystem, name string) (string, bool) {
	popularOnce.Do(loadPopular)

	if len(name) < minComparableLength || popularSet[eco][name] {
		return "", false
	}
	// The list is sorted, so the first match is the same on every run.
	for _, candidate := range popular[eco] {
		if len(candidate) < minComparableLength {
			continue
		}
		if isOneTypoApart(name, candidate) {
			return candidate, true
		}
	}
	return "", false
}

// isOneTypoApart reports whether two names differ by a single typing mistake:
// one character substituted, inserted, deleted, or two adjacent characters
// swapped. Package names in both ecosystems are ASCII by registry rule, so
// comparing bytes is comparing characters.
func isOneTypoApart(a, b string) bool {
	if a == b {
		return false
	}
	switch len(a) - len(b) {
	case 0:
		return differsBySubstitution(a, b) || differsByTransposition(a, b)
	case 1:
		return differsByOneCharacter(a, b)
	case -1:
		return differsByOneCharacter(b, a)
	default:
		return false
	}
}

// differsBySubstitution reports whether two equal-length names differ in
// exactly one position.
func differsBySubstitution(a, b string) bool {
	differences := 0
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			differences++
			if differences > 1 {
				return false
			}
		}
	}
	return differences == 1
}

// differsByTransposition reports whether two equal-length names differ only by
// two adjacent characters being swapped, which is what a fast typist produces.
func differsByTransposition(a, b string) bool {
	first := -1
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			continue
		}
		if first < 0 {
			first = i
			continue
		}
		// A second difference is only acceptable directly after the first, and
		// only if the two characters are each other's.
		if i != first+1 || a[first] != b[i] || a[i] != b[first] {
			return false
		}
		// Everything after the swapped pair must match.
		return a[i+1:] == b[i+1:]
	}
	return false
}

// differsByOneCharacter reports whether the longer name becomes the shorter one
// by removing a single character.
func differsByOneCharacter(longer, shorter string) bool {
	for i := 0; i < len(longer); i++ {
		if i < len(shorter) && longer[i] == shorter[i] {
			continue
		}
		return longer[i+1:] == shorter[i:]
	}
	// The names are equal up to the last character of the longer one.
	return true
}
