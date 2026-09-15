package osv

import (
	"math"
	"strings"
)

// scoreCVSS computes the CVSS base score for a version 3.0 or 3.1 vector
// string. Vulnerability records state the vector, not the number, and the band
// a finding lands in decides whether anyone acts on it - so the score is
// computed here rather than guessed from whatever word a database attached.
//
// The formulas are those of the CVSS v3.1 specification, section 7.1.
func scoreCVSS(vector string) (float64, bool) {
	metrics := parseVector(vector)
	if metrics == nil {
		return 0, false
	}

	av, ok := lookup(metrics, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0, false
	}
	ac, ok := lookup(metrics, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0, false
	}
	ui, ok := lookup(metrics, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0, false
	}
	conf, ok := lookup(metrics, "C", impactValues)
	if !ok {
		return 0, false
	}
	integ, ok := lookup(metrics, "I", impactValues)
	if !ok {
		return 0, false
	}
	avail, ok := lookup(metrics, "A", impactValues)
	if !ok {
		return 0, false
	}

	// A changed scope means the vulnerable component can affect resources
	// beyond its own security authority, which raises both the privilege
	// weights and the impact formula.
	scopeChanged := metrics["S"] == "C"
	if _, present := metrics["S"]; !present {
		return 0, false
	}
	privileges := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		privileges = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	}
	pr, ok := lookup(metrics, "PR", privileges)
	if !ok {
		return 0, false
	}

	iss := 1 - ((1 - conf) * (1 - integ) * (1 - avail))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	score := impact + exploitability
	if scopeChanged {
		score *= 1.08
	}
	return roundUp(math.Min(score, 10)), true
}

// impactValues are the weights shared by the confidentiality, integrity and
// availability metrics.
var impactValues = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

// parseVector splits "CVSS:3.1/AV:N/AC:L/..." into its metrics. A vector of
// another version is rejected: applying these formulas to a v2 or v4 vector
// would produce a number that looks authoritative and is wrong.
func parseVector(vector string) map[string]string {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return nil
	}
	metrics := make(map[string]string)
	for _, part := range strings.Split(vector, "/")[1:] {
		key, value, found := strings.Cut(part, ":")
		if !found {
			continue
		}
		metrics[key] = value
	}
	return metrics
}

// lookup reads one metric and maps it to its weight.
func lookup(metrics map[string]string, key string, values map[string]float64) (float64, bool) {
	value, ok := values[metrics[key]]
	return value, ok
}

// roundUp rounds to one decimal place, always upwards, as the specification
// defines it. The integer arithmetic avoids the floating point case where a
// score of exactly 8.6 rounds up to 8.7.
func roundUp(value float64) float64 {
	scaled := int(math.Round(value * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000
	}
	return (math.Floor(float64(scaled)/10000) + 1) / 10
}
