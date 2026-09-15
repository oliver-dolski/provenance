package osv

import (
	"math"
	"testing"
)

func TestScoreCVSS(t *testing.T) {
	// Vectors and scores published with the CVSS v3.1 specification and with
	// the advisories they come from.
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
	}
	for _, tc := range cases {
		got, ok := scoreCVSS(tc.vector)
		if !ok {
			t.Errorf("scoreCVSS(%q) rejected a valid vector", tc.vector)
			continue
		}
		if math.Abs(got-tc.want) > 0.001 {
			t.Errorf("scoreCVSS(%q) = %.1f, want %.1f", tc.vector, got, tc.want)
		}
	}
}

func TestScoreCVSSRejectsOtherVersions(t *testing.T) {
	// A v2 or v4 vector scored with v3 formulas would produce a number that
	// looks authoritative and is wrong.
	for _, vector := range []string{
		"",
		"AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:2.0/AV:N/AC:L",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"CVSS:3.1/AV:N/AC:L",
	} {
		if _, ok := scoreCVSS(vector); ok {
			t.Errorf("scoreCVSS(%q) produced a score it cannot compute", vector)
		}
	}
}
