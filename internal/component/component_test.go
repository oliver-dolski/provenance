package component

import "testing"

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		eco  Ecosystem
		in   string
		want string
	}{
		{PyPI, "Flask_Login", "flask-login"},
		{PyPI, "zope.interface", "zope-interface"},
		{PyPI, "ruamel.yaml.clib", "ruamel-yaml-clib"},
		{PyPI, "already-normal", "already-normal"},
		{NPM, "@scope/Name", "@scope/Name"},
	}
	for _, tc := range cases {
		if got := tc.eco.NormalizeName(tc.in); got != tc.want {
			t.Errorf("%s.NormalizeName(%q) = %q, want %q", tc.eco, tc.in, got, tc.want)
		}
	}
}

func TestPURL(t *testing.T) {
	cases := []struct {
		c    Component
		want string
	}{
		{Component{Name: "lodash", Ecosystem: NPM, Version: "4.17.21"}, "pkg:npm/lodash@4.17.21"},
		{Component{Name: "@babel/core", Ecosystem: NPM, Version: "7.24.0"}, "pkg:npm/@babel/core@7.24.0"},
		{Component{Name: "Flask", Ecosystem: PyPI, Version: "3.0.0"}, "pkg:pypi/flask@3.0.0"},
		{Component{Name: "requests", Ecosystem: PyPI}, "pkg:pypi/requests"},
	}
	for _, tc := range cases {
		if got := tc.c.PURL(); got != tc.want {
			t.Errorf("PURL(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}

func TestSetMergesDuplicates(t *testing.T) {
	s := NewSet()
	s.Add(Component{Name: "lodash", Ecosystem: NPM, Version: "4.17.21", Dev: true, Source: "package-lock.json"})
	s.Add(Component{Name: "lodash", Ecosystem: NPM, Version: "4.17.21", Direct: true, Constraint: "^4.17.0", Source: "package.json"})

	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1", s.Len())
	}
	got := s.All()[0]
	if !got.Direct {
		t.Error("merged component lost Direct")
	}
	if got.Dev {
		t.Error("merged component stayed Dev although one sighting was runtime")
	}
	if got.Constraint != "^4.17.0" {
		t.Errorf("Constraint = %q, want %q", got.Constraint, "^4.17.0")
	}
	if got.Source != "package-lock.json, package.json" {
		t.Errorf("Source = %q, want both manifests", got.Source)
	}
}

func TestSetKeepsVersionsApart(t *testing.T) {
	s := NewSet()
	s.Add(Component{Name: "lodash", Ecosystem: NPM, Version: "4.17.21"})
	s.Add(Component{Name: "lodash", Ecosystem: NPM, Version: "3.10.1"})
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2: different versions are different components", s.Len())
	}
}

func TestPyPINamesMatchAcrossSpellings(t *testing.T) {
	s := NewSet()
	s.Add(Component{Name: "Flask_Login", Ecosystem: PyPI, Version: "0.6.3", Source: "requirements.txt"})
	s.Add(Component{Name: "flask-login", Ecosystem: PyPI, Version: "0.6.3", Source: "poetry.lock"})
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1: PEP 503 makes these the same project", s.Len())
	}
}

func TestAllIsSorted(t *testing.T) {
	s := NewSet()
	s.Add(Component{Name: "zod", Ecosystem: NPM, Version: "3.22.4"})
	s.Add(Component{Name: "requests", Ecosystem: PyPI, Version: "2.31.0"})
	s.Add(Component{Name: "axios", Ecosystem: NPM, Version: "1.6.0"})

	got := s.All()
	want := []string{"axios", "zod", "requests"}
	for i, name := range want {
		if got[i].Name != name {
			t.Fatalf("All()[%d].Name = %q, want %q (order: %v)", i, got[i].Name, name, got)
		}
	}
}

func TestPinned(t *testing.T) {
	if (Component{Version: "1.0.0"}).Pinned() != true {
		t.Error("a component with a version should be pinned")
	}
	if (Component{Constraint: ">=1.0"}).Pinned() != false {
		t.Error("a component with only a constraint should not be pinned")
	}
}

func TestDeclareAnnotatesResolvedComponent(t *testing.T) {
	s := NewSet()
	s.Add(Component{Name: "lodash", Ecosystem: NPM, Version: "4.17.21", Dev: true, Source: "package-lock.json"})
	s.Declare(Component{Name: "lodash", Ecosystem: NPM, Constraint: "^4.17.0", Source: "package.json"})

	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1: a declaration must not clone the resolved package", s.Len())
	}
	got := s.All()[0]
	if !got.Direct || got.Version != "4.17.21" || got.Constraint != "^4.17.0" {
		t.Errorf("got %+v, want direct lodash@4.17.21 constrained to ^4.17.0", got)
	}
}

func TestDeclareKeepsUnresolvedDependency(t *testing.T) {
	s := NewSet()
	s.Declare(Component{Name: "express", Ecosystem: NPM, Constraint: "^4.18.0", Direct: true, Source: "package.json"})
	if s.Len() != 1 {
		t.Fatalf("Len = %d, want 1: an unpinned declaration is still a component", s.Len())
	}
	if s.All()[0].Pinned() {
		t.Error("a declaration without a lockfile must not look pinned")
	}
}
