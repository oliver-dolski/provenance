// Command provenance is a supply-chain security scanner. It reads a project's
// dependency manifests and lockfiles, builds an SBOM, and reports known
// vulnerabilities and supply-chain risks with a reason and a reference for
// each finding.
//
// This is an early scaffold: it wires up the entry point and version handling.
// Scanning is not implemented yet.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is the build version. It is overridden at release time via ldflags.
var version = "0.0.1-dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	// No scan target yet: the scanner is not implemented. Print usage so the
	// binary is honest about its current state instead of pretending to work.
	usage()
	os.Exit(2)
}

func usage() {
	fmt.Fprintf(os.Stderr, `provenance %s - supply-chain security scanner

Usage:
  provenance [flags] <project-path>

Flags:
  -version    print version and exit

Status: early scaffold. Scanning is not implemented yet.
`, version)
}
