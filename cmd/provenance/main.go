// Command provenance is a supply-chain security scanner. It reads a project's
// dependency manifests and lockfiles, builds an SBOM, and reports supply-chain
// risks with a reason and a reference for each finding.
//
// It only reads files. Nothing here installs, builds or executes any part of
// the scanned project.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is the build version. It is overridden at release time via ldflags.
var version = "0.0.1-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// Exit codes. They are part of the interface: a pipeline reacts to them.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// run holds the program so that tests can drive it with explicit arguments and
// capture what it writes, instead of reaching for the process state.
func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseArgs(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "provenance: %v\n", err)
		return exitUsage
	}
	if opts == nil {
		// A flag that prints and exits, such as -version or -help.
		return exitOK
	}

	if err := scan(*opts, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "provenance: %v\n", err)
		return exitError
	}
	return exitOK
}
