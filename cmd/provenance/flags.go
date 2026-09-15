package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
)

// options is the parsed command line.
type options struct {
	// Path is the project directory to scan.
	Path string
	// SBOMPath is where to write the CycloneDX document. Empty writes none,
	// "-" writes it to standard output.
	SBOMPath string
}

// parseArgs reads the command line. It returns a nil options, and no error,
// when a flag has already done the work and the program should simply stop.
func parseArgs(args []string, stderr io.Writer) (*options, error) {
	fs := flag.NewFlagSet("provenance", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }

	showVersion := fs.Bool("version", false, "print version and exit")
	sbomPath := fs.String("sbom", "", `write a CycloneDX SBOM to this file ("-" for stdout)`)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, nil
		}
		return nil, err
	}
	if *showVersion {
		fmt.Fprintln(stderr, version)
		return nil, nil
	}

	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return nil, errors.New("no project path given")
	}
	if len(rest) > 1 {
		return nil, fmt.Errorf("one project path expected, got %d", len(rest))
	}

	return &options{Path: rest[0], SBOMPath: *sbomPath}, nil
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `provenance %s - supply-chain security scanner

Usage:
  provenance [flags] <project-path>

Flags:
  -sbom <file>   write a CycloneDX SBOM to <file> ("-" for stdout)
  -version       print version and exit

provenance reads dependency manifests and lockfiles. It does not install,
build or execute anything from the scanned project.
`, version)
}
