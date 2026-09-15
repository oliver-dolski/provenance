package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/oliver-dolski/provenance/internal/finding"
)

// options is the parsed command line.
type options struct {
	// Path is the project directory to scan.
	Path string
	// SBOMPath is where to write the CycloneDX document. Empty writes none,
	// "-" writes it to standard output.
	SBOMPath string
	// Format is how the report itself is rendered: "text" or "json".
	Format string
	// Offline skips the vulnerability database. The supply-chain checks that
	// need no network still run, and the report states that the lookup did not.
	Offline bool
	// FailOn is the lowest severity that makes the command exit non-zero.
	// FailOnSet says whether the caller asked for that at all.
	FailOn    finding.Severity
	FailOnSet bool
}

const (
	formatText = "text"
	formatJSON = "json"
)

// parseArgs reads the command line. It returns a nil options, and no error,
// when a flag has already done the work and the program should simply stop.
func parseArgs(args []string, stderr io.Writer) (*options, error) {
	fs := flag.NewFlagSet("provenance", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }

	showVersion := fs.Bool("version", false, "print version and exit")
	sbomPath := fs.String("sbom", "", `write a CycloneDX SBOM to this file ("-" for stdout)`)
	format := fs.String("format", formatText, "report format: text or json")
	offline := fs.Bool("offline", false, "skip the vulnerability database and run only the offline checks")
	failOn := fs.String("fail-on", "none", "exit non-zero when a finding of this severity or higher is reported: none, low, medium, high, critical")

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

	opts := options{SBOMPath: *sbomPath, Format: strings.ToLower(*format), Offline: *offline}

	switch opts.Format {
	case formatText, formatJSON:
	default:
		return nil, fmt.Errorf("unknown format %q: use text or json", *format)
	}
	if opts.Format == formatJSON && opts.SBOMPath == "-" {
		// Both would be written to standard output and neither would parse.
		return nil, errors.New(`-format json and -sbom - both write to stdout: send the SBOM to a file instead`)
	}

	if threshold := strings.ToLower(strings.TrimSpace(*failOn)); threshold != "none" {
		severity, ok := finding.ParseSeverity(threshold)
		if !ok {
			return nil, fmt.Errorf("unknown severity %q for -fail-on: use none, low, medium, high or critical", *failOn)
		}
		if severity == finding.Unknown {
			return nil, errors.New(`-fail-on unknown is not a threshold: use none, low, medium, high or critical`)
		}
		opts.FailOn, opts.FailOnSet = severity, true
	}

	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return nil, errors.New("no project path given")
	}
	if len(rest) > 1 {
		return nil, fmt.Errorf("one project path expected, got %d", len(rest))
	}
	opts.Path = rest[0]

	return &opts, nil
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `provenance %s - supply-chain security scanner

Usage:
  provenance [flags] <project-path>

Flags:
  -sbom <file>       write a CycloneDX SBOM to <file> ("-" for stdout)
  -format <format>   report format: text (default) or json
  -offline           skip the vulnerability database; run only the offline checks
  -fail-on <level>   exit %d when a finding of this severity or higher is
                     reported: none (default), low, medium, high, critical
  -version           print version and exit

provenance reads dependency manifests and lockfiles. It does not install,
build or execute anything from the scanned project.
`, version, exitFindings)
}
