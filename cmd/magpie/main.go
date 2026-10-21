// Command magpie scans an iOS app (.ipa or .app) for security issues.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/checks"
	"github.com/Kumar-ranjan12345/magpie/internal/report"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `Magpie — find the shiny things you left in your iOS app.

Usage:
  magpie scan [flags] <app.ipa | App.app>
  magpie rules
  magpie version

Scan flags:
  -format text|json|html|sarif
                        output format (default text). html is a shareable
                        report page; sarif is for GitHub code scanning and CI
  -o file               write the report to a file instead of stdout
  -fail-on severity     exit with code 1 if any finding is at or above this
                        severity: info, low, medium, high, critical (default: never)
  -no-color             disable coloured output

Exit codes: 0 ok, 1 findings at or above -fail-on, 2 error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return scanCmd(args[1:], stdout, stderr)
	case "rules":
		for _, r := range checks.Rules() {
			fmt.Fprintf(stdout, "%-11s %-8s %s\n", r.ID, r.Severity, r.Title)
		}
		return 0
	case "version", "-v", "--version":
		fmt.Fprintln(stdout, "magpie", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

func scanCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	format := fs.String("format", "text", "")
	outPath := fs.String("o", "", "")
	failOn := fs.String("fail-on", "", "")
	noColor := fs.Bool("no-color", false, "")

	// Allow flags after the path too: magpie scan app.ipa -format json
	var paths []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return 2
		}
		args = fs.Args()
		if len(args) > 0 {
			paths = append(paths, args[0])
			args = args[1:]
		}
	}
	if len(paths) != 1 {
		fmt.Fprintln(stderr, "magpie scan: expected exactly one .ipa or .app path")
		return 2
	}
	if *format != "text" && *format != "json" && *format != "html" && *format != "sarif" {
		fmt.Fprintf(stderr, "magpie scan: unknown format %q\n", *format)
		return 2
	}
	threshold := scan.Severity(-1)
	if *failOn != "" {
		s, err := scan.ParseSeverity(*failOn)
		if err != nil {
			fmt.Fprintln(stderr, "magpie scan:", err)
			return 2
		}
		threshold = s
	}

	rep, err := scanPath(paths[0])
	if err != nil {
		fmt.Fprintln(stderr, "magpie scan:", err)
		return 2
	}

	out := stdout
	color := !*noColor && os.Getenv("NO_COLOR") == "" && isTerminal(stdout)
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintln(stderr, "magpie scan:", err)
			return 2
		}
		defer f.Close()
		out, color = f, false
	}

	switch *format {
	case "json":
		err = report.JSON(out, rep)
	case "html":
		err = report.HTML(out, rep)
	case "sarif":
		err = report.SARIF(out, rep)
	default:
		err = report.Text(out, rep, color)
	}
	if err != nil {
		fmt.Fprintln(stderr, "magpie scan:", err)
		return 2
	}

	if threshold >= 0 && rep.Worst() >= threshold {
		return 1
	}
	return 0
}

func scanPath(path string) (*scan.Report, error) {
	app, err := bundle.Open(path)
	if err != nil {
		return nil, err
	}
	defer app.Close()

	info := scan.AppInfo{
		Name:       firstNonEmpty(app.String("CFBundleDisplayName"), app.String("CFBundleName")),
		BundleID:   app.String("CFBundleIdentifier"),
		Version:    app.String("CFBundleShortVersionString"),
		Build:      app.String("CFBundleVersion"),
		MinOS:      firstNonEmpty(app.String("MinimumOSVersion"), app.Binary.MinOS),
		Arch:       app.Binary.Arch,
		Encrypted:  app.Binary.Encrypted,
		Executable: app.String("CFBundleExecutable"),
	}
	if info.BundleID == "" {
		return nil, errors.New("Info.plist has no CFBundleIdentifier; is this an iOS app?")
	}
	return scan.NewReport("magpie", version, info, checks.Run(app)), nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
