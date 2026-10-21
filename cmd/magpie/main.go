// Command magpie scans an iOS app (.ipa or .app) for security issues.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/Kumar-ranjan12345/magpie/internal/checks"
	"github.com/Kumar-ranjan12345/magpie/internal/engine"
	"github.com/Kumar-ranjan12345/magpie/internal/report"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
	"github.com/Kumar-ranjan12345/magpie/internal/server"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `Magpie — find the shiny things you left in your iOS app.

Usage:
  magpie scan [flags] <app.ipa | App.app>
  magpie serve [-addr host:port] [-no-open]
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

Serve opens a local web page where you can drag and drop an .ipa and read
the report in your browser (default address 127.0.0.1:8077).

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
	case "serve":
		return serveCmd(args[1:], stdout, stderr)
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

	rep, err := engine.Scan(paths[0], version)
	if err != nil {
		fmt.Fprintln(stderr, "magpie scan:", err)
		return 2
	}

	out := stdout
	color := !*noColor && os.Getenv("NO_COLOR") == "" && (isTerminal(stdout) || os.Getenv("CLICOLOR_FORCE") == "1")
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

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func serveCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	addr := fs.String("addr", "127.0.0.1:8077", "")
	noOpen := fs.Bool("no-open", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(stderr, "magpie serve:", err)
		return 2
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		fmt.Fprintln(stderr, "warning: listening beyond this computer; anyone who can reach this address can upload apps to scan")
	}
	pageURL := "http://" + net.JoinHostPort(host, port) + "/"

	fmt.Fprintf(stdout, "🐦 Magpie is running at %s\n   Drop an .ipa on the page to scan it. Press Ctrl+C to stop.\n\n", pageURL)
	if !*noOpen {
		openBrowser(pageURL)
	}

	srv := &http.Server{
		Handler:           (&server.Server{Version: version, Logger: log.New(stdout, "", log.Ltime)}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "magpie serve:", err)
		return 2
	}
	return 0
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start() // the URL is printed too, so a failure here is harmless
}
