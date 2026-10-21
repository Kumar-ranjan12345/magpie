// Package report renders a scan report for people (text) and machines (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

func JSON(w io.Writer, r *scan.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

type palette struct{ reset, bold, dim, red, magenta, yellow, blue, gray, green string }

var colors = palette{"\033[0m", "\033[1m", "\033[2m", "\033[31m", "\033[35m", "\033[33m", "\033[34m", "\033[90m", "\033[32m"}

func (p palette) severity(s scan.Severity) string {
	switch s {
	case scan.Critical:
		return p.magenta
	case scan.High:
		return p.red
	case scan.Medium:
		return p.yellow
	case scan.Low:
		return p.blue
	}
	return p.gray
}

func (p palette) grade(g string) string {
	switch g {
	case "A", "B":
		return p.green
	case "C":
		return p.yellow
	}
	return p.red
}

// Text writes a human-readable report. color enables ANSI colours.
func Text(w io.Writer, r *scan.Report, color bool) error {
	c := colors
	if !color {
		c = palette{}
	}
	b := &strings.Builder{}
	app := r.App

	fmt.Fprintf(b, "\n%s🐦 Magpie%s %s— iOS app security scan%s\n\n", c.bold, c.reset, c.dim, c.reset)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(b, "  %s%-12s%s %s\n", c.dim, k, c.reset, v)
		}
	}
	row("App", app.Name)
	row("Bundle ID", app.BundleID)
	if app.Version != "" {
		v := app.Version
		if app.Build != "" {
			v += " (" + app.Build + ")"
		}
		row("Version", v)
	}
	row("Minimum iOS", app.MinOS)
	row("Arch", app.Arch)
	if app.Encrypted {
		row("Encrypted", "yes — App Store binary, code-level checks limited")
	}

	fmt.Fprintf(b, "\n  %sGrade %s%s%s  %sscore %d/100%s   ", c.bold, c.grade(r.Grade), r.Grade, c.reset, c.dim, r.Score, c.reset)
	for _, s := range []scan.Severity{scan.Critical, scan.High, scan.Medium, scan.Low, scan.Info} {
		if n := r.Counts[s.String()]; n > 0 {
			fmt.Fprintf(b, "%s%d %s%s  ", c.severity(s), n, s, c.reset)
		}
	}
	b.WriteString("\n")

	if len(r.Findings) == 0 {
		fmt.Fprintf(b, "\n  %sNo issues found.%s\n\n", c.green, c.reset)
	}
	for _, f := range r.Findings {
		label := fmt.Sprintf("%-8s", strings.ToUpper(f.Severity.String()))
		fmt.Fprintf(b, "\n  %s%s%s%s %s%s%s  %s\n", c.bold, c.severity(f.Severity), label, c.reset, c.dim, f.ID, c.reset, c.bold+f.Title+c.reset)
		meta := f.Category
		if f.MASVS != "" {
			meta += " · " + f.MASVS
		}
		fmt.Fprintf(b, "           %s%s%s\n", c.gray, meta, c.reset)
		writeWrapped(b, f.Description, "           ", 88)
		for _, e := range f.Evidence {
			fmt.Fprintf(b, "           %s›%s %s\n", c.dim, c.reset, e)
		}
		fmt.Fprintf(b, "           %sFix:%s ", c.green, c.reset)
		writeWrapped(b, f.Remediation, "                ", 83, true)
	}
	b.WriteString("\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// writeWrapped word-wraps text at width. When continueLine is set the first line
// is written without the indent, because the caller already printed a label.
func writeWrapped(b *strings.Builder, text, indent string, width int, continueLine ...bool) {
	line := 0
	if len(continueLine) == 0 || !continueLine[0] {
		b.WriteString(indent)
	}
	for i, word := range strings.Fields(text) {
		if i > 0 && line+1+len(word) > width {
			b.WriteString("\n" + indent)
			line = 0
		} else if i > 0 {
			b.WriteString(" ")
			line++
		}
		b.WriteString(word)
		line += len(word)
	}
	b.WriteString("\n")
}
