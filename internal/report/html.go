package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

//go:embed report.html.tmpl
var htmlTemplate string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper":   strings.ToUpper,
	"sev":     func(s scan.Severity) string { return s.String() },
	"inc":     func(i int) int { return i + 1 },
	"summary": summary,
}).Parse(htmlTemplate))

// HTML writes a self-contained, shareable report page with no external assets.
func HTML(w io.Writer, r *scan.Report) error {
	return render(w, r, false)
}

// InteractiveHTML is the report as shown by `magpie serve`, with a toolbar to
// scan another app and save the report.
func InteractiveHTML(w io.Writer, r *scan.Report) error {
	return render(w, r, true)
}

func render(w io.Writer, r *scan.Report, interactive bool) error {
	return tmpl.Execute(w, struct {
		*scan.Report
		Interactive bool
	}{r, interactive})
}

// summary turns severity counts into "1 critical, 2 high, 4 info".
func summary(counts map[string]int) string {
	var parts []string
	for _, s := range []scan.Severity{scan.Critical, scan.High, scan.Medium, scan.Low, scan.Info} {
		if n := counts[s.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}
