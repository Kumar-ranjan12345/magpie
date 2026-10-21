package report

import (
	_ "embed"
	"html/template"
	"io"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

//go:embed report.html.tmpl
var htmlTemplate string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
	"count": func(c map[string]int, s string) int { return c[s] },
	"sev":   func(s scan.Severity) string { return s.String() },
}).Parse(htmlTemplate))

// HTML writes a self-contained, shareable report page with no external assets.
func HTML(w io.Writer, r *scan.Report) error {
	return tmpl.Execute(w, struct {
		*scan.Report
		Severities []string
	}{r, []string{"critical", "high", "medium", "low", "info"}})
}
