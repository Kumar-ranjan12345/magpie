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
	"sev":   func(s scan.Severity) string { return s.String() },
	"icon":  Icon,
	"gradeClass": func(g string) string {
		switch g {
		case "A", "B":
			return "g-good"
		case "C":
			return "g-mid"
		}
		return "g-bad"
	},
	"count": func(c map[string]int, s string) int { return c[s] },
	"title": func(s string) string { return strings.ToUpper(s[:1]) + s[1:] },
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
		Severities  []string
		Interactive bool
	}{r, []string{"critical", "high", "medium", "low", "info"}, interactive})
}
