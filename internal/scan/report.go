package scan

import (
	"sort"
	"time"
)

type AppInfo struct {
	Name       string `json:"name"`
	BundleID   string `json:"bundleId"`
	Version    string `json:"version"`
	Build      string `json:"build"`
	MinOS      string `json:"minimumOS"`
	Arch       string `json:"architecture"`
	Encrypted  bool   `json:"encrypted"`
	Executable string `json:"executable"`
}

type Report struct {
	Tool      string         `json:"tool"`
	Version   string         `json:"version"`
	ScannedAt time.Time      `json:"scannedAt"`
	App       AppInfo        `json:"app"`
	Score     int            `json:"score"`
	Grade     string         `json:"grade"`
	Counts    map[string]int `json:"counts"`
	Findings  []Finding      `json:"findings"`
}

// Points deducted per finding. Info findings are context, not problems.
var penalty = map[Severity]int{Critical: 30, High: 15, Medium: 8, Low: 3}

func NewReport(tool, version string, app AppInfo, findings []Finding) *Report {
	if findings == nil {
		findings = []Finding{} // encode as [] rather than null
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].ID < findings[j].ID
	})

	counts := map[string]int{}
	score := 100
	worst := Info
	for _, f := range findings {
		counts[f.Severity.String()]++
		score -= penalty[f.Severity]
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	if score < 0 {
		score = 0
	}

	return &Report{
		Tool:    tool,
		Version: version,
		// Local time, so reports show the scanning machine's time zone (IST in India).
		ScannedAt: time.Now().Truncate(time.Second),
		App:       app,
		Score:     score,
		Grade:     grade(score, worst),
		Counts:    counts,
		Findings:  findings,
	}
}

// grade maps the score to A–F. A critical finding caps the grade at D and a
// high one at C, however few other issues there are.
func grade(score int, worst Severity) string {
	g := "F"
	switch {
	case score >= 90:
		g = "A"
	case score >= 80:
		g = "B"
	case score >= 65:
		g = "C"
	case score >= 50:
		g = "D"
	}
	if worst == Critical && g < "D" {
		g = "D"
	}
	if worst == High && g < "C" {
		g = "C"
	}
	return g
}

// Worst returns the highest severity in the report, or -1 when there are no findings.
func (r *Report) Worst() Severity {
	if len(r.Findings) == 0 {
		return -1
	}
	return r.Findings[0].Severity
}
