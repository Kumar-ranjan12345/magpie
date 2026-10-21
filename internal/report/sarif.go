package report

import (
	"encoding/json"
	"io"
	"regexp"

	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

// SARIF 2.1.0, the format GitHub code scanning and most CI security dashboards read.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Help             sarifText      `json:"help"`
	Properties       map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

// GitHub's security-severity property drives the severity shown in code scanning.
var securitySeverity = map[scan.Severity]string{
	scan.Critical: "9.5", scan.High: "8.0", scan.Medium: "5.5", scan.Low: "3.0", scan.Info: "0.0",
}

func sarifLevel(s scan.Severity) string {
	switch s {
	case scan.Critical, scan.High:
		return "error"
	case scan.Medium:
		return "warning"
	}
	return "note"
}

// Evidence that ends in "(path)" names the file it was found in.
var evidenceFile = regexp.MustCompile(`\(([^()]+)\)$`)

func SARIF(w io.Writer, r *scan.Report) error {
	driver := sarifDriver{Name: "Magpie", Version: r.Version, InformationURI: "https://github.com/Kumar-ranjan12345/magpie"}
	seen := map[string]bool{}
	var results []sarifResult

	for _, f := range r.Findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			tags := []string{"security", "ios", f.Category}
			if f.MASVS != "" {
				tags = append(tags, f.MASVS)
			}
			driver.Rules = append(driver.Rules, sarifRule{
				ID:               f.ID,
				Name:             f.Title,
				ShortDescription: sarifText{f.Title},
				FullDescription:  sarifText{f.Description},
				Help:             sarifText{f.Remediation},
				Properties: map[string]any{
					"security-severity": securitySeverity[f.Severity],
					"tags":              tags,
				},
			})
		}

		msg := f.Title
		uri := r.App.Executable
		if len(f.Evidence) > 0 {
			msg += ": " + f.Evidence[0]
			if m := evidenceFile.FindStringSubmatch(f.Evidence[0]); m != nil && m[1] != "binary" {
				uri = m[1]
			}
		}
		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = uri
		results = append(results, sarifResult{RuleID: f.ID, Level: sarifLevel(f.Severity), Message: sarifText{msg}, Locations: []sarifLocation{loc}})
	}
	if results == nil {
		results = []sarifResult{}
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{driver}, Results: results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
