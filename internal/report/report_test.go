package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

func sample() *scan.Report {
	return scan.NewReport("magpie", "test", scan.AppInfo{Name: "Demo <App>", BundleID: "dev.demo", Executable: "Demo"}, []scan.Finding{
		{ID: "MP-NET-001", Title: "ATS disabled", Severity: scan.High, Category: "Network", MASVS: "MASVS-NETWORK-1",
			Description: "d", Remediation: "r", Evidence: []string{"Info.plist → NSAllowsArbitraryLoads = true"}},
		{ID: "MP-CODE-002", Title: "Source bundled", Severity: scan.Low, Category: "Code quality",
			Description: "d", Remediation: "r", Evidence: []string{"http://localhost (config.json)"}},
	})
}

func TestHTMLEscapesAndRenders(t *testing.T) {
	var b bytes.Buffer
	if err := HTML(&b, sample()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "Demo <App>") || !strings.Contains(out, "Demo &lt;App&gt;") {
		t.Error("app name not HTML-escaped")
	}
	for _, want := range []string{"MP-NET-001", `data-severity="high"`, "All · 2", "grade C"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestSARIF(t *testing.T) {
	var b bytes.Buffer
	if err := SARIF(&b, sample()); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if log.Version != "2.1.0" || len(run.Tool.Driver.Rules) != 2 || len(run.Results) != 2 {
		t.Fatalf("unexpected SARIF shape: %+v", log)
	}
	if run.Results[0].Level != "error" || run.Results[1].Level != "note" {
		t.Errorf("levels = %s, %s", run.Results[0].Level, run.Results[1].Level)
	}
	if uri := run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "config.json" {
		t.Errorf("location = %q, want config.json from the evidence", uri)
	}
}

func TestTextNoColor(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sample(), false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\033[") {
		t.Error("colour codes written with color=false")
	}
}
