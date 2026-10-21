package scan

import "testing"

func TestGrade(t *testing.T) {
	cases := []struct {
		findings []Severity
		want     string
	}{
		{nil, "A"},
		{[]Severity{Info, Info}, "A"},
		{[]Severity{Low, Low}, "A"},
		{[]Severity{Medium, Low}, "B"},
		{[]Severity{High}, "C"},     // score 85 would be B, but high caps at C
		{[]Severity{Critical}, "D"}, // score 70 would be C, but critical caps at D
		{[]Severity{Critical, Critical, High}, "F"},
	}
	for _, c := range cases {
		var fs []Finding
		for _, s := range c.findings {
			fs = append(fs, Finding{ID: "X", Severity: s})
		}
		if got := NewReport("t", "v", AppInfo{}, fs).Grade; got != c.want {
			t.Errorf("grade for %v = %s, want %s", c.findings, got, c.want)
		}
	}
}

func TestReportSortsBySeverity(t *testing.T) {
	r := NewReport("t", "v", AppInfo{}, []Finding{{ID: "B", Severity: Low}, {ID: "A", Severity: Critical}, {ID: "C", Severity: Low}})
	if r.Findings[0].ID != "A" || r.Findings[1].ID != "B" || r.Worst() != Critical {
		t.Fatalf("unexpected order: %+v", r.Findings)
	}
	if empty := NewReport("t", "v", AppInfo{}, nil); empty.Findings == nil || empty.Worst() != -1 {
		t.Fatal("empty report should have a non-nil slice and Worst() == -1")
	}
}

func TestParseSeverity(t *testing.T) {
	if s, err := ParseSeverity("HIGH"); err != nil || s != High {
		t.Fatalf("ParseSeverity(HIGH) = %v, %v", s, err)
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("expected an error for an unknown severity")
	}
}
