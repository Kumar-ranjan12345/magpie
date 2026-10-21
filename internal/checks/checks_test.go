package checks

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
)

const fixtureApp = "../../testdata/VulnerableApp.app"

// Every rule the fixture app is built to trip.
var fixtureWant = []string{
	"MP-BIN-002", "MP-BIN-004", "MP-BIN-005", "MP-BIN-008", "MP-BIN-009",
	"MP-CODE-001", "MP-CODE-002",
	"MP-ENT-001", "MP-ENT-002", "MP-ENT-003",
	"MP-NET-001", "MP-NET-004", "MP-NET-005", "MP-NET-006", "MP-NET-008", "MP-NET-010",
	"MP-PLT-001", "MP-PLT-002", "MP-PRV-001",
	"MP-STG-001", "MP-STG-002",
}

func ids(app *bundle.App) []string {
	var out []string
	for _, f := range Run(app) {
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}

func TestFixtureApp(t *testing.T) {
	app, err := bundle.Open(fixtureApp)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if got := ids(app); !slices.Equal(got, fixtureWant) {
		t.Errorf("findings mismatch\n got: %v\nwant: %v", got, fixtureWant)
	}
}

func TestFixtureAsIPA(t *testing.T) {
	ipa := filepath.Join(t.TempDir(), "VulnerableApp.ipa")
	zipDir(t, fixtureApp, "Payload/VulnerableApp.app", ipa)

	app, err := bundle.Open(ipa)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Dir(app.Path)
	if got := ids(app); !slices.Equal(got, fixtureWant) {
		t.Errorf("findings mismatch\n got: %v\nwant: %v", got, fixtureWant)
	}
	app.Close()
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Error("Close did not remove the extraction directory")
	}
}

func TestZipSlipRejected(t *testing.T) {
	ipa := filepath.Join(t.TempDir(), "evil.ipa")
	f, _ := os.Create(ipa)
	zw := zip.NewWriter(f)
	w, _ := zw.Create("../../escaped.txt")
	w.Write([]byte("x"))
	zw.Close()
	f.Close()

	_, err := bundle.Open(ipa)
	if err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("expected a path traversal error, got %v", err)
	}
}

func TestSecretPatterns(t *testing.T) {
	// Built by concatenation so the repo never contains a scannable secret literal.
	cases := map[string]string{
		"AWS access key ID":   "AKIA" + "Z3XAMPLEZ3XAMPLE",
		"Stripe secret key":   "sk_" + "live_" + strings.Repeat("a1B2", 6),
		"GitHub token":        "ghp_" + strings.Repeat("aB3d", 9),
		"Slack token":         "xoxb-" + "1234567890-abcdefghij",
		"Google API key":      "AIza" + strings.Repeat("x", 35),
		"PEM private key":     "-----BEGIN " + "RSA PRIVATE KEY-----",
		"Anthropic API key":   "sk-ant-" + strings.Repeat("k", 40),
		"JWT":                 "eyJ" + strings.Repeat("a", 12) + ".eyJ" + strings.Repeat("b", 12) + "." + strings.Repeat("c", 12),
		"Razorpay key secret": "rzp_" + "live_" + strings.Repeat("Q", 14),
	}
	for name, s := range cases {
		matched := false
		for _, p := range secretPatterns {
			if p.name == name && p.re.MatchString("let key = \""+s+"\"") {
				matched = true
			}
		}
		if !matched {
			t.Errorf("%s pattern did not match %q", name, s)
		}
	}
	for _, s := range []string{"AKIA-not-a-key", "sk_test_" + strings.Repeat("a", 24), "ghp_short"} {
		for _, p := range secretPatterns {
			if p.re.MatchString(s) {
				t.Errorf("%s pattern matched harmless string %q", p.name, s)
			}
		}
	}
}

func TestRedact(t *testing.T) {
	got := redact("AKIA" + "Z3XAMPLEZ3XAMPLE")
	if strings.Contains(got, "Z3XAMPLEZ3X") || !strings.HasPrefix(got, "AKIAZ3XA") {
		t.Errorf("redact leaked or lost the secret prefix: %q", got)
	}
}

func TestBenignHTTP(t *testing.T) {
	if !isBenignHTTP("http://www.apple.com/DTDs/PropertyList-1.0.dtd") {
		t.Error("Apple DTD URL should be ignored")
	}
	if isBenignHTTP("http://api.example.org/login") {
		t.Error("API URL should not be ignored")
	}
}

func TestRuleIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules() {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
		if r.Title == "" || r.Description == "" || r.Remediation == "" {
			t.Errorf("rule %s is missing text", r.ID)
		}
	}
}

func zipDir(t *testing.T, src, prefix, dest string) {
	t.Helper()
	f, err := os.Create(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()
	err = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		w, err := zw.Create(prefix + "/" + filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(w, in)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
