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
	"MP-RES-001", "MP-RES-002", "MP-RES-003", "MP-RES-004",
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

func TestProtectedApp(t *testing.T) {
	app, err := bundle.Open("../../testdata/ProtectedApp.app")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	var protections []string
	for _, f := range Run(app) {
		switch f.ID {
		case "MP-RES-001", "MP-RES-002", "MP-RES-003", "MP-RES-004", "MP-BIN-003":
			t.Errorf("unexpected %s: %s", f.ID, f.Title)
		case "MP-RES-005":
			protections = f.Evidence
		}
	}
	for _, want := range []string{"Jailbreak detection", "Anti-debugging: ptrace via dlsym()", "Hooking detection", "App Attest"} {
		found := false
		for _, e := range protections {
			found = found || strings.Contains(e, want)
		}
		if !found {
			t.Errorf("MP-RES-005 evidence missing %q, got %q", want, protections)
		}
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
		"AWS access key ID": "AKIA" + "Z3XAMPLEZ3XAMPLE",
		"Stripe secret key": "sk_" + "live_" + strings.Repeat("a1B2", 6),
		"GitHub token":      "ghp_" + strings.Repeat("aB3d", 9),
		"Slack token":       "xoxb-" + "1234567890-abcdefghij",
		"Google API key":    "AIza" + strings.Repeat("x", 35),
		"Anthropic API key": "sk-ant-" + strings.Repeat("k", 40),
		"JWT":               "eyJ" + strings.Repeat("a", 12) + ".eyJ" + strings.Repeat("b", 12) + "." + strings.Repeat("c", 12),
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
	// Razorpay key IDs are public by design and must not be reported.
	for _, s := range []string{"rzp_" + "live_" + strings.Repeat("Q", 14), "AKIA-not-a-key", "sk_test_" + strings.Repeat("a", 24), "ghp_short"} {
		for _, p := range secretPatterns {
			if p.re.MatchString(s) {
				t.Errorf("%s pattern matched harmless string %q", p.name, s)
			}
		}
	}
}

func TestPrivateKeyNeedsBody(t *testing.T) {
	begin, end := "-----BEGIN "+"RSA PRIVATE KEY-----", "-----END "+"RSA PRIVATE KEY-----"
	body := strings.Repeat(strings.Repeat("QUJD", 16)+"\n", 4) // filler, not a real key

	// A parser's header constants, as found in crypto libraries.
	if _, ok := hasPrivateKey([]byte(begin + "\x00" + end + "\x00")); ok {
		t.Error("bare PEM header and footer reported as a private key")
	}
	if kind, ok := hasPrivateKey([]byte("let k = \"" + begin + "\n" + body + end + "\"")); !ok || kind != "RSA PRIVATE KEY" {
		t.Errorf("full PEM block not detected (kind %q)", kind)
	}
}

func TestPEMFileClassification(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) bundle.File {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(content), 0o644)
		return bundle.File{Rel: name, Abs: p, Size: int64(len(content))}
	}
	body := strings.Repeat(strings.Repeat("QUJD", 16)+"\n", 4)
	cert := write("server.pem", "-----BEGIN CERTIFICATE-----\n"+body+"-----END CERTIFICATE-----\n")
	key := write("client.pem", "-----BEGIN "+"EC PRIVATE KEY-----\n"+body+"-----END "+"EC PRIVATE KEY-----\n")
	der := write("client.key", "\x30\x82\x01\x0a")

	if got := classifyPEM(cert).ID; got != ruleCertificates.ID {
		t.Errorf("certificate .pem classified as %s", got)
	}
	if got := classifyPEM(key).ID; got != rulePrivateKeyFile.ID {
		t.Errorf("private key .pem classified as %s", got)
	}
	if got := classifyPEM(der).ID; got != rulePrivateKeyFile.ID {
		t.Errorf("binary .key classified as %s", got)
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
