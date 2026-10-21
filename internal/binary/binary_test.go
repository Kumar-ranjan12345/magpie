package binary

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
)

func TestParseFixture(t *testing.T) {
	info, err := Parse("../../testdata/VulnerableApp.app/VulnerableApp")
	if err != nil {
		t.Fatal(err)
	}
	if info.Arch != "arm64" {
		t.Errorf("Arch = %q, want arm64", info.Arch)
	}
	if !info.PIE {
		t.Error("PIE = false, want true")
	}
	if info.StackCanary {
		t.Error("StackCanary = true, fixture is built with -fno-stack-protector")
	}
	if !info.DebugInfo {
		t.Error("DebugInfo = false, fixture is built with -g")
	}
	if info.MinOS != "14.0" {
		t.Errorf("MinOS = %q, want 14.0", info.MinOS)
	}
	for _, sym := range []string{"_CC_MD5", "_rand", "_srand"} {
		if !slices.Contains(info.Imports, sym) {
			t.Errorf("Imports missing %s", sym)
		}
	}
	if !bytes.Contains(info.Entitlements, []byte("get-task-allow")) {
		t.Error("entitlements not extracted from the code signature")
	}
	if !slices.Contains(info.Strings(8), "http://api.insecure-example.net/v1/login") {
		t.Error("Strings did not find the embedded URL")
	}
}

func TestParseRejectsNonMachO(t *testing.T) {
	if _, err := Parse("binary_test.go"); err == nil {
		t.Fatal("expected an error for a non-Mach-O file")
	}
}

func TestEntitlementsBlob(t *testing.T) {
	be := binary.BigEndian
	xml := []byte("<plist><dict/></plist>")

	blob := be.AppendUint32(nil, csEntitlements)
	blob = be.AppendUint32(blob, uint32(8+len(xml)))
	blob = append(blob, xml...)

	sig := be.AppendUint32(nil, csSuperBlob)
	sig = be.AppendUint32(sig, uint32(20+len(blob)))
	sig = be.AppendUint32(sig, 1) // one index entry
	sig = be.AppendUint32(sig, csSlotEntitlements)
	sig = be.AppendUint32(sig, 20) // blob starts right after the index
	sig = append(sig, blob...)

	if got := entitlements(sig); !bytes.Equal(got, xml) {
		t.Fatalf("entitlements() = %q, want %q", got, xml)
	}
	// Truncated or garbage signatures must not panic.
	for i := range sig {
		entitlements(sig[:i])
	}
}

func TestStrings(t *testing.T) {
	data := []byte("\x00\x01short\x00a longer string\x00a longer string\xffend")
	got := Strings(data, 8)
	want := []string{"a longer string"}
	if !slices.Equal(got, want) {
		t.Fatalf("Strings() = %q, want %q", got, want)
	}
}

func TestVersion(t *testing.T) {
	for v, want := range map[uint32]string{0x000e0000: "14.0", 0x00110502: "17.5.2"} {
		if got := version(v); got != want {
			t.Errorf("version(%#x) = %q, want %q", v, got, want)
		}
	}
}
