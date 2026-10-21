// Package binary reads the security-relevant properties of an iOS Mach-O
// executable: hardening flags, encryption, imports, entitlements and strings.
package binary

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Load commands that debug/macho does not decode for us.
const (
	lcCodeSignature      = 0x1d
	lcEncryptionInfo     = 0x21
	lcVersionMinIPhoneOS = 0x25
	lcEncryptionInfo64   = 0x2c
	lcBuildVersion       = 0x32
)

// N_OPT stab type, used only for the strip marker symbol.
const nOPT = 0x3c

// Code signature blob magics (big-endian).
const (
	csSuperBlob        = 0xfade0cc0
	csEntitlements     = 0xfade7171
	csSlotEntitlements = 5
)

type Info struct {
	Arch         string
	PIE          bool
	HasCryptInfo bool // LC_ENCRYPTION_INFO present (App Store / FairPlay-capable)
	Encrypted    bool // cryptid != 0, the code is FairPlay-encrypted
	StackCanary  bool
	ObjC         bool
	Swift        bool
	ARC          bool
	Stripped     bool
	DebugInfo    bool // DWARF or a debug map left in the binary
	MinOS        string
	Imports      []string
	Entitlements []byte // XML plist from the code signature, nil when unsigned

	data []byte // the selected architecture slice
}

// Parse reads the executable at path. For a universal binary it analyses the arm64 slice.
func Parse(path string) (*Info, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	slice, err := selectSlice(data)
	if err != nil {
		return nil, err
	}
	f, err := macho.NewFile(bytes.NewReader(slice))
	if err != nil {
		return nil, fmt.Errorf("not a Mach-O executable: %w", err)
	}
	defer f.Close()

	info := &Info{
		Arch: archName(f.Cpu),
		PIE:  f.Flags&macho.FlagPIE != 0,
		data: slice,
	}

	if imports, err := f.ImportedSymbols(); err == nil {
		info.Imports = imports
	}
	for _, s := range info.Imports {
		switch {
		case s == "___stack_chk_guard" || s == "___stack_chk_fail":
			info.StackCanary = true
		case strings.HasPrefix(s, "_objc_msgSend"):
			info.ObjC = true
		case strings.HasPrefix(s, "_swift_"):
			info.Swift = true
		}
		if s == "_objc_release" || s == "_objc_storeStrong" || s == "_objc_retainAutoreleasedReturnValue" {
			info.ARC = true
		}
	}
	for _, sec := range f.Sections {
		if strings.HasPrefix(sec.Name, "__swift5_") {
			info.Swift = true
		}
		if sec.Seg == "__DWARF" {
			info.DebugInfo = true
		}
	}
	if info.Swift {
		info.ARC = true // Swift is always reference-counted by the compiler
	}

	info.Stripped = true
	if f.Symtab != nil {
		locals := 0
		for _, s := range f.Symtab.Syms {
			if s.Type&0xe0 != 0 { // N_STAB debugging entry
				if s.Type == nOPT {
					continue // the "radr://5614542" marker strip(1) leaves in every binary
				}
				info.DebugInfo = true
				info.Stripped = false
				continue
			}
			if s.Type&0x01 == 0 && s.Name != "" { // not external
				locals++
			}
		}
		if locals > 5 {
			info.Stripped = false
		}
	}

	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < 8 {
			continue
		}
		bo := f.ByteOrder
		switch bo.Uint32(raw) {
		case lcEncryptionInfo, lcEncryptionInfo64:
			if len(raw) >= 20 {
				info.HasCryptInfo = true
				info.Encrypted = bo.Uint32(raw[16:]) != 0
			}
		case lcBuildVersion:
			if len(raw) >= 16 {
				info.MinOS = version(bo.Uint32(raw[12:]))
			}
		case lcVersionMinIPhoneOS:
			if len(raw) >= 12 && info.MinOS == "" {
				info.MinOS = version(bo.Uint32(raw[8:]))
			}
		case lcCodeSignature:
			if len(raw) >= 16 {
				off, size := bo.Uint32(raw[8:]), bo.Uint32(raw[12:])
				if uint64(off)+uint64(size) <= uint64(len(slice)) {
					info.Entitlements = entitlements(slice[off : off+size])
				}
			}
		}
	}
	return info, nil
}

func selectSlice(data []byte) ([]byte, error) {
	fat, err := macho.NewFatFile(bytes.NewReader(data))
	if errors.Is(err, macho.ErrNotFat) {
		return data, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading universal binary: %w", err)
	}
	defer fat.Close()
	if len(fat.Arches) == 0 {
		return nil, errors.New("universal binary has no architectures")
	}
	pick := fat.Arches[0]
	for _, a := range fat.Arches {
		if a.Cpu == macho.CpuArm64 {
			pick = a
			break
		}
	}
	end := uint64(pick.Offset) + uint64(pick.Size)
	if end > uint64(len(data)) {
		return nil, errors.New("universal binary slice out of range")
	}
	return data[pick.Offset:end], nil
}

// entitlements pulls the XML entitlements blob out of a code signature SuperBlob.
func entitlements(sig []byte) []byte {
	be := binary.BigEndian
	if len(sig) < 12 || be.Uint32(sig) != csSuperBlob {
		return nil
	}
	count := int(be.Uint32(sig[8:]))
	for i := 0; i < count; i++ {
		idx := 12 + i*8
		if idx+8 > len(sig) {
			return nil
		}
		if be.Uint32(sig[idx:]) != csSlotEntitlements {
			continue
		}
		off := int(be.Uint32(sig[idx+4:]))
		if off+8 > len(sig) || be.Uint32(sig[off:]) != csEntitlements {
			return nil
		}
		end := off + int(be.Uint32(sig[off+4:]))
		if end > len(sig) || end < off+8 {
			return nil
		}
		return sig[off+8 : end]
	}
	return nil
}

// version decodes Mach-O's xxxx.yy.zz nibble-packed version.
func version(v uint32) string {
	s := fmt.Sprintf("%d.%d", v>>16, (v>>8)&0xff)
	if patch := v & 0xff; patch != 0 {
		s += fmt.Sprintf(".%d", patch)
	}
	return s
}

func archName(c macho.Cpu) string {
	switch c {
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuArm:
		return "armv7"
	case macho.CpuAmd64:
		return "x86_64"
	}
	return c.String()
}

// Data returns the raw bytes of the analysed architecture slice.
func (i *Info) Data() []byte { return i.data }

// Strings returns the unique printable ASCII runs of at least min bytes in the executable.
func (i *Info) Strings(min int) []string {
	return Strings(i.data, min)
}

// Strings returns the unique printable ASCII runs of at least min bytes in data.
func Strings(data []byte, min int) []string {
	const maxLen = 4096
	seen := map[string]struct{}{}
	var out []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= min {
			s := data[start:min2(end, start+maxLen)]
			if _, ok := seen[string(s)]; !ok {
				seen[string(s)] = struct{}{}
				out = append(out, string(s))
			}
		}
		start = -1
	}
	for i, b := range data {
		if b >= 0x20 && b < 0x7f || b == '\t' {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(data))
	return out
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
