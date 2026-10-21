// Package bundle opens an .ipa archive or an .app directory and exposes the
// parts the checks look at: Info.plist, the main executable and the bundled files.
package bundle

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/binary"
	"howett.net/plist"
)

// Limits that stop a malicious archive from filling the disk (zip bomb).
const (
	maxTotalBytes = 4 << 30
	maxFiles      = 200_000
)

type File struct {
	Rel  string // path relative to the .app directory
	Abs  string
	Size int64
}

type App struct {
	Path         string // the .app directory
	Info         map[string]any
	Executable   string
	Binary       *binary.Info
	Entitlements map[string]any
	Files        []File

	tmpDir string
}

// Open loads an .ipa file or an .app directory.
func Open(path string) (*App, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	app := &App{}
	appDir := path
	if !st.IsDir() {
		tmp, err := os.MkdirTemp("", "magpie-*")
		if err != nil {
			return nil, err
		}
		app.tmpDir = tmp
		if err := extract(path, tmp); err != nil {
			app.Close()
			return nil, err
		}
		if appDir, err = findApp(tmp); err != nil {
			app.Close()
			return nil, err
		}
	} else if !strings.HasSuffix(strings.TrimRight(path, "/"), ".app") {
		if appDir, err = findApp(path); err != nil {
			return nil, err
		}
	}
	app.Path = appDir

	if err := app.load(); err != nil {
		app.Close()
		return nil, err
	}
	return app, nil
}

// Close removes the temporary extraction directory, if any.
func (a *App) Close() error {
	if a.tmpDir == "" {
		return nil
	}
	return os.RemoveAll(a.tmpDir)
}

func (a *App) load() error {
	raw, err := os.ReadFile(filepath.Join(a.Path, "Info.plist"))
	if err != nil {
		return fmt.Errorf("reading Info.plist: %w", err)
	}
	if _, err := plist.Unmarshal(raw, &a.Info); err != nil {
		return fmt.Errorf("parsing Info.plist: %w", err)
	}

	exe := a.String("CFBundleExecutable")
	if exe == "" || strings.ContainsAny(exe, `/\`) {
		return errors.New("Info.plist has no valid CFBundleExecutable")
	}
	a.Executable = filepath.Join(a.Path, exe)
	if a.Binary, err = binary.Parse(a.Executable); err != nil {
		return fmt.Errorf("reading executable %s: %w", exe, err)
	}
	if len(a.Binary.Entitlements) > 0 {
		// Malformed entitlements are reported as missing rather than failing the scan.
		_, _ = plist.Unmarshal(a.Binary.Entitlements, &a.Entitlements)
	}

	return filepath.WalkDir(a.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(a.Path, p)
		a.Files = append(a.Files, File{Rel: filepath.ToSlash(rel), Abs: p, Size: info.Size()})
		return nil
	})
}

// String returns a top-level string value from Info.plist.
func (a *App) String(key string) string {
	s, _ := a.Info[key].(string)
	return s
}

func findApp(root string) (string, error) {
	matches, _ := filepath.Glob(filepath.Join(root, "Payload", "*.app"))
	if len(matches) == 0 {
		matches, _ = filepath.Glob(filepath.Join(root, "*.app"))
	}
	switch len(matches) {
	case 0:
		return "", errors.New("no .app bundle found (expected Payload/<Name>.app inside the .ipa)")
	case 1:
		return matches[0], nil
	}
	return "", fmt.Errorf("found %d .app bundles, expected one", len(matches))
}

func extract(archive, dest string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("not a valid .ipa (zip) file: %w", err)
	}
	defer r.Close()

	if len(r.File) > maxFiles {
		return fmt.Errorf("archive has %d entries, limit is %d", len(r.File), maxFiles)
	}
	root := filepath.Clean(dest) + string(os.PathSeparator)
	var total int64
	for _, zf := range r.File {
		target := filepath.Join(dest, zf.Name)
		if !strings.HasPrefix(target, root) {
			return fmt.Errorf("archive entry %q escapes the extraction directory", zf.Name)
		}
		mode := zf.Mode()
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		case !mode.IsRegular():
			continue // symlinks and devices are skipped on purpose
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		n, err := extractFile(zf, target, maxTotalBytes-total)
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}

func extractFile(zf *zip.File, target string, budget int64) (int64, error) {
	rc, err := zf.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(rc, budget+1))
	if err != nil {
		return n, err
	}
	if n > budget {
		return n, fmt.Errorf("archive expands beyond %d GB, refusing to continue", maxTotalBytes>>30)
	}
	return n, nil
}
