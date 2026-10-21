// Package engine runs a full scan of one app and builds the report.
package engine

import (
	"errors"
	"strings"

	"github.com/Kumar-ranjan12345/magpie/internal/bundle"
	"github.com/Kumar-ranjan12345/magpie/internal/checks"
	"github.com/Kumar-ranjan12345/magpie/internal/scan"
)

// Scan opens an .ipa, a zipped .app or an .app directory and runs every check.
func Scan(path, version string) (*scan.Report, error) {
	app, err := bundle.Open(path)
	if err != nil {
		return nil, err
	}
	defer app.Close()

	info := scan.AppInfo{
		Name:       firstNonEmpty(app.String("CFBundleDisplayName"), app.String("CFBundleName")),
		BundleID:   app.String("CFBundleIdentifier"),
		Version:    app.String("CFBundleShortVersionString"),
		Build:      app.String("CFBundleVersion"),
		MinOS:      firstNonEmpty(app.String("MinimumOSVersion"), app.Binary.MinOS),
		Arch:       app.Binary.Arch,
		Encrypted:  app.Binary.Encrypted,
		Executable: app.String("CFBundleExecutable"),
	}
	if info.BundleID == "" {
		return nil, errors.New("Info.plist has no CFBundleIdentifier; is this an iOS app?")
	}
	return scan.NewReport("magpie", version, info, checks.Run(app)), nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
