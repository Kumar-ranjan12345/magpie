package report

import (
	_ "embed"
	"html/template"
)

//go:embed icon.svg
var iconSVG string

// Icon is the Magpie logo as inline SVG, so reports stay self-contained.
func Icon() template.HTML { return template.HTML(iconSVG) }

// IconSVG returns the raw logo, for serving as a favicon.
func IconSVG() []byte { return []byte(iconSVG) }
