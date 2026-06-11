package api

import (
	"strings"

	"github.com/mileusna/useragent"
)

// deviceLabelFromUA turns a raw User-Agent into a short human label like
// "Chrome on macOS" for the session list. Falls back to "Unknown device"
// when the UA is empty or isn't a recognizable browser/device (CLIs like
// curl parse with a Name but no real device classification, and bots).
func deviceLabelFromUA(ua string) string {
	if strings.TrimSpace(ua) == "" {
		return "Unknown device"
	}
	p := useragent.Parse(ua)
	// IsUnknown is true when none of Mobile/Tablet/Desktop/Bot is set, i.e.
	// the parser couldn't classify it as a real client (curl, scripts, ...).
	if p.IsUnknown() {
		return "Unknown device"
	}
	browser := strings.TrimSpace(p.Name)
	os := strings.TrimSpace(p.OS)
	switch {
	case browser != "" && os != "":
		return browser + " on " + os
	case browser != "":
		return browser
	case os != "":
		return os
	default:
		return "Unknown device"
	}
}
