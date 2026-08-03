package builtin

import (
	"regexp"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type openclawDashboardNotificationUsernameStoredXSS struct{}

var (
	openclawDashboardEventMap      = regexp.MustCompile(`\bevents\s*\.\s*map\s*\(`)
	openclawDashboardMapAssignment = regexp.MustCompile(`(?s)(?:const|let|var)\s+([a-z_$][a-z0-9_$]*)\s*=\s*[^;]{0,256}$`)
	openclawDashboardUsernameField = regexp.MustCompile(`(?:\.\s*username\b|\[\s*["']username["']\s*\])`)
	openclawDashboardDirectSink    = regexp.MustCompile(`(?s)\binnerhtml\s*=\s*(?:(?:[a-z_$][a-z0-9_$]*)(?:\(\))?\s*\.\s*)*$`)
)

func (openclawDashboardNotificationUsernameStoredXSS) ID() string {
	return "openclaw-dashboard-notification-username-stored-xss"
}
func (openclawDashboardNotificationUsernameStoredXSS) Title() string {
	return "OpenClaw Dashboard renders failed-login usernames as HTML"
}
func (openclawDashboardNotificationUsernameStoredXSS) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (openclawDashboardNotificationUsernameStoredXSS) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (openclawDashboardNotificationUsernameStoredXSS) Formats() []parse.Format {
	return []parse.Format{parse.FormatOpenClawDashboardSource}
}

func (openclawDashboardNotificationUsernameStoredXSS) Apply(doc *parse.Document) []finding.Finding {
	if doc.Format != parse.FormatOpenClawDashboardSource {
		return nil
	}

	lower := strings.ToLower(string(doc.Raw))
	if !strings.Contains(lower, "/api/notifications") ||
		!strings.Contains(lower, "notifpanelbody") {
		return nil
	}
	if !strings.Contains(lower, "notificons") &&
		!strings.Contains(lower, "notiflastseen") &&
		!strings.Contains(lower, "notificationbell") &&
		!strings.Contains(lower, "agent dashboard") {
		return nil
	}

	sinkOffset := vulnerableOpenClawDashboardNotificationSink(lower)
	if sinkOffset < 0 {
		return nil
	}

	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "openclaw-dashboard-notification-username-stored-xss",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "OpenClaw Dashboard renders failed-login usernames as HTML",
		Description:  "CVE-2026-66418: OpenClaw Dashboard v3.0.0 stores an unauthenticated failed-login username in the audit log and later concatenates it into the authenticated notification panel through innerHTML, allowing stored cross-site scripting and administrator-session takeover.",
		Path:         doc.Path,
		Line:         1 + strings.Count(string(doc.Raw[:sinkOffset]), "\n"),
		Match:        "notification username flows into body.innerHTML",
		SuggestedFix: "Replace notification HTML string concatenation with DOM nodes and textContent, or context-safely encode every audit field before rendering. Restrict and length-limit usernames before logging, then review administrator sessions and agent instruction/configuration changes.",
		Tags:         []string{"cve", "openclaw-dashboard", "stored-xss", "innerhtml", "audit-log"},
	})}
}

func vulnerableOpenClawDashboardNotificationSink(lower string) int {
	for _, mapLoc := range openclawDashboardEventMap.FindAllStringIndex(lower, -1) {
		mapEnd := mapLoc[1] + 4096
		if mapEnd > len(lower) {
			mapEnd = len(lower)
		}
		mapSegment := lower[mapLoc[1]:mapEnd]
		if join := strings.Index(mapSegment, ".join"); join >= 0 {
			mapSegment = mapSegment[:join]
			mapEnd = mapLoc[1] + join
		}
		if !hasUnescapedUsernameField(mapSegment) {
			continue
		}

		preStart := mapLoc[0] - 512
		if preStart < 0 {
			preStart = 0
		}
		pre := lower[preStart:mapLoc[0]]
		if sink := directInnerHTMLSinkOffset(pre); sink >= 0 {
			return preStart + sink
		}

		assignment := openclawDashboardMapAssignment.FindStringSubmatch(pre)
		if len(assignment) != 2 {
			continue
		}
		searchEnd := mapLoc[1] + 8192
		if searchEnd > len(lower) {
			searchEnd = len(lower)
		}
		after := lower[mapLoc[1]:searchEnd]
		indirectSink := regexp.MustCompile(`\binnerhtml\s*=\s*[^;]{0,256}\b` + regexp.QuoteMeta(assignment[1]) + `\b`)
		if loc := indirectSink.FindStringIndex(after); loc != nil {
			return mapLoc[1] + loc[0]
		}
	}
	return -1
}

func directInnerHTMLSinkOffset(pre string) int {
	loc := openclawDashboardDirectSink.FindStringIndex(pre)
	if loc == nil {
		return -1
	}
	return loc[0]
}

func hasUnescapedUsernameField(segment string) bool {
	for _, loc := range openclawDashboardUsernameField.FindAllStringIndex(segment, -1) {
		prefixStart := loc[0] - 96
		if prefixStart < 0 {
			prefixStart = 0
		}
		prefix := strings.Join(strings.Fields(segment[prefixStart:loc[0]]), "")
		escaped := false
		for _, safeCall := range []string{"escapehtml(", "escapehtmlattribute(", "htmlescape(", "escape(", "sanitizehtml(", "dompurify.sanitize(", "encodehtml(", "he.encode("} {
			if call := strings.LastIndex(prefix, safeCall); call >= 0 && !strings.Contains(prefix[call+len(safeCall):], ")") {
				escaped = true
				break
			}
		}
		if !escaped {
			return true
		}
	}
	return false
}
