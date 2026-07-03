package builtin

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type miseHTTPBackendSymlinkEscape struct{}

func (miseHTTPBackendSymlinkEscape) ID() string { return "mise-http-backend-symlink-escape" }
func (miseHTTPBackendSymlinkEscape) Title() string {
	return "mise HTTP backend version can write symlinks outside the install root"
}
func (miseHTTPBackendSymlinkEscape) Severity() finding.Severity { return finding.SeverityMedium }
func (miseHTTPBackendSymlinkEscape) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (miseHTTPBackendSymlinkEscape) Formats() []parse.Format {
	return []parse.Format{parse.FormatMiseToolVersions}
}

var miseAbsoluteHTTPBackendOption = regexp.MustCompile(`(?i)(^|[&#?;\s])(version|bin_path)=(/|[A-Za-z]:\\|[A-Za-z]:/)`)

func (miseHTTPBackendSymlinkEscape) Apply(doc *parse.Document) []finding.Finding {
	if doc.Format != parse.FormatMiseToolVersions {
		return nil
	}
	var out []finding.Finding
	for i, raw := range strings.Split(string(doc.Raw), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !miseToolVersionLineUsesHTTPBackend(line) || !miseToolVersionLineHasAbsoluteSymlinkTarget(line) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:        "mise-http-backend-symlink-escape",
			Severity:      finding.SeverityMedium,
			Taxonomy:      finding.TaxDetectable,
			Title:         "Repository .tool-versions can escape mise's install root",
			Description:   "CVE-2026-54557: mise before 2026.6.1 used the raw HTTP-backend resolved version/bin_path when creating install symlinks, allowing repository-controlled .tool-versions entries to place symlinks outside the intended mise install tree.",
			Path:          doc.Path,
			Line:          i + 1,
			Match:         strings.Fields(line)[0],
			Context:       line,
			SuggestedFix:  "Upgrade mise to 2026.6.1 or later. Remove repository-controlled HTTP backend entries whose version or bin_path resolves to an absolute path outside mise's install root before running `mise install` in the workspace.",
			Tags:          []string{"cve", "mise", "tool-versions", "symlink", "path-traversal"},
			DedupGroupKey: "mise-http-backend-symlink-escape:" + filepath.ToSlash(doc.Path) + ":" + strings.Fields(line)[0],
		}))
	}
	return out
}

func miseToolVersionLineUsesHTTPBackend(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
}

func miseToolVersionLineHasAbsoluteSymlinkTarget(line string) bool {
	if miseAbsoluteHTTPBackendOption.MatchString(line) {
		return true
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	for _, field := range fields[1:] {
		candidate := strings.Trim(field, `"'`)
		if strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://") {
			continue
		}
		if strings.HasPrefix(candidate, "/") || regexp.MustCompile(`^[A-Za-z]:[\\/]`).MatchString(candidate) {
			return true
		}
	}
	return false
}
