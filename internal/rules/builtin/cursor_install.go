package builtin

import (
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type cursorAgentSandboxWorkingDirectoryEscape struct{}

func (cursorAgentSandboxWorkingDirectoryEscape) ID() string {
	return "cursor-agent-sandbox-working-directory-escape"
}
func (cursorAgentSandboxWorkingDirectoryEscape) Title() string {
	return "Cursor version is vulnerable to agent sandbox working-directory escape"
}
func (cursorAgentSandboxWorkingDirectoryEscape) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (cursorAgentSandboxWorkingDirectoryEscape) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (cursorAgentSandboxWorkingDirectoryEscape) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON}
}

func (cursorAgentSandboxWorkingDirectoryEscape) Apply(doc *parse.Document) []finding.Finding {
	if doc.PackageJSON == nil || !isCursorAppPackageManifest(doc.Path) {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(doc.PackageJSON.Name), "cursor") ||
		!vulnerableVersionBefore(doc.PackageJSON.Version, []int{3, 0, 0}) {
		return nil
	}

	version := strings.TrimSpace(doc.PackageJSON.Version)
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "cursor-agent-sandbox-working-directory-escape",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Cursor before 3.0 allows agent sandbox working-directory escape",
		Description:  "CVE-2026-50548: Cursor before 3.0 allowed an agent-controlled working_directory to expand the terminal sandbox's writable scope outside the intended workspace. An attacker could overwrite sensitive files, including the cursorsandbox helper, and achieve unsandboxed code execution.",
		Path:         doc.Path,
		Line:         findLineContaining(doc.Raw, "version"),
		Match:        "Cursor app version " + version,
		SuggestedFix: "Upgrade Cursor to 3.0 or later before opening untrusted projects or allowing agent terminal commands.",
		Tags:         []string{"cve", "cve-2026-50548", "cursor", "sandbox", "path-traversal"},
	})}
}

func isCursorAppPackageManifest(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	return strings.HasSuffix(normalized, "/cursor.app/contents/resources/app/package.json") ||
		strings.HasSuffix(normalized, "/cursor/resources/app/package.json")
}
