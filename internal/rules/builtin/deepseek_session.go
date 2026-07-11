package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type deepseekMCPSessionIDHijack struct{}

func (deepseekMCPSessionIDHijack) ID() string { return "deepseek-mcp-session-id-hijack" }
func (deepseekMCPSessionIDHijack) Title() string {
	return "DeepSeek MCP Server version permits cross-user session ID reuse"
}
func (deepseekMCPSessionIDHijack) Severity() finding.Severity { return finding.SeverityHigh }
func (deepseekMCPSessionIDHijack) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (deepseekMCPSessionIDHijack) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}

func (deepseekMCPSessionIDHijack) Apply(doc *parse.Document) []finding.Finding {
	if doc.DependencyManifest == nil {
		return nil
	}
	for _, dep := range doc.DependencyManifest.Dependencies {
		if strings.EqualFold(strings.TrimSpace(dep.Name), "@arikusi/deepseek-mcp-server") && vulnerableDeepSeekMCPSessionVersion(dep.Version) {
			return []finding.Finding{deepseekMCPSessionIDHijackFinding(doc.Path, dep.Line, fmt.Sprintf("%s@%s", dep.Name, dep.Version))}
		}
	}
	return nil
}

func vulnerableDeepSeekMCPSessionVersion(raw string) bool {
	v := packageVersionRE.FindString(strings.TrimSpace(raw))
	return v != "" && compareVersionParts(v, []int{1, 4, 2}) >= 0 && compareVersionParts(v, []int{1, 7, 0}) < 0
}

func deepseekMCPSessionIDHijackFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "deepseek-mcp-session-id-hijack",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "DeepSeek MCP Server permits cross-user session ID reuse",
		Description:  "CVE-2026-55604: @arikusi/deepseek-mcp-server versions 1.4.2 through 1.6.x use caller-supplied process-global session IDs without binding them to an authenticated principal, allowing another caller to retrieve and continue a victim's conversation.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade @arikusi/deepseek-mcp-server to 1.7.0 or later, restart the MCP server, and rotate or invalidate active session identifiers.",
		Tags:         []string{"cve", "mcp", "npm", "dependency-manifest", "authorization-bypass"},
	})
}
