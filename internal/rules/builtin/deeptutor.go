package builtin

import (
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type deeptutorMCPToolGrantBypass struct{}

func (deeptutorMCPToolGrantBypass) ID() string { return "deeptutor-mcp-tool-grant-bypass" }
func (deeptutorMCPToolGrantBypass) Title() string {
	return "DeepTutor version can omit MCP tool grants as unrestricted access"
}
func (deeptutorMCPToolGrantBypass) Severity() finding.Severity { return finding.SeverityHigh }
func (deeptutorMCPToolGrantBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (deeptutorMCPToolGrantBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest}
}

func (deeptutorMCPToolGrantBypass) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isDeepTutorPackage, func(v string) bool {
		return vulnerableVersionBefore(v, []int{1, 4, 10})
	}, deeptutorMCPToolGrantBypassFinding)
}

func isDeepTutorPackage(name string) bool {
	return normalizePackageName(name) == "deeptutor"
}

func deeptutorMCPToolGrantBypassFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "deeptutor-mcp-tool-grant-bypass",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "DeepTutor before 1.4.10 treats missing MCP tool grants as unrestricted",
		Description:  "CVE-2026-58168: DeepTutor before 1.4.10 can return an allow result when mcp_tools is omitted from a user's grant, allowing low-privilege users or prompt-injected sessions to enumerate and invoke configured MCP tools such as filesystem, shell, and browser servers.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade deeptutor to 1.4.10 or later and audit user grants so MCP tool lists are explicit deny-by-default before exposing shell, filesystem, browser, or other sensitive MCP servers.",
		Tags:         []string{"cve", "deeptutor", "mcp", "dependency-manifest", "authorization-bypass"},
	})
}
