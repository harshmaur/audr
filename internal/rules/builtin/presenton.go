package builtin

import (
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type presentonMCPAuthBypass struct{}

func (presentonMCPAuthBypass) ID() string { return "presenton-mcp-auth-bypass" }
func (presentonMCPAuthBypass) Title() string {
	return "Presenton version exposes MCP endpoint outside session authentication"
}
func (presentonMCPAuthBypass) Severity() finding.Severity { return finding.SeverityMedium }
func (presentonMCPAuthBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (presentonMCPAuthBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}

func (presentonMCPAuthBypass) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isPresentonPackage, func(v string) bool {
		return vulnerableVersionBefore(v, []int{0, 8, 8})
	}, presentonMCPAuthBypassFinding)
}

func isPresentonPackage(name string) bool {
	return normalizePackageName(name) == "presenton"
}

func presentonMCPAuthBypassFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "presenton-mcp-auth-bypass",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Presenton before 0.8.8-beta can expose /mcp without auth",
		Description:  "CVE-2026-58446: Presenton server/Docker deployments before 0.8.8-beta can leave the bundled MCP endpoint reachable at /mcp without the session auth gate, allowing unauthenticated callers to invoke MCP tools such as presentation generation with the operator's configured LLM credentials.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade Presenton to 0.8.8-beta or later. On server/Docker deployments, verify the /mcp route is protected by the same authentication layer as the web app and rotate any LLM API keys exposed to the unauthenticated MCP endpoint.",
		Tags:         []string{"cve", "presenton", "mcp", "dependency-manifest", "authentication"},
	})
}
