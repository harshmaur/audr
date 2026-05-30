package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type lumiverseMCPArgsRCE struct{}

func (lumiverseMCPArgsRCE) ID() string { return "lumiverse-mcp-args-rce" }
func (lumiverseMCPArgsRCE) Title() string {
	return "Lumiverse MCP server version is vulnerable to args-based code execution"
}
func (lumiverseMCPArgsRCE) Severity() finding.Severity { return finding.SeverityCritical }
func (lumiverseMCPArgsRCE) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (lumiverseMCPArgsRCE) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}

func (lumiverseMCPArgsRCE) Apply(doc *parse.Document) []finding.Finding {
	if doc.DependencyManifest == nil {
		return nil
	}
	for _, dep := range doc.DependencyManifest.Dependencies {
		if isLumiversePackage(dep.Name) && vulnerableLumiverseVersion(dep.Version) {
			return []finding.Finding{lumiverseMCPArgsRCEFinding(doc.Path, dep.Line, fmt.Sprintf("%s@%s", dep.Name, dep.Version))}
		}
	}
	return nil
}

func isLumiversePackage(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	return n == "lumiverse-backend" || n == "lumiverse"
}

func vulnerableLumiverseVersion(raw string) bool {
	return vulnerableVersionBefore(raw, []int{0, 9, 7})
}

func lumiverseMCPArgsRCEFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "lumiverse-mcp-args-rce",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Lumiverse before 0.9.7 forwards unvalidated MCP server args to code-capable binaries",
		Description:  "CVE-2026-44450: Lumiverse before 0.9.7 validates only the MCP server command allowlist but forwards arbitrary args to binaries such as node, bun, python3, and deno. Inline-code flags can give a logged-in user OS-level code execution on the Lumiverse server.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade Lumiverse / lumiverse-backend to 0.9.7 or later and review locally defined MCP servers for inline-code flags such as -e or -c.",
		Tags:         []string{"cve", "lumiverse", "mcp", "dependency-manifest", "code-injection"},
	})
}
