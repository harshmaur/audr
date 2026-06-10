package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type libreChatMCPEnvSecretLeak struct{}

func (libreChatMCPEnvSecretLeak) ID() string { return "librechat-mcp-env-secret-leak" }
func (libreChatMCPEnvSecretLeak) Title() string {
	return "LibreChat version is vulnerable to MCP environment secret disclosure"
}
func (libreChatMCPEnvSecretLeak) Severity() finding.Severity { return finding.SeverityCritical }
func (libreChatMCPEnvSecretLeak) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (libreChatMCPEnvSecretLeak) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}

func (libreChatMCPEnvSecretLeak) Apply(doc *parse.Document) []finding.Finding {
	if doc.DependencyManifest == nil {
		return nil
	}
	for _, dep := range doc.DependencyManifest.Dependencies {
		if isLibreChatPackage(dep.Name) && vulnerableLibreChatMCPEnvVersion(dep.Version) {
			return []finding.Finding{libreChatMCPEnvSecretLeakFinding(doc.Path, dep.Line, fmt.Sprintf("%s@%s", dep.Name, dep.Version))}
		}
	}
	return nil
}

func isLibreChatPackage(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	return n == "librechat" || n == "@librechat/api" || n == "@librechat/api-server" || n == "@librechat/backend"
}

func vulnerableLibreChatMCPEnvVersion(raw string) bool {
	// CVE-2026-32625 affects LibreChat up to and including 0.8.3 and is
	// patched in 0.8.4-rc1. Treat the next stable semver point, 0.8.4, as the
	// first safe package boundary for manifest posture checks.
	return vulnerableVersionBefore(raw, []int{0, 8, 4})
}

func libreChatMCPEnvSecretLeakFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "librechat-mcp-env-secret-leak",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "LibreChat through 0.8.3 can leak process secrets through MCP server URLs",
		Description:  "CVE-2026-32625: LibreChat through 0.8.3 resolves ${VAR} placeholders in user-supplied MCP server URLs against the server process environment during Zod validation. An authenticated user can configure an attacker-controlled MCP URL that exfiltrates secrets such as CREDS_KEY, CREDS_IV, JWT_SECRET, or MONGO_URI.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade LibreChat to 0.8.4-rc1 / 0.8.4 or later. Until upgraded, restrict who can create MCP servers and audit existing MCP server URLs for ${VAR} placeholders before exposing secrets in the LibreChat process environment.",
		Tags:         []string{"cve", "librechat", "mcp", "secrets", "dependency-manifest"},
	})
}
