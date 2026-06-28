package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type xhsMCPMediaPathsSSRF struct{}
type directusMCPFileURLSSRF struct{}
type cloudbaseMCPOpenURLSSRF struct{}
type libreChatMCPAdminSecretResponseLeak struct{}
type libreChatMCPOAuthResourceConfusion struct{}
type rtkRewriteOpenClawExecSyncInjection struct{}

func (xhsMCPMediaPathsSSRF) ID() string { return "xhs-mcp-media-paths-ssrf" }
func (xhsMCPMediaPathsSSRF) Title() string {
	return "xhs-mcp version is vulnerable to media_paths SSRF"
}
func (xhsMCPMediaPathsSSRF) Severity() finding.Severity { return finding.SeverityMedium }
func (xhsMCPMediaPathsSSRF) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (xhsMCPMediaPathsSSRF) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (xhsMCPMediaPathsSSRF) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isXHSMCPPackage, func(v string) bool { return vulnerableExactVersion(v, []int{0, 8, 11}) }, xhsMCPMediaPathsSSRFFinding)
}

func (directusMCPFileURLSSRF) ID() string { return "directus-mcp-fileurl-ssrf" }
func (directusMCPFileURLSSRF) Title() string {
	return "directus-mcp version is vulnerable to fileUrl SSRF"
}
func (directusMCPFileURLSSRF) Severity() finding.Severity { return finding.SeverityLow }
func (directusMCPFileURLSSRF) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (directusMCPFileURLSSRF) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (directusMCPFileURLSSRF) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isDirectusMCPPackage, func(v string) bool { return vulnerableExactVersion(v, []int{1, 0, 0}) }, directusMCPFileURLSSRFFinding)
}

func (cloudbaseMCPOpenURLSSRF) ID() string { return "cloudbase-mcp-openurl-ssrf" }
func (cloudbaseMCPOpenURLSSRF) Title() string {
	return "CloudBase-MCP version is vulnerable to openUrl SSRF"
}
func (cloudbaseMCPOpenURLSSRF) Severity() finding.Severity { return finding.SeverityMedium }
func (cloudbaseMCPOpenURLSSRF) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (cloudbaseMCPOpenURLSSRF) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (cloudbaseMCPOpenURLSSRF) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isCloudBaseMCPPackage, func(v string) bool { return vulnerableVersionBefore(v, []int{2, 17, 1}) }, cloudbaseMCPOpenURLSSRFFinding)
}

func (libreChatMCPAdminSecretResponseLeak) ID() string {
	return "librechat-mcp-admin-secret-response-leak"
}
func (libreChatMCPAdminSecretResponseLeak) Title() string {
	return "LibreChat version is vulnerable to MCP admin-managed secret disclosure"
}
func (libreChatMCPAdminSecretResponseLeak) Severity() finding.Severity { return finding.SeverityMedium }
func (libreChatMCPAdminSecretResponseLeak) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (libreChatMCPAdminSecretResponseLeak) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (libreChatMCPAdminSecretResponseLeak) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isLibreChatPackage, func(v string) bool { return vulnerableVersionBefore(v, []int{0, 8, 4}) }, libreChatMCPAdminSecretResponseLeakFinding)
}

func (libreChatMCPOAuthResourceConfusion) ID() string {
	return "librechat-mcp-oauth-resource-confusion"
}
func (libreChatMCPOAuthResourceConfusion) Title() string {
	return "LibreChat version is vulnerable to MCP OAuth resource confusion"
}
func (libreChatMCPOAuthResourceConfusion) Severity() finding.Severity { return finding.SeverityHigh }
func (libreChatMCPOAuthResourceConfusion) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (libreChatMCPOAuthResourceConfusion) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (libreChatMCPOAuthResourceConfusion) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isLibreChatPackage, func(v string) bool { return vulnerableVersionBefore(v, []int{0, 8, 5}) }, libreChatMCPOAuthResourceConfusionFinding)
}

func (rtkRewriteOpenClawExecSyncInjection) ID() string {
	return "rtk-rewrite-openclaw-execsync-injection"
}
func (rtkRewriteOpenClawExecSyncInjection) Title() string {
	return "@rtk-ai/rtk-rewrite 1.0.0 is vulnerable to shell command injection"
}
func (rtkRewriteOpenClawExecSyncInjection) Severity() finding.Severity { return finding.SeverityMedium }
func (rtkRewriteOpenClawExecSyncInjection) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (rtkRewriteOpenClawExecSyncInjection) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (rtkRewriteOpenClawExecSyncInjection) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isRTKRewritePackage, func(v string) bool { return vulnerableExactVersion(v, []int{1, 0, 0}) }, rtkRewriteOpenClawExecSyncInjectionFinding)
}

func dependencyVersionFinding(doc *parse.Document, matchesPackage func(string) bool, vulnerable func(string) bool, makeFinding func(string, int, string) finding.Finding) []finding.Finding {
	if doc.DependencyManifest == nil {
		return nil
	}
	for _, dep := range doc.DependencyManifest.Dependencies {
		if matchesPackage(dep.Name) && vulnerable(dep.Version) {
			return []finding.Finding{makeFinding(doc.Path, dep.Line, fmt.Sprintf("%s@%s", dep.Name, dep.Version))}
		}
	}
	return nil
}

func isXHSMCPPackage(name string) bool      { return normalizePackageName(name) == "xhs-mcp" }
func isDirectusMCPPackage(name string) bool { return normalizePackageName(name) == "directus-mcp" }
func isCloudBaseMCPPackage(name string) bool {
	n := normalizePackageName(name)
	return n == "@cloudbase/cloudbase-mcp" || n == "cloudbase-mcp"
}
func isRTKRewritePackage(name string) bool {
	return normalizePackageName(name) == "@rtk-ai/rtk-rewrite"
}

func normalizePackageName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	return strings.ReplaceAll(n, "_", "-")
}

func vulnerableExactVersion(raw string, target []int) bool {
	v := strings.TrimSpace(raw)
	if v == "" || strings.ContainsAny(v, "*xX") || strings.HasPrefix(v, "git+") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "workspace:") {
		return false
	}
	m := packageVersionRE.FindString(v)
	if m == "" {
		return false
	}
	return compareVersionParts(m, target) == 0
}

func xhsMCPMediaPathsSSRFFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "xhs-mcp-media-paths-ssrf",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "xhs-mcp 0.8.11 allows SSRF through media_paths",
		Description:  "CVE-2026-7417: Algovate xhs-mcp 0.8.11 accepts MCP media_paths input that can be steered to attacker-chosen URLs or internal endpoints, creating SSRF risk when exposed to agent prompts.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Remove xhs-mcp 0.8.11 from MCP server manifests or upgrade to a fixed release once available; avoid exposing media_paths URL handling to untrusted prompts.",
		Tags:         []string{"cve", "mcp", "dependency-manifest", "ssrf"},
	})
}

func directusMCPFileURLSSRFFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "directus-mcp-fileurl-ssrf",
		Severity:     finding.SeverityLow,
		Taxonomy:     finding.TaxDetectable,
		Title:        "directus-mcp 1.0.0 allows SSRF through fileUrl validation",
		Description:  "CVE-2026-7729: pixelsock directus-mcp 1.0.0 validates fileUrl insufficiently, allowing MCP callers to reach attacker-chosen URLs or internal services through Directus media handling.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Remove directus-mcp 1.0.0 from MCP server manifests or upgrade to a fixed release once available; restrict which Directus MCP callers can supply fileUrl values.",
		Tags:         []string{"cve", "mcp", "dependency-manifest", "ssrf"},
	})
}

func cloudbaseMCPOpenURLSSRFFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "cloudbase-mcp-openurl-ssrf",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "CloudBase-MCP before 2.17.1 allows SSRF through openUrl",
		Description:  "CVE-2026-7221: TencentCloudBase CloudBase-MCP before 2.17.1 exposes openUrl behavior that can be abused for SSRF when an agent or MCP caller controls the URL.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade @cloudbase/cloudbase-mcp to 2.17.1 or later and review MCP clients that allowed untrusted prompts to call openUrl.",
		Tags:         []string{"cve", "mcp", "dependency-manifest", "ssrf"},
	})
}

func libreChatMCPAdminSecretResponseLeakFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "librechat-mcp-admin-secret-response-leak",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "LibreChat through 0.8.3 can leak admin-managed MCP secrets to VIEW users",
		Description:  "CVE-2026-44653: LibreChat through 0.8.3 can return decrypted admin-managed MCP server secrets from GET /api/mcp/servers to users with VIEW access, exposing credentials configured for MCP servers.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade LibreChat to 0.8.4 or later, rotate exposed MCP server secrets, and review which users had VIEW access to MCP server definitions.",
		Tags:         []string{"cve", "librechat", "mcp", "secrets", "dependency-manifest"},
	})
}

func libreChatMCPOAuthResourceConfusionFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "librechat-mcp-oauth-resource-confusion",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxDetectable,
		Title:        "LibreChat before 0.8.5 can send MCP OAuth tokens to the wrong resource",
		Description:  "CVE-2026-54030: LibreChat before 0.8.5 did not verify that OAuth Protected Resource metadata matched the configured MCP server URL, allowing a malicious MCP server to obtain access tokens intended for another server.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade LibreChat to 0.8.5 or later, rotate OAuth tokens issued through untrusted MCP servers, and review configured MCP OAuth resource URLs.",
		Tags:         []string{"cve", "librechat", "mcp", "oauth", "dependency-manifest"},
	})
}

func rtkRewriteOpenClawExecSyncInjectionFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "rtk-rewrite-openclaw-execsync-injection",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "@rtk-ai/rtk-rewrite 1.0.0 shell-expands OpenClaw exec tool input",
		Description:  "CVE-2026-55249: @rtk-ai/rtk-rewrite 1.0.0 passes OpenClaw exec tool input into a shell-backed execSync template; command substitutions such as $() can execute before rtk is invoked.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Remove @rtk-ai/rtk-rewrite 1.0.0 from OpenClaw/plugin manifests or upgrade to a fixed release that avoids shell-backed execSync interpolation.",
		Tags:         []string{"cve", "openclaw", "rtk", "dependency-manifest", "command-injection"},
	})
}
