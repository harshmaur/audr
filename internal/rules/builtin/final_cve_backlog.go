package builtin

import (
	"fmt"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type anythingLLMFilesystemRGOptionInjection struct{}
type mcpilotServerBaseURLSSRF struct{}
type junoClawPluginShellRawBlocklistBypass struct{}
type junoClawPluginShellShCAgentCommand struct{}
type hermesAgentSkillsGuardMultiwordPatterns struct{}
type libreChatAPIKeysUserIDIDOR struct{}
type aiderMCPWorkingDirEditableFilesCommandInjection struct{}

func (anythingLLMFilesystemRGOptionInjection) ID() string {
	return "anythingllm-filesystem-rg-option-injection"
}
func (anythingLLMFilesystemRGOptionInjection) Title() string {
	return "AnythingLLM version is vulnerable to filesystem-search rg option injection"
}
func (anythingLLMFilesystemRGOptionInjection) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (anythingLLMFilesystemRGOptionInjection) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (anythingLLMFilesystemRGOptionInjection) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (anythingLLMFilesystemRGOptionInjection) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isAnythingLLMPackage, func(v string) bool { return vulnerableVersionBefore(v, []int{1, 13, 0}) }, anythingLLMFilesystemRGOptionInjectionFinding)
}

func (mcpilotServerBaseURLSSRF) ID() string { return "mcpilot-serverbaseurl-ssrf" }
func (mcpilotServerBaseURLSSRF) Title() string {
	return "mcpilot client version is vulnerable to serverBaseUrl SSRF"
}
func (mcpilotServerBaseURLSSRF) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpilotServerBaseURLSSRF) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpilotServerBaseURLSSRF) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (mcpilotServerBaseURLSSRF) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isMCPilotClientPackage, func(v string) bool { return vulnerableExactVersion(v, []int{0, 1, 0}) }, mcpilotServerBaseURLSSRFFinding)
}

func (junoClawPluginShellRawBlocklistBypass) ID() string {
	return "junoclaw-plugin-shell-raw-blocklist-bypass"
}
func (junoClawPluginShellRawBlocklistBypass) Title() string {
	return "JunoClaw plugin-shell version is vulnerable to raw blocklist bypass"
}
func (junoClawPluginShellRawBlocklistBypass) Severity() finding.Severity { return finding.SeverityHigh }
func (junoClawPluginShellRawBlocklistBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (junoClawPluginShellRawBlocklistBypass) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest}
}
func (junoClawPluginShellRawBlocklistBypass) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isJunoClawPluginShellPackage, isVulnerableJunoClawPluginShellVersion, junoClawPluginShellRawBlocklistBypassFinding)
}

func (junoClawPluginShellShCAgentCommand) ID() string {
	return "junoclaw-plugin-shell-sh-c-agent-command"
}
func (junoClawPluginShellShCAgentCommand) Title() string {
	return "JunoClaw plugin-shell version wraps agent commands in a shell"
}
func (junoClawPluginShellShCAgentCommand) Severity() finding.Severity { return finding.SeverityHigh }
func (junoClawPluginShellShCAgentCommand) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (junoClawPluginShellShCAgentCommand) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest}
}
func (junoClawPluginShellShCAgentCommand) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isJunoClawPluginShellPackage, isVulnerableJunoClawPluginShellVersion, junoClawPluginShellShCAgentCommandFinding)
}

func (hermesAgentSkillsGuardMultiwordPatterns) ID() string {
	return "hermes-agent-skills-guard-multiword-patterns"
}
func (hermesAgentSkillsGuardMultiwordPatterns) Title() string {
	return "hermes-agent version has weaker Skills Guard multi-word prompt patterns"
}
func (hermesAgentSkillsGuardMultiwordPatterns) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (hermesAgentSkillsGuardMultiwordPatterns) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (hermesAgentSkillsGuardMultiwordPatterns) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (hermesAgentSkillsGuardMultiwordPatterns) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, func(name string) bool { return normalizePackageName(name) == "hermes-agent" }, func(v string) bool { return vulnerableVersionBefore(v, []int{0, 15, 0}) }, hermesAgentSkillsGuardMultiwordPatternsFinding)
}

func (libreChatAPIKeysUserIDIDOR) ID() string { return "librechat-api-keys-userid-idor" }
func (libreChatAPIKeysUserIDIDOR) Title() string {
	return "LibreChat version is vulnerable to API key userId IDOR"
}
func (libreChatAPIKeysUserIDIDOR) Severity() finding.Severity { return finding.SeverityHigh }
func (libreChatAPIKeysUserIDIDOR) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (libreChatAPIKeysUserIDIDOR) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (libreChatAPIKeysUserIDIDOR) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isLibreChatPackage, func(v string) bool { return vulnerableVersionBefore(v, []int{0, 8, 3}) }, libreChatAPIKeysUserIDIDORFinding)
}

func (aiderMCPWorkingDirEditableFilesCommandInjection) ID() string {
	return "aider-mcp-working-dir-editable-files-command-injection"
}
func (aiderMCPWorkingDirEditableFilesCommandInjection) Title() string {
	return "aider-mcp server launched from vulnerable GitHub source"
}
func (aiderMCPWorkingDirEditableFilesCommandInjection) Severity() finding.Severity {
	return finding.SeverityMedium
}
func (aiderMCPWorkingDirEditableFilesCommandInjection) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (aiderMCPWorkingDirEditableFilesCommandInjection) Formats() []parse.Format {
	return parse.AllMCPFormats()
}
func (aiderMCPWorkingDirEditableFilesCommandInjection) Apply(doc *parse.Document) []finding.Finding {
	var out []finding.Finding
	for _, s := range parse.NormalizeMCPServers(doc) {
		if s.Disabled || !looksLikeAiderMCPGitHubSource(s) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "aider-mcp-working-dir-editable-files-command-injection",
			Severity:     finding.SeverityMedium,
			Taxonomy:     finding.TaxDetectable,
			Title:        "aider-mcp launched from vulnerable GitHub source",
			Description:  fmt.Sprintf("CVE-2026-7316: server %q launches eiliyaabedini/aider-mcp, whose working_dir / editable_files handling can be abused for command injection when MCP callers influence those arguments.", s.Name),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Remove eiliyaabedini/aider-mcp from MCP configs or pin to a reviewed fixed commit/fork that avoids shell interpolation of working_dir and editable file paths.",
			Tags:         []string{"cve", "mcp", "github-source", "command-injection"},
		}))
	}
	return out
}

func isAnythingLLMPackage(name string) bool {
	n := normalizePackageName(name)
	return n == "anything-llm" || n == "anythingllm"
}

func isMCPilotClientPackage(name string) bool {
	n := normalizePackageName(name)
	return n == "mcpilot-client" || n == "mcpilot"
}

func isJunoClawPluginShellPackage(name string) bool {
	n := normalizePackageName(name)
	return n == "plugin-shell" || n == "junoclaw-plugin-shell"
}

func isVulnerableJunoClawPluginShellVersion(raw string) bool {
	return vulnerableVersionBefore(raw, []int{0, 1, 1})
}

func looksLikeAiderMCPGitHubSource(s parse.NormalizedMCPServer) bool {
	joined := strings.ToLower(s.Name + " " + s.Command + " " + strings.Join(s.Args, " "))
	return strings.Contains(joined, "github.com/eiliyaabedini/aider-mcp") || strings.Contains(joined, "eiliyaabedini/aider-mcp")
}

func anythingLLMFilesystemRGOptionInjectionFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{RuleID: "anythingllm-filesystem-rg-option-injection", Severity: finding.SeverityHigh, Taxonomy: finding.TaxDetectable, Title: "AnythingLLM before 1.13.0 allows filesystem-search rg option injection", Description: "CVE-2026-48116: AnythingLLM before 1.13.0 passes agent-controlled filesystem-search terms to ripgrep in a way that can be abused as option injection.", Path: path, Line: line, Match: match, SuggestedFix: "Upgrade AnythingLLM to 1.13.0 or later and review filesystem-search tool exposure to untrusted prompts.", Tags: []string{"cve", "anythingllm", "dependency-manifest", "option-injection"}})
}

func mcpilotServerBaseURLSSRFFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{RuleID: "mcpilot-serverbaseurl-ssrf", Severity: finding.SeverityHigh, Taxonomy: finding.TaxDetectable, Title: "mcpilot client 0.1.0 allows serverBaseUrl SSRF", Description: "CVE-2026-10280: horizon921 mcpilot client 0.1.0 lets MCP API calls use attacker-controlled serverBaseUrl values, enabling SSRF against internal or cloud metadata endpoints.", Path: path, Line: line, Match: match, SuggestedFix: "Remove mcpilot-client 0.1.0 from source trees/manifests or upgrade to a fixed release once available; do not expose serverBaseUrl to untrusted prompts.", Tags: []string{"cve", "mcp", "dependency-manifest", "ssrf"}})
}

func junoClawPluginShellRawBlocklistBypassFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{RuleID: "junoclaw-plugin-shell-raw-blocklist-bypass", Severity: finding.SeverityHigh, Taxonomy: finding.TaxDetectable, Title: "JunoClaw plugin-shell raw blocklist can be bypassed", Description: "CVE-2026-43991: JunoClaw plugin-shell 0.1.0 relies on substring blocklists that adversarial prompts can bypass to execute dangerous shell behavior.", Path: path, Line: line, Match: match, SuggestedFix: "Upgrade plugin-shell to a fixed JunoClaw release or remove the shell plugin from agent-accessible plugin manifests.", Tags: []string{"cve", "junoclaw", "cargo", "dependency-manifest", "command-injection"}})
}

func junoClawPluginShellShCAgentCommandFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{RuleID: "junoclaw-plugin-shell-sh-c-agent-command", Severity: finding.SeverityHigh, Taxonomy: finding.TaxDetectable, Title: "JunoClaw plugin-shell wraps agent commands in sh -c / cmd /C", Description: "CVE-2026-43990: JunoClaw plugin-shell 0.1.0 wraps agent-supplied commands in a system shell, making prompt-injected metacharacters and shell expansions dangerous.", Path: path, Line: line, Match: match, SuggestedFix: "Upgrade plugin-shell to a fixed JunoClaw release that avoids shell wrapping or remove the shell plugin from agent-accessible plugin manifests.", Tags: []string{"cve", "junoclaw", "cargo", "dependency-manifest", "command-injection"}})
}

func hermesAgentSkillsGuardMultiwordPatternsFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{RuleID: "hermes-agent-skills-guard-multiword-patterns", Severity: finding.SeverityHigh, Taxonomy: finding.TaxDetectable, Title: "hermes-agent before 0.15.0 has weaker Skills Guard multi-word prompt patterns", Description: "CVE-2026-9353: hermes-agent releases before 0.15.0 did not include the hardened Skills Guard multi-word prompt pattern coverage added in 0.15.0.", Path: path, Line: line, Match: match, SuggestedFix: "Upgrade hermes-agent to 0.15.0 or later.", Tags: []string{"cve", "hermes-agent", "dependency-manifest", "prompt-injection"}})
}

func libreChatAPIKeysUserIDIDORFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{RuleID: "librechat-api-keys-userid-idor", Severity: finding.SeverityHigh, Taxonomy: finding.TaxDetectable, Title: "LibreChat before 0.8.3 is vulnerable to API key userId IDOR", Description: "CVE-2026-31942: LibreChat versions through 0.7.6 allowed API key update requests to carry userId fields that could target other users' keys. Fixed releases sanitize the request body before updateUserKey.", Path: path, Line: line, Match: match, SuggestedFix: "Upgrade LibreChat to 0.8.3-rc1 / 0.8.3 or later and rotate API keys that may have been exposed or modified.", Tags: []string{"cve", "librechat", "dependency-manifest", "idor"}})
}
