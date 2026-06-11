package builtin

import (
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type mcpChatStudioModelsBaseURLSSRF struct{}
type mcpURLDownloaderValidateURLSafeSSRF struct{}
type aiderMCPServerRelativeEditableFilesCommandInjection struct{}
type mcpDataVisWebScraperSSRF struct{}
type clineMCPMemoryBankInitializePathTraversal struct{}

func (mcpChatStudioModelsBaseURLSSRF) ID() string { return "mcp-chat-studio-models-base-url-ssrf" }
func (mcpChatStudioModelsBaseURLSSRF) Title() string {
	return "mcp-chat-studio version is vulnerable to models base_url SSRF"
}
func (mcpChatStudioModelsBaseURLSSRF) Severity() finding.Severity { return finding.SeverityMedium }
func (mcpChatStudioModelsBaseURLSSRF) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpChatStudioModelsBaseURLSSRF) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (mcpChatStudioModelsBaseURLSSRF) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, func(name string) bool { return normalizePackageName(name) == "mcp-chat-studio" }, func(v string) bool { return vulnerableVersionBefore(v, []int{1, 5, 1}) }, mcpChatStudioModelsBaseURLSSRFFinding)
}

func (mcpURLDownloaderValidateURLSafeSSRF) ID() string {
	return "mcp-url-downloader-validate-url-safe-ssrf"
}
func (mcpURLDownloaderValidateURLSafeSSRF) Title() string {
	return "mcp-url-downloader version is vulnerable to URL validation SSRF"
}
func (mcpURLDownloaderValidateURLSafeSSRF) Severity() finding.Severity { return finding.SeverityMedium }
func (mcpURLDownloaderValidateURLSafeSSRF) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpURLDownloaderValidateURLSafeSSRF) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (mcpURLDownloaderValidateURLSafeSSRF) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, func(name string) bool { return normalizePackageName(name) == "mcp-url-downloader" }, func(v string) bool { return vulnerableExactVersion(v, []int{0, 1, 0}) }, mcpURLDownloaderValidateURLSafeSSRFFinding)
}

func (aiderMCPServerRelativeEditableFilesCommandInjection) ID() string {
	return "aider-mcp-server-relative-editable-files-command-injection"
}
func (aiderMCPServerRelativeEditableFilesCommandInjection) Title() string {
	return "aider-mcp-server version is vulnerable to editable-files command injection"
}
func (aiderMCPServerRelativeEditableFilesCommandInjection) Severity() finding.Severity {
	return finding.SeverityMedium
}
func (aiderMCPServerRelativeEditableFilesCommandInjection) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (aiderMCPServerRelativeEditableFilesCommandInjection) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (aiderMCPServerRelativeEditableFilesCommandInjection) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, func(name string) bool { return normalizePackageName(name) == "aider-mcp-server" }, func(v string) bool { return vulnerableExactVersion(v, []int{0, 1, 0}) }, aiderMCPServerRelativeEditableFilesCommandInjectionFinding)
}

func (mcpDataVisWebScraperSSRF) ID() string { return "mcp-data-vis-web-scraper-ssrf" }
func (mcpDataVisWebScraperSSRF) Title() string {
	return "mcp-data-vis version is vulnerable to web-scraper SSRF"
}
func (mcpDataVisWebScraperSSRF) Severity() finding.Severity { return finding.SeverityMedium }
func (mcpDataVisWebScraperSSRF) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpDataVisWebScraperSSRF) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (mcpDataVisWebScraperSSRF) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, func(name string) bool { return normalizePackageName(name) == "mcp-data-vis" }, func(v string) bool { return vulnerableExactVersion(v, []int{1, 0, 0}) }, mcpDataVisWebScraperSSRFFinding)
}

func (clineMCPMemoryBankInitializePathTraversal) ID() string {
	return "cline-mcp-memory-bank-initialize-path-traversal"
}
func (clineMCPMemoryBankInitializePathTraversal) Title() string {
	return "cline-mcp-memory-bank version is vulnerable to initialize path traversal"
}
func (clineMCPMemoryBankInitializePathTraversal) Severity() finding.Severity {
	return finding.SeverityMedium
}
func (clineMCPMemoryBankInitializePathTraversal) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (clineMCPMemoryBankInitializePathTraversal) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest, parse.FormatPackageJSON}
}
func (clineMCPMemoryBankInitializePathTraversal) Apply(doc *parse.Document) []finding.Finding {
	return dependencyVersionFinding(doc, isMemoryBankServerPackage, func(v string) bool { return vulnerableExactVersion(v, []int{0, 1, 0}) }, clineMCPMemoryBankInitializePathTraversalFinding)
}

func isMemoryBankServerPackage(name string) bool {
	n := normalizePackageName(name)
	return n == "memory-bank-server" || n == "cline-mcp-memory-bank"
}

func mcpChatStudioModelsBaseURLSSRFFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "mcp-chat-studio-models-base-url-ssrf",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "mcp-chat-studio through 1.5.0 allows SSRF through model base_url",
		Description:  "CVE-2026-7147: mcp-chat-studio through 1.5.0 accepts LLM model API base_url values that can be abused for SSRF when agent-controlled or untrusted inputs reach the MCP server.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade mcp-chat-studio once a fixed release is available or remove the server from MCP configs that expose model base_url changes to untrusted prompts.",
		Tags:         []string{"cve", "mcp", "dependency-manifest", "ssrf"},
	})
}

func mcpURLDownloaderValidateURLSafeSSRFFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "mcp-url-downloader-validate-url-safe-ssrf",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "mcp-url-downloader 0.1.0 has insufficient URL validation",
		Description:  "CVE-2026-7158: mcp-url-downloader 0.1.0 contains an insufficient _validate_url_safe SSRF guard, allowing MCP callers to download attacker-chosen or internal URLs.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Remove mcp-url-downloader 0.1.0 from MCP server manifests or upgrade to a fixed release once available; do not expose URL downloader tools to untrusted prompts.",
		Tags:         []string{"cve", "mcp", "pypi", "dependency-manifest", "ssrf"},
	})
}

func aiderMCPServerRelativeEditableFilesCommandInjectionFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "aider-mcp-server-relative-editable-files-command-injection",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "aider-mcp-server 0.1.0 allows command injection through editable file arguments",
		Description:  "CVE-2026-7157: aider-mcp-server 0.1.0 exposes relative_editable_files / working_dir handling that can be abused for shell command injection when MCP callers influence file path arguments.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Remove aider-mcp-server 0.1.0 from MCP server manifests or upgrade to a fixed release once available; restrict editable file arguments to trusted callers.",
		Tags:         []string{"cve", "mcp", "pypi", "dependency-manifest", "command-injection"},
	})
}

func mcpDataVisWebScraperSSRFFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "mcp-data-vis-web-scraper-ssrf",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "mcp-data-vis 1.0.0 web scraper can be abused for SSRF",
		Description:  "CVE-2026-7146: mcp-data-vis 1.0.0 exposes web-scraper URL handling that can request attacker-chosen or internal URLs through an MCP tool.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Remove mcp-data-vis 1.0.0 from MCP server manifests or upgrade to a fixed release once available; avoid exposing web-scraper tools to untrusted prompts.",
		Tags:         []string{"cve", "mcp", "dependency-manifest", "ssrf"},
	})
}

func clineMCPMemoryBankInitializePathTraversalFinding(path string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "cline-mcp-memory-bank-initialize-path-traversal",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "cline-mcp-memory-bank 0.1.0 can traverse paths during initialization",
		Description:  "CVE-2026-9468: dazeb cline-mcp-memory-bank / memory-bank-server 0.1.0 handles projectPath during initialize in a way that can write outside the intended memory-bank directory.",
		Path:         path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Remove memory-bank-server 0.1.0 from MCP server manifests or upgrade to a fixed release once available; review initialized memory-bank paths for unexpected writes.",
		Tags:         []string{"cve", "mcp", "dependency-manifest", "path-traversal"},
	})
}
