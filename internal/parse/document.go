// Package parse contains format-specific parsers for the file types
// Audr scans. Each parser fills in the relevant typed field on a
// Document; rules iterate over Documents and emit findings.
package parse

import (
	"path/filepath"
	"strings"
)

// Format identifies which kind of artifact a Document represents.
// Rules register for one or more formats and only run on matching docs.
type Format string

const (
	FormatMCPConfig              Format = "mcp-config"               // .mcp.json, .cursor/mcp.json
	FormatClaudeSettings         Format = "claude-settings"          // .claude/settings.json, settings.local.json
	FormatSkill                  Format = "skill"                    // .claude/skills/**/*.md
	FormatAgentDoc               Format = "agent-doc"                // AGENTS.md, CLAUDE.md, CODEX.md, GEMINI.md, .cursorrules
	FormatGHAWorkflow            Format = "gha-workflow"             // .github/workflows/*.yml
	FormatShellRC                Format = "shellrc"                  // .bashrc, .zshrc, .profile, etc.
	FormatPowerShellProfile      Format = "powershell-profile"       // Microsoft.PowerShell_profile.ps1, $PROFILE
	FormatEnv                    Format = "env"                      // .env, .env.local, .env.example
	FormatCodexConfig            Format = "codex-config"             // ~/.codex/config.toml, .codex/config.toml (v0.2)
	FormatWindsurfMCP            Format = "windsurf-mcp"             // ~/.codeium/windsurf/mcp_config.json (v0.2.0-alpha.3)
	FormatCursorPermissions      Format = "cursor-permissions"       // ~/.cursor/permissions.json (v0.2.0-alpha.4)
	FormatPackageJSON            Format = "package-json"             // package.json manifests for agent packages
	FormatDependencyManifest     Format = "dependency-manifest"      // language manifests/lockfiles for agent package CVEs
	FormatReleaseAgeConfig       Format = "release-age-config"       // package-manager/dependency-bot release-age cooldown configs
	FormatAPMPluginManifest      Format = "apm-plugin-manifest"      // Microsoft APM plugin.json component manifests
	FormatKiotaOpenAPISpec       Format = "kiota-openapi-spec"       // OpenAPI/Swagger specs used for Kiota plugin generation
	FormatGitConfig              Format = "git-config"               // bare/nested git config files with executable hooks/helpers
	FormatMiseToolVersions       Format = "mise-tool-versions"       // .tool-versions dev-tool install/version config
	FormatDockerfile             Format = "dockerfile"               // Dockerfile build posture checks
	FormatMiniShaiHuludArtifact  Format = "mini-shai-hulud-artifact" // known local IOC/persistence files
	FormatNPMMalwareArtifact     Format = "npm-malware-artifact"     // bounded package-root supply-chain IOCs
	FormatPyPIMalwareArtifact    Format = "pypi-malware-artifact"    // bounded PyPI package/drop supply-chain IOCs
	FormatAsyncAPIMiasmaArtifact Format = "asyncapi-miasma-artifact" // AsyncAPI Miasma package/drop IOCs
	FormatClawVetAuthSource      Format = "clawvet-auth-source"      // ClawVet self-hosted API authentication source
	FormatSiYuanConfig           Format = "siyuan-config"            // SiYuan workspace conf/conf.json or ~/.siyuan/conf.json
	FormatUnknown                Format = ""
)

// FormatOpenClawDashboardSource identifies canonical OpenClaw Dashboard browser source.
const FormatOpenClawDashboardSource Format = "openclaw-dashboard-source"

// Document is the generic container produced by parsers and consumed by rules.
type Document struct {
	Path   string // absolute or scan-relative path
	Format Format
	Raw    []byte // full file contents (subject to size cap)

	// Parsed forms. PackageJSON files also populate DependencyManifest so
	// package-version CVE rules can share one normalized dependency surface.
	MCPConfig          *MCPConfig
	ClaudeSettings     *ClaudeSettings
	Skill              *Skill
	AgentDoc           *AgentDoc
	Workflow           *Workflow
	ShellRC            *ShellRC
	PowerShellProfile  *PowerShellProfile
	Env                *EnvFile
	CodexConfig        *CodexConfig       // v0.2
	WindsurfMCP        *WindsurfMCP       // v0.2.0-alpha.3
	CursorPermissions  *CursorPermissions // v0.2.0-alpha.4
	PackageJSON        *PackageJSON
	DependencyManifest *DependencyManifest
	SiYuanConfig       *SiYuanConfig

	// ParseError is set if parsing failed; rules treat this as an advisory
	// finding, the scan continues.
	ParseError error
}

// MCPServer describes one entry in the `mcpServers` section of an MCP config.
type MCPServer struct {
	Name    string            // server key from the JSON object
	Command string            // command to launch
	Args    []string          // positional args
	Env     map[string]string // env vars passed to the process
	URL     string            // for HTTP/SSE transports
	Type    string            // "stdio", "sse", "streamable-http", etc.
	// Line is the line number in the source file where this server was defined.
	Line int
}

// MCPConfig is the parsed form of a .mcp.json or similar.
type MCPConfig struct {
	Servers []MCPServer
}

// ClaudeSettings represents user/repo-level Claude Code configuration.
//
// Raw is the full top-level decoded JSON. Rules added in v0.2 (hook-shell-rce,
// skip-permission-prompt, third-party-plugin) walk Raw directly because the
// keys they need (statusLine, enabledPlugins, skipDangerousModePermissionPrompt,
// extraKnownMarketplaces) shift across Claude Code versions and don't
// warrant per-key struct fields.
type ClaudeSettings struct {
	Raw          map[string]any
	Permissions  map[string]any
	AllowedTools []string
	Env          map[string]string
	Hooks        map[string]any
	OtherKeys    []string
}

// Skill represents a parsed agent skill (Markdown with optional frontmatter).
type Skill struct {
	Name        string            // from frontmatter or filename
	Frontmatter map[string]string // top-level key/value (string-coerced)
	Body        string            // markdown body
	Tools       []string          // declared in frontmatter `allowed-tools` or detected in body
}

// AgentDoc captures content from agent-instruction documents like CLAUDE.md.
type AgentDoc struct {
	Lines []string // for line-number reporting
}

// Workflow is the parsed form of a GitHub Actions YAML.
type Workflow struct {
	Name        string
	Triggers    map[string]bool
	Permissions map[string]string // top-level permissions block, if any
	Jobs        map[string]Job
}

// Job is one job in a GitHub Actions workflow.
type Job struct {
	Name        string
	If          string
	Permissions map[string]string
	Steps       []Step
	RunsOn      []string
}

// Step is one step in a job.
type Step struct {
	Name string
	If   string
	Uses string
	Run  string
	Env  map[string]string
	With map[string]string
	Line int
}

// ShellRC is a parsed shell rc file (.bashrc / .zshrc / .profile).
type ShellRC struct {
	// EnvVars are export statements: KEY=VALUE assignments.
	EnvVars map[string]string
	// Sources are `source` / `.` invocations of other files.
	Sources []string
	// Lines retains line numbers for each EnvVar by name.
	EnvVarLines map[string]int
}

// PowerShellProfile is a parsed PowerShell profile script
// (Microsoft.PowerShell_profile.ps1 and friends). Same shape as
// ShellRC: rule authors get a flat list of env-var assignments,
// dot-sourced files, aliases, and module imports. The parser is
// deliberately not a full PowerShell AST — heredocs (`@'...'@` /
// `@"..."@`), command substitution, and function bodies are out
// of scope. Rules that need those run against the raw text.
type PowerShellProfile struct {
	// EnvVars are $env:KEY = "value" assignments. Bare $var = ...
	// assignments are tracked in Vars instead.
	EnvVars     map[string]string
	EnvVarLines map[string]int

	// Vars are bare $var = ... assignments (excluding $env:* which
	// land in EnvVars).
	Vars     map[string]string
	VarLines map[string]int

	// Sources are dot-sourced scripts: `. ./other.ps1` or
	// `. C:\path\to\script.ps1`.
	Sources []string

	// Modules are Import-Module / Add-PSSnapin / Using module
	// targets. The value is the module name or path as written.
	Modules []string

	// Aliases are Set-Alias / New-Alias mappings: alias name → value.
	Aliases    map[string]string
	AliasLines map[string]int

	// Pipelines is a list of pipeline expressions detected on a
	// single source line (the line is split into stages by `|`).
	// Rules use this to flag dangerous patterns like
	// `Invoke-WebRequest <url> | Invoke-Expression`.
	Pipelines []PowerShellPipeline

	// Lines is the line-split source. Rules with line-number
	// reporting can index by 0-based line index.
	Lines []string
}

// PowerShellPipeline is one pipeline expression as it appeared on a
// single line. Stages preserves the raw text of each pipeline stage
// in left-to-right order; Line is 1-based for finding emission.
type PowerShellPipeline struct {
	Stages []string
	Line   int
}

// EnvFile is a parsed .env-style file.
type EnvFile struct {
	Vars  map[string]string
	Lines map[string]int // line per key
}

// CodexConfig is the parsed form of `~/.codex/config.toml`.
//
// Captures only the fields the v0.2 ruleset needs to make a decision. Other
// fields exist in the file (model, personality, features, etc.) but are
// not security-relevant for static analysis.
type CodexConfig struct {
	// ApprovalPolicy is the top-level `approval_policy` setting.
	// Known values: "untrusted", "on-request", "never", "granular".
	ApprovalPolicy string

	// SandboxMode is the top-level `sandbox_mode` setting.
	// Known values: "read-only", "workspace-write", "danger-full-access".
	SandboxMode string

	// TrustedProjects maps a project path to its trust_level. Codex uses this
	// to decide whether to load a project's .codex/ layer (hooks, rules,
	// project-local config). `[projects."<path>"]` table with
	// `trust_level = "trusted"` is the risk shape: trust_level=trusted on
	// $HOME or a broad path disables sandboxing for everything inside it.
	TrustedProjects map[string]string

	// MCPServers are the [mcp_servers.<name>] tables. The v0.2 design treats
	// these as part of a normalized MCP model (added in a later iteration);
	// for now we keep them as a typed list specific to Codex.
	MCPServers []CodexMCPServer
}

// WindsurfMCP is the parsed form of ~/.codeium/windsurf/mcp_config.json.
//
// Shape:
//
//	{ "mcpServers": {
//	    "<name>": { "type": "http"|"stdio", "url": "...", "command": "...",
//	                "args": [...], "env": {...}, "headers": {...},
//	                "alwaysAllow": [...], "disabled": bool }
//	} }
type WindsurfMCP struct {
	Servers []WindsurfMCPServer
}

// WindsurfMCPServer is a single MCP server entry in a Windsurf config.
type WindsurfMCPServer struct {
	Name        string
	Type        string // "http" | "stdio" | "sse"
	URL         string // for HTTP transports
	Command     string // for stdio transports
	Args        []string
	Env         map[string]string
	Headers     map[string]string // remote auth headers — Windsurf's analog of Codex's http_headers
	AlwaysAllow []string          // Windsurf-specific: tools auto-approved without prompt
	Disabled    bool
	Line        int
}

// NormalizedMCPServer is a uniform shape that rules iterate over regardless
// of which harness config file the server came from. Populated by the
// NormalizeMCPServers helper from MCPConfig (.mcp.json), CodexConfig, or
// WindsurfMCP. The same risk shape (plaintext credential, unpinned npx,
// unauth remote URL) shows up in all three with different serializations,
// so rules walk this slice instead of three different typed fields.
type NormalizedMCPServer struct {
	Name        string
	Source      Format // which format produced this server
	Command     string // stdio command
	Args        []string
	Env         map[string]string // process env
	URL         string            // remote transport URL
	Headers     map[string]string // remote auth headers
	AlwaysAllow []string          // Windsurf's per-server allowlist (empty for other sources)
	Disabled    bool
	Line        int
}

// CursorPermissions is the parsed form of ~/.cursor/permissions.json.
//
// Schema (per Cursor docs):
//
//	{
//	  "mcpAllowlist":      ["github:*", "linear:list_issues", "*:my_tool"],
//	  "terminalAllowlist": ["git", "npm:install*", "cargo build"]
//	}
//
// Both fields are optional; either can be omitted (or empty array).
// Cursor docs explicitly state these are "best-effort convenience, not
// security guarantees", but they're the most readable signal of how
// loose a user's Cursor auto-run permissions are.
type CursorPermissions struct {
	MCPAllowlist      []string
	TerminalAllowlist []string
	// Hint: when both arrays are explicitly empty, Cursor falls back to
	// no auto-run. When the file is missing, IDE settings apply.
	HasMCPAllowlist      bool // true if the key was present (vs missing)
	HasTerminalAllowlist bool
}

// PackageJSON is the subset of package.json needed by version-posture rules.
type PackageJSON struct {
	Name                 string
	Version              string
	Dependencies         map[string]string
	DevDependencies      map[string]string
	OptionalDependencies map[string]string
	PeerDependencies     map[string]string
}

// DependencyManifest is a normalized package manifest for language ecosystems
// that can host vulnerable AI-agent packages.
type DependencyManifest struct {
	Ecosystem    string
	Dependencies []Dependency
}

// Dependency is one package declaration in a manifest.
type Dependency struct {
	Name    string
	Version string
	Scope   string
	Line    int
}

// CodexMCPServer is a single [mcp_servers.<name>] entry from config.toml.
type CodexMCPServer struct {
	Name        string
	Command     string            // for stdio transports
	Args        []string          // command args
	Env         map[string]string // process env (rare in Codex)
	URL         string            // for HTTP/SSE transports
	HTTPHeaders map[string]string // [mcp_servers.<name>.http_headers] table — Codex's place for plaintext API keys
	Enabled     *bool             // optional `enabled = true|false`
	// Line is the line number in the source file where this server was defined.
	Line int
}

// DetectFormat picks a Format based on the file path. Returns FormatUnknown
// for files that aren't Audr-relevant.
//
// Normalizes backslashes to forward slashes before basename
// extraction so a Windows-native path passed in from a cross-platform
// scan (e.g. `C:\Users\X\.bashrc`) detects the same on Linux/macOS
// hosts as it does on Windows. filepath.Base is OS-aware and on Linux
// would return the whole string for a backslash-separated path.
func DetectFormat(path string) Format {
	// Use ToSlash for the basename extraction so backslash-separated
	// Windows paths classify correctly even when audr runs on a
	// non-Windows host. The original path is preserved for any
	// downstream rule that needs the native separator.
	normalized := strings.ReplaceAll(path, "\\", "/")
	base := filepath.Base(normalized)
	dir := filepath.Dir(normalized)

	// MCP configs.
	switch base {
	case ".mcp.json", "mcp.json":
		return FormatMCPConfig
	}
	if strings.HasSuffix(path, "/.cursor/mcp.json") || strings.HasSuffix(path, "\\.cursor\\mcp.json") {
		return FormatMCPConfig
	}

	// Claude settings.
	if (base == "settings.json" || base == "settings.local.json") &&
		(strings.Contains(dir, ".claude") || strings.Contains(dir, "/.config/Claude")) {
		return FormatClaudeSettings
	}

	// Codex CLI config (v0.2). User config at ~/.codex/config.toml; project-local
	// override at <project>/.codex/config.toml.
	if base == "config.toml" && (strings.Contains(dir, "/.codex") || strings.HasSuffix(dir, "/.codex")) {
		return FormatCodexConfig
	}

	// Windsurf MCP config (v0.2.0-alpha.3). Lives at ~/.codeium/windsurf/mcp_config.json
	// on macOS/Linux. Same logical shape as Cursor's mcp.json, different path.
	if base == "mcp_config.json" && strings.Contains(dir, "/.codeium/windsurf") {
		return FormatWindsurfMCP
	}

	// Cursor global permissions config (v0.2.0-alpha.4). Lives at
	// ~/.cursor/permissions.json. Distinct from .cursor/mcp.json (already
	// FormatMCPConfig). Holds mcpAllowlist + terminalAllowlist arrays.
	if base == "permissions.json" && strings.Contains(dir, "/.cursor") {
		return FormatCursorPermissions
	}

	// SiYuan's persisted application configuration. The workspace layout uses
	// conf/conf.json; desktop installs can also expose it under ~/.siyuan/.
	if base == "conf.json" && (strings.HasSuffix(dir, "/conf") || strings.HasSuffix(dir, "/.siyuan")) {
		return FormatSiYuanConfig
	}

	// OpenClaw Dashboard ships as a standalone index.html. Keep path routing
	// bounded to canonical checkout/install directory names; content-level rules
	// additionally require product markers and the vulnerable data flow.
	lowerDir := strings.ToLower(dir)
	canonicalDashboardDir := false
	for _, component := range strings.Split(lowerDir, "/") {
		if component == "openclaw-dashboard" || component == "agent-dashboard" {
			canonicalDashboardDir = true
			break
		}
	}
	if strings.EqualFold(base, "index.html") && canonicalDashboardDir {
		return FormatOpenClawDashboardSource
	}

	// Skill files: anything under .claude/skills/ ending in .md.
	if strings.HasSuffix(path, ".md") && strings.Contains(path, "/.claude/skills/") {
		return FormatSkill
	}

	// Agent instruction docs.
	switch base {
	case "AGENTS.md", "CLAUDE.md", "CODEX.md", "GEMINI.md", ".cursorrules":
		return FormatAgentDoc
	}

	// GitHub Actions workflows.
	if strings.Contains(path, "/.github/workflows/") &&
		(strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
		return FormatGHAWorkflow
	}

	// Exact package-root/source files from bounded npm compromise campaigns.
	// node_modules stays skipped by default; the scanner walker has a matching
	// bounded exception that enqueues only these paths.
	if IsInjectiveWalletStealerArtifactPath(normalized) {
		return FormatNPMMalwareArtifact
	}
	for _, suffix := range []string{
		"/node_modules/jscrambler/dist/intro.js",
		"/node_modules/jscrambler/dist/setup.js",
		"/node_modules/jscrambler/dist/index.js",
		"/node_modules/jscrambler/dist/bin/jscrambler.js",
		"/node_modules/tslint-conf/index.js",
		"/node_modules/tslint-conf/lib/caller.js",
		"/node_modules/tslint-conf/lib/const.js",
	} {
		if strings.HasSuffix(normalized, suffix) {
			return FormatNPMMalwareArtifact
		}
	}
	if isMarketfrontCampaignPostinstallPath(normalized) {
		return FormatNPMMalwareArtifact
	}
	if IsAmazonInspectorNPMMalwareArtifactPath(normalized) {
		return FormatNPMMalwareArtifact
	}
	if IsAda8877SentryVerifyArtifactPath(normalized) {
		return FormatNPMMalwareArtifact
	}
	if IsApexCopilotMalwareArtifactPath(normalized) {
		return FormatNPMMalwareArtifact
	}
	if IsPygameRenderkitMalwareArtifactPath(normalized) {
		return FormatPyPIMalwareArtifact
	}
	if IsMLflowOtelSystemdHelperArtifactPath(normalized) {
		return FormatPyPIMalwareArtifact
	}
	if IsMultyproccessMalwareArtifactPath(normalized) {
		return FormatPyPIMalwareArtifact
	}
	if IsXYQDramaSkillArtifactPath(normalized) {
		return FormatPyPIMalwareArtifact
	}
	if IsMrMustardMalwareArtifactPath(normalized) {
		return FormatPyPIMalwareArtifact
	}
	if IsCfgzenMalwareArtifactPath(normalized) {
		return FormatPyPIMalwareArtifact
	}
	if IsScrambleeerMalwareArtifactPath(normalized) {
		return FormatPyPIMalwareArtifact
	}
	if IsTronixPyPIKeyExfilArtifactPath(normalized) {
		return FormatPyPIMalwareArtifact
	}
	if IsSpaysrbdataDiscordNVArtifactPath(normalized) {
		return FormatPyPIMalwareArtifact
	}
	if IsAsyncAPIMiasmaArtifactPath(normalized) {
		return FormatAsyncAPIMiasmaArtifact
	}
	if IsMiniShaiHuludOpenAPICodegenArtifactPath(normalized) {
		return FormatMiniShaiHuludArtifact
	}
	if strings.HasSuffix(normalized, "/apps/api/src/routes/auth.ts") ||
		strings.HasSuffix(normalized, "/apps/api/src/services/resolve-user.ts") {
		return FormatClawVetAuthSource
	}

	// Mini Shai-Hulud persistence artifacts that are not otherwise parsed by
	// Audr. GitHub Actions and Claude settings have dedicated formats above.
	if strings.HasSuffix(path, "/.vscode/tasks.json") ||
		strings.HasSuffix(path, "\\.vscode\\tasks.json") ||
		strings.HasSuffix(path, "/.vscode/setup.mjs") ||
		strings.HasSuffix(path, "\\.vscode\\setup.mjs") ||
		strings.HasSuffix(path, "/.claude/setup.mjs") ||
		strings.HasSuffix(path, "\\.claude\\setup.mjs") ||
		strings.HasSuffix(path, "/.claude/router_runtime.js") ||
		strings.HasSuffix(path, "\\.claude\\router_runtime.js") ||
		strings.HasSuffix(path, "/.claude/package/index.js") ||
		strings.HasSuffix(path, "\\.claude\\package\\index.js") ||
		strings.HasSuffix(path, "/.codex/package/index.js") ||
		strings.HasSuffix(path, "\\.codex\\package\\index.js") ||
		strings.HasSuffix(path, "/.local/share/kitty/cat.py") ||
		strings.HasSuffix(path, "\\.local\\share\\kitty\\cat.py") ||
		strings.HasSuffix(path, "/.local/bin/gh-token-monitor.sh") ||
		strings.HasSuffix(path, "\\.local\\bin\\gh-token-monitor.sh") ||
		strings.HasSuffix(path, "/var/tmp/.gh_update_state") ||
		strings.HasSuffix(path, "\\var\\tmp\\.gh_update_state") ||
		(base == "router_init.js" && strings.Contains(path, "node_modules")) ||
		(base == "tanstack_runner.js" && strings.Contains(path, "node_modules")) ||
		base == "gh-token-monitor.service" ||
		base == "com.user.gh-token-monitor.plist" ||
		base == "kitty-monitor.service" ||
		base == "com.user.kitty-monitor.plist" {
		return FormatMiniShaiHuludArtifact
	}

	// Shell rc.
	switch base {
	case ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile":
		return FormatShellRC
	}

	// PowerShell profile + history. Windows agent users land
	// settings here, and PSReadLine_history.txt is a known
	// secret-leak surface (commands the user typed at the prompt
	// land in plaintext). Same parser handles both; rules
	// distinguish by basename when they need to.
	switch base {
	case "Microsoft.PowerShell_profile.ps1",
		"Microsoft.VSCode_profile.ps1",
		"profile.ps1",
		"ConsoleHost_history.txt":
		return FormatPowerShellProfile
	}

	// Env files.
	if strings.HasPrefix(base, ".env") {
		return FormatEnv
	}

	// Package-manager/dependency-bot release-age cooldown configs.
	if base == "bunfig.toml" || base == ".npmrc" || base == "pnpm-workspace.yaml" ||
		base == ".yarnrc.yml" || base == "renovate.json" || base == "renovate.json5" ||
		(base == "dependabot.yml" && strings.Contains(path, "/.github/")) ||
		(base == "dependabot.yaml" && strings.Contains(path, "/.github/")) {
		return FormatReleaseAgeConfig
	}

	if base == "package.json" {
		return FormatPackageJSON
	}
	if base == "plugin.json" {
		return FormatAPMPluginManifest
	}
	lowerBase := strings.ToLower(base)
	ext := strings.ToLower(filepath.Ext(lowerBase))
	stem := strings.TrimSuffix(lowerBase, ext)
	if (ext == ".json" || ext == ".yaml" || ext == ".yml") &&
		(strings.Contains(stem, "openapi") || strings.Contains(stem, "swagger")) {
		return FormatKiotaOpenAPISpec
	}
	if isGitConfigPath(normalized, base, dir) {
		return FormatGitConfig
	}
	if base == ".tool-versions" {
		return FormatMiseToolVersions
	}
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		return FormatDockerfile
	}

	switch base {
	case "requirements.txt", "pyproject.toml", "go.mod", "Cargo.toml", "Gemfile", "composer.json", "pnpm-lock.yaml":
		return FormatDependencyManifest
	}

	return FormatUnknown
}

// IsMiniShaiHuludOpenAPICodegenArtifactPath bounds the August 2026
// @7nohe/openapi-react-query-codegen campaign variant to the exact package
// root files that carried or launched the payload. Package/version exposure
// remains delegated to OSV-Scanner.
func IsMiniShaiHuludOpenAPICodegenArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	marker := "/node_modules/"
	idx := strings.LastIndex(normalized, marker)
	if idx < 0 {
		return false
	}
	rel := normalized[idx+len(marker):]
	switch rel {
	case "@7nohe/openapi-react-query-codegen/3fwcvzduyzg.js",
		"@7nohe/openapi-react-query-codegen/binding.gyp",
		"@7nohe/openapi-react-query-codegen/package.json":
		return true
	default:
		return false
	}
}

func isMarketfrontCampaignPostinstallPath(path string) bool {
	if strings.HasSuffix(path, "/node_modules/@tqm-mfe/main/scripts/postinstall.js") {
		return true
	}
	marker := "/node_modules/@marketfront/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return false
	}
	parts := strings.Split(path[idx+len(marker):], "/")
	return len(parts) == 3 && parts[0] != "" && parts[1] == "scripts" && parts[2] == "postinstall.js"
}

// IsAmazonInspectorNPMMalwareArtifactPath bounds the July 2026 Amazon
// Inspector advisory backfill to exact package-root files carrying native IOCs.
// Package/version exposure remains delegated to OSV-Scanner.
func IsAmazonInspectorNPMMalwareArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	marker := "/node_modules/"
	idx := strings.LastIndex(normalized, marker)
	if idx < 0 {
		return false
	}
	rel := normalized[idx+len(marker):]
	credentialPackages := []string{
		"chalk-utils", "joi-pack", "rimraf-utils", "nock-helper",
		"glob-helper", "solc-helper", "ethers-common", "hardhat-core",
	}
	for _, packageName := range credentialPackages {
		if rel == packageName+"/postinstall.js" {
			return true
		}
	}
	switch rel {
	case "solc-helper/package.json",
		"sysbin/pointer.py",
		"env-threads/lib/main.js",
		"typography-stylecss/src/index.js",
		"hello-world-pkg-value-value-p/index.js",
		"streak-core-math/index.mjs",
		"streak-daily-lib/index.mjs",
		"streak-core-lib/index.mjs",
		"streak-day-utils/index.mjs",
		"api-node-sdk/test.js",
		"app-soda-layer/test.js",
		"sigchain-js/dist/sigchain-js.cjs.js",
		"sigchain-js/dist/sigchain-js.esm.js",
		"sigchain-js/dist/sigchain-js.umd.js",
		"chain-analyze/dist/sigchain-js.cjs.js",
		"chain-analyze/dist/sigchain-js.esm.js",
		"chain-analyze/dist/sigchain-js.umd.js",
		"react-puller/index.js",
		"claude-remote-agent/agent.js",
		"llm-interceptor/defaults.json",
		"map-streak-kit/dist/index.mjs",
		"map-streak-kit/dist/internal/calc-math.dat",
		"streak-map-kit/dist/index.mjs",
		"streak-map-kit/dist/internal/calc-mapping.bin",
		"kit-vim-map/dist/internal/calc-math.dat",
		"kit-map-vim/dist/index.mjs",
		"kit-map-vim/dist/internal/calc-math.dat",
		"dim-hydration-ui/dist/index.mjs",
		"dim-hydration-ui/dist/internal/math.bin",
		"w-screenctl/src/wscreenctl.mjs",
		"aclade-agent/dist/index.js",
		"agenthub-ai/dist-publish/main.js",
		"uibabai/index.js",
		"simple-date-formatter-new-9/package.json",
		"simple-date-formatter-new-9/postinstall.js",
		"simple-date-formatter-new-10/package.json",
		"simple-date-formatter-new-10/postinstall.js",
		"tokocrytodev/index.js",
		"cryptostock/index.js",
		"notafollower/package.json",
		"depcruise-wrap-stream-in-html/package.json",
		"pfp-forms-sme-loan/_bridge.js",
		"checkout-desktop-total/_platform.js",
		"core-tailwindcss-utility/index.js",
		"bcc-design/notify.js",
		"bcc-design-icons/notify.js",
		"setup-codex/lib/report.js",
		"expect-dotenv/lib/workers/plugin.worker.js",
		"@httttt/mcp-demo/dist/index.js",
		"mcp-dev-toolkit/c2_exfil.js",
		"express-session-handler/index.js",
		"chai-as-soul/lib/initializecaller.js",
		"chai-as-otc/lib/initializecaller.js",
		"chai-as-org/lib/initializecaller.js",
		"spotify-url-infos/index.js",
		"spotify-url-resolvers/index.js",
		"octopus-action/index.js",
		"mt-ts-serverless-starter/index.js",
		"@gfe/lx-watcher/install.js",
		"fuel-react/postinstall.js",
		"lumen-pages-community/dc.js",
		"@js-lib-team/env-parser/index.js",
		"conversa-sdk/postinstall.js",
		"grafeno-billing/preinstall.js",
		"grafeno-payments/preinstall.js",
		"grafeno-webhook/preinstall.js",
		"@guangnao/agent-proxy/dist/cli.js",
		"@yancyyu/agentcli/bin/hermit.mjs":
		return true
	default:
		return false
	}
}

// IsAda8877SentryVerifyArtifactPath bounds the ada8877 campaign payload to
// examples/verify.js under one of the five known dependency-confusion package
// roots. The final node_modules segment makes npm and pnpm layouts equivalent.
func IsAda8877SentryVerifyArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	marker := "/node_modules/"
	idx := strings.LastIndex(normalized, marker)
	if idx < 0 {
		return false
	}
	rel := normalized[idx+len(marker):]
	switch rel {
	case "syft-acp-atoms/examples/verify.js",
		"syft-acp-uikit/examples/verify.js",
		"syft-acp-core/examples/verify.js",
		"@edgecommons/streamlog-node/examples/verify.js",
		"@edgecommons/edgecommons/examples/verify.js":
		return true
	default:
		return false
	}
}

// IsApexCopilotMalwareArtifactPath recognizes only the package-root source,
// exact macOS persistence, and staging paths published for the July 2026
// @apexfdn/apex and @copilot-mcp/apex infostealer campaign.
func IsApexCopilotMalwareArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	if apexCopilotPackageArtifactRelativePath(normalized) != "" {
		return true
	}
	if normalized == "/tmp/osalogging.zip" {
		return true
	}
	return strings.HasSuffix(normalized, "/library/launchagents/com.system.notifications.agent.plist") ||
		strings.HasSuffix(normalized, "/library/application support/system/system notifications.app/contents/macos/system notifications")
}

func apexCopilotPackageArtifactRelativePath(path string) string {
	marker := "/node_modules/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return ""
	}
	rel := path[idx+len(marker):]
	for _, packagePath := range []string{"@apexfdn/apex/", "@copilot-mcp/apex/"} {
		if !strings.HasPrefix(rel, packagePath) {
			continue
		}
		leaf := strings.TrimPrefix(rel, packagePath)
		switch leaf {
		case "install.cjs", "loader.sh", "payload.enc":
			return leaf
		}
	}
	return ""
}

// IsMLflowOtelSystemdHelperArtifactPath bounds the August 2026
// mlflow-otel-instrumentor / cryptgraphy campaign to its two source
// distribution installers and exact temporary payload path. Installer content
// remains gated by the builtin rule before a finding is emitted.
func IsMLflowOtelSystemdHelperArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	if IsMLflowOtelSystemdHelperDropPath(normalized) {
		return true
	}
	if !strings.HasSuffix(normalized, "/setup.py") {
		return false
	}
	parent := filepath.Base(filepath.Dir(normalized))
	return parent == "mlflow-otel-instrumentor-1.1.0" || parent == "cryptgraphy-1.0.0"
}

// IsMLflowOtelSystemdHelperDropPath recognizes only the campaign's exact
// Linux/macOS temporary payload locations, not project-local lookalikes.
func IsMLflowOtelSystemdHelperDropPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return normalized == "/tmp/systemd-helper" || normalized == "/private/tmp/systemd-helper"
}

// IsMultyproccessMalwareArtifactPath bounds the August 2026 multyproccess
// infostealer campaign to setup.py files from the four known malicious source
// distributions. The builtin rule content-gates the installer behavior before
// emitting a finding; package/version exposure remains delegated to OSV.
func IsMultyproccessMalwareArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	leaf := filepath.Base(normalized)
	if leaf != "setup.py" && !strings.HasSuffix(normalized, "/request/.payload") {
		return false
	}
	packageDir := filepath.Dir(normalized)
	if leaf == ".payload" {
		packageDir = filepath.Dir(packageDir)
	}
	parent := filepath.Base(packageDir)
	switch parent {
	case "multyproccess-2.32.3", "multyproccess-2.32.4", "multyproccess-2.32.5", "multyproccess-2.32.6":
		return true
	default:
		return false
	}
}

// IsMultyproccessBundledPayloadPath identifies the campaign's exact bundled
// payload location under a known malicious source-distribution root.
func IsMultyproccessBundledPayloadPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return strings.HasSuffix(normalized, "/request/.payload") &&
		IsMultyproccessMalwareArtifactPath(normalized)
}

// IsXYQDramaSkillArtifactPath bounds the xyq-drama-skill malware surface to
// the campaign's exact hidden home-directory drop, package helper, and
// installer filename. setup.py is content-gated by the rule before a finding
// is emitted.
func IsXYQDramaSkillArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return IsXYQDramaSkillDropPath(normalized) ||
		strings.HasSuffix(normalized, "/xyq_drama_skill/_helper.py") ||
		strings.HasSuffix(normalized, "/setup.py")
}

// IsXYQDramaSkillDropPath recognizes the campaign's ~/.log-helper drop only at
// conventional Linux, macOS, and Windows home-directory locations. This avoids
// treating an unrelated project-local .log-helper file as critical malware.
func IsXYQDramaSkillDropPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	parts := strings.Split(strings.Trim(normalized, "/"), "/")
	if len(parts) < 2 || parts[len(parts)-1] != ".log-helper" {
		return false
	}
	if len(parts) == 2 && parts[0] == "root" {
		return true
	}
	if len(parts) == 3 && (parts[0] == "home" || parts[0] == "users") && parts[1] != "" {
		return true
	}
	return len(parts) == 4 && strings.HasSuffix(parts[0], ":") &&
		parts[1] == "users" && parts[2] != ""
}

// IsMrMustardMalwareArtifactPath recognizes only the package source,
// Python-startup launcher, and exact hidden payload path published for the
// July 2026 mrmustard 0.7.4 credential-stealer campaign. The source and .pth
// files are content-gated by the rule before a finding is emitted.
func IsMrMustardMalwareArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return IsMrMustardPayloadDropPath(normalized) ||
		strings.HasSuffix(normalized, "/mrmustard/__init__.py") ||
		strings.HasSuffix(normalized, "/site-packages/mmcompat.pth") ||
		strings.HasSuffix(normalized, "/dist-packages/mmcompat.pth")
}

// IsMrMustardPayloadDropPath bounds the compiled hw_probe.pyc payload to a
// conventional user home. Mounted home-directory backups are intentionally
// supported, so /home/<user>/ and /Users/<user>/ may occur below a scan root.
func IsMrMustardPayloadDropPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	const suffix = "/.cache/.tf_cache/hw_probe.pyc"
	if !strings.HasSuffix(normalized, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(normalized, suffix)
	if prefix == "/root" {
		return true
	}
	parts := strings.Split(strings.Trim(prefix, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if (parts[i] == "home" || parts[i] == "users") && parts[i+1] != "" {
			return i+2 == len(parts)
		}
	}
	return len(parts) == 3 && strings.HasSuffix(parts[0], ":") &&
		parts[1] == "users" && parts[2] != ""
}

// IsCfgzenMalwareArtifactPath recognizes the Python-startup and package-root
// surfaces published for the July 2026 cfgzen infostealer campaign. Generic
// .pth files are limited to Python package directories and all candidate files
// remain content- or hash-gated by the rule.
func IsCfgzenMalwareArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	if strings.HasSuffix(normalized, "/7t4wyu.bin") {
		return true
	}
	if strings.HasSuffix(normalized, ".pth") &&
		(strings.Contains(normalized, "/site-packages/") || strings.Contains(normalized, "/dist-packages/")) {
		return true
	}
	if strings.Contains(normalized, "/site-packages/cfgzen/") ||
		strings.Contains(normalized, "/dist-packages/cfgzen/") {
		return true
	}
	if !strings.Contains(normalized, "/cfgzen/") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(normalized))
	switch ext {
	case ".py", ".pyc", ".so", ".pyd", ".dll", ".dylib", ".c", ".cc", ".cpp", ".h", ".hpp", ".rs":
		return true
	default:
		return false
	}
}

// IsScrambleeerMalwareArtifactPath bounds the August 2026 scrambleeer /
// scrambleeeer reverse-shell campaign to the original package root and the
// exact three-e core.py source/install paths. Candidate files remain
// content-gated by the builtin rule.
func IsScrambleeerMalwareArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	ext := strings.ToLower(filepath.Ext(normalized))
	if (ext == ".py" || ext == ".pyc") &&
		(strings.HasSuffix(normalized, "/scrambleeer.py") || strings.Contains(normalized, "/scrambleeer/")) {
		return true
	}
	if ext != ".py" {
		return false
	}
	return strings.HasSuffix(normalized, "/src/scrambleeeer/core.py") ||
		strings.HasSuffix(normalized, "/site-packages/scrambleeeer/core.py") ||
		strings.HasSuffix(normalized, "/dist-packages/scrambleeeer/core.py")
}

var tronixPyPIPackageRoots = map[string]struct{}{
	"hexadec": {}, "hexadecpy": {}, "hexcon": {}, "hexdec": {},
	"hexdeci": {}, "hexdecimal": {}, "hexdecli": {}, "hexdeclink": {},
	"hexdecnet": {}, "hexdecpy": {}, "tronapinet": {}, "tronapipy": {},
	"troncloud": {}, "trondec": {}, "trongap": {}, "trongapy": {},
	"trongithpy": {}, "trongitpy": {}, "trongridapi": {}, "trongriden": {},
	"trongrider": {}, "trongridet": {}, "trongridev": {}, "trongridlib": {},
	"trongridme": {}, "trongridmy": {}, "trongridor": {}, "trongridperm": {},
	"trongridweb": {}, "trongridy": {}, "tronhap": {}, "tronhapy": {},
	"tronhex": {}, "tronhexpy": {}, "tronix": {}, "tronjoi": {},
	"tronkeep": {}, "tronkeeppy": {}, "tronkeypy": {}, "tronkeyspy": {},
	"tronlab": {}, "tronlabpy3": {}, "tronlast": {}, "tronlastpy": {},
	"tronlib": {}, "tronlibapi": {}, "tronlibpy": {}, "tronlid": {},
	"tronlinker": {}, "tronlinknet": {}, "tronlix": {}, "tronpad": {},
	"tronpak": {}, "tronpath": {}, "tronpropy": {}, "tronpyapi": {},
	"tronsev": {}, "tronwalletpy": {}, "tronwe": {}, "tronwebwpy": {},
	"trxone": {}, "trxtwo": {}, "wallettron": {}, "wallettronpy": {},
}

// IsTronixPyPIKeyExfilArtifactPath bounds the 2025-04 Tronix campaign to
// Python source or bytecode inside one of the 64 exact package roots published
// by kam193. The builtin rule additionally requires a campaign domain, wallet
// material collection, and outbound request behavior before emitting.
func IsTronixPyPIKeyExfilArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	ext := strings.ToLower(filepath.Ext(normalized))
	if ext != ".py" && ext != ".pyc" {
		return false
	}
	components := strings.FieldsFunc(strings.Trim(normalized, "/"), func(r rune) bool { return r == '/' })
	for i, component := range components {
		if component == "site-packages" || component == "dist-packages" {
			if i+1 >= len(components) {
				return false
			}
			installedRoot := strings.TrimSuffix(components[i+1], filepath.Ext(components[i+1]))
			_, ok := tronixPyPIPackageRoots[installedRoot]
			return ok
		}
		for packageName := range tronixPyPIPackageRoots {
			prefix := packageName + "-"
			if strings.HasPrefix(component, prefix) && isLikelyTronixPyPIPackageVersion(component[len(prefix):]) {
				return true
			}
		}
	}
	return false
}

func isLikelyTronixPyPIPackageVersion(version string) bool {
	if version == "" || version[0] < '0' || version[0] > '9' {
		return false
	}
	for _, char := range version {
		if (char >= '0' && char <= '9') ||
			(char >= 'a' && char <= 'z') ||
			char == '.' || char == '+' || char == '_' {
			continue
		}
		return false
	}
	return true
}

// IsSpaysrbdataDiscordNVArtifactPath bounds the 2026-06 spaysrbdata
// credential-stealer campaign to the two published discordnv 0.8.0 source
// files inside installed site-packages or dist-packages roots. The builtin rule
// additionally requires a published hash or multiple independent
// credential-theft, exfiltration, and persistence markers.
func IsSpaysrbdataDiscordNVArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	if !strings.HasSuffix(normalized, "/discordnv/__init__.py") &&
		!strings.HasSuffix(normalized, "/discordnv/main.py") {
		return false
	}
	return strings.Contains(normalized, "/site-packages/discordnv/") ||
		strings.Contains(normalized, "/dist-packages/discordnv/")
}

// IsPygameRenderkitMalwareArtifactPath bounds the August 2026
// pygame-renderkit / flask-header-guard campaign to exact source-distribution,
// installed-module, dropped-payload, and persistence paths. Every candidate
// remains content- or hash-gated by the builtin rule; package/version exposure
// remains delegated to OSV-Scanner.
func IsPygameRenderkitMalwareArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	if IsPygameRenderkitReconDropPath(normalized) ||
		IsPygameRenderkitSystemdPersistencePath(normalized) ||
		IsPygameRenderkitSudoersPersistencePath(normalized) ||
		IsFlaskHeaderGuardReconDropPath(normalized) ||
		IsFlaskHeaderGuardSudoersPersistencePath(normalized) ||
		IsFlaskHeaderGuardBackdoorPath(normalized) {
		return true
	}
	if !strings.HasSuffix(normalized, "/setup.py") {
		return false
	}
	parent := filepath.Base(filepath.Dir(normalized))
	return parent == "pygame-renderkit-1.2.0" || parent == "pygame_renderkit-1.2.0" ||
		parent == "flask-header-guard-1.0.0" || parent == "flask_header_guard-1.0.0"
}

// IsPygameRenderkitReconDropPath recognizes the campaign's exact temporary
// Python payload. A scan-root prefix is allowed so synthetic fixtures and
// mounted filesystem images retain the same suffix.
func IsPygameRenderkitReconDropPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return strings.HasSuffix(normalized, "/tmp/.rk_recon.py") ||
		strings.HasSuffix(normalized, "/private/tmp/.rk_recon.py")
}

// IsPygameRenderkitSystemdPersistencePath recognizes only the exact user-unit
// filename used by the campaign.
func IsPygameRenderkitSystemdPersistencePath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return strings.HasSuffix(normalized, "/.config/systemd/user/renderkit.service")
}

// IsPygameRenderkitSudoersPersistencePath recognizes only the exact sudoers
// drop used by the campaign.
func IsPygameRenderkitSudoersPersistencePath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return strings.HasSuffix(normalized, "/etc/sudoers.d/.renderkit")
}

// IsFlaskHeaderGuardReconDropPath recognizes the follow-up campaign package's
// exact temporary reverse-shell payload.
func IsFlaskHeaderGuardReconDropPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return strings.HasSuffix(normalized, "/tmp/.fhg_recon.py") ||
		strings.HasSuffix(normalized, "/private/tmp/.fhg_recon.py")
}

// IsFlaskHeaderGuardSudoersPersistencePath recognizes only the hidden sudoers
// file used by flask-header-guard 1.0.0.
func IsFlaskHeaderGuardSudoersPersistencePath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return strings.HasSuffix(normalized, "/etc/sudoers.d/.fhg")
}

// IsFlaskHeaderGuardBackdoorPath bounds source and installed-package checks to
// the exact malicious module path. Content or hash checks are still required.
func IsFlaskHeaderGuardBackdoorPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return strings.HasSuffix(normalized, "/flask_header_guard/backdoor.py")
}

// IsAsyncAPIMiasmaArtifactPath bounds the AsyncAPI Miasma campaign surface to
// exact compromised package files and the campaign's platform-specific drop.
func IsAsyncAPIMiasmaArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	for _, suffix := range []string{
		"/node_modules/@asyncapi/generator/lib/templates/config/validator.js",
		"/node_modules/@asyncapi/generator-helpers/src/utils.js",
		"/node_modules/@asyncapi/generator-components/src/utils/errorhandling.js",
		"/node_modules/@asyncapi/specs/index.js",
	} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return IsAsyncAPIMiasmaDropPath(normalized)
}

// IsAsyncAPIMiasmaDropPath recognizes the sync.js persistence locations used
// by the campaign without matching arbitrary NodeJS/sync.js files elsewhere.
func IsAsyncAPIMiasmaDropPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	return strings.HasSuffix(normalized, "/.local/share/nodejs/sync.js") ||
		strings.HasSuffix(normalized, "/library/application support/nodejs/sync.js") ||
		strings.HasSuffix(normalized, "/appdata/local/nodejs/sync.js")
}

// IsInjectiveWalletStealerArtifactPath bounds the Injective SDK wallet-stealer
// surface to the compromised source file and the two generated account bundles
// shipped in @injectivelabs/sdk-ts 1.20.21. The generated bundle hash suffix is
// intentionally variable so npm and pnpm layouts are both covered.
func IsInjectiveWalletStealerArtifactPath(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	if strings.HasSuffix(normalized, "/packages/sdk-ts/src/utils/key-derivation-telemetry.ts") {
		return true
	}
	marker := "/node_modules/@injectivelabs/sdk-ts/dist/"
	idx := strings.LastIndex(normalized, marker)
	if idx < 0 {
		return false
	}
	parts := strings.Split(normalized[idx+len(marker):], "/")
	if len(parts) != 2 || (parts[0] != "esm" && parts[0] != "cjs") {
		return false
	}
	return strings.HasPrefix(parts[1], "accounts-") &&
		(strings.HasSuffix(parts[1], ".js") || strings.HasSuffix(parts[1], ".cjs"))
}

func isGitConfigPath(path, base, dir string) bool {
	if base != "config" {
		return false
	}
	if strings.HasSuffix(path, "/.git/config") || strings.Contains(path, "/.git/modules/") {
		return true
	}
	if strings.HasSuffix(dir, ".git") {
		return true
	}
	return false
}
