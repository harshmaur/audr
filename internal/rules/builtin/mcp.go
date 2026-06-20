// Rules over the normalized MCP server model. Each rule returns
// parse.AllMCPFormats() so it fires across .mcp.json (Cursor, project),
// ~/.codex/config.toml, and ~/.codeium/windsurf/mcp_config.json. The
// per-format parsers populate the model via parse.NormalizeMCPServers.
package builtin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

// --- mcp-unpinned-npx ------------------------------------------------------

type mcpUnpinnedNPX struct{}

func (mcpUnpinnedNPX) ID() string                 { return "mcp-unpinned-npx" }
func (mcpUnpinnedNPX) Title() string              { return "MCP server uses unpinned npx" }
func (mcpUnpinnedNPX) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpUnpinnedNPX) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (mcpUnpinnedNPX) Formats() []parse.Format    { return parse.AllMCPFormats() }
func (mcpUnpinnedNPX) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Command != "npx" {
			continue
		}
		// Look at args[0] (skipping "-y" / "--yes" / other flags) for an `@version` suffix.
		pkg := ""
		for _, a := range s.Args {
			if a == "-y" || a == "--yes" || strings.HasPrefix(a, "-") {
				continue
			}
			pkg = a
			break
		}
		if pkg == "" {
			continue
		}
		// Pinning rules:
		//   "name"                       -> unpinned (no @)
		//   "name@1.2.3"                 -> pinned (1 @, not at start)
		//   "@scope/name"                -> unpinned (scope only, no version)
		//   "@scope/name@1.2.3"          -> pinned (2 @s, starts with @)
		ats := strings.Count(pkg, "@")
		isPinned := false
		if !strings.HasPrefix(pkg, "@") && ats >= 1 {
			isPinned = true
		} else if strings.HasPrefix(pkg, "@") && ats >= 2 {
			isPinned = true
		}
		if isPinned {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "mcp-unpinned-npx",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxEnforced,
			Title:        "MCP server launched via unpinned npx",
			Description:  fmt.Sprintf("Server %q (in %s) runs `%s %s` without a pinned package version. The package can change between runs, exposing the agent to supply-chain risk.", s.Name, s.Source, s.Command, strings.Join(s.Args, " ")),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Pin the package version, e.g. `\"args\": [\"-y\", \"" + pkg + "@1.2.3\"]`.",
			Tags:         []string{"mcp", "supply-chain"},
		}))
	}
	return out
}

// --- mcp-prod-secret-env --------------------------------------------------

type mcpProdSecretEnv struct{}

func (mcpProdSecretEnv) ID() string                 { return "mcp-prod-secret-env" }
func (mcpProdSecretEnv) Title() string              { return "MCP server receives production secret env" }
func (mcpProdSecretEnv) Severity() finding.Severity { return finding.SeverityCritical }
func (mcpProdSecretEnv) Taxonomy() finding.Taxonomy { return finding.TaxEnforced }
func (mcpProdSecretEnv) Formats() []parse.Format    { return []parse.Format{parse.FormatMCPConfig} }

var prodEnvPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^PROD_`),
	regexp.MustCompile(`(?i)_PROD_`),
	regexp.MustCompile(`(?i)_PROD$`),
	regexp.MustCompile(`(?i)^AWS_PROD_`),
	regexp.MustCompile(`(?i)^STRIPE_LIVE_`),
	regexp.MustCompile(`(?i)_LIVE_`),
	regexp.MustCompile(`(?i)^PRODUCTION_`),
}

func (mcpProdSecretEnv) Apply(doc *parse.Document) []finding.Finding {
	if doc.MCPConfig == nil {
		return nil
	}
	var out []finding.Finding
	for _, s := range doc.MCPConfig.Servers {
		for k := range s.Env {
			for _, pat := range prodEnvPatterns {
				if pat.MatchString(k) {
					out = append(out, finding.New(finding.Args{
						RuleID:       "mcp-prod-secret-env",
						Severity:     finding.SeverityCritical,
						Taxonomy:     finding.TaxEnforced,
						Title:        "Production secret exposed to MCP server",
						Description:  fmt.Sprintf("Server %q receives env var %q whose name suggests a production credential. Agents with broad capability surface should never receive prod credentials.", s.Name, k),
						Path:         doc.Path,
						Line:         s.Line,
						Match:        fmt.Sprintf("%s=%s", k, s.Env[k]),
						SuggestedFix: "Use a read-only staging variant of the credential, or remove the env injection if the server doesn't need it.",
						Tags:         []string{"mcp", "secrets", "prod"},
					}))
					break
				}
			}
		}
	}
	return out
}

// --- mcp-shell-pipeline-command -------------------------------------------

type mcpShellPipelineCommand struct{}

func (mcpShellPipelineCommand) ID() string                 { return "mcp-shell-pipeline-command" }
func (mcpShellPipelineCommand) Title() string              { return "MCP server uses shell pipeline as command" }
func (mcpShellPipelineCommand) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpShellPipelineCommand) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpShellPipelineCommand) Formats() []parse.Format    { return []parse.Format{parse.FormatMCPConfig} }
func (mcpShellPipelineCommand) Apply(doc *parse.Document) []finding.Finding {
	if doc.MCPConfig == nil {
		return nil
	}
	var out []finding.Finding
	for _, s := range doc.MCPConfig.Servers {
		joined := strings.ToLower(s.Command + " " + strings.Join(s.Args, " "))
		hit := false
		switch {
		case strings.Contains(s.Command, "bash") && containsAny(s.Args, "-c"):
			hit = true
		case strings.Contains(s.Command, "sh") && containsAny(s.Args, "-c"):
			hit = true
		case strings.Contains(joined, "|"):
			hit = true
		case strings.Contains(joined, "&&"), strings.Contains(joined, "||"):
			hit = true
		}
		if !hit {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "mcp-shell-pipeline-command",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "MCP server launched via shell pipeline",
			Description:  fmt.Sprintf("Server %q is launched through `bash -c` or a shell pipeline. This widens attack surface (arbitrary command injection) and bypasses argument-level review.", s.Name),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Invoke the server binary directly with explicit args. Avoid `bash -c` indirection.",
			Tags:         []string{"mcp", "shell", "injection"},
		}))
	}
	return out
}

// --- mcp-plaintext-api-key -------------------------------------------------

type mcpPlaintextAPIKey struct{}

func (mcpPlaintextAPIKey) ID() string                 { return "mcp-plaintext-api-key" }
func (mcpPlaintextAPIKey) Title() string              { return "MCP server has plaintext API key" }
func (mcpPlaintextAPIKey) Severity() finding.Severity { return finding.SeverityCritical }
func (mcpPlaintextAPIKey) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpPlaintextAPIKey) Formats() []parse.Format    { return parse.AllMCPFormats() }

func (mcpPlaintextAPIKey) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		// Check both Env (process env) and Headers (remote auth headers).
		// Codex uses Headers; Cursor/Windsurf historically used Env, but
		// modern Windsurf also uses Headers. The risk shape is identical.
		emit := func(loc, k, v string) {
			out = append(out, finding.New(finding.Args{
				RuleID:       "mcp-plaintext-api-key",
				Severity:     finding.SeverityCritical,
				Taxonomy:     finding.TaxDetectable,
				Title:        fmt.Sprintf("Plaintext API key in MCP server %s", loc),
				Description:  fmt.Sprintf("Server %q (in %s) has %s key %q whose value matches a known credential pattern. Plaintext credentials in version-controllable config files are a common breach vector.", s.Name, s.Source, loc, k),
				Path:         doc.Path,
				Line:         s.Line,
				Match:        fmt.Sprintf("%s=%s", k, v),
				SuggestedFix: "Reference the credential via a secret manager (e.g. `${KEYCHAIN:foo}`) or environment variable that's set at runtime, not in the JSON/TOML.",
				Tags:         []string{"mcp", "secrets"},
			}))
		}
		for k, v := range s.Env {
			if matchesCredential(k, v) {
				emit("env", k, v)
			}
		}
		for k, v := range s.Headers {
			if matchesCredential(k, v) {
				emit("headers", k, v)
			}
		}
	}
	return out
}

// --- mcp-dynamic-config-injection ------------------------------------------

type mcpDynamicConfigInjection struct{}

func (mcpDynamicConfigInjection) ID() string                 { return "mcp-dynamic-config-injection" }
func (mcpDynamicConfigInjection) Title() string              { return "MCP config fetched from URL at runtime" }
func (mcpDynamicConfigInjection) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpDynamicConfigInjection) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpDynamicConfigInjection) Formats() []parse.Format {
	return []parse.Format{parse.FormatMCPConfig}
}
func (mcpDynamicConfigInjection) Apply(doc *parse.Document) []finding.Finding {
	if doc.MCPConfig == nil {
		return nil
	}
	var out []finding.Finding
	for _, s := range doc.MCPConfig.Servers {
		joined := s.Command + " " + strings.Join(s.Args, " ")
		if !strings.Contains(joined, "curl ") && !strings.Contains(joined, "wget ") {
			continue
		}
		// Heuristic: command runs `curl URL | sh` or similar.
		if strings.Contains(joined, "|") || strings.Contains(joined, "$(") {
			out = append(out, finding.New(finding.Args{
				RuleID:       "mcp-dynamic-config-injection",
				Severity:     finding.SeverityHigh,
				Taxonomy:     finding.TaxDetectable,
				Title:        "MCP server loads code from network at runtime",
				Description:  fmt.Sprintf("Server %q's command pipes a network fetch into the shell, meaning every launch may execute different code than was reviewed.", s.Name),
				Path:         doc.Path,
				Line:         s.Line,
				Match:        joined,
				SuggestedFix: "Pin the upstream artifact (commit SHA, signed tag, or vendored copy) and verify before launching.",
				Tags:         []string{"mcp", "supply-chain"},
			}))
		}
	}
	return out
}

// --- mcp-unauth-remote-url -------------------------------------------------

type mcpUnauthRemoteURL struct{}

func (mcpUnauthRemoteURL) ID() string                 { return "mcp-unauth-remote-url" }
func (mcpUnauthRemoteURL) Title() string              { return "MCP server uses remote URL without auth headers" }
func (mcpUnauthRemoteURL) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpUnauthRemoteURL) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpUnauthRemoteURL) Formats() []parse.Format    { return parse.AllMCPFormats() }

// authHeaderNames are header keys that, if present, satisfy the "auth was
// configured" check. Case-insensitive prefix match.
var authHeaderNames = []string{
	"authorization",
	"x-api-key",
	"x-auth-token",
	"x-access-token",
	"api-key",
	"token",
	"bearer",
	"cookie",
}

func hasAuthHeader(headers map[string]string) bool {
	for k := range headers {
		lk := strings.ToLower(k)
		for _, prefix := range authHeaderNames {
			if strings.HasPrefix(lk, prefix) {
				return true
			}
		}
		// Anything ending in _api_key, _token, etc. also counts. Reuse the
		// credentialNameSuffix matcher (it already encodes "this name looks
		// like an auth credential").
		if credentialNameSuffix.MatchString(k) {
			return true
		}
	}
	return false
}

func (mcpUnauthRemoteURL) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		// Only applies to remote (URL-based) servers.
		if s.URL == "" {
			continue
		}
		// Skip localhost / 127.0.0.1 — local-only, different threat model.
		// 0.0.0.0 binding is its own (deferred) rule.
		lu := strings.ToLower(s.URL)
		if strings.Contains(lu, "://localhost") ||
			strings.Contains(lu, "://127.0.0.1") ||
			strings.Contains(lu, "://[::1]") {
			continue
		}
		if hasAuthHeader(s.Headers) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:   "mcp-unauth-remote-url",
			Severity: finding.SeverityHigh,
			Taxonomy: finding.TaxDetectable,
			Title:    "MCP server points at remote URL without auth headers",
			Description: fmt.Sprintf(
				"Server %q (in %s) connects to %s with no Authorization, X-API-Key, or other auth-shaped header. Any party who controls the upstream service or sits on-path between the agent and the URL can act as the server, returning attacker-controlled tool definitions and tool outputs.",
				s.Name, s.Source, s.URL,
			),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        s.URL,
			SuggestedFix: "Add an Authorization or X-API-Key header (sourced from a secret manager). If the upstream really has no auth, switch to a server that supports OAuth 2.1 or self-host inside your network.",
			Tags:         []string{"mcp", "remote", "auth"},
		}))
	}
	return out
}

// --- wireshark-mcp-export-objects-unbounded --------------------------------

type wiresharkMCPExportObjectsUnbounded struct{}

func (wiresharkMCPExportObjectsUnbounded) ID() string {
	return "wireshark-mcp-export-objects-unbounded"
}
func (wiresharkMCPExportObjectsUnbounded) Title() string {
	return "Wireshark MCP server can export objects outside an allowlisted directory"
}
func (wiresharkMCPExportObjectsUnbounded) Severity() finding.Severity { return finding.SeverityMedium }
func (wiresharkMCPExportObjectsUnbounded) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (wiresharkMCPExportObjectsUnbounded) Formats() []parse.Format    { return parse.AllMCPFormats() }

func (wiresharkMCPExportObjectsUnbounded) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Disabled || !looksLikeWiresharkMCPServer(s) {
			continue
		}
		if hasWiresharkMCPAllowedDirs(s) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "wireshark-mcp-export-objects-unbounded",
			Severity:     finding.SeverityMedium,
			Taxonomy:     finding.TaxDetectable,
			Title:        "Wireshark MCP server lacks WIRESHARK_MCP_ALLOWED_DIRS",
			Description:  fmt.Sprintf("CVE-2026-43901: server %q launches wireshark-mcp without WIRESHARK_MCP_ALLOWED_DIRS. wireshark-mcp 1.1.5 and earlier allowed the wireshark_export_objects tool to pass an attacker-controlled destination directory to tshark --export-objects when no allowlist was configured.", s.Name),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Upgrade wireshark-mcp beyond 1.1.5 and set WIRESHARK_MCP_ALLOWED_DIRS to the smallest export directory set required by your workflow, or remove the server from agent-accessible MCP configs.",
			Tags:         []string{"cve", "wireshark-mcp", "mcp", "arbitrary-file-write", "export-objects"},
		}))
	}
	return out
}

func looksLikeWiresharkMCPServer(s parse.NormalizedMCPServer) bool {
	joined := strings.ToLower(s.Name + " " + s.Command + " " + strings.Join(s.Args, " "))
	return strings.Contains(joined, "wireshark-mcp") || strings.Contains(joined, "wireshark_mcp")
}

func hasWiresharkMCPAllowedDirs(s parse.NormalizedMCPServer) bool {
	for k, v := range s.Env {
		if strings.EqualFold(k, "WIRESHARK_MCP_ALLOWED_DIRS") && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// --- nocturne-memory-missing-api-token -------------------------------------

type nocturneMemoryMissingAPIToken struct{}

func (nocturneMemoryMissingAPIToken) ID() string {
	return "nocturne-memory-missing-api-token"
}
func (nocturneMemoryMissingAPIToken) Title() string {
	return "Nocturne Memory MCP server is missing API_TOKEN"
}
func (nocturneMemoryMissingAPIToken) Severity() finding.Severity { return finding.SeverityHigh }
func (nocturneMemoryMissingAPIToken) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (nocturneMemoryMissingAPIToken) Formats() []parse.Format    { return parse.AllMCPFormats() }

func (nocturneMemoryMissingAPIToken) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Disabled || !looksLikeNocturneMemoryServer(s) || hasNocturneMemoryAPIToken(s) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "nocturne-memory-missing-api-token",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "Nocturne Memory MCP server lacks API_TOKEN",
			Description:  fmt.Sprintf("CVE-2026-44830: server %q launches Nocturne Memory without a non-empty API_TOKEN. Nocturne Memory before 2.4.1 bypassed bearer-token authentication when API_TOKEN was unset or empty, and common Docker/MCP setups could expose the memory API on LAN-reachable hosts.", s.Name),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Upgrade Nocturne Memory to 2.4.1 or later and set a strong API_TOKEN for the MCP/server process; avoid binding the memory API to 0.0.0.0 unless it is protected by network controls.",
			Tags:         []string{"cve", "nocturne-memory", "mcp", "missing-auth", "prompt-injection"},
		}))
	}
	return out
}

func looksLikeNocturneMemoryServer(s parse.NormalizedMCPServer) bool {
	joined := strings.ToLower(s.Name + " " + s.Command + " " + strings.Join(s.Args, " "))
	needles := []string{"nocturne-memory", "nocturne_memory", "nocturne memory"}
	for _, needle := range needles {
		if strings.Contains(joined, needle) {
			return true
		}
	}
	return false
}

func hasNocturneMemoryAPIToken(s parse.NormalizedMCPServer) bool {
	for k, v := range s.Env {
		if strings.EqualFold(k, "API_TOKEN") && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// --- mcp-server-kubernetes-tool-filter-bypass ------------------------------

type mcpServerKubernetesToolFilterBypass struct{}

func (mcpServerKubernetesToolFilterBypass) ID() string {
	return "mcp-server-kubernetes-tool-filter-bypass"
}
func (mcpServerKubernetesToolFilterBypass) Title() string {
	return "MCP Server Kubernetes relies on bypassable tool filters"
}
func (mcpServerKubernetesToolFilterBypass) Severity() finding.Severity { return finding.SeverityHigh }
func (mcpServerKubernetesToolFilterBypass) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpServerKubernetesToolFilterBypass) Formats() []parse.Format    { return parse.AllMCPFormats() }

func (mcpServerKubernetesToolFilterBypass) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Disabled || !looksLikeMCPServerKubernetes(s) {
			continue
		}
		control, value, ok := mcpServerKubernetesAccessControlEnv(s)
		if !ok {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "mcp-server-kubernetes-tool-filter-bypass",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "MCP Server Kubernetes tool filter can be bypassed",
			Description:  fmt.Sprintf("CVE-2026-46519: server %q launches mcp-server-kubernetes with %s set. Versions before 3.6.0 enforced ALLOW_ONLY_READONLY_TOOLS, ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS, and ALLOWED_TOOLS only in tools/list, so clients that knew a tool name could still invoke restricted tools directly through tools/call.", s.Name, control),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s=%s", control, value),
			SuggestedFix: "Upgrade mcp-server-kubernetes to 3.6.0 or later before relying on these tool restriction environment variables; also constrain Kubernetes RBAC for the kubeconfig used by the MCP server.",
			Tags:         []string{"cve", "mcp-server-kubernetes", "mcp", "kubernetes", "authorization-bypass"},
		}))
	}
	return out
}

func looksLikeMCPServerKubernetes(s parse.NormalizedMCPServer) bool {
	joined := strings.ToLower(s.Name + " " + s.Command + " " + strings.Join(s.Args, " "))
	needles := []string{"mcp-server-kubernetes", "mcp_server_kubernetes", "mcp server kubernetes"}
	for _, needle := range needles {
		if strings.Contains(joined, needle) {
			return true
		}
	}
	return false
}

func mcpServerKubernetesAccessControlEnv(s parse.NormalizedMCPServer) (string, string, bool) {
	controls := []string{"ALLOW_ONLY_READONLY_TOOLS", "ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS", "ALLOWED_TOOLS"}
	for _, control := range controls {
		for k, v := range s.Env {
			if strings.EqualFold(k, control) && strings.TrimSpace(v) != "" {
				return k, v, true
			}
		}
	}
	return "", "", false
}

// --- mcp-server-kubernetes-kubectl-flag-token-exfil ------------------------

type mcpServerKubernetesKubectlFlagTokenExfil struct{}
type mcpPinotUnauthHTTPDefault struct{}
type googleapisMCPToolboxLegacyProtocolScopeBypass struct{}

func (mcpServerKubernetesKubectlFlagTokenExfil) ID() string {
	return "mcp-server-kubernetes-kubectl-flag-token-exfil"
}
func (mcpServerKubernetesKubectlFlagTokenExfil) Title() string {
	return "MCP Server Kubernetes can pass unsafe kubectl flags"
}
func (mcpServerKubernetesKubectlFlagTokenExfil) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (mcpServerKubernetesKubectlFlagTokenExfil) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (mcpServerKubernetesKubectlFlagTokenExfil) Formats() []parse.Format {
	return parse.AllMCPFormats()
}

func (mcpServerKubernetesKubectlFlagTokenExfil) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Disabled || !looksLikeMCPServerKubernetes(s) {
			continue
		}
		pkg, version, ok := mcpServerKubernetesPackageSpec(s)
		if !ok || !vulnerableVersionBefore(version, []int{3, 7, 0}) {
			continue
		}
		if !mcpServerKubernetesUsesKubeconfig(s) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "mcp-server-kubernetes-kubectl-flag-token-exfil",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "MCP Server Kubernetes before 3.7.0 can exfiltrate kubeconfig tokens through kubectl flags",
			Description:  fmt.Sprintf("CVE-2026-47250: server %q invokes %s before 3.7.0 with a local kubeconfig posture. A prompt-injected agent can call kubectl_generic with attacker-controlled --server and --insecure-skip-tls-verify flags, causing kubectl to send the operator's bearer token to an attacker-controlled endpoint.", s.Name, pkg),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s@%s args=%q", pkg, version, strings.Join(s.Args, " ")),
			SuggestedFix: "Upgrade mcp-server-kubernetes to 3.7.0 or later. Until upgraded, remove the MCP server from agent configs or run it only with tightly scoped Kubernetes credentials that cannot read sensitive logs or access privileged cluster resources.",
			Tags:         []string{"cve", "mcp-server-kubernetes", "mcp", "kubernetes", "token-exfiltration", "argument-injection"},
		}))
	}
	return out
}

func mcpServerKubernetesPackageSpec(s parse.NormalizedMCPServer) (pkg string, version string, ok bool) {
	candidates := append([]string{s.Command}, s.Args...)
	for _, raw := range candidates {
		name, ver, matched := splitMCPServerKubernetesPackageSpec(raw)
		if matched {
			return name, ver, true
		}
	}
	return "", "", false
}

func splitMCPServerKubernetesPackageSpec(raw string) (pkg string, version string, ok bool) {
	s := strings.TrimSpace(strings.Trim(raw, "'\""))
	for strings.HasPrefix(s, "npm:") {
		s = strings.TrimPrefix(s, "npm:")
	}
	name := s
	ver := ""
	if i := strings.LastIndex(s, "@"); i > 0 {
		name = s[:i]
		ver = s[i+1:]
	}
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	if normalized == "mcp-server-kubernetes" {
		return normalized, ver, true
	}
	return "", "", false
}

func mcpServerKubernetesUsesKubeconfig(s parse.NormalizedMCPServer) bool {
	for k, v := range s.Env {
		if strings.EqualFold(k, "KUBECONFIG") && strings.TrimSpace(v) != "" {
			return true
		}
	}
	for i, arg := range s.Args {
		la := strings.ToLower(strings.TrimSpace(arg))
		if strings.HasPrefix(la, "--kubeconfig=") && strings.TrimSpace(strings.TrimPrefix(arg, "--kubeconfig=")) != "" {
			return true
		}
		if la == "--kubeconfig" && i+1 < len(s.Args) && strings.TrimSpace(s.Args[i+1]) != "" {
			return true
		}
	}
	return false
}

// --- mcp-pinot-unauth-http-default -----------------------------------------

func (mcpPinotUnauthHTTPDefault) ID() string { return "mcp-pinot-unauth-http-default" }
func (mcpPinotUnauthHTTPDefault) Title() string {
	return "mcp-pinot exposes unauthenticated HTTP defaults"
}
func (mcpPinotUnauthHTTPDefault) Severity() finding.Severity { return finding.SeverityCritical }
func (mcpPinotUnauthHTTPDefault) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (mcpPinotUnauthHTTPDefault) Formats() []parse.Format    { return parse.AllMCPFormats() }

func (mcpPinotUnauthHTTPDefault) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Disabled || !looksLikeMCPPinot(s) {
			continue
		}
		pkg, version, ok := mcpPinotPackageSpec(s)
		if !ok || !vulnerableVersionBefore(version, []int{3, 0, 2}) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "mcp-pinot-unauth-http-default",
			Severity:     finding.SeverityCritical,
			Taxonomy:     finding.TaxDetectable,
			Title:        "mcp-pinot 3.0.1 or earlier can expose an unauthenticated HTTP MCP server",
			Description:  fmt.Sprintf("CVE-2026-49257: server %q launches %s %s. mcp-pinot 3.0.1 and earlier defaulted to an unauthenticated HTTP server on 0.0.0.0:8080, exposing Apache Pinot operations to any client that can reach the MCP endpoint.", s.Name, pkg, version),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Upgrade mcp-pinot beyond 3.0.1 before exposing it to agents. Until upgraded, remove it from MCP configs or bind it only to loopback behind explicit authentication and network controls.",
			Tags:         []string{"cve", "mcp-pinot", "mcp", "apache-pinot", "missing-auth", "http-exposure"},
		}))
	}
	return out
}

func looksLikeMCPPinot(s parse.NormalizedMCPServer) bool {
	joined := strings.ToLower(s.Name + " " + s.Command + " " + strings.Join(s.Args, " "))
	return strings.Contains(joined, "mcp-pinot") || strings.Contains(joined, "mcp_pinot")
}

func mcpPinotPackageSpec(s parse.NormalizedMCPServer) (pkg string, version string, ok bool) {
	candidates := append([]string{s.Command}, s.Args...)
	for _, raw := range candidates {
		name, ver, matched := splitMCPPinotPackageSpec(raw)
		if matched {
			return name, ver, true
		}
	}
	return "", "", false
}

func splitMCPPinotPackageSpec(raw string) (pkg string, version string, ok bool) {
	s := strings.TrimSpace(strings.Trim(raw, "'\""))
	for strings.HasPrefix(s, "npm:") {
		s = strings.TrimPrefix(s, "npm:")
	}
	name := s
	ver := ""
	if strings.Contains(s, "==") {
		parts := strings.SplitN(s, "==", 2)
		name, ver = parts[0], parts[1]
	} else if i := strings.LastIndex(s, "@"); i > 0 {
		name, ver = s[:i], s[i+1:]
	}
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	if normalized == "mcp-pinot" {
		return normalized, ver, true
	}
	return "", "", false
}

// --- googleapis-mcp-toolbox-wildcard-origin-host ---------------------------

type googleapisMCPToolboxWildcardOriginHost struct{}

func (googleapisMCPToolboxWildcardOriginHost) ID() string {
	return "googleapis-mcp-toolbox-wildcard-origin-host"
}
func (googleapisMCPToolboxWildcardOriginHost) Title() string {
	return "Google APIs MCP Toolbox allows wildcard Origin or Host"
}
func (googleapisMCPToolboxWildcardOriginHost) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (googleapisMCPToolboxWildcardOriginHost) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (googleapisMCPToolboxWildcardOriginHost) Formats() []parse.Format { return parse.AllMCPFormats() }

func (googleapisMCPToolboxWildcardOriginHost) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Disabled || !looksLikeGoogleapisMCPToolbox(s) {
			continue
		}
		missing := googleapisMCPToolboxWildcardOrMissingControls(s)
		if len(missing) == 0 {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "googleapis-mcp-toolbox-wildcard-origin-host",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "Google APIs MCP Toolbox lacks strict Origin/Host allowlists",
			Description:  fmt.Sprintf("CVE-2026-11624: server %q launches Google APIs MCP Toolbox with %s. MCP Toolbox before v0.25.0 had no Host validation flag, and later releases default --allowed-hosts and --allowed-origins to '*', allowing DNS rebinding from a malicious browser page to control a local Toolbox MCP server.", s.Name, strings.Join(missing, " and ")),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Upgrade MCP Toolbox to v0.25.0 or later and launch it with strict --allowed-hosts and --allowed-origins values for the local hostnames/origins you actually use; avoid '*' or omitted allowlists for agent-accessible database tools.",
			Tags:         []string{"cve", "mcp-toolbox", "mcp", "dns-rebinding", "origin-validation", "host-validation"},
		}))
	}
	return out
}

func looksLikeGoogleapisMCPToolbox(s parse.NormalizedMCPServer) bool {
	joined := strings.ToLower(s.Name + " " + s.Command + " " + strings.Join(s.Args, " "))
	needles := []string{
		"@toolbox-sdk/server",
		"googleapis/mcp-toolbox",
		"googleapis/genai-toolbox",
		"mcp-toolbox",
		"genai-toolbox",
	}
	for _, needle := range needles {
		if strings.Contains(joined, needle) {
			return true
		}
	}
	if strings.EqualFold(s.Name, "toolbox") || strings.EqualFold(s.Name, "toolbox-postgres") || strings.EqualFold(s.Name, "toolbox-mysql") {
		return true
	}
	cmd := strings.Trim(strings.ToLower(s.Command), "'\"")
	return cmd == "toolbox" || strings.HasSuffix(cmd, "/toolbox") || cmd == "toolbox.exe"
}

// --- googleapis-mcp-toolbox-legacy-protocol-scope-bypass --------------------

func (googleapisMCPToolboxLegacyProtocolScopeBypass) ID() string {
	return "googleapis-mcp-toolbox-legacy-protocol-scope-bypass"
}
func (googleapisMCPToolboxLegacyProtocolScopeBypass) Title() string {
	return "Google APIs MCP Toolbox legacy protocol bypasses tool scopes"
}
func (googleapisMCPToolboxLegacyProtocolScopeBypass) Severity() finding.Severity {
	return finding.SeverityHigh
}
func (googleapisMCPToolboxLegacyProtocolScopeBypass) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (googleapisMCPToolboxLegacyProtocolScopeBypass) Formats() []parse.Format {
	return parse.AllMCPFormats()
}

func (googleapisMCPToolboxLegacyProtocolScopeBypass) Apply(doc *parse.Document) []finding.Finding {
	servers := parse.NormalizeMCPServers(doc)
	if len(servers) == 0 {
		return nil
	}
	var out []finding.Finding
	for _, s := range servers {
		if s.Disabled || !looksLikeGoogleapisMCPToolbox(s) {
			continue
		}
		pkg, version, ok := googleapisMCPToolboxPackageSpec(s)
		if !ok || !vulnerableVersionBefore(version, []int{1, 4, 0}) {
			continue
		}
		out = append(out, finding.New(finding.Args{
			RuleID:       "googleapis-mcp-toolbox-legacy-protocol-scope-bypass",
			Severity:     finding.SeverityHigh,
			Taxonomy:     finding.TaxDetectable,
			Title:        "MCP Toolbox before 1.4.0 can bypass per-tool scopes through legacy protocol handlers",
			Description:  fmt.Sprintf("CVE-2026-11719: server %q launches Google APIs MCP Toolbox package %s version %s. Versions before 1.4.0 did not enforce scopesRequired consistently across older MCP protocol handlers, so a low-privilege authenticated client could request or omit legacy MCP-Protocol-Version values and execute higher-privilege tools.", s.Name, pkg, version),
			Path:         doc.Path,
			Line:         s.Line,
			Match:        fmt.Sprintf("%s %s", s.Command, strings.Join(s.Args, " ")),
			SuggestedFix: "Upgrade MCP Toolbox to v1.4.0 or later and review exposed tool scopes for clients that could select older MCP protocol versions. Until upgraded, keep Toolbox bound to trusted local clients and avoid exposing admin tools to low-privilege tokens.",
			Tags:         []string{"cve", "mcp-toolbox", "mcp", "authorization-bypass", "scope-bypass"},
		}))
	}
	return out
}

func googleapisMCPToolboxPackageSpec(s parse.NormalizedMCPServer) (pkg string, version string, ok bool) {
	candidates := append([]string{s.Command}, s.Args...)
	for _, raw := range candidates {
		name, ver, matched := splitGoogleapisMCPToolboxPackageSpec(raw)
		if matched {
			return name, ver, true
		}
	}
	return "", "", false
}

func splitGoogleapisMCPToolboxPackageSpec(raw string) (pkg string, version string, ok bool) {
	s := strings.TrimSpace(strings.Trim(raw, "'\""))
	for strings.HasPrefix(s, "npm:") {
		s = strings.TrimPrefix(s, "npm:")
	}
	name := s
	ver := ""
	if i := strings.LastIndex(s, "@"); i > 0 {
		name = s[:i]
		ver = s[i+1:]
	}
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	switch normalized {
	case "@toolbox-sdk/server", "googleapis/mcp-toolbox", "googleapis/genai-toolbox", "mcp-toolbox", "genai-toolbox":
		return normalized, ver, true
	}
	return "", "", false
}

func googleapisMCPToolboxWildcardOrMissingControls(s parse.NormalizedMCPServer) []string {
	hosts, hasHosts := mcpFlagValue(s.Args, "--allowed-hosts")
	origins, hasOrigins := mcpFlagValue(s.Args, "--allowed-origins")
	var missing []string
	if !hasHosts || isWildcardList(hosts) {
		missing = append(missing, "missing or wildcard --allowed-hosts")
	}
	if !hasOrigins || isWildcardList(origins) {
		missing = append(missing, "missing or wildcard --allowed-origins")
	}
	return missing
}

func mcpFlagValue(args []string, flag string) (string, bool) {
	for i, raw := range args {
		arg := strings.TrimSpace(strings.Trim(raw, "'\""))
		if arg == flag {
			if i+1 < len(args) {
				return strings.TrimSpace(strings.Trim(args[i+1], "'\"")), true
			}
			return "", true
		}
		if strings.HasPrefix(arg, flag+"=") {
			return strings.TrimSpace(strings.TrimPrefix(arg, flag+"=")), true
		}
	}
	return "", false
}

func isWildcardList(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return true
	}
	for _, part := range strings.Split(trimmed, ",") {
		if strings.TrimSpace(part) == "*" {
			return true
		}
	}
	return false
}
