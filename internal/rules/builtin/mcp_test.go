package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

// --- mcp-unpinned-npx ------------------------------------------------------

func TestRule_MCPUnpinnedNPX(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantFires int
	}{
		{
			name:      "unpinned npx triggers",
			raw:       `{"mcpServers":{"foo":{"command":"npx","args":["@modelcontextprotocol/server-foo"]}}}`,
			wantFires: 1,
		},
		{
			name:      "pinned @version does not trigger",
			raw:       `{"mcpServers":{"foo":{"command":"npx","args":["@modelcontextprotocol/server-foo@1.2.3"]}}}`,
			wantFires: 0,
		},
		{
			name:      "non-npx command does not trigger",
			raw:       `{"mcpServers":{"foo":{"command":"node","args":["server.js"]}}}`,
			wantFires: 0,
		},
		{
			name:      "npx with -y flag and pinned version OK",
			raw:       `{"mcpServers":{"foo":{"command":"npx","args":["-y","my-pkg@2.0.0"]}}}`,
			wantFires: 0,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			doc := parse.Parse("/test/.mcp.json", []byte(tt.raw))
			fires := 0
			for _, id := range applyRule(doc) {
				if id == "mcp-unpinned-npx" {
					fires++
				}
			}
			if fires != tt.wantFires {
				t.Errorf("got %d fires, want %d", fires, tt.wantFires)
			}
		})
	}
}

// Generalized: same rule fires across .mcp.json, Codex TOML, Windsurf JSON
// via the normalized MCP model.
func TestRule_MCPUnpinnedNPX_GeneralizedAcrossSources(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor .mcp.json with unpinned npx (existing v0.1 behavior)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"foo":{"command":"npx","args":["@modelcontextprotocol/server-foo"]}}}`,
			want: true,
		},
		{
			name: "Codex TOML with @latest (counts as pinned per existing rule semantics)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.playwright]` + "\n" + `command = "npx"` + "\n" + `args = ["@playwright/mcp@latest"]`,
			want: false,
		},
		{
			name: "Codex TOML with truly unpinned package",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.foo]` + "\n" + `command = "npx"` + "\n" + `args = ["server-foo"]`,
			want: true,
		},
		{
			name: "Windsurf JSON with unpinned npx (Mac scan: mastra/sequential-thinking)",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"mastra":{"command":"npx","args":["-y","@mastra/mcp-docs-server"]}}}`,
			want: true,
		},
		{
			name: "Windsurf JSON with pinned package",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"foo":{"command":"npx","args":["-y","pkg@2.0.0"]}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "mcp-unpinned-npx"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- mcp-prod-secret-env --------------------------------------------------

func TestRule_MCPProdSecretEnv(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantFires int
	}{
		{
			name:      "PROD_ env var fires",
			raw:       `{"mcpServers":{"foo":{"command":"x","env":{"PROD_DB_URL":"postgres://..."}}}}`,
			wantFires: 1,
		},
		{
			name:      "STRIPE_LIVE_ env var fires",
			raw:       `{"mcpServers":{"foo":{"command":"x","env":{"STRIPE_LIVE_KEY":"sk_live_xxx"}}}}`,
			wantFires: 1,
		},
		{
			name:      "staging env does not fire",
			raw:       `{"mcpServers":{"foo":{"command":"x","env":{"STAGING_DB_URL":"postgres://..."}}}}`,
			wantFires: 0,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			doc := parse.Parse("/test/.mcp.json", []byte(tt.raw))
			fires := 0
			for _, id := range applyRule(doc) {
				if id == "mcp-prod-secret-env" {
					fires++
				}
			}
			if fires != tt.wantFires {
				t.Errorf("got %d fires, want %d", fires, tt.wantFires)
			}
		})
	}
}

// --- mcp-plaintext-api-key (existing) -------------------------------------

func TestRule_MCPPlaintextAPIKey(t *testing.T) {
	doc := parse.Parse("/test/.mcp.json", []byte(`{"mcpServers":{"github":{"command":"x","env":{"GITHUB_TOKEN":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}`))
	fires := 0
	var fr []string
	for _, id := range applyRule(doc) {
		if id == "mcp-plaintext-api-key" {
			fires++
		}
		fr = append(fr, id)
	}
	if fires == 0 {
		t.Errorf("plaintext github token should fire; rules fired: %v", fr)
	}

	// Verify redaction in finding output.
	for _, r := range rules.All() {
		if r.ID() != "mcp-plaintext-api-key" {
			continue
		}
		findings := r.Apply(doc)
		for _, f := range findings {
			if strings.Contains(f.Match, "ghp_aaa") {
				t.Errorf("finding match leaked secret: %q", f.Match)
			}
		}
	}
}

// alpha.1 → alpha.3 transition: codex-mcp-plaintext-header-key was removed,
// the generalized mcp-plaintext-api-key now covers Codex headers too.
func TestRule_MCPPlaintextAPIKey_CodexHeaders(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want bool
	}{
		{
			name: "ctx7sk- prefix in header (Mac scan case)",
			toml: `[mcp_servers.context7]` + "\n" +
				`url = "https://mcp.context7.com/mcp"` + "\n" +
				`[mcp_servers.context7.http_headers]` + "\n" +
				`CONTEXT7_API_KEY = "ctx7sk-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"`,
			want: true,
		},
		{
			name: "github token in header (well-known prefix)",
			toml: `[mcp_servers.gh.http_headers]` + "\n" +
				`Authorization = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`,
			want: true,
		},
		{
			name: "no headers at all",
			toml: `[mcp_servers.simple]` + "\n" + `url = "https://example.com"`,
			want: false,
		},
		{
			name: "header value too short to be a credential",
			toml: `[mcp_servers.s.http_headers]` + "\n" + `X-Foo = "bar"`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse("/u/.codex/config.toml", []byte(c.toml))
			if got := fired(doc, "mcp-plaintext-api-key"); got != c.want {
				t.Errorf("fired = %v, want %v (full apply: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// alpha.3 generalization: same rule fires on Codex + Windsurf headers.
func TestRule_MCPPlaintextAPIKey_GeneralizedAcrossSources(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor .mcp.json env (existing v0.1 behavior)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"gh":{"command":"node","env":{"GITHUB_TOKEN":"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}`,
			want: true,
		},
		{
			name: "Codex headers (subsumes deleted codex-mcp-plaintext-header-key)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.context7.http_headers]` + "\n" + `CONTEXT7_API_KEY = "ctx7sk-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"`,
			want: true,
		},
		{
			name: "Windsurf headers (Mac scan case)",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"context7":{"serverUrl":"https://x.com","headers":{"CONTEXT7_API_KEY":"ctx7sk-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}}}}`,
			want: true,
		},
		{
			name: "Windsurf with no credentials",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"foo":{"url":"https://example.com"}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "mcp-plaintext-api-key"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- mcp-unauth-remote-url -------------------------------------------------

func TestRule_MCPUnauthRemoteURL(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor: GitLab URL with no headers (Mac scan case)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"GitLab":{"url":"https://gitlab.com/api/v4/mcp"}}}`,
			want: true,
		},
		{
			name: "Codex: GitLab URL with no headers (Mac scan case)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.GitLab]` + "\n" + `url = "https://gitlab.com/api/v4/mcp"`,
			want: true,
		},
		{
			name: "Windsurf: GitLab URL with no headers (Mac scan case)",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"GitLab":{"type":"http","url":"https://gitlab.com/api/v4/mcp"}}}`,
			want: true,
		},
		{
			name: "Codex: URL with auth header (safe)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.x]` + "\n" + `url = "https://example.com"` + "\n" +
				`[mcp_servers.x.http_headers]` + "\n" + `Authorization = "Bearer aaaaaaaaaaaaaaaaaaaa"`,
			want: false,
		},
		{
			name: "Windsurf: URL with X-API-Key (safe)",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"x":{"url":"https://example.com","headers":{"X-API-Key":"aaaaaaaaaaaaaaaaaaaa"}}}}`,
			want: false,
		},
		{
			name: "stdio server has no URL (rule does not apply)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"local":{"command":"node","args":["server.js"]}}}`,
			want: false,
		},
		{
			name: "localhost URL (different threat model — skip)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"dev":{"url":"http://localhost:3000/mcp"}}}`,
			want: false,
		},
		{
			name: "127.0.0.1 URL (skip)",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"dev":{"url":"http://127.0.0.1:8080/mcp"}}}`,
			want: false,
		},
		{
			name: "credential-name-suffix header counts as auth (CONTEXT7_API_KEY)",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.x]` + "\n" + `url = "https://example.com"` + "\n" +
				`[mcp_servers.x.http_headers]` + "\n" + `CONTEXT7_API_KEY = "ctx7sk-aaa"`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "mcp-unauth-remote-url"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- wireshark-mcp-export-objects-unbounded --------------------------------

func TestRule_WiresharkMCPExportObjectsUnbounded(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor uvx wireshark-mcp without allowed dirs fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"wireshark":{"command":"uvx","args":["wireshark-mcp"]}}}`,
			want: true,
		},
		{
			name: "allowlisted export dirs suppresses finding",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"wireshark":{"command":"uvx","args":["wireshark-mcp"],"env":{"WIRESHARK_MCP_ALLOWED_DIRS":"/tmp/pcap-exports"}}}}`,
			want: false,
		},
		{
			name: "Codex python module form fires",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.wireshark]` + "\n" + `command = "python"` + "\n" + `args = ["-m", "wireshark_mcp"]`,
			want: true,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"wireshark":{"command":"uvx","args":["wireshark-mcp"],"disabled":true}}}`,
			want: false,
		},
		{
			name: "unrelated MCP server does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"filesystem":{"command":"npx","args":["@modelcontextprotocol/server-filesystem@1.0.0"]}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "wireshark-mcp-export-objects-unbounded"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- nocturne-memory-missing-api-token -------------------------------------

func TestRule_NocturneMemoryMissingAPIToken(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor npx nocturne-memory without API_TOKEN fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"memory":{"command":"npx","args":["nocturne-memory@2.4.0"]}}}`,
			want: true,
		},
		{
			name: "empty API_TOKEN still fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"memory":{"command":"npx","args":["nocturne-memory@2.4.0"],"env":{"API_TOKEN":""}}}}`,
			want: true,
		},
		{
			name: "non-empty API_TOKEN suppresses finding",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"memory":{"command":"npx","args":["nocturne-memory@2.4.0"],"env":{"API_TOKEN":"set-from-secret-manager"}}}}`,
			want: false,
		},
		{
			name: "Codex python module form fires",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.nocturne]` + "\n" + `command = "python"` + "\n" + `args = ["-m", "nocturne_memory"]`,
			want: true,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"nocturne":{"command":"npx","args":["nocturne-memory"],"disabled":true}}}`,
			want: false,
		},
		{
			name: "unrelated memory server does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"memory":{"command":"npx","args":["@modelcontextprotocol/server-memory@1.0.0"]}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "nocturne-memory-missing-api-token"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- mcp-server-kubernetes-tool-filter-bypass ------------------------------

func TestRule_MCPServerKubernetesToolFilterBypass(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor npx mcp-server-kubernetes readonly filter fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes@3.5.9"],"env":{"ALLOW_ONLY_READONLY_TOOLS":"true"}}}}`,
			want: true,
		},
		{
			name: "ALLOWED_TOOLS filter fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes"],"env":{"ALLOWED_TOOLS":"pods_list,pods_get"}}}}`,
			want: true,
		},
		{
			name: "Kubernetes server without access-control env does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes@3.6.0"]}}}`,
			want: false,
		},
		{
			name: "empty access-control env does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes@3.5.9"],"env":{"ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS":""}}}}`,
			want: false,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes@3.5.9"],"env":{"ALLOW_ONLY_READONLY_TOOLS":"true"},"disabled":true}}}`,
			want: false,
		},
		{
			name: "unrelated Kubernetes MCP package does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["@modelcontextprotocol/server-kubernetes"],"env":{"ALLOW_ONLY_READONLY_TOOLS":"true"}}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "mcp-server-kubernetes-tool-filter-bypass"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- mcp-server-kubernetes-kubectl-flag-token-exfil ------------------------

func TestRule_MCPServerKubernetesKubectlFlagTokenExfil(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "vulnerable server with KUBECONFIG env fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes@3.6.9"],"env":{"KUBECONFIG":"/home/user/.kube/config"}}}}`,
			want: true,
		},
		{
			name: "vulnerable server with kubeconfig arg fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes@3.6.2","--kubeconfig","/home/user/.kube/admin.conf"]}}}`,
			want: true,
		},
		{
			name: "fixed version does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes@3.7.0"],"env":{"KUBECONFIG":"/home/user/.kube/config"}}}}`,
			want: false,
		},
		{
			name: "vulnerable version without kubeconfig posture does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes@3.6.9"]}}}`,
			want: false,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"kubernetes":{"command":"npx","args":["mcp-server-kubernetes@3.6.9"],"env":{"KUBECONFIG":"/home/user/.kube/config"},"disabled":true}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "mcp-server-kubernetes-kubectl-flag-token-exfil"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- line-desktop-mcp-unauth-http-mode -------------------------------------

func TestRule_LineDesktopMCPUnauthHTTPMode(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "vulnerable line-desktop-mcp HTTP mode fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"line":{"command":"npx","args":["line-desktop-mcp@1.1.1","--http-mode"]}}}`,
			want: true,
		},
		{
			name: "equals form HTTP mode fires",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.line]` + "\n" + `command = "npx"` + "\n" + `args = ["line-desktop-mcp@1.0.0", "--http-mode=true"]`,
			want: true,
		},
		{
			name: "fixed version does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"line":{"command":"npx","args":["line-desktop-mcp@1.1.2","--http-mode"]}}}`,
			want: false,
		},
		{
			name: "stdio mode does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"line":{"command":"npx","args":["line-desktop-mcp@1.1.1"]}}}`,
			want: false,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"line":{"command":"npx","args":["line-desktop-mcp@1.1.1","--http-mode"],"disabled":true}}}`,
			want: false,
		},
		{
			name: "unrelated package does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"line":{"command":"npx","args":["line-bot-mcp-server@1.1.1","--http-mode"]}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "line-desktop-mcp-unauth-http-mode"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- windows-mcp-unauth-http-cors ------------------------------------------

func TestRule_WindowsMCPUnauthHTTPCORS(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "uvx vulnerable Windows-MCP HTTP transport with wildcard CORS fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"windows":{"command":"uvx","args":["windows-mcp==0.7.4","--transport","http","--allow_origins","*"]}}}`,
			want: true,
		},
		{
			name: "at-version package form and equals flags fire",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.windows]` + "\n" + `command = "uvx"` + "\n" + `args = ["windows-mcp@0.7.4", "--transport=streamable-http", "--cors-origin=*"]`,
			want: true,
		},
		{
			name: "wildcard CORS env fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"windows":{"command":"uvx","args":["windows-mcp==0.7.4","--http"],"env":{"ALLOW_ORIGINS":"*"}}}}`,
			want: true,
		},
		{
			name: "fixed version does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"windows":{"command":"uvx","args":["windows-mcp==0.7.5","--transport","http","--allow_origins","*"]}}}`,
			want: false,
		},
		{
			name: "strict CORS origin does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"windows":{"command":"uvx","args":["windows-mcp==0.7.4","--transport","http","--allow_origins","http://127.0.0.1:6274"]}}}`,
			want: false,
		},
		{
			name: "stdio mode does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"windows":{"command":"uvx","args":["windows-mcp==0.7.4","--allow_origins","*"]}}}`,
			want: false,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"windows":{"command":"uvx","args":["windows-mcp==0.7.4","--transport","http","--allow_origins","*"],"disabled":true}}}`,
			want: false,
		},
		{
			name: "unrelated windows package does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"windows":{"command":"uvx","args":["windows-utils==0.7.4","--transport","http","--allow_origins","*"]}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "windows-mcp-unauth-http-cors"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- network-ai-mcp-sse-empty-secret ---------------------------------------

func TestRule_NetworkAIMCPSSEEmptySecret(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "Cursor npx vulnerable Network-AI with no secret fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"network-ai":{"command":"npx","args":["network-ai@5.7.1","--transport","sse"]}}}`,
			want: true,
		},
		{
			name: "empty MCP secret still fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"network-ai":{"command":"npx","args":["network-ai@5.7.1"],"env":{"MCP_SECRET":""}}}}`,
			want: true,
		},
		{
			name: "fixed version does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"network-ai":{"command":"npx","args":["network-ai@5.7.2"]}}}`,
			want: false,
		},
		{
			name: "strong explicit secret suppresses finding",
			path: "/test/.codex/config.toml",
			body: `[mcp_servers.network_ai]` + "\n" + `command = "npx"` + "\n" + `args = ["network-ai@5.7.1"]` + "\n" + `[mcp_servers.network_ai.env]` + "\n" + `MCP_SECRET = "0123456789abcdef0123456789abcdef"`,
			want: false,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"network-ai":{"command":"npx","args":["network-ai@5.7.1"],"disabled":true}}}`,
			want: false,
		},
		{
			name: "unrelated package does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"other":{"command":"npx","args":["@modelcontextprotocol/server-memory@1.0.0"]}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "network-ai-mcp-sse-empty-secret"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- mcp-pinot-unauth-http-default -----------------------------------------

func TestRule_MCPPinotUnauthHTTPDefault(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "uvx vulnerable mcp-pinot version fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"pinot":{"command":"uvx","args":["mcp-pinot==3.0.1"]}}}`,
			want: true,
		},
		{
			name: "npx vulnerable mcp-pinot version fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"pinot":{"command":"npx","args":["mcp-pinot@3.0.0","--host","0.0.0.0","--port","8080"]}}}`,
			want: true,
		},
		{
			name: "fixed version does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"pinot":{"command":"uvx","args":["mcp-pinot==3.0.2"]}}}`,
			want: false,
		},
		{
			name: "unpinned package is handled by generic supply-chain rule only",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"pinot":{"command":"uvx","args":["mcp-pinot"]}}}`,
			want: false,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"pinot":{"command":"uvx","args":["mcp-pinot==3.0.1"],"disabled":true}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "mcp-pinot-unauth-http-default"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- googleapis-mcp-toolbox-wildcard-origin-host ---------------------------

func TestRule_GoogleapisMCPToolboxWildcardOriginHost(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "npx toolbox sdk without host or origin allowlists fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"toolbox-postgres":{"command":"npx","args":["@toolbox-sdk/server","--prebuilt","postgres"]}}}`,
			want: true,
		},
		{
			name: "binary toolbox with wildcard host fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"toolbox":{"command":"toolbox","args":["--config","tools.yaml","--allowed-hosts=*","--allowed-origins","http://127.0.0.1:6274"]}}}`,
			want: true,
		},
		{
			name: "strict host and origin allowlists suppress finding",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"toolbox":{"command":"toolbox","args":["--config","tools.yaml","--allowed-hosts=127.0.0.1:5000,localhost:5000","--allowed-origins","http://127.0.0.1:6274"]}}}`,
			want: false,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"toolbox":{"command":"npx","args":["@toolbox-sdk/server"],"disabled":true}}}`,
			want: false,
		},
		{
			name: "unrelated generic toolbox name does not fire unless command matches",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"utilities":{"command":"python","args":["-m","toolbox_helpers"]}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "googleapis-mcp-toolbox-wildcard-origin-host"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}

// --- googleapis-mcp-toolbox-legacy-protocol-scope-bypass --------------------

func TestRule_GoogleapisMCPToolboxLegacyProtocolScopeBypass(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want bool
	}{
		{
			name: "npx vulnerable toolbox sdk version fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"toolbox-postgres":{"command":"npx","args":["@toolbox-sdk/server@1.3.0","--prebuilt","postgres"]}}}`,
			want: true,
		},
		{
			name: "github package coordinate before fixed release fires",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"toolbox":{"command":"npx","args":["googleapis/mcp-toolbox@1.3.0","--config","tools.yaml"]}}}`,
			want: true,
		},
		{
			name: "fixed toolbox sdk version does not fire",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"toolbox-postgres":{"command":"npx","args":["@toolbox-sdk/server@1.4.0","--prebuilt","postgres"]}}}`,
			want: false,
		},
		{
			name: "unpinned toolbox is handled by generic supply-chain and origin rules only",
			path: "/test/.cursor/mcp.json",
			body: `{"mcpServers":{"toolbox-postgres":{"command":"npx","args":["@toolbox-sdk/server","--prebuilt","postgres"]}}}`,
			want: false,
		},
		{
			name: "disabled Windsurf server is ignored",
			path: "/test/.codeium/windsurf/mcp_config.json",
			body: `{"mcpServers":{"toolbox":{"command":"npx","args":["@toolbox-sdk/server@1.3.0"],"disabled":true}}}`,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := parse.Parse(c.path, []byte(c.body))
			if got := fired(doc, "googleapis-mcp-toolbox-legacy-protocol-scope-bypass"); got != c.want {
				t.Errorf("fired = %v, want %v (rules: %v)", got, c.want, applyRule(doc))
			}
		})
	}
}
