package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestCodeRunnerMCPServerUnauthHTTP_FlagsVulnerableHTTPTransport(t *testing.T) {
	doc := parse.Parse(".mcp.json", []byte(`{
  "mcpServers": {
    "runner": {
      "command": "npx",
      "args": ["-y", "mcp-server-code-runner@0.1.8", "--transport", "http"]
    }
  }
}`))
	findings := (codeRunnerMCPServerUnauthHTTP{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "code-runner-mcp-unauth-http-rce" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestCodeRunnerMCPServerUnauthHTTP_AllowsStdioTransport(t *testing.T) {
	doc := parse.Parse(".mcp.json", []byte(`{
  "mcpServers": {
    "runner": {
      "command": "npx",
      "args": ["mcp-server-code-runner@0.1.8"]
    }
  }
}`))
	findings := (codeRunnerMCPServerUnauthHTTP{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestCodeRunnerMCPServerUnauthHTTP_FlagsGitHubPackageWithHTTPFlag(t *testing.T) {
	doc := parse.Parse("/test/.codex/config.toml", []byte(`
[mcp_servers.runner]
command = "npx"
args = ["github:formulahendry/mcp-server-code-runner", "--transport=http"]
`))
	findings := (codeRunnerMCPServerUnauthHTTP{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}
