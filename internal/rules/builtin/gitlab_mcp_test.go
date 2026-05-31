package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestGitlabMCPServerUnauthHTTP_FlagsVulnerableHTTPTransport(t *testing.T) {
	doc := parse.Parse(".mcp.json", []byte(`{
  "mcpServers": {
    "gitlab": {
      "command": "npx",
      "args": ["-y", "@yoda.digital/gitlab-mcp-server@0.5.9", "--transport", "http"],
      "env": {"GITLAB_PERSONAL_ACCESS_TOKEN": "${GITLAB_PERSONAL_ACCESS_TOKEN}"}
    }
  }
}`))
	findings := (gitlabMCPServerUnauthHTTP{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "gitlab-mcp-server-unauth-http" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
}

func TestGitlabMCPServerUnauthHTTP_AllowsFixedVersion(t *testing.T) {
	doc := parse.Parse(".mcp.json", []byte(`{
  "mcpServers": {
    "gitlab": {
      "command": "npx",
      "args": ["@yoda.digital/gitlab-mcp-server@0.6.0", "--transport=http"]
    }
  }
}`))
	findings := (gitlabMCPServerUnauthHTTP{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}

func TestGitlabMCPServerUnauthHTTP_AllowsStdioTransport(t *testing.T) {
	doc := parse.Parse(".mcp.json", []byte(`{
  "mcpServers": {
    "gitlab": {
      "command": "npx",
      "args": ["@yoda.digital/gitlab-mcp-server@0.5.9"]
    }
  }
}`))
	findings := (gitlabMCPServerUnauthHTTP{}).Apply(doc)
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}
}
