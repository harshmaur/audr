package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

func TestMCPPackageCVEs_FlagVulnerablePackageAndAllowFixed(t *testing.T) {
	tests := []struct {
		name       string
		ruleID     string
		pkg        string
		vulnerable string
		fixed      string
		apply      func(*parse.Document) []finding.Finding
	}{
		{"xhs mcp", "xhs-mcp-media-paths-ssrf", "xhs-mcp", "0.8.11", "0.8.12", func(d *parse.Document) []finding.Finding { return (xhsMCPMediaPathsSSRF{}).Apply(d) }},
		{"directus mcp", "directus-mcp-fileurl-ssrf", "directus-mcp", "1.0.0", "1.0.1", func(d *parse.Document) []finding.Finding { return (directusMCPFileURLSSRF{}).Apply(d) }},
		{"cloudbase mcp", "cloudbase-mcp-openurl-ssrf", "@cloudbase/cloudbase-mcp", "2.17.0", "2.17.1", func(d *parse.Document) []finding.Finding { return (cloudbaseMCPOpenURLSSRF{}).Apply(d) }},
		{"librechat secret response", "librechat-mcp-admin-secret-response-leak", "librechat", "0.8.3", "0.8.4", func(d *parse.Document) []finding.Finding { return (libreChatMCPAdminSecretResponseLeak{}).Apply(d) }},
	}

	for _, tc := range tests {
		t.Run(tc.name+" vulnerable", func(t *testing.T) {
			doc := parse.Parse("package.json", []byte(`{"dependencies":{"`+tc.pkg+`":"`+tc.vulnerable+`"}}`))
			findings := tc.apply(doc)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].RuleID != tc.ruleID {
				t.Fatalf("rule id = %q, want %q", findings[0].RuleID, tc.ruleID)
			}
		})

		t.Run(tc.name+" fixed", func(t *testing.T) {
			doc := parse.Parse("package.json", []byte(`{"dependencies":{"`+tc.pkg+`":"`+tc.fixed+`"}}`))
			if findings := tc.apply(doc); len(findings) != 0 {
				t.Fatalf("got %d findings, want 0", len(findings))
			}
		})
	}
}
