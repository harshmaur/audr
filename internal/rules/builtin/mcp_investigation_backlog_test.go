package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

func TestMCPInvestigationBacklogRules_FlagVulnerableAndAllowFixed(t *testing.T) {
	tests := []struct {
		name       string
		ruleID     string
		pkg        string
		vulnerable string
		fixed      string
		manifest   string
		apply      func(*parse.Document) []finding.Finding
	}{
		{"mcp chat studio", "mcp-chat-studio-models-base-url-ssrf", "mcp-chat-studio", "1.5.0", "1.5.1", "package.json", func(d *parse.Document) []finding.Finding { return (mcpChatStudioModelsBaseURLSSRF{}).Apply(d) }},
		{"mcp url downloader", "mcp-url-downloader-validate-url-safe-ssrf", "mcp-url-downloader", "0.1.0", "0.1.1", "pyproject.toml", func(d *parse.Document) []finding.Finding { return (mcpURLDownloaderValidateURLSafeSSRF{}).Apply(d) }},
		{"aider mcp server", "aider-mcp-server-relative-editable-files-command-injection", "aider-mcp-server", "0.1.0", "0.1.1", "pyproject.toml", func(d *parse.Document) []finding.Finding {
			return (aiderMCPServerRelativeEditableFilesCommandInjection{}).Apply(d)
		}},
		{"mcp data vis", "mcp-data-vis-web-scraper-ssrf", "mcp-data-vis", "1.0.0", "1.0.1", "package.json", func(d *parse.Document) []finding.Finding { return (mcpDataVisWebScraperSSRF{}).Apply(d) }},
		{"memory bank server", "cline-mcp-memory-bank-initialize-path-traversal", "memory-bank-server", "0.1.0", "0.1.1", "package.json", func(d *parse.Document) []finding.Finding {
			return (clineMCPMemoryBankInitializePathTraversal{}).Apply(d)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name+" vulnerable", func(t *testing.T) {
			doc := manifestDoc(tc.manifest, tc.pkg, tc.vulnerable)
			findings := tc.apply(doc)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].RuleID != tc.ruleID {
				t.Fatalf("rule id = %q, want %q", findings[0].RuleID, tc.ruleID)
			}
		})
		t.Run(tc.name+" fixed", func(t *testing.T) {
			doc := manifestDoc(tc.manifest, tc.pkg, tc.fixed)
			if findings := tc.apply(doc); len(findings) != 0 {
				t.Fatalf("got %d findings, want 0", len(findings))
			}
		})
	}
}

func manifestDoc(path, name, version string) *parse.Document {
	if path == "pyproject.toml" {
		return parse.Parse(path, []byte("[project]\nname = \""+name+"\"\nversion = \""+version+"\"\n"))
	}
	return parse.Parse(path, []byte(`{"name":"`+name+`","version":"`+version+`"}`))
}
