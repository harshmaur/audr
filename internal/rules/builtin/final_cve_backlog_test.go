package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

func TestFinalCVEBacklogDependencyRules(t *testing.T) {
	tests := []struct {
		name       string
		ruleID     string
		path       string
		pkg        string
		vulnerable string
		fixed      string
		apply      func(*parse.Document) []finding.Finding
	}{
		{"anythingllm", "anythingllm-filesystem-rg-option-injection", "package.json", "anything-llm", "1.12.9", "1.13.0", func(d *parse.Document) []finding.Finding { return (anythingLLMFilesystemRGOptionInjection{}).Apply(d) }},
		{"mcpilot", "mcpilot-serverbaseurl-ssrf", "package.json", "mcpilot-client", "0.1.0", "0.1.1", func(d *parse.Document) []finding.Finding { return (mcpilotServerBaseURLSSRF{}).Apply(d) }},
		{"junoclaw raw", "junoclaw-plugin-shell-raw-blocklist-bypass", "Cargo.toml", "plugin-shell", "0.1.0", "0.1.1", func(d *parse.Document) []finding.Finding { return (junoClawPluginShellRawBlocklistBypass{}).Apply(d) }},
		{"junoclaw shc", "junoclaw-plugin-shell-sh-c-agent-command", "Cargo.toml", "plugin-shell", "0.1.0", "0.1.1", func(d *parse.Document) []finding.Finding { return (junoClawPluginShellShCAgentCommand{}).Apply(d) }},
		{"hermes", "hermes-agent-skills-guard-multiword-patterns", "pyproject.toml", "hermes-agent", "0.14.9", "0.15.0", func(d *parse.Document) []finding.Finding { return (hermesAgentSkillsGuardMultiwordPatterns{}).Apply(d) }},
		{"librechat", "librechat-api-keys-userid-idor", "package.json", "librechat", "0.7.6", "0.8.3", func(d *parse.Document) []finding.Finding { return (libreChatAPIKeysUserIDIDOR{}).Apply(d) }},
	}
	for _, tc := range tests {
		t.Run(tc.name+" vulnerable", func(t *testing.T) {
			doc := backlogManifestDoc(tc.path, tc.pkg, tc.vulnerable)
			findings := tc.apply(doc)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].RuleID != tc.ruleID {
				t.Fatalf("rule id = %q, want %q", findings[0].RuleID, tc.ruleID)
			}
		})
		t.Run(tc.name+" fixed", func(t *testing.T) {
			doc := backlogManifestDoc(tc.path, tc.pkg, tc.fixed)
			if findings := tc.apply(doc); len(findings) != 0 {
				t.Fatalf("got %d findings, want 0", len(findings))
			}
		})
	}
}

func TestAiderMCPWorkingDirEditableFilesCommandInjection(t *testing.T) {
	doc := parse.Parse(".mcp.json", []byte(`{"mcpServers":{"aider":{"command":"uvx","args":["--from","git+https://github.com/eiliyaabedini/aider-mcp","aider-mcp"]}}}`))
	findings := (aiderMCPWorkingDirEditableFilesCommandInjection{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "aider-mcp-working-dir-editable-files-command-injection" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}

	clean := parse.Parse(".mcp.json", []byte(`{"mcpServers":{"other":{"command":"uvx","args":["aider-mcp-server"]}}}`))
	if findings := (aiderMCPWorkingDirEditableFilesCommandInjection{}).Apply(clean); len(findings) != 0 {
		t.Fatalf("got %d findings for non-matching source, want 0", len(findings))
	}
}

func TestAerostackMCPWhatsAppMediaURLSSRF(t *testing.T) {
	rule := aerostackMCPWhatsAppMediaURLSSRF{}
	doc := parse.Parse(".mcp.json", []byte(`{"mcpServers":{"whatsapp":{"command":"uvx","args":["--from","git+https://github.com/aerostackdev/aerostack-mcp@6315dfde7df0a15aaf743f88d91347115e09ba23","mcp-whatsapp"]}}}`))
	findings := rule.Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "aerostack-mcp-whatsapp-media-url-ssrf" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}

	clean := parse.Parse(".mcp.json", []byte(`{"mcpServers":{"whatsapp":{"command":"uvx","args":["mcp-whatsapp"]}}}`))
	if findings := rule.Apply(clean); len(findings) != 0 {
		t.Fatalf("got %d findings for unidentifiable package source, want 0", len(findings))
	}
}

func TestAngularLanguageServiceTrustedMarkdownCommandURI(t *testing.T) {
	rule := angularLanguageServiceTrustedMarkdownCommandURI{}
	doc := parse.Parse("/home/u/.vscode/extensions/angular.ng-template-21.2.3/package.json", []byte(`{
		"name": "ng-template",
		"displayName": "Angular Language Service",
		"publisher": "Angular",
		"version": "21.2.3"
	}`))
	findings := rule.Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].RuleID != "angular-language-service-trusted-markdown-command-uri" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}

	fixed := parse.Parse("/home/u/.vscode/extensions/angular.ng-template-21.2.4/package.json", []byte(`{
		"name": "ng-template",
		"displayName": "Angular Language Service",
		"publisher": "Angular",
		"version": "21.2.4"
	}`))
	if findings := rule.Apply(fixed); len(findings) != 0 {
		t.Fatalf("got %d findings for fixed extension, want 0", len(findings))
	}

	unrelated := parse.Parse("/repo/package.json", []byte(`{"name":"ng-template","version":"21.2.3"}`))
	if findings := rule.Apply(unrelated); len(findings) != 0 {
		t.Fatalf("got %d findings for unrelated package, want 0", len(findings))
	}
}

func backlogManifestDoc(path, name, version string) *parse.Document {
	switch path {
	case "pyproject.toml":
		return parse.Parse(path, []byte("[project]\nname = \""+name+"\"\nversion = \""+version+"\"\n"))
	case "Cargo.toml":
		return parse.Parse(path, []byte("[package]\nname = \""+name+"\"\nversion = \""+version+"\"\n"))
	default:
		return parse.Parse(path, []byte(`{"name":"`+name+`","version":"`+version+`"}`))
	}
}
