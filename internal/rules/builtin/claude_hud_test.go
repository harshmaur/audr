package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestRule_ClaudeHUDComspecCommandInjectionPackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"claude-hud":"0.0.12"}}`))
	if !fired(doc, "claude-hud-comspec-command-injection") {
		t.Fatalf("expected Claude HUD COMSPEC rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestRule_ClaudeHUDComspecCommandInjectionScopedPackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"devDependencies":{"@anthropic-ai/claude-hud":"^0.0.12"}}`))
	if !fired(doc, "claude-hud-comspec-command-injection") {
		t.Fatalf("expected Claude HUD COMSPEC rule to fire for scoped package; rules fired: %v", applyRule(doc))
	}
}

func TestRule_ClaudeHUDComspecCommandInjectionFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"claude-hud":"0.0.13"}}`))
	if fired(doc, "claude-hud-comspec-command-injection") {
		t.Fatalf("did not expect fixed Claude HUD version to fire; rules fired: %v", applyRule(doc))
	}
}

func TestRule_ClaudeHUDOSC8TerminalInjectionPackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"claude-hud":"0.0.12"}}`))
	if !fired(doc, "claude-hud-osc8-terminal-injection") {
		t.Fatalf("expected Claude HUD OSC 8 rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestRule_ClaudeHUDOSC8TerminalInjectionScopedPackage(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"devDependencies":{"@claude-hud/cli":"~0.0.12"}}`))
	if !fired(doc, "claude-hud-osc8-terminal-injection") {
		t.Fatalf("expected Claude HUD OSC 8 rule to fire for scoped package; rules fired: %v", applyRule(doc))
	}
}

func TestRule_ClaudeHUDOSC8TerminalInjectionFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{"dependencies":{"claude-hud":"0.0.13"}}`))
	if fired(doc, "claude-hud-osc8-terminal-injection") {
		t.Fatalf("did not expect fixed Claude HUD version to fire; rules fired: %v", applyRule(doc))
	}
}
