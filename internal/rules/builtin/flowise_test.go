package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestFlowiseCustomMCPMissingAuthEmptyPassword(t *testing.T) {
	doc := parse.Parse("/repo/.env", []byte("FLOWISE_USERNAME=admin\nFLOWISE_PASSWORD=\n"))
	if !fired(doc, "flowise-custom-mcp-missing-auth") {
		t.Fatalf("expected Flowise missing auth rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestFlowiseCustomMCPMissingAuthEmptyUsername(t *testing.T) {
	doc := parse.Parse("/repo/.env.local", []byte("FLOWISE_USERNAME=\nFLOWISE_PASSWORD=super-secret\n"))
	if !fired(doc, "flowise-custom-mcp-missing-auth") {
		t.Fatalf("expected Flowise missing auth rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestFlowiseCustomMCPMissingAuthNonEmptyCredentials(t *testing.T) {
	doc := parse.Parse("/repo/.env", []byte("FLOWISE_USERNAME=admin\nFLOWISE_PASSWORD=super-secret\n"))
	if fired(doc, "flowise-custom-mcp-missing-auth") {
		t.Fatalf("did not expect Flowise missing auth rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestFlowiseCustomMCPMissingAuthIgnoresGenericEnv(t *testing.T) {
	doc := parse.Parse("/repo/.env", []byte("USERNAME=\nPASSWORD=\n"))
	if fired(doc, "flowise-custom-mcp-missing-auth") {
		t.Fatalf("did not expect generic env blanks to fire Flowise rule; rules fired: %v", applyRule(doc))
	}
}
