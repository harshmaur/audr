package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestPresentonMCPAuthBypassPackageManifest(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{
		"name": "presenton",
		"version": "0.8.7"
	}`))
	if !fired(doc, "presenton-mcp-auth-bypass") {
		t.Fatalf("expected Presenton package finding; rules fired: %v", applyRule(doc))
	}
}

func TestPresentonMCPAuthBypassDependencyManifest(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{
		"name": "workspace",
		"version": "1.0.0",
		"dependencies": { "presenton": "0.8.7" }
	}`))
	if !fired(doc, "presenton-mcp-auth-bypass") {
		t.Fatalf("expected Presenton dependency finding; rules fired: %v", applyRule(doc))
	}
}

func TestPresentonMCPAuthBypassFixedVersion(t *testing.T) {
	doc := parse.Parse("package.json", []byte(`{
		"name": "presenton",
		"version": "0.8.8-beta"
	}`))
	if fired(doc, "presenton-mcp-auth-bypass") {
		t.Fatalf("expected fixed Presenton version to be clean; rules fired: %v", applyRule(doc))
	}
}
