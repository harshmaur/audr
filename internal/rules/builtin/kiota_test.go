package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestKiotaOpenAPISpecFormat(t *testing.T) {
	tests := map[string]parse.Format{
		"/repo/openapi.yaml":           parse.FormatKiotaOpenAPISpec,
		"/repo/swagger.json":           parse.FormatKiotaOpenAPISpec,
		"/repo/petstore-openapi.yml":   parse.FormatKiotaOpenAPISpec,
		"/repo/unrelated/settings.yml": parse.FormatUnknown,
	}
	for path, want := range tests {
		if got := parse.DetectFormat(path); got != want {
			t.Fatalf("DetectFormat(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestKiotaPluginStaticTemplateTraversalDetectsAdaptiveCardPath(t *testing.T) {
	doc := parse.Parse("/repo/openapi.json", []byte(`{
		"openapi": "3.1.0",
		"paths": {
			"/pets": {"get": {"x-ai-adaptive-card": {
				"title": "Pet card",
				"data_path": "$.pet",
				"file": "../../../../etc/passwd"
			}}}
		}
	}`))

	findings := kiotaPluginStaticTemplateTraversal{}.Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %#v", len(findings), findings)
	}
	if findings[0].RuleID != "kiota-plugin-static-template-traversal" {
		t.Fatalf("RuleID = %q", findings[0].RuleID)
	}
	if findings[0].Line == 0 {
		t.Fatalf("expected source line: %#v", findings[0])
	}
}

func TestKiotaPluginStaticTemplateTraversalDetectsCapabilitiesURI(t *testing.T) {
	raw := []byte(`openapi: 3.0.0
paths:
  /pets:
    get:
      x-ai-capabilities:
        response_semantics:
          static_template:
            file: file:///etc/passwd
`)
	doc := parse.Parse("/repo/openapi.yaml", raw)
	findings := kiotaPluginStaticTemplateTraversal{}.Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %#v", len(findings), findings)
	}
}

func TestKiotaPluginStaticTemplateTraversalIgnoresSafeOrInactivePaths(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "safe relative capability template",
			raw:  `{"openapi":"3.1.0","x-ai-capabilities":{"response_semantics":{"static_template":{"file":"cards/pet.json"}}}}`,
		},
		{
			name: "adaptive card without title is not propagated",
			raw:  `{"openapi":"3.1.0","x-ai-adaptive-card":{"file":"../../etc/passwd"}}`,
		},
		{
			name: "not an OpenAPI description",
			raw:  `{"x-ai-capabilities":{"response_semantics":{"static_template":{"file":"../../etc/passwd"}}}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse("/repo/openapi.json", []byte(tc.raw))
			if findings := (kiotaPluginStaticTemplateTraversal{}).Apply(doc); len(findings) != 0 {
				t.Fatalf("findings = %#v, want none", findings)
			}
		})
	}
}

func TestKiotaStaticTemplatePathUnsafe(t *testing.T) {
	tests := map[string]bool{
		"cards/pet.json":                false,
		"../secrets/card.json":          true,
		"/etc/passwd":                   true,
		`C:\\Users\\alice\\secret.json`: true,
		`\Windows\secret.json`:          true,
		`\\\\server\\share\\card.json`:  true,
		"//attacker.test/card.json":     true,
		"https://attacker.test/x":       true,
	}
	for path, want := range tests {
		if got := kiotaStaticTemplatePathUnsafe(path); got != want {
			t.Errorf("kiotaStaticTemplatePathUnsafe(%q) = %v, want %v", path, got, want)
		}
	}
}
