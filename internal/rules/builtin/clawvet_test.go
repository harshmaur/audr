package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

func TestClawVetHardcodedJWTSecretDetectsVulnerableAuthSource(t *testing.T) {
	doc := parse.Parse("/repo/apps/api/src/routes/auth.ts", []byte(`const JWT_SECRET = process.env.JWT_SECRET || "clawvet-dev-secret-change-me";`))
	if got := string(doc.Format); got != "clawvet-auth-source" {
		t.Fatalf("format = %q, want clawvet-auth-source", got)
	}
	if !fired(doc, "clawvet-hardcoded-jwt-secret") {
		t.Fatalf("expected ClawVet JWT rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestClawVetHardcodedJWTSecretDetectsVulnerableEnvDefault(t *testing.T) {
	doc := parse.Parse("/repo/.env.example", []byte("JWT_SECRET=clawvet-dev-secret-change-me\n"))
	if !fired(doc, "clawvet-hardcoded-jwt-secret") {
		t.Fatalf("expected ClawVet JWT rule to fire; rules fired: %v", applyRule(doc))
	}
}

func TestClawVetHardcodedJWTSecretIgnoresFixedAndUnrelatedArtifacts(t *testing.T) {
	tests := []struct {
		path string
		raw  string
	}{
		{"/repo/apps/api/src/routes/auth.ts", `const secret = process.env.JWT_SECRET; if (!secret) throw new Error("JWT_SECRET required");`},
		{"/repo/apps/api/src/services/resolve-user.ts", `const secret = process.env.JWT_SECRET; if (!secret) throw new Error("JWT_SECRET required");`},
		{"/repo/.env.example", "JWT_SECRET=operator-generated-secret\n"},
		{"/repo/packages/cli/package.json", `{"name":"clawvet","version":"0.7.4"}`},
		{"/repo/docs/auth.ts", `const JWT_SECRET = "clawvet-dev-secret-change-me";`},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			if fired(doc, "clawvet-hardcoded-jwt-secret") {
				t.Fatalf("did not expect ClawVet JWT rule for %s; rules fired: %v", tc.path, applyRule(doc))
			}
		})
	}
}

func TestClawVetHardcodedJWTSecretFindingDoesNotEchoSecret(t *testing.T) {
	doc := parse.Parse("/repo/apps/api/src/routes/auth.ts", []byte(`const JWT_SECRET = process.env.JWT_SECRET || "clawvet-dev-secret-change-me";`))
	for _, rule := range rules.All() {
		if rule.ID() != "clawvet-hardcoded-jwt-secret" {
			continue
		}
		findings := rule.Apply(doc)
		if len(findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(findings))
		}
		if findings[0].Match == "clawvet-dev-secret-change-me" {
			t.Fatal("finding Match echoed the hard-coded JWT value")
		}
		return
	}
	t.Fatal("clawvet-hardcoded-jwt-secret rule is not registered")
}
