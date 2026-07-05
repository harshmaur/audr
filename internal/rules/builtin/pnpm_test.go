package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestPNPMLockfileMissingIntegrity(t *testing.T) {
	raw := []byte(`lockfileVersion: '9.0'

packages:
  left-pad@1.3.0:
    resolution:
      tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz

snapshots: {}
`)
	doc := parse.Parse("/repo/pnpm-lock.yaml", raw)
	findings := (pnpmLockfileMissingIntegrity{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].RuleID != "pnpm-lockfile-missing-integrity" {
		t.Fatalf("RuleID = %q", findings[0].RuleID)
	}
	if findings[0].Line != 5 {
		t.Fatalf("Line = %d, want 5", findings[0].Line)
	}
}

func TestPNPMLockfileMissingIntegrityInlineTarball(t *testing.T) {
	raw := []byte(`lockfileVersion: '9.0'

packages:
  left-pad@1.3.0:
    resolution: {tarball: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
`)
	doc := parse.Parse("/repo/pnpm-lock.yaml", raw)
	if findings := (pnpmLockfileMissingIntegrity{}).Apply(doc); len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
}

func TestPNPMLockfileMissingIntegrityIgnoresIntegrity(t *testing.T) {
	doc := parse.Parse("/repo/pnpm-lock.yaml", []byte(`lockfileVersion: '9.0'

packages:
  left-pad@1.3.0:
    resolution:
      tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz
      integrity: sha512-abc
`))
	if fired(doc, "pnpm-lockfile-missing-integrity") {
		t.Fatal("did not expect integrity-present lockfile to fire")
	}
}

func TestPNPMUnscopedAuthTokenRegistryForwarding(t *testing.T) {
	doc := parse.Parse("/repo/.npmrc", []byte("registry=https://registry.attacker.example/\n_authToken=secret-token\n"))
	if !fired(doc, "pnpm-unscoped-auth-token-registry-forwarding") {
		t.Fatalf("expected pnpm unscoped token registry-forwarding rule to fire; rules fired: %v", applyRule(doc))
	}
	findings := (pnpmUnscopedAuthTokenRegistryForwarding{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("direct rule findings = %d, want 1", len(findings))
	}
	if findings[0].Match != "_authToken=<redacted>" {
		t.Fatalf("token match was not redacted: %q", findings[0].Match)
	}
}

func TestPNPMUnscopedAuthTokenRequiresRegistry(t *testing.T) {
	doc := parse.Parse("/repo/.npmrc", []byte("_authToken=secret-token\n"))
	if fired(doc, "pnpm-unscoped-auth-token-registry-forwarding") {
		t.Fatalf("did not expect unscoped token without registry override to fire; rules fired: %v", applyRule(doc))
	}
}

func TestPNPMScopedAuthTokenRegistryForwardingIgnored(t *testing.T) {
	doc := parse.Parse("/repo/.npmrc", []byte("registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=secret-token\n"))
	if fired(doc, "pnpm-unscoped-auth-token-registry-forwarding") {
		t.Fatalf("did not expect scoped registry token to fire; rules fired: %v", applyRule(doc))
	}
}

func TestPNPMLockfileRuleIgnoresOtherManifests(t *testing.T) {
	raw := []byte(`packages:
  left-pad@1.3.0:
    resolution: {tarball: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
`)
	doc := parse.Parse("/repo/package-lock.json", raw)
	if findings := (pnpmLockfileMissingIntegrity{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
	}
}
