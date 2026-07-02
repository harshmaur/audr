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

func TestPNPMLockfileWithIntegrityIsClean(t *testing.T) {
	raw := []byte(`lockfileVersion: '9.0'

packages:
  left-pad@1.3.0:
    resolution:
      tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz
      integrity: sha512-deadbeef
`)
	doc := parse.Parse("/repo/pnpm-lock.yaml", raw)
	if findings := (pnpmLockfileMissingIntegrity{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(findings))
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
