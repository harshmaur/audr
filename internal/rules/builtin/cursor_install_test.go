package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestCursorAgentSandboxWorkingDirectoryEscape_VulnerableAppManifest(t *testing.T) {
	doc := parse.Parse("/Applications/Cursor.app/Contents/Resources/app/package.json", []byte(`{"name":"cursor","version":"2.5.0"}`))
	findings := (cursorAgentSandboxWorkingDirectoryEscape{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].RuleID != "cursor-agent-sandbox-working-directory-escape" {
		t.Fatalf("rule id = %q", findings[0].RuleID)
	}
	if findings[0].Line != 1 {
		t.Fatalf("line = %d, want 1", findings[0].Line)
	}
}

func TestCursorAgentSandboxWorkingDirectoryEscape_FixedAppManifest(t *testing.T) {
	doc := parse.Parse("/usr/share/cursor/resources/app/package.json", []byte(`{"name":"cursor","version":"3.0.0"}`))
	if findings := (cursorAgentSandboxWorkingDirectoryEscape{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("fixed Cursor manifest produced findings: %+v", findings)
	}
}

func TestCursorAgentSandboxWorkingDirectoryEscape_IgnoresUnrelatedNPMPackage(t *testing.T) {
	doc := parse.Parse("/workspace/package.json", []byte(`{"name":"cursor","version":"2.5.0"}`))
	if findings := (cursorAgentSandboxWorkingDirectoryEscape{}).Apply(doc); len(findings) != 0 {
		t.Fatalf("unrelated npm package produced findings: %+v", findings)
	}
}
