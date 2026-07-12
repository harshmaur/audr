package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/policy"
	_ "github.com/harshmaur/audr/internal/rules/builtin"
	"github.com/harshmaur/audr/internal/scan"
	"github.com/harshmaur/audr/internal/suppress"
)

const cursorEscapingSymlinkRuleID = "cursor-workspace-escaping-symlink-cve-2026-50549"

func TestScan_CursorReadableEscapingSymlinkDoesNotFire(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on many Windows hosts")
	}

	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(filepath.Join(workspace, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".cursor", "mcp.json"), []byte(`{"mcpServers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "go.mod"), []byte("module example.test/workspace\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "owned.txt")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workspace, "escape")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{tmp}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if hasFinding(res.Findings, cursorEscapingSymlinkRuleID) {
		t.Fatalf("readable outside symlink should not fire when canonicalization succeeds: %+v", res.Findings)
	}
}

func TestScan_CursorMissingEscapingSymlinkCVE202650549(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on many Windows hosts")
	}

	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".cursor", "mcp.json"), []byte(`{"mcpServers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "go.mod"), []byte("module example.test/workspace\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workspace, "escape")
	if err := os.Symlink(filepath.Join(tmp, "outside", "missing.txt"), link); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{tmp}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := requireFinding(t, res.Findings, cursorEscapingSymlinkRuleID)
	if f.Path != link {
		t.Fatalf("finding path = %q, want %q", f.Path, link)
	}
	for _, want := range []string{"vulnerable posture", "Cursor 3.0 or later"} {
		if !strings.Contains(f.Description, want) && !strings.Contains(f.SuggestedFix, want) {
			t.Fatalf("finding should frame %q honestly; description=%q fix=%q", want, f.Description, f.SuggestedFix)
		}
	}
}

func TestScan_CursorEscapingSymlinkRequiresCursorWorkspaceEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on many Windows hosts")
	}

	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	outside := filepath.Join(tmp, "outside")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "escape")); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{tmp}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if hasFinding(res.Findings, cursorEscapingSymlinkRuleID) {
		t.Fatalf("rule fired without .cursor/mcp.json or .cursorrules evidence: %+v", res.Findings)
	}
}

func TestScan_CursorEscapingSymlinkHonorsPolicySuppression(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on many Windows hosts")
	}

	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".cursorrules"), []byte("review project rules"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workspace, "escape")
	if err := os.Symlink(filepath.Join(tmp, "outside", "missing.txt"), link); err != nil {
		t.Fatal(err)
	}

	eff := policy.NewEffective(policy.Policy{
		Version: policy.PolicyVersion,
		Suppressions: []policy.Suppression{{
			Rule:   cursorEscapingSymlinkRuleID,
			Path:   link,
			Reason: "test suppression",
		}},
	}, testingNow())
	res, err := scan.Run(context.Background(), scan.Options{
		Roots:  []string{tmp},
		Policy: eff,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if hasFinding(res.Findings, cursorEscapingSymlinkRuleID) {
		t.Fatalf("policy suppression should silence structural finding: %+v", res.Findings)
	}
}

func TestScan_CursorEscapingSymlinkRelativeRootSuppression(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on many Windows hosts")
	}

	tmp := t.TempDir()
	t.Chdir(tmp)

	workspace := "workspace"
	if err := os.MkdirAll(filepath.Join(workspace, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".cursorrules"), []byte("review project rules"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(workspace, "escape")
	if err := os.Symlink(filepath.Join("..", "outside", "missing.txt"), link); err != nil {
		t.Fatal(err)
	}

	suppressions, err := suppress.Parse(strings.NewReader(cursorEscapingSymlinkRuleID + " " + filepath.ToSlash(link) + "\n"))
	if err != nil {
		t.Fatalf("parse suppression: %v", err)
	}
	res, err := scan.Run(context.Background(), scan.Options{
		Roots:    []string{workspace},
		Suppress: suppressions,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if hasFinding(res.Findings, cursorEscapingSymlinkRuleID) {
		t.Fatalf("relative-root .audrignore suppression should silence structural finding: %+v", res.Findings)
	}
	if res.Suppressed == 0 {
		t.Fatalf("expected suppression count to increase for relative path %q", link)
	}
}

func TestScan_CursorSymlinkInsideWorkspaceDoesNotFire(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated permissions on many Windows hosts")
	}

	tmp := t.TempDir()
	workspace := filepath.Join(tmp, "workspace")
	inside := filepath.Join(workspace, "inside")
	if err := os.MkdirAll(filepath.Join(workspace, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".cursorrules"), []byte("review project rules"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, filepath.Join(workspace, "inside-link")); err != nil {
		t.Fatal(err)
	}

	res, err := scan.Run(context.Background(), scan.Options{Roots: []string{tmp}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if hasFinding(res.Findings, cursorEscapingSymlinkRuleID) {
		t.Fatalf("inside-workspace symlink should not fire: %+v", res.Findings)
	}
}

func testingNow() time.Time {
	return time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
}

func requireFinding(t *testing.T, findings []finding.Finding, ruleID string) finding.Finding {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f
		}
	}
	t.Fatalf("missing finding %q; findings=%+v", ruleID, findings)
	return finding.Finding{}
}

func hasFinding(findings []finding.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}
