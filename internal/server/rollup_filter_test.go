package server

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/harshmaur/audr/internal/daemon"
	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/state"
)

// projectFilterTestServer seeds three findings: two in
// projects/audr (one critical, one high) and one in
// projects/billing (high). Same DedupGroupKey across all three so
// they roll up to ONE row spanning two projects — the exact shape D6
// describes.
func projectFilterTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	p := daemon.Paths{State: filepath.Join(dir, "state"), Logs: filepath.Join(dir, "logs")}
	if err := p.Ensure(); err != nil {
		t.Fatalf("ensure paths: %v", err)
	}
	store, err := state.Open(state.Options{Path: filepath.Join(p.State, "audr.db")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel() })
	go func() { _ = store.Run(ctx) }()
	time.Sleep(5 * time.Millisecond)
	t.Cleanup(func() { _ = store.Close() })

	scanID, err := store.OpenScan("all")
	if err != nil {
		t.Fatal(err)
	}

	upsert := func(fp, severity, projID, projLabel string) {
		if _, err := store.UpsertFinding(state.Finding{
			Fingerprint:   fp,
			RuleID:        "osv-npm-package",
			Severity:      severity,
			Category:      "deps",
			Kind:          "dep-package",
			Locator:       []byte(`{"path":"` + projID + `/package-lock.json"}`),
			Title:         "vuln",
			Description:   "d",
			DedupGroupKey: "osv:npm:next:15.0.4:",
			FixAuthority:  "you",
			ProjectID:     projID,
			ProjectLabel:  projLabel,
			ProjectClass:  "code-project",
			FirstSeenScan: scanID,
			LastSeenScan:  scanID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	upsert("fp-audr-1", finding.SeverityCritical.String(), "/home/u/projects/audr", "audr")
	upsert("fp-audr-2", finding.SeverityHigh.String(), "/home/u/projects/audr", "audr")
	upsert("fp-billing", finding.SeverityHigh.String(), "/home/u/projects/billing", "billing")

	// One additional finding under a different bucket so class filters can be exercised.
	if _, err := store.UpsertFinding(state.Finding{
		Fingerprint:   "fp-claude",
		RuleID:        "rule-secrets",
		Severity:      finding.SeverityHigh.String(),
		Category:      "secrets",
		Kind:          "file",
		Locator:       []byte(`{"path":"/home/u/.claude/skills/x/SKILL.md"}`),
		Title:         "leak",
		Description:   "d",
		DedupGroupKey: "secrets:claude-skill-leak",
		FixAuthority:  "you",
		ProjectID:     "/home/u/.claude",
		ProjectLabel:  ".claude",
		ProjectClass:  "agent-state",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	}); err != nil {
		t.Fatal(err)
	}

	rem, _ := NewDemoRemediation()
	srv, err := NewServer(Options{Paths: p, Store: store, Remediation: rem, ListenHost: "127.0.0.1", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Bind(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Run(context.Background()) }()
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// TestRollupFilter_NoFilterReturnsAllRows is a baseline. Without
// query params, the endpoint must return every rolled-up row and the
// existing wire shape.
func TestRollupFilter_NoFilterReturnsAllRows(t *testing.T) {
	srv := projectFilterTestServer(t)
	body := getRollup(t, srv, "")
	// We seeded two DedupGroupKeys (next-RCE and claude-skill-leak).
	if len(body.Rows) != 2 {
		t.Errorf("expected 2 rolled-up rows, got %d", len(body.Rows))
	}
	if len(body.Projects) < 3 {
		t.Errorf("expected projects summary to include >=3 entries, got %d: %+v",
			len(body.Projects), projectLabelsFromSummaries(body.Projects))
	}
	if body.ClassTotals["code-project"].Count != 3 {
		t.Errorf("code-project class total = %d, want 3", body.ClassTotals["code-project"].Count)
	}
	if body.ClassTotals["agent-state"].Count != 1 {
		t.Errorf("agent-state class total = %d, want 1", body.ClassTotals["agent-state"].Count)
	}
}

// TestRollupFilter_FilterByProjectNarrowsLocations is the load-bearing
// per-location semantic (D6). Filtering by a single project must:
//   - keep the rolled-up row (it has a location in that project)
//   - narrow locations[] to only that project's paths
func TestRollupFilter_FilterByProjectNarrowsLocations(t *testing.T) {
	srv := projectFilterTestServer(t)
	body := getRollup(t, srv, "?project=%2Fhome%2Fu%2Fprojects%2Faudr")

	// The next-RCE row spans both audr and billing — should still be present.
	// The claude row is in a different project — should be excluded.
	if len(body.Rows) != 1 {
		t.Fatalf("expected 1 row after filter, got %d", len(body.Rows))
	}
	row := body.Rows[0]
	if row.RuleID != "osv-npm-package" {
		t.Errorf("wrong row survived filter: %+v", row)
	}

	// Across all groups, every Path's ProjectID must be the audr one.
	for _, g := range row.Groups {
		for _, p := range g.Paths {
			if p.ProjectID != "/home/u/projects/audr" {
				t.Errorf("location leaked from non-audr project: %+v", p)
			}
		}
	}

	// Projects + ClassTotals must reflect the UNFILTERED store (the
	// dashboard needs the global landscape even when viewing one
	// project tab).
	if body.ClassTotals["agent-state"].Count != 1 {
		t.Errorf("class totals must be unfiltered; agent-state = %d, want 1",
			body.ClassTotals["agent-state"].Count)
	}
}

// TestRollupFilter_FilterByProjectExcludesRowsWithNoMatch verifies
// that a row whose locations are entirely outside the filtered
// project is dropped — not returned with an empty Groups[].
func TestRollupFilter_FilterByProjectExcludesRowsWithNoMatch(t *testing.T) {
	srv := projectFilterTestServer(t)
	body := getRollup(t, srv, "?project=%2Fhome%2Fu%2Fprojects%2Fbilling")
	// billing has the next-RCE row (audr's twin) but NOT the claude row.
	if len(body.Rows) != 1 {
		t.Errorf("expected 1 row, got %d", len(body.Rows))
	}
	if len(body.Rows) > 0 && body.Rows[0].RuleID != "osv-npm-package" {
		t.Errorf("wrong row: %+v", body.Rows[0])
	}
}

// TestRollupFilter_FilterByClassMultipleValues exercises the CSV
// project_class filter. Filtering to "code-project,agent-state"
// includes everything; filtering to just "agent-state" includes only
// the claude row.
func TestRollupFilter_FilterByClassMultipleValues(t *testing.T) {
	srv := projectFilterTestServer(t)

	all := getRollup(t, srv, "?project_class=code-project,agent-state")
	if len(all.Rows) != 2 {
		t.Errorf("class=code-project,agent-state should match both rows, got %d", len(all.Rows))
	}

	agentOnly := getRollup(t, srv, "?project_class=agent-state")
	if len(agentOnly.Rows) != 1 {
		t.Fatalf("class=agent-state should match 1 row, got %d", len(agentOnly.Rows))
	}
	if agentOnly.Rows[0].RuleID != "rule-secrets" {
		t.Errorf("wrong row in agent-state filter: %+v", agentOnly.Rows[0])
	}
}

// TestRollupFilter_UnknownProjectReturnsEmptyRows verifies graceful
// handling of an unknown ?project= value.
func TestRollupFilter_UnknownProjectReturnsEmptyRows(t *testing.T) {
	srv := projectFilterTestServer(t)
	body := getRollup(t, srv, "?project=%2Fno%2Fsuch%2Fproject")
	if len(body.Rows) != 0 {
		t.Errorf("unknown project should return zero rows, got %d", len(body.Rows))
	}
	// Summaries stay global.
	if body.ClassTotals["code-project"].Count == 0 {
		t.Errorf("class totals should remain global even when rows are empty")
	}
}

// --- helpers ---

func getRollup(t *testing.T, s *Server, query string) RolledUpResponse {
	t.Helper()
	url := "/api/findings/rollup?t=" + s.Token()
	if query != "" {
		url += "&" + query[1:] // strip leading '?'
	}
	resp := mustDo(t, s, "GET", url, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d for %q", resp.StatusCode, url)
	}
	var body RolledUpResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

func projectLabelsFromSummaries(ps []ProjectSummary) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Label
	}
	return out
}
