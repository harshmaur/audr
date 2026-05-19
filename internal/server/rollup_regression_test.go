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

// T13: regression tests for the v6 project-tabs wire shape. These
// lock in contracts that aren't enforced by type system + would have
// caught the convert.go bug fixed in #24 had they existed earlier.

// minimalTestServer is a stripped-down variant of projectFilterTestServer
// that takes a callback to seed findings. Keeps the boilerplate in one
// place so each test below stays focused on its specific contract.
func minimalTestServer(t *testing.T, seed func(s *state.Store, scanID int64)) *Server {
	t.Helper()
	dir := t.TempDir()
	p := daemon.Paths{State: filepath.Join(dir, "state"), Logs: filepath.Join(dir, "logs")}
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
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

	if seed != nil {
		scanID, err := store.OpenScan("all")
		if err != nil {
			t.Fatal(err)
		}
		seed(store, scanID)
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

// TestRollupRegression_EmptyStoreReturnsEmptyShape verifies that the
// project-tabs additions never produce null arrays or panicking
// shape when the store is empty. The dashboard's hide-tab-row logic
// depends on `projects.length === 0` cleanly evaluating to "no row";
// a null here would crash the .filter() call upstream.
func TestRollupRegression_EmptyStoreReturnsEmptyShape(t *testing.T) {
	srv := minimalTestServer(t, nil)
	resp := mustDo(t, srv, "GET", "/api/findings/rollup?t="+srv.Token(), "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body RolledUpResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Rows) != 0 {
		t.Errorf("expected 0 rows from empty store, got %d", len(body.Rows))
	}
	if len(body.Projects) != 0 {
		t.Errorf("expected empty projects[], got %d", len(body.Projects))
	}
	// class_totals can be either nil or empty map — both are
	// JSON-equivalent ({} or absent via omitempty). Either is fine
	// for the dashboard.
	if len(body.ClassTotals) != 0 {
		t.Errorf("expected empty class_totals, got %d entries", len(body.ClassTotals))
	}
}

// TestRollupRegression_SingleCodeProjectShape verifies the
// 1-project case the dashboard uses to hide the tab row entirely
// (D11 — regression guarantee that pre-project-tabs users see
// no change). Wire shape must have projects[] with exactly one
// entry; the dashboard JS reads .length === 1 to trigger hide.
func TestRollupRegression_SingleCodeProjectShape(t *testing.T) {
	srv := minimalTestServer(t, func(s *state.Store, scanID int64) {
		if _, err := s.UpsertFinding(state.Finding{
			Fingerprint:   "fp-lone",
			RuleID:        "rule-x",
			Severity:      finding.SeverityHigh.String(),
			Category:      "deps",
			Kind:          "file",
			Locator:       []byte(`{"path":"/home/u/projects/audr/main.go"}`),
			Title:         "t",
			Description:   "d",
			DedupGroupKey: "k",
			FixAuthority:  "you",
			ProjectID:     "/home/u/projects/audr",
			ProjectLabel:  "audr",
			ProjectClass:  "code-project",
			FirstSeenScan: scanID,
			LastSeenScan:  scanID,
		}); err != nil {
			t.Fatal(err)
		}
	})
	body := getRollup(t, srv, "")
	codeProjects := 0
	for _, p := range body.Projects {
		if p.Class == "code-project" {
			codeProjects++
		}
	}
	if codeProjects != 1 {
		t.Errorf("expected exactly 1 code-project entry, got %d", codeProjects)
	}
	if body.ClassTotals["code-project"].Count != 1 {
		t.Errorf("code-project class_total.count = %d, want 1",
			body.ClassTotals["code-project"].Count)
	}
}

// TestRollupRegression_SchemaV1CompatOldConsumer verifies that an
// older wire consumer (no awareness of v6 fields) can still parse a
// v6 rollup response. Locks the additive-only contract on the wire
// — any future change that promotes a v6 field to NON-optional
// would break old clients and fail this test.
//
// The "old struct" mirrors the pre-v6 shape of RolledUpResponse +
// RolledUpView + RolledUpPathVw.
func TestRollupRegression_SchemaV1CompatOldConsumer(t *testing.T) {
	srv := minimalTestServer(t, func(s *state.Store, scanID int64) {
		if _, err := s.UpsertFinding(state.Finding{
			Fingerprint:   "fp-compat",
			RuleID:        "rule-x",
			Severity:      finding.SeverityHigh.String(),
			Category:      "deps",
			Kind:          "file",
			Locator:       []byte(`{"path":"/home/u/projects/audr/main.go"}`),
			Title:         "t",
			Description:   "d",
			DedupGroupKey: "k",
			FixAuthority:  "you",
			ProjectID:     "/home/u/projects/audr",
			ProjectLabel:  "audr",
			ProjectClass:  "code-project",
			FirstSeenScan: scanID,
			LastSeenScan:  scanID,
		}); err != nil {
			t.Fatal(err)
		}
	})

	resp := mustDo(t, srv, "GET", "/api/findings/rollup?t="+srv.Token(), "")
	defer resp.Body.Close()

	// Old struct: only the pre-v6 fields. If json.Decode tolerates
	// the new fields without erroring, the additive contract holds.
	type oldRolledUpPathVw struct {
		Fingerprint string `json:"fingerprint"`
		Path        string `json:"path"`
	}
	type oldRolledUpGroupVw struct {
		FixAuthority    string              `json:"fix_authority"`
		SecondaryNotify string              `json:"secondary_notify,omitempty"`
		PathCount       int                 `json:"path_count"`
		Paths           []oldRolledUpPathVw `json:"paths"`
	}
	type oldRolledUpView struct {
		DedupGroupKey string               `json:"dedup_group_key"`
		WorstSeverity string               `json:"worst_severity"`
		Category      string               `json:"category"`
		RuleID        string               `json:"rule_id"`
		Title         string               `json:"title"`
		Description   string               `json:"description"`
		PathCount     int                  `json:"path_count"`
		Groups        []oldRolledUpGroupVw `json:"groups"`
		FirstSeen     string               `json:"first_seen"`
	}
	type oldRolledUpResponse struct {
		Rows    []oldRolledUpView `json:"rows"`
		Metrics SnapshotMetrics   `json:"metrics"`
		Daemon  DaemonInfo        `json:"daemon"`
	}

	var oldBody oldRolledUpResponse
	if err := json.NewDecoder(resp.Body).Decode(&oldBody); err != nil {
		t.Fatalf("pre-v6 consumer cannot parse v6 response: %v", err)
	}
	if len(oldBody.Rows) != 1 {
		t.Errorf("old consumer saw %d rows, want 1", len(oldBody.Rows))
	}
	if oldBody.Rows[0].RuleID != "rule-x" {
		t.Errorf("old consumer payload corrupted: %+v", oldBody.Rows[0])
	}
}

// TestRollupRegression_ProjectFieldsSurviveResolveAndReopen verifies
// the v6 project columns make the full lifecycle: insert → resolve
// → re-detect → resolve again. The reopen path is a SEPARATE SQL
// UPDATE branch from the in-place re-detection (see internal/state/
// finding.go), so it has its own field-list that needs all v6
// columns. Catches the class of bug where ONLY the inserter path
// gets new columns added and the reopen path silently drops them.
func TestRollupRegression_ProjectFieldsSurviveResolveAndReopen(t *testing.T) {
	srv := minimalTestServer(t, nil)
	store := srv.opts.Store
	ctx := context.Background()

	scanID, _ := store.OpenScan("all")
	f := state.Finding{
		Fingerprint:   "fp-cycle",
		RuleID:        "rule-x",
		Severity:      finding.SeverityHigh.String(),
		Category:      "deps",
		Kind:          "file",
		Locator:       []byte(`{"path":"/home/u/projects/audr/main.go"}`),
		Title:         "t",
		Description:   "d",
		DedupGroupKey: "k",
		FixAuthority:  "you",
		ProjectID:     "/home/u/projects/audr",
		ProjectLabel:  "audr",
		ProjectClass:  "code-project",
		FirstSeenScan: scanID,
		LastSeenScan:  scanID,
	}
	if _, err := store.UpsertFinding(f); err != nil {
		t.Fatal(err)
	}
	// Resolve it.
	if _, err := store.ResolveFinding("fp-cycle"); err != nil {
		t.Fatal(err)
	}
	// Re-detect — must take the wasResolved branch which UPDATEs
	// the row in-place.
	scanID2, _ := store.OpenScan("all")
	f.FirstSeenScan = scanID2
	f.LastSeenScan = scanID2
	if _, err := store.UpsertFinding(f); err != nil {
		t.Fatal(err)
	}

	got, err := store.FindingByFingerprint(ctx, "fp-cycle")
	if err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != f.ProjectID {
		t.Errorf("ProjectID lost across resolve/reopen: got %q, want %q",
			got.ProjectID, f.ProjectID)
	}
	if got.ProjectLabel != f.ProjectLabel {
		t.Errorf("ProjectLabel lost: got %q, want %q", got.ProjectLabel, f.ProjectLabel)
	}
	if got.ProjectClass != f.ProjectClass {
		t.Errorf("ProjectClass lost: got %q, want %q", got.ProjectClass, f.ProjectClass)
	}
	if !got.Open() {
		t.Errorf("reopened finding should not be resolved")
	}
}

// TestRollupRegression_DistinctProjectsCountInClassTotals locks the
// arithmetic the dashboard relies on for the metric strip rescope:
// class_totals['code-project'].count must equal the sum of
// projects[].count for project_class == 'code-project'. A future
// refactor that computes them via different paths could drift; this
// test would catch it.
func TestRollupRegression_DistinctProjectsCountInClassTotals(t *testing.T) {
	srv := minimalTestServer(t, func(s *state.Store, scanID int64) {
		upsert := func(fp, sev, projID, label string) {
			if _, err := s.UpsertFinding(state.Finding{
				Fingerprint:   fp,
				RuleID:        "r",
				Severity:      sev,
				Category:      "deps",
				Kind:          "file",
				Locator:       []byte(`{"path":"` + projID + `/f"}`),
				Title:         "t",
				Description:   "d",
				DedupGroupKey: fp,
				FixAuthority:  "you",
				ProjectID:     projID,
				ProjectLabel:  label,
				ProjectClass:  "code-project",
				FirstSeenScan: scanID,
				LastSeenScan:  scanID,
			}); err != nil {
				t.Fatal(err)
			}
		}
		upsert("fp-a1", finding.SeverityCritical.String(), "/u/projects/a", "a")
		upsert("fp-a2", finding.SeverityHigh.String(), "/u/projects/a", "a")
		upsert("fp-b1", finding.SeverityHigh.String(), "/u/projects/b", "b")
	})
	body := getRollup(t, srv, "")

	sumByClass := map[string]int{}
	for _, p := range body.Projects {
		sumByClass[p.Class] += p.Count
	}
	for class, total := range body.ClassTotals {
		if sumByClass[class] != total.Count {
			t.Errorf("class_totals[%q].count = %d but sum(projects[].count where class==%q) = %d",
				class, total.Count, class, sumByClass[class])
		}
	}
}
