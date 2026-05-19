package server

import (
	"testing"

	"github.com/harshmaur/audr/internal/state"
)

// TestComputeProjectsAndClassTotals_BucketsByProject verifies basic
// grouping: findings sharing (class, id) collapse into one
// ProjectSummary with summed counts.
func TestComputeProjectsAndClassTotals_BucketsByProject(t *testing.T) {
	rows := []state.Finding{
		// Two findings under projects/audr (one critical, one high)
		mkFinding("fp1", "high", "code-project", "/home/u/projects/audr", "audr"),
		mkFinding("fp2", "critical", "code-project", "/home/u/projects/audr", "audr"),
		// One finding under projects/billing
		mkFinding("fp3", "medium", "code-project", "/home/u/projects/billing", "billing"),
		// Two findings in .claude (agent-state)
		mkFinding("fp4", "low", "agent-state", "/home/u/.claude", ".claude"),
		mkFinding("fp5", "high", "agent-state", "/home/u/.claude", ".claude"),
	}
	projects, classTotals := computeProjectsAndClassTotals(rows)

	if len(projects) != 3 {
		t.Fatalf("expected 3 projects (audr, billing, .claude), got %d: %+v", len(projects), projects)
	}

	// audr should come first: has a critical.
	if projects[0].Label != "audr" {
		t.Errorf("expected audr to sort first (has crit); got order: %v", projectLabels(projects))
	}
	if projects[0].Count != 2 {
		t.Errorf("audr count = %d, want 2", projects[0].Count)
	}
	if projects[0].SeverityCounts["critical"] != 1 || projects[0].SeverityCounts["high"] != 1 {
		t.Errorf("audr severity counts wrong: %+v", projects[0].SeverityCounts)
	}

	// Class totals
	cp := classTotals["code-project"]
	if cp.Count != 3 {
		t.Errorf("code-project total = %d, want 3", cp.Count)
	}
	if cp.SeverityCounts["critical"] != 1 || cp.SeverityCounts["high"] != 1 || cp.SeverityCounts["medium"] != 1 {
		t.Errorf("code-project severity counts wrong: %+v", cp.SeverityCounts)
	}
	as := classTotals["agent-state"]
	if as.Count != 2 || as.SeverityCounts["high"] != 1 || as.SeverityCounts["low"] != 1 {
		t.Errorf("agent-state class total wrong: %+v", as)
	}
}

// TestComputeProjectsAndClassTotals_UnclassifiedBucketsAsLoose covers
// CLI-scan / pre-v6 rows: empty project metadata flows to a synthetic
// "(unclassified)" entry in the loose class.
func TestComputeProjectsAndClassTotals_UnclassifiedBucketsAsLoose(t *testing.T) {
	rows := []state.Finding{
		// Project-classified row.
		mkFinding("fp1", "critical", "code-project", "/home/u/projects/audr", "audr"),
		// No project metadata at all.
		mkFinding("fp2", "high", "", "", ""),
		mkFinding("fp3", "high", "", "", ""),
	}
	projects, classTotals := computeProjectsAndClassTotals(rows)
	if len(projects) != 2 {
		t.Fatalf("expected 2 projects, got %d: %+v", len(projects), projects)
	}

	var loose *ProjectSummary
	for i := range projects {
		if projects[i].Class == "loose" {
			loose = &projects[i]
			break
		}
	}
	if loose == nil {
		t.Fatal("no loose entry produced for unclassified rows")
	}
	if loose.Label != "(unclassified)" {
		t.Errorf("loose label = %q, want (unclassified)", loose.Label)
	}
	if loose.Count != 2 {
		t.Errorf("loose count = %d, want 2", loose.Count)
	}
	if classTotals["loose"].Count != 2 {
		t.Errorf("loose class total = %d, want 2", classTotals["loose"].Count)
	}
}

// TestComputeProjectsAndClassTotals_ExcludesResolved verifies the
// summary respects the same open-only semantic the dashboard uses
// for the metric strip.
func TestComputeProjectsAndClassTotals_ExcludesResolved(t *testing.T) {
	resolved := int64(100)
	rows := []state.Finding{
		mkFinding("fp1", "critical", "code-project", "/p/audr", "audr"),
		{
			Fingerprint:  "fp-resolved",
			Severity:     "critical",
			ProjectClass: "code-project",
			ProjectID:    "/p/audr",
			ProjectLabel: "audr",
			ResolvedAt:   &resolved,
		},
	}
	projects, classTotals := computeProjectsAndClassTotals(rows)
	if len(projects) != 1 || projects[0].Count != 1 {
		t.Errorf("resolved finding leaked into summary: %+v", projects)
	}
	if classTotals["code-project"].Count != 1 {
		t.Errorf("class total includes resolved row: %d", classTotals["code-project"].Count)
	}
}

// TestComputeProjectsAndClassTotals_SortOrder verifies severity-first,
// count-second, label-third ordering — exactly what the dashboard
// expects so it can render tabs without re-sorting client side.
func TestComputeProjectsAndClassTotals_SortOrder(t *testing.T) {
	rows := []state.Finding{
		// Project Z: high only
		mkFinding("z1", "high", "code-project", "/p/z", "z"),
		// Project A: critical (worse than high)
		mkFinding("a1", "critical", "code-project", "/p/a", "a"),
		// Project B: high but more of them (count tiebreaker)
		mkFinding("b1", "high", "code-project", "/p/b", "b"),
		mkFinding("b2", "high", "code-project", "/p/b", "b"),
		mkFinding("b3", "high", "code-project", "/p/b", "b"),
	}
	projects, _ := computeProjectsAndClassTotals(rows)
	got := projectLabels(projects)
	want := []string{"a", "b", "z"} // crit first; then b > z by count
	if !equal(got, want) {
		t.Errorf("sort order: got %v, want %v", got, want)
	}
}

// --- helpers ---

func mkFinding(fp, sev, class, id, label string) state.Finding {
	return state.Finding{
		Fingerprint:  fp,
		Severity:     sev,
		ProjectClass: class,
		ProjectID:    id,
		ProjectLabel: label,
	}
}

func projectLabels(ps []ProjectSummary) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Label
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
