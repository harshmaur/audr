package server

import (
	"sort"

	"github.com/harshmaur/audr/internal/state"
)

// computeProjectsAndClassTotals walks an open-findings slice and
// returns two summaries used by the dashboard's project tabs:
//
//   - projects: one ProjectSummary per distinct (project_class,
//     project_id) pair, with severity counts; one entry per pseudo-
//     project bucket for class != "code-project" (e.g. all the
//     findings under ".claude" collapse into one entry).
//
//   - classTotals: top-line tally per project_class — used to render
//     the MY PROJECTS union tab and the OTHER LOCATIONS header.
//
// Findings without project metadata (pre-v6 rows, CLI-scan rows that
// didn't run through a classifier) bucket into the "loose" class
// with a synthetic ID "" + Label "(unclassified)". The dashboard
// renders this alongside Downloads/Documents/snap when it appears.
//
// Sort order: projects sorted by worst severity in the project
// (critical first), then count descending within tier, then label
// ascending for determinism. Dashboard re-sorts but a stable
// server-side order keeps test snapshots and curl output predictable.
func computeProjectsAndClassTotals(rows []state.Finding) ([]ProjectSummary, map[string]ClassTotal) {
	type key struct {
		class, id, label string
	}
	bucket := map[key]*ProjectSummary{}
	classTotals := map[string]*ClassTotal{}

	for _, f := range rows {
		if !f.Open() {
			continue
		}
		k := projectKeyFor(f)
		ps, ok := bucket[k]
		if !ok {
			ps = &ProjectSummary{
				Class:          k.class,
				ID:             k.id,
				Label:          k.label,
				SeverityCounts: map[string]int{},
			}
			bucket[k] = ps
		}
		ps.Count++
		ps.SeverityCounts[f.Severity]++

		ct, ok := classTotals[k.class]
		if !ok {
			ct = &ClassTotal{SeverityCounts: map[string]int{}}
			classTotals[k.class] = ct
		}
		ct.Count++
		ct.SeverityCounts[f.Severity]++
	}

	// Flatten bucket → slice. Stable sort below.
	out := make([]ProjectSummary, 0, len(bucket))
	for _, ps := range bucket {
		out = append(out, *ps)
	}
	sort.SliceStable(out, func(i, j int) bool {
		// Lower rank = worse severity; project with a crit sorts
		// before project with only highs.
		ri, rj := projectWorstSeverityRank(out[i]), projectWorstSeverityRank(out[j])
		if ri != rj {
			return ri < rj
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})

	// classTotals map[string]ClassTotal (not pointers) for JSON
	// marshal cleanliness.
	totalsByVal := make(map[string]ClassTotal, len(classTotals))
	for c, t := range classTotals {
		totalsByVal[c] = *t
	}
	return out, totalsByVal
}

// projectKeyFor maps a Finding to the (class, id, label) tuple used
// as the bucket key in computeProjectsAndClassTotals. Mirrors the
// dashboard's expected grouping:
//
//   - Findings with project_class + project_id set: use as-is.
//   - Empty project metadata: bucket as "loose" with synthetic
//     "(unclassified)" label. Pre-v6 rows + CLI-scan rows.
func projectKeyFor(f state.Finding) (k struct{ class, id, label string }) {
	if f.ProjectClass != "" {
		k.class = f.ProjectClass
		k.id = f.ProjectID
		k.label = f.ProjectLabel
		if k.label == "" {
			// Defensive: a class without a label is unexpected but
			// shouldn't crash the summary. Fall back to ID.
			k.label = k.id
		}
		return k
	}
	// Pre-v6 / CLI fallback.
	k.class = "loose"
	k.id = ""
	k.label = "(unclassified)"
	return k
}

// projectWorstSeverityRank returns the lowest severity rank in the
// project's SeverityCounts. Lower rank = worse (critical=0).
func projectWorstSeverityRank(p ProjectSummary) int {
	if p.SeverityCounts["critical"] > 0 {
		return 0
	}
	if p.SeverityCounts["high"] > 0 {
		return 1
	}
	if p.SeverityCounts["medium"] > 0 {
		return 2
	}
	if p.SeverityCounts["low"] > 0 {
		return 3
	}
	return 99
}
