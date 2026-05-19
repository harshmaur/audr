package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harshmaur/audr/internal/remediate"
	"github.com/harshmaur/audr/internal/state"
)

// rolledUpPathsCapDefault bounds the response size per fix-authority
// bucket. Picked to keep the largest realistic vulnerability row under
// ~10KB of JSON (50 paths * ~200 bytes path + fingerprint). When a
// bucket has more, the dashboard renders the cap + a "show all"
// affordance and re-queries with cap=0.
const rolledUpPathsCapDefault = 50

// overrideDisclaimer is the F3-mitigation prose the dashboard MUST
// render adjacent to every snippet body. Pinning a transitive dep can
// break the build; saying so out loud is the difference between a tool
// that helps and one that gets blamed.
const overrideDisclaimer = "⚠️ This override pins the transitive dep. Verify your build + tests pass before committing — semver compatibility isn't guaranteed when bypassing a maintainer's resolution."

// handleFindingsRollup serves the v1.3 default dashboard view: one row
// per unique vulnerability with three fix-authority sub-buckets each.
// Wire shape is RolledUpResponse — mirrors handleFindings (the flat
// /audit view) for daemon info + metrics + version so the dashboard
// can render the strip identically across both routes.
func (s *Server) handleFindingsRollup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	cap := rolledUpPathsCapDefault
	if v := q.Get("cap"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cap = n
		}
	}

	// Project / class filters. Both are optional and AND together when
	// both are present (a row is kept iff it survives both filters).
	//
	//   ?project=<canonical_id>  — single project; row included iff
	//                              ANY of its locations is in this
	//                              project; row's locations[] is
	//                              narrowed to only that project's
	//                              paths (D6 of the project-tabs
	//                              design — per-location filtering).
	//
	//   ?project_class=<csv>     — one or more comma-separated class
	//                              names from {code-project,
	//                              agent-state, system, os-package,
	//                              loose}; row included iff ANY of
	//                              its locations matches; locations[]
	//                              narrowed to matching paths.
	projectFilter := q.Get("project")
	classFilter := parseClassFilter(q.Get("project_class"))

	rolled, err := s.opts.Store.ListRolledUp(ctx, cap)
	if err != nil {
		http.Error(w, "rolled-up findings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Always recompute project summaries from the full (un-filtered)
	// findings set — the dashboard needs to know the global
	// landscape of tabs even when viewing a single project. See the
	// RolledUpResponse type doc.
	rows, err := s.opts.Store.SnapshotFindings(ctx)
	if err != nil {
		http.Error(w, "snapshot findings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	views := make([]RolledUpView, 0, len(rolled))
	for _, row := range rolled {
		v := RolledUpView{
			DedupGroupKey:    row.DedupGroupKey,
			WorstSeverity:    row.WorstSeverity,
			Category:         row.Category,
			RuleID:           row.RuleID,
			Title:            row.Title,
			Description:      row.Description,
			PathCount:        row.PathCount,
			FirstSeen:        time.Unix(row.WorstFirstSeen, 0).UTC().Format(time.RFC3339),
			AffectedProjects: row.AffectedProjects,
		}
		// Build groups, narrowing locations[] to filter-matching paths.
		// Track whether any location passed the filter so we know
		// whether to include the row at all.
		anyMatched := false
		for _, g := range row.Groups {
			groupView := RolledUpGroupVw{
				FixAuthority:    g.FixAuthority,
				SecondaryNotify: g.SecondaryNotify,
				PathCount:       g.PathCount, // unchanged: reflects unfiltered count
			}
			for _, p := range g.Paths {
				if !pathMatchesFilters(p, projectFilter, classFilter) {
					continue
				}
				anyMatched = true
				groupView.Paths = append(groupView.Paths, RolledUpPathVw{
					Fingerprint:  p.Fingerprint,
					Path:         p.Path,
					ProjectID:    p.ProjectID,
					ProjectLabel: p.ProjectLabel,
					ProjectClass: p.ProjectClass,
				})
			}
			// Drop empty groups so the dashboard doesn't render
			// fix-authority sections with zero rows when filtering.
			if len(groupView.Paths) == 0 && (projectFilter != "" || classFilter != nil) {
				continue
			}
			v.Groups = append(v.Groups, groupView)
		}

		// Skip rows whose locations were all filtered out. When no
		// filter is active, anyMatched stays true for every row that
		// had any path (and rows with zero paths were already missing
		// from the store).
		if (projectFilter != "" || classFilter != nil) && !anyMatched {
			continue
		}
		views = append(views, v)
	}

	projects, classTotals := computeProjectsAndClassTotals(rows)
	resp := RolledUpResponse{
		Rows:        views,
		Metrics:     computeMetrics(rows),
		Daemon:      DaemonInfo{State: "RUN", Version: s.opts.Version},
		Projects:    projects,
		ClassTotals: classTotals,
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseClassFilter splits a comma-separated list of class names into a
// set. Returns nil when input is empty so callers can distinguish
// "no filter" from "filter to no classes" (the latter would be a
// nonsense query that returns nothing).
func parseClassFilter(csv string) map[string]bool {
	if csv == "" {
		return nil
	}
	out := map[string]bool{}
	for _, c := range strings.Split(csv, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		out[c] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pathMatchesFilters reports whether a path passes the project and
// class filters. Empty filter means "match everything." Both filters
// AND together when both are set.
func pathMatchesFilters(p state.RolledUpPath, projectFilter string, classFilter map[string]bool) bool {
	if projectFilter != "" && p.ProjectID != projectFilter {
		return false
	}
	if classFilter != nil && !classFilter[p.ProjectClass] {
		return false
	}
	return true
}

// handleRemediateSnippet renders an override-snippet for a single
// dep-package finding. Reads the finding's DedupGroupKey to extract
// the OSV (ecosystem, package, fixed-version, advisory) tuple, looks
// at the path-shaped Locator to detect the lockfile format, and
// emits the format-appropriate snippet plus the F3 disclaimer.
//
// Returns 404 when the fingerprint is unknown. Returns an empty
// snippet (200 with `snippet: ""`) when no upstream fix is available
// or the lockfile format isn't recognised — the dashboard renders
// "Track upstream" in that case.
func (s *Server) handleRemediateSnippet(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	if fp == "" {
		http.Error(w, "missing fingerprint", http.StatusBadRequest)
		return
	}
	f, err := s.opts.Store.FindingByFingerprint(r.Context(), fp)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no finding for fingerprint " + fp})
			return
		}
		http.Error(w, "lookup finding: "+err.Error(), http.StatusInternalServerError)
		return
	}

	lockfilePath := extractLockfilePathFromLocator(f.Locator)
	snippet := remediate.SnippetForOSVFinding(f.DedupGroupKey, lockfilePath)

	resp := RemediateSnippetResponse{
		Fingerprint:  fp,
		Snippet:      snippet,
		LockfilePath: lockfilePath,
		LockfileFmt:  string(remediate.DetectFormat(lockfilePath)),
	}
	if snippet != "" {
		resp.Disclaimer = overrideDisclaimer
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRemediateMaintainer renders the maintainer-notify view for a
// finding whose authority is MAINTAINER or whose path lives in a
// vendor dir. The dashboard's "File issue" button calls this, opens
// IssueURL in a new tab when present, and falls back to clipboard-
// copying BodyMarkdown when not.
func (s *Server) handleRemediateMaintainer(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	if fp == "" {
		http.Error(w, "missing fingerprint", http.StatusBadRequest)
		return
	}
	f, err := s.opts.Store.FindingByFingerprint(r.Context(), fp)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no finding for fingerprint " + fp})
			return
		}
		http.Error(w, "lookup finding: "+err.Error(), http.StatusInternalServerError)
		return
	}

	details := remediate.IssueDetails{
		Maintainer:    f.SecondaryNotify,
		RuleID:        f.RuleID,
		AffectedPaths: []string{extractLockfilePathFromLocator(f.Locator)},
		Severity:      f.Severity,
		Title:         f.Title,
	}
	if key, ok := remediate.ParseOSVDedupKey(f.DedupGroupKey); ok {
		details.AdvisoryID = key.AdvisoryID
		details.Package = key.Package
		details.FixedVersion = key.FixedVersion
	}
	link := remediate.MaintainerLinkFor(details)

	writeJSON(w, http.StatusOK, RemediateMaintainerResponse{
		Fingerprint:  fp,
		IssueURL:     link.IssueURL,
		BodyMarkdown: link.BodyMarkdown,
		LabelHint:    link.LabelHint,
	})
}

// extractLockfilePathFromLocator pulls the manifest_path / path field
// out of a locator JSON blob. The two converter shapes use different
// field names — dep-package locator uses "manifest_path", file locator
// uses "path". Try both.
func extractLockfilePathFromLocator(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, key := range []string{"manifest_path", "path"} {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}
