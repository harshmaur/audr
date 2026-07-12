package scan

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
)

const cursorEscapingSymlinkRuleID = "cursor-workspace-escaping-symlink-cve-2026-50549"

type cursorWorkspaceEvidence struct {
	root    string
	rootAbs string
	path    string
}

type symlinkEntry struct {
	path    string
	pathAbs string
	target  string
}

type cursorSymlinkPostureCollector struct {
	enabled  bool
	evidence []cursorWorkspaceEvidence
	symlinks []symlinkEntry
}

func newCursorSymlinkPostureCollector(opts Options) *cursorSymlinkPostureCollector {
	if opts.Policy != nil && !opts.Policy.IsRuleEnabled(cursorEscapingSymlinkRuleID) {
		return nil
	}
	return &cursorSymlinkPostureCollector{enabled: true}
}

func (c *cursorSymlinkPostureCollector) observe(path string, d os.DirEntry, logger *slog.Logger) {
	if c == nil || !c.enabled || d == nil || d.IsDir() {
		return
	}
	if d.Type()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			logger.Debug("cursor-symlink-readlink-error", "path", path, "err", err)
			return
		}
		c.symlinks = append(c.symlinks, symlinkEntry{path: filepath.Clean(path), pathAbs: cleanAbs(path), target: target})
		return
	}
	if workspaceRoot, ok := cursorWorkspaceRootForEvidence(path); ok {
		c.evidence = append(c.evidence, cursorWorkspaceEvidence{
			root:    filepath.Clean(workspaceRoot),
			rootAbs: cleanAbs(workspaceRoot),
			path:    filepath.Clean(path),
		})
	}
}

func (c *cursorSymlinkPostureCollector) findings(opts Options) []finding.Finding {
	if c == nil || !c.enabled || len(c.evidence) == 0 || len(c.symlinks) == 0 {
		return nil
	}

	sort.Slice(c.evidence, func(i, j int) bool {
		return len(c.evidence[i].rootAbs) > len(c.evidence[j].rootAbs)
	})

	var out []finding.Finding
	seen := map[string]bool{}
	for _, link := range c.symlinks {
		ev, ok := nearestCursorWorkspaceEvidence(link.pathAbs, c.evidence)
		if !ok {
			continue
		}
		if opts.Policy != nil && !opts.Policy.IsPathInScope(cursorEscapingSymlinkRuleID, link.path) {
			continue
		}
		if opts.Policy != nil && opts.Policy.IsSuppressed(cursorEscapingSymlinkRuleID, link.path) {
			continue
		}
		lexicalTarget, err := canonicalizeSymlinkTarget(link.pathAbs, link.target)
		if err == nil || pathWithin(lexicalTarget, ev.rootAbs) {
			continue
		}
		if seen[link.pathAbs] {
			continue
		}
		seen[link.pathAbs] = true

		severity := finding.SeverityHigh
		if opts.Policy != nil {
			severity = opts.Policy.EffectiveSeverity(cursorEscapingSymlinkRuleID, severity)
		}
		out = append(out, finding.New(finding.Args{
			RuleID:      cursorEscapingSymlinkRuleID,
			Severity:    severity,
			Taxonomy:    finding.TaxDetectable,
			Title:       "Cursor workspace contains symlink escaping workspace boundary",
			Description: "CVE-2026-50549: Cursor before 3.0 could fall back after path canonicalization failure and write through an in-workspace symlink to a path outside the workspace. Audr found concrete Cursor workspace evidence plus an escaping symlink; scanned files do not prove the installed Cursor version, so treat this as vulnerable posture that requires Cursor 3.0 or later and removal or intentional isolation of the symlink.",
			Path:        link.path,
			Match: fmt.Sprintf("symlink target %q points outside Cursor workspace %q and canonicalization failed (%v); evidence %q",
				link.target, ev.root, err, ev.path),
			SuggestedFix:  "Upgrade Cursor to 3.0 or later. Remove or replace the escaping symlink, or move it outside workspaces opened in Cursor.",
			Tags:          []string{"cursor", "symlink", "cve-2026-50549"},
			DedupGroupKey: cursorEscapingSymlinkRuleID + ":" + ev.rootAbs + ":" + link.pathAbs,
		}))
	}
	return out
}

func cursorWorkspaceRootForEvidence(path string) (string, bool) {
	cleaned := filepath.Clean(path)
	base := filepath.Base(cleaned)
	dir := filepath.Dir(cleaned)
	if base == ".cursorrules" {
		return dir, true
	}
	if base == "mcp.json" && filepath.Base(dir) == ".cursor" {
		workspaceRoot := filepath.Dir(dir)
		if cursorWorkspaceHasProjectMarker(workspaceRoot) {
			return workspaceRoot, true
		}
	}
	return "", false
}

func cursorWorkspaceHasProjectMarker(root string) bool {
	for _, marker := range []string{".git", "package.json", "go.mod", "pyproject.toml", "Cargo.toml"} {
		if _, err := os.Lstat(filepath.Join(root, marker)); err == nil {
			return true
		}
	}
	return false
}

func nearestCursorWorkspaceEvidence(path string, evidence []cursorWorkspaceEvidence) (cursorWorkspaceEvidence, bool) {
	for _, ev := range evidence {
		if pathWithin(path, ev.rootAbs) {
			return ev, true
		}
	}
	return cursorWorkspaceEvidence{}, false
}

func canonicalizeSymlinkTarget(linkPath, target string) (string, error) {
	if target == "" {
		return "", os.ErrInvalid
	}
	candidate := target
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(filepath.Dir(linkPath), candidate)
	}
	candidate = cleanAbs(candidate)
	if evaluated, err := filepath.EvalSymlinks(candidate); err == nil {
		return cleanAbs(evaluated), nil
	} else {
		return candidate, err
	}
}

func cleanAbs(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(path)
}

func pathWithin(path, root string) bool {
	path = cleanAbs(path)
	root = cleanAbs(root)
	if path == root {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
