// Package classify owns project-aware path classification for the
// dashboard. Given a finding's path, the classifier returns a
// ProjectInfo carrying:
//
//   - Class: code-project | agent-state | system | os-package | loose
//   - ID:    canonical (symlink-resolved) absolute path identifying the
//            owning project across collisions (e.g. two `audr/` dirs in
//            different scan roots)
//   - Label: basename for the dashboard tab (collision-disambiguated
//            with parent-dir suffix when basenames clash globally — the
//            caller resolves cross-classifier collisions; the classifier
//            itself just returns the basename).
//
// Classification semantics (locked in D2 + D7 of the project-tabs
// design):
//
//  1. Walk the path's segments LEFT-TO-RIGHT (root → leaf). If ANY
//     segment matches a known agent-state dot-dir (.claude, .codex,
//     .hermes, …), return ("agent-state", <that-dir-canonical>, basename).
//     This wins over code-project so that a manifest deeper inside an
//     agent state dir (e.g. .claude/skills/foo/package.json) does NOT
//     promote the path to "code-project".
//
//  2. Same scan for known system dot-dirs (.local, .config, .cache,
//     .ssh, .npm). Returns ("system", ...).
//
//  3. Only if neither bucket matched: walk LEAF-TO-ROOT looking for a
//     manifest file (go.mod, package.json, etc.) or `.git/` directory.
//     The nearest match wins → monorepos with per-package manifests
//     resolve as distinct sub-projects. Returns ("code-project", ...).
//
//  4. Empty path → ("os-package", "", "").
//
//  5. Fallback → ("loose", <first-segment-canonical>, <first-segment-base>).
//
// Symlinks: every path is resolved via filepath.EvalSymlinks before
// classification. So two paths that point at the same on-disk
// directory collapse to the same ProjectInfo (one tab in the
// dashboard).
//
// Cache: classification is dominated by directory-walk stat calls.
// We cache results per directory (sync.Map keyed by abs(dir)) so a
// project with 50 findings does the manifest probe once, not 50
// times. Cache is invalidated when ~/.audr/classify.toml changes
// (handled by NewClassifier's fsnotify watcher).
package classify

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Class is the top-level bucket every path falls into.
type Class string

const (
	ClassCodeProject Class = "code-project"
	ClassAgentState  Class = "agent-state"
	ClassSystem      Class = "system"
	ClassOSPackage   Class = "os-package"
	ClassLoose       Class = "loose"
)

// ProjectInfo is the three-field shape returned by Classify. Wire
// format mirrors this (see internal/server/types.go RolledUpPathVw).
type ProjectInfo struct {
	// ID is the canonical, symlink-resolved absolute path identifying
	// the project. Always non-empty except for ClassOSPackage. Used as
	// the wire identity for /api/findings/rollup?project= filtering and
	// for URL fragment state in the dashboard.
	ID string

	// Label is the basename for tab rendering. May collide with other
	// projects' basenames — the dashboard renders collisions as
	// "audr (projects)" / "audr (work)" via the parent-dir
	// disambiguator (D3 in the design doc).
	Label string

	// Class is the top-level bucket. Drives tab placement (MY PROJECTS
	// vs OTHER LOCATIONS) and overrides default visibility.
	Class Class
}

// Classifier holds the rules + cache. Construct via NewClassifier;
// daemon owns one instance for the lifetime of the process.
type Classifier struct {
	mu sync.RWMutex // protects rules + cache during config reload

	rules *rules

	// homeDirAbs is the canonical absolute form of the user's home
	// directory. Stored so the loose-path fallback can produce
	// meaningful labels for paths under $HOME — e.g. ~/Downloads/x
	// labels as "Downloads", not the literal first segment "home".
	// Empty when NewClassifier was constructed with empty homeDir.
	homeDirAbs string

	// cache maps a canonical absolute directory path to its ProjectInfo.
	// Findings in the same directory hit the cache; the manifest probe
	// runs once per directory per config epoch.
	cache sync.Map // map[string]ProjectInfo
}

// NewClassifier constructs a classifier with the embedded default
// ruleset, then overlays ~/.audr/classify.toml if present.
//
// homeDir is the user's home directory (pass os.UserHomeDir() at the
// call site). Empty homeDir disables the user-override file lookup
// AND disables home-aware loose-path labeling — useful for tests.
func NewClassifier(homeDir string) (*Classifier, error) {
	r, err := loadRules(homeDir)
	if err != nil {
		return nil, fmt.Errorf("classify: load rules: %w", err)
	}
	c := &Classifier{rules: r}
	if homeDir != "" {
		// Symlink-resolve home so paths classified against it match
		// the EvalSymlinks-resolved form of finding paths.
		if abs, err := resolveAbs(homeDir); err == nil {
			c.homeDirAbs = abs
		}
	}
	return c, nil
}

// Classify returns the ProjectInfo for a finding's path.
//
// The path may be relative or absolute. Empty path returns
// (ClassOSPackage, ID="", Label=""), indicating a finding without a
// filesystem locator (typically an OS package vulnerability).
//
// Errors are returned only for filesystem inconsistencies the
// classifier can't recover from (e.g. EvalSymlinks failed AND a
// fallback stat also failed). In normal operation the classifier
// always succeeds, falling back to ClassLoose for unrecognised paths.
func (c *Classifier) Classify(path string) (ProjectInfo, error) {
	if path == "" {
		return ProjectInfo{Class: ClassOSPackage}, nil
	}

	// Resolve symlinks first. Two paths pointing at the same on-disk
	// directory must produce the same ProjectInfo (D12).
	abs, err := resolveAbs(path)
	if err != nil {
		// Don't fail the whole classification: a transient stat error
		// shouldn't block a finding from appearing in the dashboard.
		// Fall back to the raw path. ClassLoose with the original
		// first-segment label keeps the finding visible.
		abs = path
	}

	// Cache key: the directory containing the file. Project membership
	// is a property of the directory, not individual files; one cache
	// entry serves every finding in that directory.
	dir := filepath.Dir(abs)
	if cached, ok := c.cache.Load(dir); ok {
		return cached.(ProjectInfo), nil
	}

	c.mu.RLock()
	info := c.classifyUncached(abs, dir)
	c.mu.RUnlock()

	c.cache.Store(dir, info)
	return info, nil
}

// classifyUncached runs the rule precedence without consulting the
// cache. Caller is expected to hold c.mu.RLock().
//
//	abs is the symlink-resolved absolute path of the finding's file.
//	dir is filepath.Dir(abs); pre-computed by caller for cache lookup.
func (c *Classifier) classifyUncached(abs, dir string) ProjectInfo {
	segs := splitSegments(abs)

	// Rule 1 + 2: scan path segments for an agent-state or system
	// dot-dir. First match wins; agent-state checked first because
	// agent state matters more to the dashboard's primary noise story.
	for i, seg := range segs {
		if class, ok := c.rules.classifyDotDirSegment(seg); ok {
			// Canonical ID = absolute path up through this segment.
			// On POSIX that's "/" + joined prefix; on Windows the
			// drive letter is already in segs[0].
			id := canonicalIDFromSegments(segs[:i+1])
			return ProjectInfo{
				ID:    id,
				Label: seg,
				Class: class,
			}
		}
	}

	// Rule 3: walk leaf-to-root looking for manifest or .git.
	if proj, ok := c.findCodeProjectRoot(dir); ok {
		return proj
	}

	// Rule 5: loose fallback.
	//
	// For paths under $HOME, use the first segment AFTER $HOME as
	// the label/ID anchor — `~/Downloads/x` labels as "Downloads",
	// not "home". For paths outside $HOME (or when homeDir wasn't
	// set), fall back to segs[0].
	if c.homeDirAbs != "" && strings.HasPrefix(abs, c.homeDirAbs+string(filepath.Separator)) {
		rel := strings.TrimPrefix(abs, c.homeDirAbs+string(filepath.Separator))
		relSegs := splitSegments(rel)
		if len(relSegs) > 0 {
			anchorAbs := filepath.Join(c.homeDirAbs, relSegs[0])
			return ProjectInfo{
				ID:    anchorAbs,
				Label: relSegs[0],
				Class: ClassLoose,
			}
		}
	}
	if len(segs) > 0 {
		return ProjectInfo{
			ID:    canonicalIDFromSegments(segs[:1]),
			Label: segs[0],
			Class: ClassLoose,
		}
	}
	return ProjectInfo{Class: ClassLoose}
}

// findCodeProjectRoot walks from `dir` up to the filesystem root,
// returning the nearest ancestor that contains a manifest file or
// `.git/` directory. Monorepos with per-package manifests therefore
// resolve as distinct subprojects: a finding in
// /repo/packages/billing/src/x.ts finds packages/billing's
// package.json before reaching /repo/.git.
//
// Returns ok=false if no marker is found anywhere up the chain. The
// caller then falls back to ClassLoose.
func (c *Classifier) findCodeProjectRoot(dir string) (ProjectInfo, bool) {
	const maxAscent = 64 // pathological-symlink guard

	cur := dir
	for i := 0; i < maxAscent; i++ {
		// `.git` directory marks any repo (no manifest needed).
		gitDir := filepath.Join(cur, ".git")
		if st, err := os.Stat(gitDir); err == nil && st.IsDir() {
			return ProjectInfo{
				ID:    cur,
				Label: filepath.Base(cur),
				Class: ClassCodeProject,
			}, true
		}

		// Known manifest files.
		for _, m := range c.rules.Manifests {
			if _, err := os.Stat(filepath.Join(cur, m)); err == nil {
				return ProjectInfo{
					ID:    cur,
					Label: filepath.Base(cur),
					Class: ClassCodeProject,
				}, true
			}
		}

		// Ascend. Stop at filesystem root (parent == self on
		// POSIX; parent ends with the drive letter on Windows).
		parent := filepath.Dir(cur)
		if parent == cur || parent == "." {
			return ProjectInfo{}, false
		}
		cur = parent
	}
	return ProjectInfo{}, false
}

// resolveAbs returns the absolute, symlink-resolved form of path.
// On error (path doesn't exist, broken symlink chain, etc.), returns
// the absolute form WITHOUT resolution alongside the error so the
// caller can decide whether to fall back.
func resolveAbs(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// EvalSymlinks needs the path to exist. For paths that don't
		// (e.g. a transient file the scanner saw but is now gone),
		// return the absolute non-resolved form. Classification can
		// still proceed correctly for the non-existent-path case.
		if errors.Is(err, os.ErrNotExist) {
			return abs, nil
		}
		return abs, err
	}
	return resolved, nil
}

// splitSegments normalizes a path to forward slashes and returns its
// non-empty components. The leading slash on POSIX is preserved as a
// virtual "" segment which is then dropped (the empty-segment check
// filters it out).
func splitSegments(p string) []string {
	p = strings.ReplaceAll(p, `\`, "/")
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// canonicalIDFromSegments reconstructs an absolute path from segments
// (which were split via splitSegments). On POSIX the result starts
// with `/`. On Windows the first segment is the drive letter and the
// result starts with that.
func canonicalIDFromSegments(segs []string) string {
	if len(segs) == 0 {
		return ""
	}
	// Windows drive letter: starts with letter + colon.
	if len(segs[0]) >= 2 && segs[0][1] == ':' {
		return strings.Join(segs, "/")
	}
	return "/" + strings.Join(segs, "/")
}
