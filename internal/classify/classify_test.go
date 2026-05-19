package classify

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// newTestClassifier constructs a classifier with the embedded defaults
// and no user-override file. The home dir is set to t.TempDir() so the
// test never accidentally reads a real ~/.audr/classify.toml.
func newTestClassifier(t *testing.T) *Classifier {
	t.Helper()
	c, err := NewClassifier(t.TempDir())
	if err != nil {
		t.Fatalf("NewClassifier: %v", err)
	}
	return c
}

// TestClassify_AgentStateWinsOverManifest is the load-bearing case
// Codex caught: a manifest deeper inside a known agent-state dot-dir
// must NOT promote the path to code-project.
func TestClassify_AgentStateWinsOverManifest(t *testing.T) {
	tmp := t.TempDir()
	// .claude/skills/foo/package.json  — manifest INSIDE .claude
	skillsDir := filepath.Join(tmp, ".claude", "skills", "foo")
	if err := os.MkdirAll(skillsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(skillsDir, "package.json")
	if err := os.WriteFile(pkg, []byte(`{"name":"foo"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	finding := filepath.Join(skillsDir, "main.js")
	if err := os.WriteFile(finding, []byte(`// example`), 0o644); err != nil {
		t.Fatal(err)
	}

	c := newTestClassifier(t)
	info, err := c.Classify(finding)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if info.Class != ClassAgentState {
		t.Errorf("expected ClassAgentState, got %v (info=%+v)", info.Class, info)
	}
	if info.Label != ".claude" {
		t.Errorf("expected Label=.claude, got %q", info.Label)
	}
	// ID is the canonical absolute path of the .claude dir.
	wantID, _ := filepath.EvalSymlinks(filepath.Join(tmp, ".claude"))
	if info.ID != wantID {
		t.Errorf("expected ID=%q, got %q", wantID, info.ID)
	}
}

// TestClassify_NearestManifestWinsForCodeProjects covers monorepos.
// A finding inside packages/billing classifies as that sub-project,
// not the outer .git root.
func TestClassify_NearestManifestWinsForCodeProjects(t *testing.T) {
	tmp := t.TempDir()
	// Outer repo with .git
	outer := filepath.Join(tmp, "big-mono")
	if err := os.MkdirAll(filepath.Join(outer, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Inner package with package.json
	inner := filepath.Join(outer, "packages", "billing")
	if err := os.MkdirAll(filepath.Join(inner, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "package.json"), []byte(`{"name":"billing"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	finding := filepath.Join(inner, "src", "main.ts")
	if err := os.WriteFile(finding, []byte(`// example`), 0o644); err != nil {
		t.Fatal(err)
	}

	c := newTestClassifier(t)
	info, err := c.Classify(finding)
	if err != nil {
		t.Fatal(err)
	}
	if info.Class != ClassCodeProject {
		t.Errorf("expected ClassCodeProject, got %v", info.Class)
	}
	if info.Label != "billing" {
		t.Errorf("expected Label=billing (nearest manifest), got %q", info.Label)
	}
	wantID, _ := filepath.EvalSymlinks(inner)
	if info.ID != wantID {
		t.Errorf("expected ID=%q (the packages/billing dir), got %q", wantID, info.ID)
	}
}

// TestClassify_GitOnlyRoot covers the "shell-script repo with no
// manifest" case. .git directory alone is enough to mark a project.
func TestClassify_GitOnlyRoot(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "ops-scripts")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	finding := filepath.Join(root, "deploy.sh")
	if err := os.WriteFile(finding, []byte(`#!/bin/sh`), 0o644); err != nil {
		t.Fatal(err)
	}

	c := newTestClassifier(t)
	info, _ := c.Classify(finding)
	if info.Class != ClassCodeProject {
		t.Errorf("expected ClassCodeProject for .git-only repo, got %v", info.Class)
	}
	if info.Label != "ops-scripts" {
		t.Errorf("expected Label=ops-scripts, got %q", info.Label)
	}
}

// TestClassify_SystemDotDir covers .local / .config / etc.
func TestClassify_SystemDotDir(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, ".local", "share", "foo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	finding := filepath.Join(dir, "config.json")
	if err := os.WriteFile(finding, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	c := newTestClassifier(t)
	info, _ := c.Classify(finding)
	if info.Class != ClassSystem {
		t.Errorf("expected ClassSystem, got %v", info.Class)
	}
	if info.Label != ".local" {
		t.Errorf("expected Label=.local, got %q", info.Label)
	}
}

// TestClassify_OSPackage covers the no-path case.
func TestClassify_OSPackage(t *testing.T) {
	c := newTestClassifier(t)
	info, err := c.Classify("")
	if err != nil {
		t.Fatal(err)
	}
	if info.Class != ClassOSPackage {
		t.Errorf("expected ClassOSPackage for empty path, got %v", info.Class)
	}
	if info.ID != "" {
		t.Errorf("expected empty ID for os-package, got %q", info.ID)
	}
}

// TestClassify_LooseFallback covers paths with no project signal
// anywhere — random downloaded files, ad-hoc fixtures, etc.
func TestClassify_LooseFallback(t *testing.T) {
	tmp := t.TempDir()
	// No .git, no manifest, no known dot-dir.
	dir := filepath.Join(tmp, "Downloads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	finding := filepath.Join(dir, "random.env")
	if err := os.WriteFile(finding, []byte(`KEY=value`), 0o644); err != nil {
		t.Fatal(err)
	}

	c := newTestClassifier(t)
	info, _ := c.Classify(finding)
	if info.Class != ClassLoose {
		t.Errorf("expected ClassLoose, got %v (info=%+v)", info.Class, info)
	}
}

// TestClassify_LooseUsesFirstSegmentBelowHome verifies that a loose
// path under $HOME labels by the first segment AFTER home, not the
// literal first segment of the absolute path.
//
// Regression: ~/Downloads/x.env used to label as "home" (segs[0]).
// Fixed by storing the resolved homeDirAbs on the Classifier and
// stripping it before picking the loose anchor segment.
func TestClassify_LooseUsesFirstSegmentBelowHome(t *testing.T) {
	home := t.TempDir()
	// Loose path under home with no manifest or dot-dir markers.
	downloads := filepath.Join(home, "Downloads")
	if err := os.MkdirAll(downloads, 0o755); err != nil {
		t.Fatal(err)
	}
	finding := filepath.Join(downloads, "random.env")
	if err := os.WriteFile(finding, []byte(`KEY=value`), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := NewClassifier(home)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := c.Classify(finding)
	if info.Class != ClassLoose {
		t.Fatalf("expected ClassLoose, got %v", info.Class)
	}
	if info.Label != "Downloads" {
		t.Errorf("expected Label=Downloads (first segment under home), got %q", info.Label)
	}
	wantID, _ := filepath.EvalSymlinks(downloads)
	if info.ID != wantID {
		t.Errorf("expected ID=%q, got %q", wantID, info.ID)
	}
}

// TestClassify_SymlinkResolution covers D12: symlinked paths must
// collapse to the same ProjectInfo as the real path.
func TestClassify_SymlinkResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test requires admin on Windows")
	}
	tmp := t.TempDir()

	// Real project
	real := filepath.Join(tmp, "projects", "audr")
	if err := os.MkdirAll(filepath.Join(real, "cmd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "go.mod"), []byte(`module audr`), 0o644); err != nil {
		t.Fatal(err)
	}
	realFinding := filepath.Join(real, "cmd", "main.go")
	if err := os.WriteFile(realFinding, []byte(`package main`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Symlink: ~/work/audr -> ~/projects/audr
	linkParent := filepath.Join(tmp, "work")
	if err := os.MkdirAll(linkParent, 0o755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(linkParent, "audr")
	if err := os.Symlink(real, linkPath); err != nil {
		t.Fatal(err)
	}
	linkedFinding := filepath.Join(linkPath, "cmd", "main.go")

	c := newTestClassifier(t)
	infoReal, _ := c.Classify(realFinding)
	infoLinked, _ := c.Classify(linkedFinding)

	if infoReal.ID != infoLinked.ID {
		t.Errorf("symlink and real path produced different IDs:\n  real:   %s\n  linked: %s", infoReal.ID, infoLinked.ID)
	}
	if infoReal.Class != ClassCodeProject || infoLinked.Class != ClassCodeProject {
		t.Errorf("expected both to be ClassCodeProject; real=%v linked=%v", infoReal.Class, infoLinked.Class)
	}
}

// TestClassify_CacheReusesPerDirectory verifies that two findings in
// the same directory share a single manifest-probe.
func TestClassify_CacheReusesPerDirectory(t *testing.T) {
	tmp := t.TempDir()
	proj := filepath.Join(tmp, "p")
	if err := os.MkdirAll(filepath.Join(proj, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "go.mod"), []byte(`module p`), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.go", "b.go", "c.go"} {
		if err := os.WriteFile(filepath.Join(proj, "src", name), []byte(`package main`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	c := newTestClassifier(t)
	for _, name := range []string{"a.go", "b.go", "c.go"} {
		info, _ := c.Classify(filepath.Join(proj, "src", name))
		if info.Class != ClassCodeProject || info.Label != "p" {
			t.Errorf("classify %q: got %+v", name, info)
		}
	}

	// Cache must have ONE entry (the src dir), not three.
	count := 0
	c.cache.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != 1 {
		t.Errorf("expected 1 cache entry (the src/ dir), got %d", count)
	}
}

// TestClassify_TOMLOverride asserts ~/.audr/classify.toml replaces
// default lists. User can reclassify .hermes as code-project by
// removing it from agent_state_dirs in the override.
func TestClassify_TOMLOverride(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".audr"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Override removes .hermes from agent_state_dirs (kept others).
	cfg := `agent_state_dirs = [".claude", ".codex"]` + "\n"
	if err := os.WriteFile(filepath.Join(home, ".audr", "classify.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// Build a fake .hermes tree WITH a manifest so the leaf-to-root
	// scan can promote it to code-project.
	work := t.TempDir()
	hermes := filepath.Join(work, ".hermes")
	if err := os.MkdirAll(hermes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hermes, "go.mod"), []byte(`module hermes`), 0o644); err != nil {
		t.Fatal(err)
	}
	finding := filepath.Join(hermes, "main.go")
	if err := os.WriteFile(finding, []byte(`package main`), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := NewClassifier(home)
	if err != nil {
		t.Fatalf("NewClassifier: %v", err)
	}
	info, _ := c.Classify(finding)
	if info.Class != ClassCodeProject {
		t.Errorf("with .hermes removed from agent_state_dirs, .hermes/main.go should be code-project (has go.mod); got %v (info=%+v)", info.Class, info)
	}
	if info.Label != ".hermes" {
		t.Errorf("expected Label=.hermes (the project root), got %q", info.Label)
	}
}

// TestClassify_TOMLOverrideMalformed: bad TOML degrades gracefully to
// the defaults. Daemon must NOT crash on user error.
func TestClassify_TOMLOverrideMalformed(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".audr"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".audr", "classify.toml"), []byte(`agent_state_dirs = `), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := NewClassifier(home)
	if err == nil {
		t.Fatal("expected NewClassifier to return an error for malformed TOML")
	}
	// The error should describe what failed, but the caller (daemon)
	// is expected to log + retry without crashing.
}

// TestClassify_EmptyPath returns ClassOSPackage and no error.
func TestClassify_EmptyPath(t *testing.T) {
	c := newTestClassifier(t)
	info, err := c.Classify("")
	if err != nil {
		t.Errorf("empty path should not error: %v", err)
	}
	if info.Class != ClassOSPackage {
		t.Errorf("expected ClassOSPackage, got %v", info.Class)
	}
}

// TestClassify_NonExistentPath: a path that doesn't exist on disk
// shouldn't crash. EvalSymlinks fails for non-existent paths; we fall
// back to the abs form and classify it as ClassLoose (or whatever
// rule its segments match).
func TestClassify_NonExistentPath(t *testing.T) {
	c := newTestClassifier(t)
	info, err := c.Classify("/no/such/path/file.go")
	if err != nil {
		t.Errorf("non-existent path should not error: %v", err)
	}
	// Without any signals, falls through to ClassLoose.
	if info.Class != ClassLoose {
		t.Errorf("expected ClassLoose for non-existent unknown path, got %v", info.Class)
	}
}
