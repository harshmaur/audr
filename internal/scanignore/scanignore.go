// Package scanignore owns the canonical list of directory path-segments
// audr never scans.
//
// Two consumers today:
//
//   - audr's native walker (internal/scan) — passes these as base-name skips.
//   - Betterleaks shell-outs (internal/secretscan) — materialized to a
//     `.betterleaks.toml` config passed via `--config` (allowlist paths).
//
// Centralizing here avoids drift between the two surfaces. When the daemon
// (Phase 1+) lands, the watch+poll engine and OS-pkg enumerator also consume
// these via Defaults().
package scanignore

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DaemonAdditionalSegments lists path segments the long-running daemon
// excludes on top of Defaults(). These intentionally do NOT live in
// Defaults() because explicit `audr scan <ROOT>` runs — including the
// CI fixture scans of testdata/laptops/dirty + testdata/laptops/clean
// — need to walk through them. The daemon's broad $HOME scan, however,
// would otherwise descend into every project's testdata/ tree and
// surface its intentionally-bad fixtures (planted MCP configs, planted
// shell rcs, planted credential-shape tokens) as if they were real
// developer-machine findings. Excluding `testdata` segments in
// daemon-mode keeps the dashboard signal honest without breaking the
// explicit-fixture-scan path other tools rely on.
//
// The orchestrator (daemon-only) injects these into each scanner
// subsystem's exclude inputs. scan.Options.SkipDirs is extended with
// these, secretscan.RunOptions.ExtraExcludeSegments forwards them to
// the betterleaks config, watch.Options.ExtraExcludeSegments forwards
// them to the watcher's exclude set. One-shot `audr scan` calls never
// touch the orchestrator and therefore never see these.
func DaemonAdditionalSegments() []string {
	return []string{
		"testdata",
	}
}

// Defaults returns the canonical list of path-segments audr skips during
// recursive scans. Each entry is either:
//
//   - a single-segment basename ("node_modules") matched against any
//     path component, OR
//   - a multi-segment relative path ("go/pkg", ".cargo/registry")
//     matched as a contiguous subsequence of path components.
//
// New entries belong here, not in scattered constants across scanners.
// Single-segment entries are checked with O(1) per dir during a walk;
// multi-segment entries with PathExcluded() which does a path-component
// subsequence match.
func Defaults() []string {
	return []string{
		// Build artifacts / vendored / VCS metadata.
		// Parity with internal/scan/scan.go skip list.
		"node_modules",
		"vendor",
		".git",
		"dist",
		"build",
		"target",
		"__pycache__",
		".next",
		".cache",

		// Python virtualenvs.
		".venv",
		"venv",

		// Per-language tool caches at $HOME root. These are top-level
		// dirs that are 100%-cache: skipping them whole is safe (the
		// user's actual code lives in ~/code or ~/projects, not in
		// these tool-internal dirs).
		".bun",        // Bun's install cache + globals
		".pnpm-store", // pnpm global content-addressed cache
		".yarn",       // Yarn's cache + global/install state
		".deno",       // Deno's module cache
		".gem",        // RubyGems user cache
		".m2",         // Maven local repository
		".gradle",     // Gradle build + dependency cache
		".cargo",      // Rust crates cache (registry + git + bin)

		// Multi-segment cache paths (sub-paths within larger dirs the
		// user might legitimately also have CODE in — e.g., ~/go has
		// both pkg/mod (cache) AND src (potentially user repos)).
		"go/pkg",             // Go module cache
		".npm/_cacache",      // npm install cache (keep .npm/global)
		".npm/_npx",          // npx ephemeral package extracts — rotate on every `npx <pkg>` run
		".npm/_logs",         // npm debug logs — rotate on every install/error
		".gradle/caches",     // explicit second match in case .gradle isn't matched at root
		"Library/Caches",     // macOS user caches
		"AppData/Local/Temp", // Windows user temp
		"AppData/Local/Microsoft/Windows/INetCache",

		// audr's own SQLite state directory. Scanning it triggers a
		// self-amplifying loop: betterleaks reads audr.db (binary),
		// matches generic-api-key / jwt / private-key bytes inside the
		// page data, and emits hundreds-to-thousands of findings per
		// scan. Those findings get persisted back into audr.db, which
		// changes the file, shifts the byte offsets, mutates the
		// fingerprints next cycle, and the resolve-detector marks the
		// old fingerprints resolved while opening brand-new rows for
		// the same bytes under different offsets. The "Resolved today"
		// metric balloons into the hundreds of thousands with zero real
		// remediation work. (Same shape as the browser-DB churn the
		// list above already mitigates.) BinaryFileExtensions below
		// excludes the .db / .db-wal / .db-shm files generally; this
		// path entry is the belt-and-suspenders self-exclusion so any
		// future non-DB state file audr drops here is also skipped.
		".local/state/audr",

		// Browser user-data directories. These hold SQLite DBs
		// (History, Cookies, Favicons), extension assets, and
		// component-update payloads that auto-rotate on a sub-hourly
		// cadence. Trufflehog's URI detector fires on the URLs packed
		// inside, producing hundreds of false positives per scan and
		// — because the files rotate — a churn loop where old
		// fingerprints get marked resolved and new ones open. Net
		// effect: "Resolved Today" inflates without bound while the
		// real signal is buried. Excluding these directories drops
		// daemon noise by >95% on a typical developer machine.
		// Linux:
		".config/BraveSoftware",
		".config/google-chrome",
		".config/chromium",
		".config/microsoft-edge",
		".mozilla/firefox",
		// macOS:
		"Library/Application Support/BraveSoftware",
		"Library/Application Support/Google/Chrome",
		"Library/Application Support/Chromium",
		"Library/Application Support/Microsoft Edge",
		"Library/Application Support/Firefox",
		// Windows:
		"AppData/Local/BraveSoftware/Brave-Browser/User Data",
		"AppData/Local/Google/Chrome/User Data",
		"AppData/Local/Chromium/User Data",
		"AppData/Local/Microsoft/Edge/User Data",
		"AppData/Roaming/Mozilla/Firefox",
	}
}

// BinaryFileExtensions returns the file-extension allowlist that
// the external secret scanner should NEVER inspect. These are
// compiled / packaged binary outputs where regex detectors hit random
// byte sequences that look like URLs or tokens and produce
// non-deterministic findings (different "matches" every scan). The
// native walker doesn't use this list — it dispatches rules per-rule
// which already specify the path glob they care about, so binary
// files are filtered upstream there.
//
// Why exclude rather than tune detectors: the cheapest fix is to
// skip the file entirely. Real secrets in source code are still
// caught; real secrets baked into a compiled binary are an
// exfiltration concern, not a leak-prevention concern, and belong
// to a different scanner anyway.
func BinaryFileExtensions() []string {
	return []string{
		// Mobile build outputs
		"apk", // Android package
		"aab", // Android App Bundle
		"ipa", // iOS app archive
		"dex", // Dalvik executable inside APKs
		// Native / shared libraries
		"so",    // Linux shared object
		"dll",   // Windows dynamic library
		"dylib", // macOS dynamic library
		"o",     // object file
		"a",     // static archive
		"lib",   // Windows static library
		// JVM bytecode + archives
		"class", // Java compiled class
		"jar",   // Java archive
		"war",   // Web application archive
		"ear",   // Enterprise archive
		// Executables
		"exe", // Windows executable
		"bin", // generic binary
		"img", // disk / firmware image
		"iso", // CD image
		// Archives (also frequently full of false-positive entropy)
		"zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar",
		// Compiled python / wheels
		"pyc", "pyo", "whl",
		// SQLite-family databases. Apps write redacted secrets,
		// session tokens, URLs, and JWT-shaped page metadata into
		// these as routine state; betterleaks's regex detectors hit
		// the bytes and emit thousands of false positives per scan.
		// Worse, the WAL/SHM sidecars rotate on every write, so the
		// daemon's fingerprint hashes shift between scans, mass-
		// resolving old rows and opening new ones for the same bytes —
		// the "Resolved today" counter inflates without bound. Covers
		// audr's own audr.db (single biggest offender — 99% of the
		// reported phantom resolutions in one user repro), plus
		// .hermes/state.db, .codex/logs_*.sqlite, and the entire
		// state-snapshot trees Hermes/Codex keep around for rollback.
		"db", "db-wal", "db-shm",
		"sqlite", "sqlite3",
		"sqlite-wal", "sqlite-shm",
		// Media (rare false positives but worth excluding — never source for secrets)
		"png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tiff",
		"mp3", "mp4", "mov", "avi", "wav", "flac", "ogg", "webm",
		"pdf", "psd", "ai", "eps",
		"woff", "woff2", "ttf", "otf", "eot",
	}
}

// WriteBetterleaksConfig materializes Defaults() + binary extensions
// into a `.betterleaks.toml` tempfile suitable for passing via
// `betterleaks dir --config`. Returns the tempfile path and a
// cleanup func the caller MUST call (typically via defer).
//
// Shape:
//
//	[extend]
//	useDefault = true            # load betterleaks's shipped rule set
//
//	[[allowlists]]
//	description = "audr exclude segments"
//	paths = [
//	  '''(^|/)node_modules(/|$)''',
//	  ...
//	  '''\.apk$''',
//	  ...
//	]
//
// Two pattern families:
//
//   - Directory entries (from Defaults()) become
//     `(^|/)<escaped-segment>(/|$)` so they match the segment as a
//     real path component, not as a substring (e.g., `node_modules`
//     matches `./node_modules/foo` but not `node_modules.lock`).
//   - File-extension entries (from BinaryFileExtensions()) become
//     `\.<ext>$` so they match the suffix of the candidate path
//     case-sensitively. Lowercase only; APKs from the wild use
//     lowercase suffixes universally.
//
// Patterns use TOML literal strings (triple single quotes) so
// backslashes in `\.apk$` etc. don't need escaping.
func WriteBetterleaksConfig() (path string, cleanup func(), err error) {
	return WriteBetterleaksConfigWithExtras(nil)
}

// WriteBetterleaksConfigWithExtras is WriteBetterleaksConfig with an
// extra set of single-segment names appended to the allowlist. Used by
// the daemon to inject DaemonAdditionalSegments() (e.g. "testdata")
// without changing Defaults() — explicit `audr scan` calls keep the
// unchanged path-allowlist behavior. extraSegments may be nil.
func WriteBetterleaksConfigWithExtras(extraSegments []string) (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "audr-betterleaks-*.toml")
	if err != nil {
		return "", nil, fmt.Errorf("create betterleaks config tempfile: %w", err)
	}
	cleanup = func() {
		_ = os.Remove(f.Name())
	}
	defer f.Close()

	write := func(s string) error {
		if _, err := f.WriteString(s); err != nil {
			cleanup()
			return fmt.Errorf("write betterleaks config: %w", err)
		}
		return nil
	}

	if err := write("# audr-generated betterleaks config. Do not edit by hand.\n"); err != nil {
		return "", nil, err
	}
	if err := write("[extend]\nuseDefault = true\n\n"); err != nil {
		return "", nil, err
	}
	if err := write("[[allowlists]]\ndescription = \"audr exclude segments\"\npaths = [\n"); err != nil {
		return "", nil, err
	}
	for _, segment := range Defaults() {
		if err := write("  '''" + patternForSegment(segment) + "''',\n"); err != nil {
			return "", nil, err
		}
	}
	for _, segment := range extraSegments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		if err := write("  '''" + patternForSegment(segment) + "''',\n"); err != nil {
			return "", nil, err
		}
	}
	for _, ext := range BinaryFileExtensions() {
		if err := write("  '''" + patternForExtension(ext) + "''',\n"); err != nil {
			return "", nil, err
		}
	}
	if err := write("]\n"); err != nil {
		return "", nil, err
	}

	return f.Name(), cleanup, nil
}

// patternForExtension converts a file extension into a regex pattern
// that matches the end of a path.
func patternForExtension(ext string) string {
	return `\.` + regexp.QuoteMeta(ext) + `$`
}

// patternForSegment converts a Defaults() entry into a regex pattern
// that matches the segment as a path component.
func patternForSegment(segment string) string {
	const sep = `[\\/]`
	parts := splitPathSegments(strings.TrimSpace(segment))
	if len(parts) == 0 {
		return `a^`
	}
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return `(^|` + sep + `)` + strings.Join(parts, sep) + `(` + sep + `|$)`
}

// PathExcluded reports whether the given path contains any of the
// Defaults() entries as path-component subsequences. Used by walkers
// to skip cache trees, build artifacts, and VCS metadata before
// descending into them.
//
// Single-segment entries (e.g., "node_modules") match if any path
// component equals them. Multi-segment entries (e.g., "go/pkg") match
// if their components appear contiguously somewhere in the path.
//
// Path is normalized to forward-slash separators before matching, so
// Windows-style paths work identically.
func PathExcluded(path string) bool {
	if path == "" {
		return false
	}
	segs := splitPathSegments(path)
	for _, entry := range Defaults() {
		entrySegs := splitPathSegments(entry)
		if len(entrySegs) == 0 {
			continue
		}
		if containsSegmentSubsequence(segs, entrySegs) {
			return true
		}
	}
	return false
}

// IsExcludedBaseName is the fast-path check: returns true iff the
// given basename matches any single-segment entry in Defaults(). Use
// this in walk callbacks where you only have the directory's
// basename without computing the full path.
//
// Multi-segment entries (e.g., "go/pkg", ".cargo/registry") return
// false here — callers that need them must use PathExcluded() with
// the full path.
func IsExcludedBaseName(name string) bool {
	for _, entry := range Defaults() {
		if !strings.ContainsRune(entry, '/') && entry == name {
			return true
		}
	}
	return false
}

// LooksLikeGoStdlibSrcRoot returns true when path is the `src`
// subdirectory of a Go installation tree (GOROOT/src). Structural
// detection: looks for a sibling `bin/go` (or `bin/go.exe` on
// Windows) alongside `src`, which is the canonical layout for every
// Go install — system package, manual tarball, gvm/asdf/goenv,
// `~/.local/go` user-install.
//
// This can't be a basename-only or component-subsequence skip:
//
//   - "src" alone is too greedy (every project has a src/ directory).
//   - "go/src" alone is too greedy (collides with $GOPATH/src where
//     user code lives, and with any project nested under a dir named
//     "go"). Structural confirmation via the sibling binary is what
//     distinguishes "this is GOROOT/src" from "this is just a src/
//     under a dir that happens to be named 'go'".
//
// Why this matters: scanning Go's stdlib emits hundreds of false-
// positive findings (`crypto/`, `runtime/`, etc. contain example
// tokens and test vectors that secret-pattern rules legitimately
// fire on). The user can't fix Go's stdlib; treating it as in-scope
// just pollutes the dashboard.
//
// Not skipped: $GOPATH/src (user code lives there) or $GOPATH/pkg/mod
// (handled by the multi-segment "go/pkg" entry in Defaults() above).
//
// Three call sites today:
//
//   - internal/scan walker — invoked per-directory during the file walk.
//   - internal/depscan project-root discovery + lockfile fingerprinting.
//   - secretscan / betterleaks does NOT call this directly; its skip
//     list comes from PathExcluded() + WriteBetterleaksConfig() which
//     are statically-typed regex patterns. The walker-side skip handles
//     it before betterleaks ever sees the stdlib path.
func LooksLikeGoStdlibSrcRoot(path string) bool {
	if filepath.Base(path) != "src" {
		return false
	}
	parent := filepath.Dir(path)
	if filepath.Base(parent) != "go" {
		return false
	}
	// Confirm with sibling `bin/go` (or `bin/go.exe` on Windows).
	if _, err := os.Stat(filepath.Join(parent, "bin", "go")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(parent, "bin", "go.exe")); err == nil {
		return true
	}
	return false
}

// splitPathSegments normalizes a path to forward slashes and splits
// it into non-empty components.
func splitPathSegments(p string) []string {
	// Convert backslashes to slashes for Windows paths.
	p = strings.ReplaceAll(p, `\`, "/")
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// containsSegmentSubsequence reports whether needle appears as a
// contiguous subsequence of haystack. Pure component matching, not
// substring: ["foo","bar","baz"] contains ["bar","baz"] but not
// ["bar","ba"].
func containsSegmentSubsequence(haystack, needle []string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		ok := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
