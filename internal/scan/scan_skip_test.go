package scan

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestWalkRoot_SkipsGoStdlib asserts the walker prunes the Go stdlib
// subtree entirely. The fake GOROOT contains a file that would otherwise
// be enqueued for parsing (a package.json under GOROOT/src/crypto/).
// After the skip, the walker emits zero paths from that subtree.
func TestWalkRoot_SkipsGoStdlib(t *testing.T) {
	tmp := t.TempDir()
	// Fake GOROOT
	goRoot := filepath.Join(tmp, ".local", "go")
	cryptoDir := filepath.Join(goRoot, "src", "crypto")
	binDir := filepath.Join(goRoot, "bin")
	if err := os.MkdirAll(cryptoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Sibling bin/go to trigger the structural check.
	binGo := "go"
	if runtime.GOOS == "windows" {
		binGo = "go.exe"
	}
	if err := os.WriteFile(filepath.Join(binDir, binGo), []byte("fake"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A file under the stdlib tree that would otherwise be enqueued.
	// .go isn't a format audr's scanner detects by default for secrets,
	// so we plant a package.json which DetectFormat recognizes.
	stdlibFile := filepath.Join(cryptoDir, "package.json")
	if err := os.WriteFile(stdlibFile, []byte(`{"name":"fake"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Control file: a regular project's package.json that SHOULD be enqueued.
	projDir := filepath.Join(tmp, "projects", "myapp")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	projFile := filepath.Join(projDir, "package.json")
	if err := os.WriteFile(projFile, []byte(`{"name":"myapp"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Collect every path the walker emits.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	out := make(chan string, 64)
	go func() {
		walkRoot(ctx, tmp, map[string]bool{}, out, logger, nil)
		close(out)
	}()
	seen := map[string]bool{}
	for p := range out {
		seen[p] = true
	}

	if seen[stdlibFile] {
		t.Errorf("walker emitted %q from inside fake Go stdlib — skip not applied", stdlibFile)
	}
	if !seen[projFile] {
		t.Errorf("walker did NOT emit %q — control project skipped by mistake", projFile)
	}
}
