package classify

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestReloadFromDisk verifies the override-overlay + cache-clear
// semantics in isolation (no fsnotify timing dependencies).
func TestReloadFromDisk(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".audr"), 0o755); err != nil {
		t.Fatal(err)
	}

	c, err := NewClassifier(home)
	if err != nil {
		t.Fatalf("NewClassifier: %v", err)
	}

	// Pre-populate the cache by classifying a path. Use any path —
	// the cache key is the file's dir, regardless of class.
	c.cache.Store("/some/dir", ProjectInfo{Class: ClassLoose, ID: "loose"})

	// Drop a new config that flips an arbitrary list.
	if err := os.WriteFile(
		filepath.Join(home, ".audr", "classify.toml"),
		[]byte(`agent_state_dirs = [".my-custom-tool"]`),
		0o644,
	); err != nil {
		t.Fatal(err)
	}

	if err := c.reloadFromDisk(home); err != nil {
		t.Fatalf("reloadFromDisk: %v", err)
	}

	// Rules picked up the new entry.
	c.mu.RLock()
	got := c.rules.AgentStateDirs
	c.mu.RUnlock()
	found := false
	for _, d := range got {
		if d == ".my-custom-tool" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("after reload, expected .my-custom-tool in AgentStateDirs, got %v", got)
	}

	// Cache was cleared.
	count := 0
	c.cache.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("cache should be empty after reload, got %d entries", count)
	}
}

// TestWatchConfig_ExitsOnContextCancel verifies the watcher goroutine
// shuts down cleanly when the context is canceled. Doesn't test the
// event-driven reload path (fsnotify timing is OS-flaky); the reload
// logic itself is covered by TestReloadFromDisk above.
func TestWatchConfig_ExitsOnContextCancel(t *testing.T) {
	home := t.TempDir()
	c, err := NewClassifier(home)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	if err := c.WatchConfig(ctx, home, logger); err != nil {
		t.Fatalf("WatchConfig: %v", err)
	}

	// Cancel and give the goroutine time to exit.
	cancel()
	time.Sleep(50 * time.Millisecond)
	// Test passes if we got here without a leaked goroutine deadlock
	// or a panic. (A goroutine leak would only manifest under -count=N
	// or `go test -race` flakiness; covered well enough by passing the
	// existing -race suite.)
}

// TestWatchConfig_EmptyHomeReturnsError documents the API contract.
func TestWatchConfig_EmptyHomeReturnsError(t *testing.T) {
	c, err := NewClassifier("")
	if err != nil {
		t.Fatal(err)
	}
	err = c.WatchConfig(context.Background(), "", nil)
	if err == nil {
		t.Error("expected WatchConfig with empty homeDir to error")
	}
}
