package classify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchConfig starts a goroutine that watches ~/.audr/classify.toml.
// On change: reload the override into c.rules and clear the directory
// cache (since classification of every cached directory may differ
// under the new rules).
//
// Behavior is intentionally conservative:
//
//   - Watches the parent directory (~/.audr/) rather than the file
//     directly. Editors that rename-then-write (vim, helix, mosaic)
//     would otherwise lose the watch on the original inode after the
//     first save.
//
//   - Debounces rapid sequential events with a 200ms window. A single
//     :w in vim can fire 3-5 events (Create, Remove, Rename, Write);
//     we don't want to reload N times.
//
//   - If ~/.audr/ doesn't exist yet, we still start the watcher and
//     poll for the directory to appear. Cheap (1 stat / 5s) and lets
//     users create the config file after the daemon is already
//     running.
//
//   - On reload parse error: log and keep the previous rules. Bad
//     config does not crash the daemon.
//
// Cancel via ctx. The watcher exits cleanly when ctx.Done fires.
//
// homeDir must match the value passed to NewClassifier. logger MAY be
// nil; when nil, watch events log via slog.Default().
func (c *Classifier) WatchConfig(ctx context.Context, homeDir string, logger *slog.Logger) error {
	if homeDir == "" {
		return errors.New("WatchConfig: empty homeDir")
	}
	if logger == nil {
		logger = slog.Default()
	}

	configDir := filepath.Join(homeDir, ".audr")
	configPath := filepath.Join(configDir, "classify.toml")

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("classify: fsnotify.NewWatcher: %w", err)
	}

	// addWatch (re)registers the watch when the directory exists.
	// Returns true if the directory was successfully watched.
	addWatch := func() bool {
		if _, err := os.Stat(configDir); err != nil {
			return false
		}
		if err := w.Add(configDir); err != nil {
			logger.Debug("classify: fsnotify add", "dir", configDir, "err", err)
			return false
		}
		return true
	}

	watching := addWatch()

	go func() {
		defer w.Close()

		// Poll ticker: if ~/.audr/ doesn't exist yet, periodically
		// check for it. Cheap. Stops once the watch succeeds.
		pollTick := time.NewTicker(5 * time.Second)
		defer pollTick.Stop()

		// Debounce: collapses rapid event bursts into one reload.
		var debounceTimer *time.Timer
		debounceCh := make(chan struct{}, 1)

		scheduleReload := func() {
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(200*time.Millisecond, func() {
				select {
				case debounceCh <- struct{}{}:
				default:
				}
			})
		}

		for {
			select {
			case <-ctx.Done():
				return

			case <-pollTick.C:
				if !watching {
					watching = addWatch()
				}

			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				// Only act on events touching the target file.
				if filepath.Base(ev.Name) != "classify.toml" {
					continue
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
					scheduleReload()
				}

			case <-debounceCh:
				if err := c.reloadFromDisk(homeDir); err != nil {
					logger.Warn("classify: reload classify.toml failed; keeping previous rules", "err", err, "path", configPath)
					continue
				}
				logger.Info("classify: reloaded classify.toml", "path", configPath)

			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				logger.Debug("classify: fsnotify error", "err", err)
			}
		}
	}()
	return nil
}

// reloadFromDisk parses the override file and atomically swaps it in
// alongside a cache clear. Caller (the WatchConfig goroutine) catches
// the error and decides whether to log and continue.
func (c *Classifier) reloadFromDisk(homeDir string) error {
	r, err := loadRules(homeDir)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.rules = r
	c.mu.Unlock()

	// Clear the cache: every cached directory's classification may
	// change under the new rules.
	c.cache.Range(func(k, _ any) bool {
		c.cache.Delete(k)
		return true
	})
	return nil
}
