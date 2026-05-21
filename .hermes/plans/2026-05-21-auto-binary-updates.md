# Plan: automatic AUDR binary updates

## Goal
Ship the fast bridge before dynamic rule bundles: let existing daemon users receive daily rule-bearing AUDR releases automatically after one upgrade.

## Scope for this pass
1. Add a reusable `internal/selfupdate` package that can:
   - resolve the latest stable GitHub Release;
   - download the platform artifact plus `SHA256SUMS`, `.sig`, and `.crt`;
   - verify with existing `internal/verify`;
   - extract the `audr` binary;
   - atomically replace the installed binary with rollback backup.
2. Add `audr update`:
   - `--check` prints current/latest;
   - default prompts before replacing;
   - `--yes` runs non-interactively;
   - `--version` pins a specific tag;
   - `--install-path` supports tests/custom installs.
3. Add daemon update preference commands:
   - `audr daemon updates --status|--on|--off`.
4. Wire daemon auto-update conservatively:
   - default off until user enables it;
   - if enabled, verified self-update runs after the existing updater sees a newer release;
   - failed updates never stop scanning.

## Not in scope today
- Dynamic rule bundles.
- Custom rule DSL.
- Update channels beyond stable GitHub Releases.
- Windows auto-restart perfection. Keep Windows compile-safe and prefer manual update there if replacement semantics are unsafe.

## Verification
- Unit tests for self-update planning/install using local HTTP fixtures.
- Focused tests: `go test ./internal/selfupdate ./internal/updater ./cmd/audr`.
- Build: `go build -o audr ./cmd/audr`.
