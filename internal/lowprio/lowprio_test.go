package lowprio

import (
	"context"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestRunnerCapturesStdout pins the basic happy path: Run executes
// the binary and returns its stdout. Stderr stays separate.
//
// Uses /bin/sh -c so the test doesn't depend on any specific binary
// being on PATH. Skipped on Windows where the shell layout differs.
func TestRunnerCapturesStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-shell test; Windows would need a different invocation")
	}
	out, err := Runner{}.Run(context.Background(), "/bin/sh", "-c", "echo hello-stdout; echo hello-stderr 1>&2")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != "hello-stdout" {
		t.Errorf("stdout = %q, want hello-stdout (stderr should not be in stdout)", got)
	}
}

// TestRunnerCapsGoSchedulerCPU verifies daemon sidecars launched via
// lowprio.Runner inherit GOMAXPROCS=1. Betterleaks is Go-based, so
// this caps its runtime scheduler to one CPU during daemon scans even
// if its own file walk would otherwise fan out across cores.
func TestRunnerCapsGoSchedulerCPU(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-shell test; Windows would need a different invocation")
	}
	out, err := Runner{}.Run(context.Background(), "/bin/sh", "-c", "printf %s \"$GOMAXPROCS\"")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != "1" {
		t.Errorf("GOMAXPROCS = %q, want 1", got)
	}
}

// TestRunnerReportsNonZeroExit covers the failure path: a non-zero
// child exit returns an error with the stderr text folded in.
func TestRunnerReportsNonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-shell test")
	}
	_, err := Runner{}.Run(context.Background(), "/bin/sh", "-c", "echo problem 1>&2; exit 7")
	if err == nil {
		t.Fatal("Run: want error on non-zero exit, got nil")
	}
	if !strings.Contains(err.Error(), "problem") {
		t.Errorf("error should fold in stderr text 'problem', got: %v", err)
	}
}

// TestRunnerActuallyDropsPriority verifies the child process runs at
// the expected reduced priority. On Linux/macOS the priority value
// is exposed via /proc/<pid>/stat (Linux) or in `ps -o nice` output.
// We use the latter since it's portable across both.
//
// The shell command prints its own nice value (via `ps -p $$ -o nice=`)
// and exits. We assert that value is the expected nice 19 (Linux/macOS)
// or that we got SOMETHING back (Windows uses BELOW_NORMAL_PRIORITY_CLASS
// which doesn't surface a numeric nice in `ps`).
func TestRunnerActuallyDropsPriority(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses priority class, not numeric nice — see TestRunnerWindowsLowPriority")
	}
	// Runner applies the nice drop immediately after Start. macOS can let the
	// child shell reach ps before that post-start setpriority call lands, so keep
	// this probe deliberately slower than a scheduler tick instead of racing the
	// parent and intermittently observing the inherited nice value.
	out, err := Runner{}.Run(context.Background(), "/bin/sh", "-c", "sleep 0.25; ps -p $$ -o nice= 2>/dev/null")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := strings.TrimSpace(string(out))
	n, err := strconv.Atoi(got)
	if err != nil {
		t.Fatalf("could not parse nice value %q: %v", got, err)
	}
	// nice 19 is the target. Some kernels clamp differently, so we
	// accept anything >= 10 as "meaningfully reduced." A normal
	// process is at 0; we'd never be there with the post-start
	// drop applied. If this assertion fails the priority drop
	// silently no-op'd somehow.
	if n < 10 {
		t.Errorf("child nice = %d, want >= 10 (priority drop should have applied)", n)
	}
}

// TestRunnerWindowsLowPriority is the Windows analogue of
// TestRunnerActuallyDropsPriority. It can't read a nice value via
// `ps` so it probes priority via PowerShell's
// (Get-Process -Id $PID).PriorityClass which returns one of the
// PROCESS_PRIORITY_CLASS names (Idle, BelowNormal, Normal,
// AboveNormal, High, RealTime).
//
// Asserts the child reports "BelowNormal" — the priority class set
// by applyPreStart. IoPriorityHintLow doesn't surface in this query;
// verifying that needs SetThreadInformation-readable counterparts
// and a per-thread test which we don't write here (the syscall is
// stateless and either succeeds or no-ops gracefully — the
// applyPostStart contract).
//
// Runs only on Windows; skipped elsewhere.
func TestRunnerWindowsLowPriority(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific priority-class test")
	}
	// `powershell -Command "(Get-Process -Id $PID).PriorityClass"` prints
	// the enum name as text. $PID expands to the PowerShell process's
	// own PID — which is the process Runner started.
	out, err := Runner{}.Run(context.Background(), "powershell.exe",
		"-NoProfile", "-Command", "(Get-Process -Id $PID).PriorityClass")
	if err != nil {
		t.Fatalf("Run powershell: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != "BelowNormal" {
		t.Errorf("PriorityClass = %q, want BelowNormal", got)
	}
}
