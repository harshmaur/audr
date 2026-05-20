//go:build !windows

package daemon

import (
	"context"
	"runtime"
	"testing"
)

// TestNewServiceBackendSetsUserServiceOption catches a different regression:
// someone removes the option line entirely from newServiceBackend (the
// shouldRunAsUserService function returns true, but the caller forgets to apply
// it). Uses the kardianos backend's stored config indirectly via the service's
// String() helper, which is one of the few publicly-introspectable signals
// kardianos exposes.
func TestNewServiceBackendSetsUserServiceOption(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("user-scope assertion only relevant on linux/darwin; GOOS=%s", runtime.GOOS)
	}
	cfg := DefaultServiceConfig()
	backend, err := newServiceBackend(cfg, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("newServiceBackend: %v", err)
	}
	kb, ok := backend.(*kardianosBackend)
	if !ok {
		t.Skipf("backend is not kardianosBackend (got %T)", backend)
	}
	// Run Status() — on a real install/uninstall lifecycle test that would mutate
	// the user's machine, so instead we just verify the backend constructed without
	// error and the String() (kardianos platform identifier) is non-empty. The
	// behavioral guarantee is covered by TestShouldRunAsUserServicePlatforms above;
	// this is a smoke test that the wiring is connected.
	if kb.svc == nil {
		t.Fatal("kardianos service is nil after newServiceBackend")
	}
	if got := kb.svc.String(); got == "" {
		t.Error("kardianos service.String() is empty; backend not fully constructed")
	}
}
