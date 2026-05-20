//go:build windows

package daemon

// shouldRunAsUserService reports whether the daemon registers at per-user
// scope. Windows uses the schtasks backend rather than kardianos UserService,
// so this is always false on Windows. The non-Windows implementation lives in
// service_kardianos.go next to the kardianos backend wiring.
func shouldRunAsUserService() bool {
	return false
}
