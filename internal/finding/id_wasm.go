//go:build js && wasm

package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// StableID returns the first 12 hex characters of the finding fingerprint.
func (f Finding) StableID() string {
	fp, err := f.Fingerprint()
	if err != nil {
		return ""
	}
	if len(fp) < 12 {
		return fp
	}
	return fp[:12]
}

// Fingerprint returns a deterministic file-finding hash for the browser WASM
// build without importing internal/state's SQLite-backed package graph.
func (f Finding) Fingerprint() (string, error) {
	locatorBytes, err := json.Marshal(map[string]any{
		"path": f.Path,
		"line": f.Line,
	})
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(fingerprintRuleIDWASM(f.RuleID)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte("file"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(locatorBytes)
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(f.Match))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fingerprintRuleIDWASM(ruleID string) string {
	switch ruleID {
	case "secret-betterleaks-valid", "secret-betterleaks-unverified":
		return "secret-betterleaks"
	default:
		return ruleID
	}
}
