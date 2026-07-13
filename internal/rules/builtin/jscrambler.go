package builtin

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

const jscramblerPayloadSHA256 = "a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86"

var jscramblerPayloadMagic = []byte{0x1b, 0x43, 0x53, 0x49, 0x01}

type jscramblerMaliciousPayloadIOC struct{}

func (jscramblerMaliciousPayloadIOC) ID() string { return "jscrambler-malicious-payload-ioc" }
func (jscramblerMaliciousPayloadIOC) Title() string {
	return "Jscrambler npm compromise payload present"
}
func (jscramblerMaliciousPayloadIOC) Severity() finding.Severity {
	return finding.SeverityCritical
}
func (jscramblerMaliciousPayloadIOC) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (jscramblerMaliciousPayloadIOC) Formats() []parse.Format {
	return []parse.Format{parse.FormatNPMMalwareArtifact}
}

func (jscramblerMaliciousPayloadIOC) Apply(doc *parse.Document) []finding.Finding {
	path := filepath.ToSlash(doc.Path)
	base := filepath.Base(path)
	match := ""
	line := 1

	if strings.HasSuffix(path, "/node_modules/jscrambler/dist/intro.js") {
		digest := fmt.Sprintf("%x", sha256.Sum256(doc.Raw))
		if digest == jscramblerPayloadSHA256 {
			match = "known malicious dist/intro.js SHA-256"
		} else if bytes.HasPrefix(doc.Raw, jscramblerPayloadMagic) {
			match = "malicious dist/intro.js container magic"
		}
	} else if isJscramblerDropperPath(path) && containsJscramblerDropperSource(doc.Raw) {
		match = "dist/intro.js native-payload dropper"
		line = findLineContaining(doc.Raw, "intro.js")
	}

	if match == "" {
		return nil
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "jscrambler-malicious-payload-ioc",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "Jscrambler npm compromise payload present",
		Description:  "This file matches the bounded package-root payload or dropper used in the July 2026 compromise of the official jscrambler npm package. The payload steals browser and Bitwarden data and establishes Windows or macOS persistence.",
		Path:         doc.Path,
		Line:         line,
		Match:        match + " (" + base + ")",
		SuggestedFix: "Isolate the machine, preserve evidence, remove affected jscrambler versions, reinstall dependencies from a clean lockfile, audit scheduled tasks and LaunchAgents, and rotate browser, Bitwarden, npm, and developer credentials exposed on the host.",
		Tags:         []string{"jscrambler", "npm", "supply-chain", "infostealer", "malware"},
	})}
}

func isJscramblerDropperPath(path string) bool {
	return strings.HasSuffix(path, "/node_modules/jscrambler/dist/setup.js") ||
		strings.HasSuffix(path, "/node_modules/jscrambler/dist/index.js") ||
		strings.HasSuffix(path, "/node_modules/jscrambler/dist/bin/jscrambler.js")
}

func containsJscramblerDropperSource(raw []byte) bool {
	lower := strings.ToLower(string(raw))
	return strings.Contains(lower, "intro.js") &&
		strings.Contains(lower, "0x1b") &&
		strings.Contains(lower, "0x43") &&
		strings.Contains(lower, "0x53") &&
		strings.Contains(lower, "0x49") &&
		strings.Contains(lower, "gunzipsync") &&
		strings.Contains(lower, "spawn") &&
		strings.Contains(lower, "detached")
}
