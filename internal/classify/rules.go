package classify

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// rules is the in-memory representation of the classifier's
// configuration. Loaded from defaultRulesTOML and overlaid with
// ~/.audr/classify.toml when present.
//
// Field tags use TOML names directly so a custom rules.toml stays
// human-editable.
type rules struct {
	// Manifests is the list of filenames that mark a directory as
	// the root of a code-project. Default list covers Go, Node,
	// Python, Rust, Ruby, Java, PHP.
	Manifests []string `toml:"manifests"`

	// AgentStateDirs is the list of dot-dir basenames whose contents
	// are AI-agent state (Claude Code, Codex, Hermes, etc.). Matches
	// ANY segment of the finding's path → ANY descendant classifies
	// as agent-state regardless of nested manifests.
	AgentStateDirs []string `toml:"agent_state_dirs"`

	// SystemDirs is the list of dot-dir basenames whose contents are
	// system / cache state (.local, .config, etc.). Same matching
	// semantics as AgentStateDirs.
	SystemDirs []string `toml:"system_dirs"`
}

// classifyDotDirSegment reports whether seg matches a known
// agent-state or system dot-dir. Returns the matched Class and ok=true
// on match. Used by Classifier.classifyUncached's left-to-right
// segment scan.
//
// Agent-state checked first because agent-state is the primary noise
// story in the design.
func (r *rules) classifyDotDirSegment(seg string) (Class, bool) {
	for _, d := range r.AgentStateDirs {
		if d == seg {
			return ClassAgentState, true
		}
	}
	for _, d := range r.SystemDirs {
		if d == seg {
			return ClassSystem, true
		}
	}
	return "", false
}

//go:embed default_rules.toml
var defaultRulesTOML []byte

// loadRules parses defaultRulesTOML, then overlays ~/.audr/classify.toml
// if present. If the override file exists but fails to parse, the
// classifier falls back to the defaults and reports the parse error to
// the caller (which logs a warning and continues — bad config should
// degrade gracefully, not crash the daemon).
func loadRules(homeDir string) (*rules, error) {
	var r rules
	if err := toml.Unmarshal(defaultRulesTOML, &r); err != nil {
		return nil, fmt.Errorf("parse embedded defaults: %w", err)
	}

	if homeDir == "" {
		return &r, nil
	}

	override := filepath.Join(homeDir, ".audr", "classify.toml")
	data, err := os.ReadFile(override)
	if err != nil {
		// No override file is the common case; not an error.
		if os.IsNotExist(err) {
			return &r, nil
		}
		return &r, fmt.Errorf("read override %q: %w", override, err)
	}

	// Overlay semantics: override REPLACES default lists (rather than
	// merging). Users who want to "add a manifest" copy the defaults
	// + their addition. Simpler than merge semantics and avoids the
	// "how do I REMOVE a default" problem.
	var ovr rules
	if err := toml.Unmarshal(data, &ovr); err != nil {
		return &r, fmt.Errorf("parse override %q: %w", override, err)
	}
	if len(ovr.Manifests) > 0 {
		r.Manifests = ovr.Manifests
	}
	if len(ovr.AgentStateDirs) > 0 {
		r.AgentStateDirs = ovr.AgentStateDirs
	}
	if len(ovr.SystemDirs) > 0 {
		r.SystemDirs = ovr.SystemDirs
	}
	return &r, nil
}
