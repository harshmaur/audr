package builtin

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type pnpmLockfileMissingIntegrity struct{}
type pnpmUnscopedAuthTokenRegistryForwarding struct{}

func (pnpmLockfileMissingIntegrity) ID() string { return "pnpm-lockfile-missing-integrity" }
func (pnpmLockfileMissingIntegrity) Title() string {
	return "pnpm lockfile contains tarball resolutions without integrity"
}
func (pnpmLockfileMissingIntegrity) Severity() finding.Severity { return finding.SeverityMedium }
func (pnpmLockfileMissingIntegrity) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (pnpmLockfileMissingIntegrity) Formats() []parse.Format {
	return []parse.Format{parse.FormatDependencyManifest}
}
func (pnpmLockfileMissingIntegrity) Apply(doc *parse.Document) []finding.Finding {
	if !isPNPMLockfile(doc.Path) {
		return nil
	}
	line, match := firstPNPMTarballResolutionMissingIntegrity(string(doc.Raw))
	if line == 0 {
		return nil
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "pnpm-lockfile-missing-integrity",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        "pnpm-lock.yaml has a tarball resolution without integrity",
		Description:  "CVE-2026-50021: pnpm before 10.34.0 / 11.4.0 can skip tarball integrity verification when pnpm-lock.yaml resolution entries omit integrity, allowing altered registry responses to be installed with --frozen-lockfile.",
		Path:         doc.Path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Upgrade pnpm to 10.34.0 / 11.4.0 or later, then regenerate pnpm-lock.yaml so every tarball resolution includes an integrity value.",
		Tags:         []string{"cve", "pnpm", "lockfile", "integrity"},
	})}
}

func isPNPMLockfile(path string) bool {
	return filepath.Base(filepath.ToSlash(path)) == "pnpm-lock.yaml"
}

func firstPNPMTarballResolutionMissingIntegrity(raw string) (int, string) {
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "resolution:") || strings.Contains(trimmed, "integrity:") {
			continue
		}
		indent := leadingSpaces(line)
		blockEnd := len(lines)
		hasTarball := strings.Contains(trimmed, "tarball:") || strings.Contains(trimmed, "http://") || strings.Contains(trimmed, "https://")
		hasIntegrity := false
		for j := i + 1; j < len(lines); j++ {
			candidate := lines[j]
			candidateTrimmed := strings.TrimSpace(candidate)
			if candidateTrimmed == "" || strings.HasPrefix(candidateTrimmed, "#") {
				continue
			}
			if leadingSpaces(candidate) <= indent {
				blockEnd = j
				break
			}
			if strings.HasPrefix(candidateTrimmed, "integrity:") {
				hasIntegrity = true
			}
			if strings.HasPrefix(candidateTrimmed, "tarball:") || strings.Contains(candidateTrimmed, "http://") || strings.Contains(candidateTrimmed, "https://") {
				hasTarball = true
			}
		}
		if hasTarball && !hasIntegrity {
			return i + 1, summarizePNPMResolution(lines[i:blockEnd])
		}
	}
	return 0, ""
}

func leadingSpaces(s string) int {
	count := 0
	for _, r := range s {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func summarizePNPMResolution(lines []string) string {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "tarball:") || strings.Contains(trimmed, "http://") || strings.Contains(trimmed, "https://") {
			return trimmed
		}
	}
	if len(lines) == 0 {
		return "resolution missing integrity"
	}
	return fmt.Sprintf("%s (missing integrity)", strings.TrimSpace(lines[0]))
}

func (pnpmUnscopedAuthTokenRegistryForwarding) ID() string {
	return "pnpm-unscoped-auth-token-registry-forwarding"
}
func (pnpmUnscopedAuthTokenRegistryForwarding) Title() string {
	return "pnpm can forward an unscoped npm token to a repository registry"
}
func (pnpmUnscopedAuthTokenRegistryForwarding) Severity() finding.Severity {
	return finding.SeverityMedium
}
func (pnpmUnscopedAuthTokenRegistryForwarding) Taxonomy() finding.Taxonomy {
	return finding.TaxDetectable
}
func (pnpmUnscopedAuthTokenRegistryForwarding) Formats() []parse.Format {
	return []parse.Format{parse.FormatReleaseAgeConfig}
}

func (pnpmUnscopedAuthTokenRegistryForwarding) Apply(doc *parse.Document) []finding.Finding {
	if filepath.Base(filepath.ToSlash(doc.Path)) != ".npmrc" {
		return nil
	}
	tokenLine, tokenMatch := firstUnscopedNPMAuthTokenLine(string(doc.Raw))
	if tokenLine == 0 || !npmrcSetsRegistry(string(doc.Raw)) {
		return nil
	}
	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "pnpm-unscoped-auth-token-registry-forwarding",
		Severity:     finding.SeverityMedium,
		Taxonomy:     finding.TaxDetectable,
		Title:        ".npmrc combines a registry override with an unscoped auth token",
		Description:  "CVE-2026-50017: pnpm before 10.34.0 / 11.4.0 could bind user-level unscoped npm credentials to a repository-selected registry. A .npmrc that combines registry= with _authToken= is the local posture that can leak credentials when vulnerable pnpm versions are used.",
		Path:         doc.Path,
		Line:         tokenLine,
		Match:        tokenMatch,
		SuggestedFix: "Upgrade pnpm to 10.34.0 / 11.4.0 or later. Remove unscoped _authToken entries and scope tokens to their intended registry host, for example //registry.npmjs.org/:_authToken=..., before running pnpm in untrusted workspaces.",
		Tags:         []string{"cve", "pnpm", "npmrc", "credential-leak", "registry"},
	})}
}

func firstUnscopedNPMAuthTokenLine(raw string) (int, string) {
	for i, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "_authToken=") {
			return i + 1, "_authToken=<redacted>"
		}
	}
	return 0, ""
}

func npmrcSetsRegistry(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "registry=") {
			return true
		}
	}
	return false
}
