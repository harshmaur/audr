package builtin

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

const (
	xyqDramaSkillDownloadURL = "https://douyin-cloud.tos-cn-beijing.volces.com/obj/hosts/log-helper"
	xyqDramaSkillC2Domain    = "s62fhr06buoa937godru4.apigateway-cn-beijing.volceapi.com"
)

var xyqDramaSkillKnownSourceSHA256 = map[string]string{
	"/setup.py":                   "06663cfed7234c3b4899803c654b33f65850cd1569b8739302f5809c16ae4f81",
	"/xyq_drama_skill/_helper.py": "e93f5a6258036cf233118b4c35ef262ab26b3fce38133c1658faf93e5130fd42",
}

type xyqDramaSkillLogHelperIOC struct{}

func (xyqDramaSkillLogHelperIOC) ID() string { return "xyq-drama-skill-log-helper-ioc" }
func (xyqDramaSkillLogHelperIOC) Title() string {
	return "xyq-drama-skill hidden log-helper malware indicator present"
}
func (xyqDramaSkillLogHelperIOC) Severity() finding.Severity { return finding.SeverityCritical }
func (xyqDramaSkillLogHelperIOC) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (xyqDramaSkillLogHelperIOC) Formats() []parse.Format {
	return []parse.Format{parse.FormatPyPIMalwareArtifact}
}

func (xyqDramaSkillLogHelperIOC) Apply(doc *parse.Document) []finding.Finding {
	if doc.Format != parse.FormatPyPIMalwareArtifact || !parse.IsXYQDramaSkillArtifactPath(doc.Path) {
		return nil
	}

	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(doc.Path), `\`, "/"))
	match := ""
	line := 1
	if parse.IsXYQDramaSkillDropPath(normalized) {
		match = "xyq-drama-skill hidden ~/.log-helper drop path"
	} else {
		if isXYQDramaSkillKnownSourceHash(normalized, doc.Raw) {
			match = "known malicious xyq-drama-skill source SHA-256"
		} else {
			lower := strings.ToLower(string(doc.Raw))
			hasDownload := strings.Contains(lower, xyqDramaSkillDownloadURL)
			hasDrop := strings.Contains(lower, ".log-helper")
			hasLaunch := strings.Contains(lower, "popen") &&
				(strings.Contains(lower, "start_new_session") || strings.Contains(lower, "setsid"))
			switch {
			case strings.Contains(lower, xyqDramaSkillC2Domain):
				match = "xyq-drama-skill command-and-control domain"
				line = findLineContaining(doc.Raw, xyqDramaSkillC2Domain)
			case hasDownload && hasDrop && hasLaunch:
				match = "xyq-drama-skill log-helper download and detached-launch markers"
				line = findLineContaining(doc.Raw, "douyin-cloud.tos-cn-beijing.volces.com")
			default:
				return nil
			}
		}
	}

	return []finding.Finding{finding.New(finding.Args{
		RuleID:       "xyq-drama-skill-log-helper-ioc",
		Severity:     finding.SeverityCritical,
		Taxonomy:     finding.TaxDetectable,
		Title:        "xyq-drama-skill hidden log-helper malware indicator present",
		Description:  "This bounded path, hash, or source marker matches the July 2026 xyq-drama-skill PyPI campaign that downloaded a likely COFFLoader beacon to ~/.log-helper and launched it detached during installation or console-script execution.",
		Path:         doc.Path,
		Line:         line,
		Match:        match,
		SuggestedFix: "Isolate the machine, preserve the payload and package files for incident response, remove xyq-drama-skill and ~/.log-helper after containment, rebuild the Python environment from trusted manifests, and rotate developer, source-control, cloud, and CI credentials reachable from the host.",
		Tags:         []string{"xyq-drama-skill", "pypi", "supply-chain", "coffloader", "credential-theft", "malware"},
	})}
}

func isXYQDramaSkillKnownSourceHash(path string, raw []byte) bool {
	normalized := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	for suffix, want := range xyqDramaSkillKnownSourceSHA256 {
		if strings.HasSuffix(normalized, suffix) && strings.EqualFold(digest, want) {
			return true
		}
	}
	return false
}
