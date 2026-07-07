package builtin

import (
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
)

type vLLMFlashInferDependencyConfusion struct{}

func (vLLMFlashInferDependencyConfusion) ID() string { return "vllm-flashinfer-dependency-confusion" }
func (vLLMFlashInferDependencyConfusion) Title() string {
	return "vLLM Dockerfile can install flashinfer-jit-cache from PyPI"
}
func (vLLMFlashInferDependencyConfusion) Severity() finding.Severity { return finding.SeverityHigh }
func (vLLMFlashInferDependencyConfusion) Taxonomy() finding.Taxonomy { return finding.TaxDetectable }
func (vLLMFlashInferDependencyConfusion) Formats() []parse.Format {
	return []parse.Format{parse.FormatDockerfile}
}

func (vLLMFlashInferDependencyConfusion) Apply(doc *parse.Document) []finding.Finding {
	if doc.Format != parse.FormatDockerfile {
		return nil
	}
	raw := string(doc.Raw)
	lower := strings.ToLower(raw)
	if !strings.Contains(lower, "flashinfer-jit-cache") {
		return nil
	}
	if !strings.Contains(lower, "--extra-index-url") || !strings.Contains(lower, "flashinfer.ai/whl") {
		return nil
	}
	if !strings.Contains(lower, "uv_index_strategy") || !strings.Contains(lower, "unsafe-best-match") {
		return nil
	}
	line, context := firstLineContaining(raw, "flashinfer-jit-cache")
	return []finding.Finding{finding.New(finding.Args{
		RuleID:        "vllm-flashinfer-dependency-confusion",
		Severity:      finding.SeverityHigh,
		Taxonomy:      finding.TaxDetectable,
		Title:         "vLLM Dockerfile uses dependency-confusion-prone flashinfer install",
		Description:   "CVE-2026-54232: vLLM before 0.22.1 used a Dockerfile build posture that installed flashinfer-jit-cache via --extra-index-url while UV_INDEX_STRATEGY=unsafe-best-match was set, allowing a malicious PyPI package with a higher/better version to execute during image builds.",
		Path:          doc.Path,
		Line:          line,
		Match:         "flashinfer-jit-cache",
		Context:       context,
		SuggestedFix:  "Upgrade vLLM to 0.22.1 or later. Remove UV_INDEX_STRATEGY=unsafe-best-match for this build, pin flashinfer-jit-cache to a trusted index with index-strategy first-index or an equivalent index constraint, and rebuild any images produced from the vulnerable Dockerfile.",
		Tags:          []string{"cve", "vllm", "dockerfile", "dependency-confusion", "supply-chain"},
		DedupGroupKey: "vllm-flashinfer-dependency-confusion:" + filepath.ToSlash(doc.Path),
	})}
}

func firstLineContaining(raw, needle string) (int, string) {
	needleLower := strings.ToLower(needle)
	for i, line := range strings.Split(raw, "\n") {
		if strings.Contains(strings.ToLower(line), needleLower) {
			return i + 1, strings.TrimSpace(line)
		}
	}
	return 0, ""
}
