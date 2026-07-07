package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestRule_vLLMFlashInferDependencyConfusion(t *testing.T) {
	dockerfile := strings.Join([]string{
		"FROM python:3.12",
		"ENV UV_INDEX_STRATEGY=unsafe-best-match",
		"RUN uv pip install --extra-index-url https://flashinfer.ai/whl/ flashinfer-jit-cache==0.6.11.post2",
	}, "\n")
	doc := parse.Parse("/repo/Dockerfile", []byte(dockerfile))
	if doc.Format != parse.FormatDockerfile {
		t.Fatalf("format = %q, want %q", doc.Format, parse.FormatDockerfile)
	}
	findings := (vLLMFlashInferDependencyConfusion{}).Apply(doc)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1; rules fired: %v", len(findings), applyRule(doc))
	}
	if findings[0].Line != 3 {
		t.Fatalf("line = %d, want 3", findings[0].Line)
	}
}

func TestRule_vLLMFlashInferDependencyConfusionRequiresUnsafeBestMatch(t *testing.T) {
	dockerfile := strings.Join([]string{
		"FROM python:3.12",
		"ENV UV_INDEX_STRATEGY=first-index",
		"RUN uv pip install --extra-index-url https://flashinfer.ai/whl/ flashinfer-jit-cache==0.6.11.post2",
	}, "\n")
	doc := parse.Parse("/repo/Dockerfile", []byte(dockerfile))
	if fired(doc, "vllm-flashinfer-dependency-confusion") {
		t.Fatalf("did not expect safe index strategy to fire; rules fired: %v", applyRule(doc))
	}
}

func TestRule_vLLMFlashInferDependencyConfusionRequiresFlashInferIndex(t *testing.T) {
	dockerfile := strings.Join([]string{
		"FROM python:3.12",
		"ENV UV_INDEX_STRATEGY=unsafe-best-match",
		"RUN uv pip install flashinfer-jit-cache==0.6.11.post2",
	}, "\n")
	doc := parse.Parse("/repo/Dockerfile.gpu", []byte(dockerfile))
	if fired(doc, "vllm-flashinfer-dependency-confusion") {
		t.Fatalf("did not expect package name without flashinfer extra index to fire; rules fired: %v", applyRule(doc))
	}
}
