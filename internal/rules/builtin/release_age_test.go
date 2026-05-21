package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

func releaseAgeFindings(path, raw string) int {
	doc := parse.Parse(path, []byte(raw))
	count := 0
	for _, f := range rules.Apply(doc) {
		if f.RuleID == "dependency-minimum-release-age-missing" {
			count++
		}
	}
	return count
}

func TestDependencyMinimumReleaseAgeDetectFormat(t *testing.T) {
	cases := map[string]parse.Format{
		"/repo/bunfig.toml":              parse.FormatReleaseAgeConfig,
		"/repo/.npmrc":                   parse.FormatReleaseAgeConfig,
		"/repo/pnpm-workspace.yaml":      parse.FormatReleaseAgeConfig,
		"/repo/.yarnrc.yml":              parse.FormatReleaseAgeConfig,
		"/repo/renovate.json":            parse.FormatReleaseAgeConfig,
		"/repo/.github/dependabot.yml":   parse.FormatReleaseAgeConfig,
		"/repo/.github/workflows/ci.yml": parse.FormatGHAWorkflow,
		"/repo/pyproject.toml":           parse.FormatDependencyManifest,
		"/repo/package.json":             parse.FormatPackageJSON,
		"/repo/random/dependabot.yml":    parse.FormatUnknown,
	}
	for path, want := range cases {
		if got := parse.DetectFormat(path); got != want {
			t.Fatalf("DetectFormat(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestDependencyMinimumReleaseAgeBun(t *testing.T) {
	if got := releaseAgeFindings("/repo/bunfig.toml", "[install]\nminimumReleaseAge = 864000\n"); got != 0 {
		t.Fatalf("compliant Bun config findings = %d, want 0", got)
	}
	if got := releaseAgeFindings("/repo/bunfig.toml", "[install]\nminimumReleaseAge = 604800\n"); got == 0 {
		t.Fatal("weak Bun release age produced no finding")
	}
	if got := releaseAgeFindings("/repo/bunfig.toml", "[install]\nminimumReleaseAge = 864000\nminimumReleaseAgeExcludes = [\"@myorg/*\"]\n"); got == 0 {
		t.Fatal("broad Bun bypass produced no finding")
	}
}

func TestDependencyMinimumReleaseAgeNPM(t *testing.T) {
	if got := releaseAgeFindings("/repo/.npmrc", "min-release-age=10\n"); got != 0 {
		t.Fatalf("compliant npm config findings = %d, want 0", got)
	}
	if got := releaseAgeFindings("/repo/.npmrc", "min-release-age=7\n"); got == 0 {
		t.Fatal("weak npm release age produced no finding")
	}
	if got := releaseAgeFindings("/repo/.npmrc", "registry=https://registry.npmjs.org/\n"); got == 0 {
		t.Fatal("missing npm release age produced no finding")
	}
}

func TestDependencyMinimumReleaseAgePNPM(t *testing.T) {
	if got := releaseAgeFindings("/repo/pnpm-workspace.yaml", "minimumReleaseAge: 14400\n"); got != 0 {
		t.Fatalf("compliant pnpm config findings = %d, want 0", got)
	}
	if got := releaseAgeFindings("/repo/pnpm-workspace.yaml", "minimumReleaseAge: 10080\n"); got == 0 {
		t.Fatal("weak pnpm release age produced no finding")
	}
	if got := releaseAgeFindings("/repo/pnpm-workspace.yaml", "minimumReleaseAge: 14400\nminimumReleaseAgeExclude:\n  - '@myorg/*'\n"); got == 0 {
		t.Fatal("broad pnpm bypass produced no finding")
	}
}

func TestDependencyMinimumReleaseAgeYarn(t *testing.T) {
	if got := releaseAgeFindings("/repo/.yarnrc.yml", "npmMinimalAgeGate: \"10d\"\n"); got != 0 {
		t.Fatalf("compliant Yarn config findings = %d, want 0", got)
	}
	if got := releaseAgeFindings("/repo/.yarnrc.yml", "npmMinimalAgeGate: \"7d\"\n"); got == 0 {
		t.Fatal("weak Yarn release age produced no finding")
	}
	if got := releaseAgeFindings("/repo/.yarnrc.yml", "npmMinimalAgeGate: \"10d\"\nnpmPreapprovedPackages:\n  - \"*\"\n"); got == 0 {
		t.Fatal("broad Yarn bypass produced no finding")
	}
}

func TestDependencyMinimumReleaseAgeUV(t *testing.T) {
	compliant := "[project]\ndependencies = [\"requests\"]\n[tool.uv]\nexclude-newer = \"10d\"\n"
	if got := releaseAgeFindings("/repo/pyproject.toml", compliant); got != 0 {
		t.Fatalf("compliant uv config findings = %d, want 0", got)
	}
	weak := "[project]\ndependencies = [\"requests\"]\n[tool.uv]\nexclude-newer = \"7d\"\n"
	if got := releaseAgeFindings("/repo/pyproject.toml", weak); got == 0 {
		t.Fatal("weak uv exclude-newer produced no finding")
	}
	missing := "[project]\ndependencies = [\"requests\"]\n"
	if got := releaseAgeFindings("/repo/pyproject.toml", missing); got == 0 {
		t.Fatal("missing uv exclude-newer produced no finding")
	}
}

func TestDependencyMinimumReleaseAgeRenovate(t *testing.T) {
	if got := releaseAgeFindings("/repo/renovate.json", `{"minimumReleaseAge":"10 days"}`); got != 0 {
		t.Fatalf("compliant Renovate config findings = %d, want 0", got)
	}
	if got := releaseAgeFindings("/repo/renovate.json", `{"minimumReleaseAge":"7 days"}`); got == 0 {
		t.Fatal("weak Renovate release age produced no finding")
	}
	if got := releaseAgeFindings("/repo/renovate.json", `{"packageRules":[{"matchPackageNames":["left-pad"],"minimumReleaseAge":null}]}`); got == 0 {
		t.Fatal("Renovate disabled cooldown bypass produced no finding")
	}
}

func TestDependencyMinimumReleaseAgeDependabot(t *testing.T) {
	compliant := "updates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n    cooldown:\n      default-days: 10\n"
	if got := releaseAgeFindings("/repo/.github/dependabot.yml", compliant); got != 0 {
		t.Fatalf("compliant Dependabot config findings = %d, want 0", got)
	}
	weak := "updates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n    cooldown:\n      default-days: 7\n"
	if got := releaseAgeFindings("/repo/.github/dependabot.yml", weak); got == 0 {
		t.Fatal("weak Dependabot cooldown produced no finding")
	}
	missing := "updates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n"
	if got := releaseAgeFindings("/repo/.github/dependabot.yml", missing); got == 0 {
		t.Fatal("missing Dependabot cooldown produced no finding")
	}
}

func TestDependencyMinimumReleaseAgePackageJSONRecommendation(t *testing.T) {
	if got := releaseAgeFindings("/repo/package.json", `{"dependencies":{"left-pad":"^1.3.0"}}`); got == 0 {
		t.Fatal("package.json with dependencies produced no release-age recommendation")
	}
	if got := releaseAgeFindings("/repo/package.json", `{"name":"empty"}`); got != 0 {
		t.Fatalf("package.json without dependencies findings = %d, want 0", got)
	}
}
