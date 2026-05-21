package builtin

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/harshmaur/audr/internal/finding"
	"github.com/harshmaur/audr/internal/parse"
	"gopkg.in/yaml.v3"
)

const recommendedMinimumReleaseAgeDays = 10
const recommendedMinimumReleaseAgeSeconds = recommendedMinimumReleaseAgeDays * 24 * 60 * 60
const recommendedMinimumReleaseAgeMinutes = recommendedMinimumReleaseAgeDays * 24 * 60

type dependencyMinimumReleaseAgeMissing struct{}

func (dependencyMinimumReleaseAgeMissing) ID() string {
	return "dependency-minimum-release-age-missing"
}
func (dependencyMinimumReleaseAgeMissing) Title() string {
	return "Dependency updates do not enforce a 10-day minimum release age"
}
func (dependencyMinimumReleaseAgeMissing) Severity() finding.Severity { return finding.SeverityHigh }
func (dependencyMinimumReleaseAgeMissing) Taxonomy() finding.Taxonomy { return finding.TaxAdvisory }
func (dependencyMinimumReleaseAgeMissing) Formats() []parse.Format {
	return []parse.Format{parse.FormatPackageJSON, parse.FormatDependencyManifest, parse.FormatReleaseAgeConfig}
}

func (dependencyMinimumReleaseAgeMissing) Apply(doc *parse.Document) []finding.Finding {
	if doc == nil {
		return nil
	}
	base := filepath.Base(normalizePathSlashes(doc.Path))
	switch doc.Format {
	case parse.FormatPackageJSON:
		if doc.PackageJSON == nil || !packageJSONHasDependencies(doc.PackageJSON) {
			return nil
		}
		return []finding.Finding{releaseAgeFinding(doc, "JavaScript dependencies are present but AUDR did not see a native minimum-release-age policy in package.json. Configure npm/Bun/pnpm/Yarn or your dependency bot to wait at least 10 days before installing newly published packages.", releaseAgeSnippetFor("javascript"), 0, "package.json")}
	case parse.FormatDependencyManifest:
		if base != "pyproject.toml" || doc.DependencyManifest == nil || len(doc.DependencyManifest.Dependencies) == 0 {
			return nil
		}
		if ok, age, line := uvReleaseAgeOK(doc.Raw); ok {
			if age >= recommendedMinimumReleaseAgeDays {
				return nil
			}
			return []finding.Finding{releaseAgeFinding(doc, fmt.Sprintf("uv exclude-newer is configured for %d days, below AUDR's recommended 10-day release-age gate.", age), releaseAgeSnippetFor("uv"), line, "exclude-newer")}
		}
		return []finding.Finding{releaseAgeFinding(doc, "Python dependencies are present but uv's exclude-newer release-age gate is missing. Configure a 10-day gate for normal dependency resolution and keep emergency bypasses scoped and documented.", releaseAgeSnippetFor("uv"), 0, "pyproject.toml")}
	case parse.FormatReleaseAgeConfig:
		return checkReleaseAgeConfig(doc, base)
	default:
		return nil
	}
}

func checkReleaseAgeConfig(doc *parse.Document, base string) []finding.Finding {
	raw := string(doc.Raw)
	switch base {
	case "bunfig.toml":
		age, line, ok := findIntAssignment(raw, `(?m)^\s*minimumReleaseAge\s*=\s*([0-9]+)\b`)
		if !ok {
			return []finding.Finding{releaseAgeFinding(doc, "Bun install.minimumReleaseAge is missing. Add a 10-day age gate so newly published packages have time to be detected and yanked before installation.", releaseAgeSnippetFor("bun"), 0, "minimumReleaseAge")}
		}
		if age < recommendedMinimumReleaseAgeSeconds {
			return []finding.Finding{releaseAgeFinding(doc, fmt.Sprintf("Bun minimumReleaseAge is %d seconds, below AUDR's recommended 864000 seconds (10 days).", age), releaseAgeSnippetFor("bun"), line, "minimumReleaseAge")}
		}
		return broadBypassFindings(doc, raw, `minimumReleaseAgeExcludes\s*=\s*\[([^\]]*)\]`, "Bun minimumReleaseAgeExcludes contains a broad package bypass. Keep emergency bypasses package+version scoped where possible and document advisory, approver, and expiry.")
	case ".npmrc":
		age, line, ok := findIntAssignment(raw, `(?m)^\s*min-release-age\s*=\s*([0-9]+)\b`)
		if !ok {
			return []finding.Finding{releaseAgeFinding(doc, "npm min-release-age is missing. npm v11.10+ can delay newly published packages; configure at least 10 days and use audited one-off bypasses for emergency security patches.", releaseAgeSnippetFor("npm"), 0, "min-release-age")}
		}
		if age < recommendedMinimumReleaseAgeDays {
			return []finding.Finding{releaseAgeFinding(doc, fmt.Sprintf("npm min-release-age is %d days, below AUDR's recommended 10 days.", age), releaseAgeSnippetFor("npm"), line, "min-release-age")}
		}
		return nil
	case "pnpm-workspace.yaml":
		age, line, ok := findIntAssignment(raw, `(?m)^\s*minimumReleaseAge\s*:\s*([0-9]+)\b`)
		if !ok {
			return []finding.Finding{releaseAgeFinding(doc, "pnpm minimumReleaseAge is missing. Configure a 10-day release-age gate (14400 minutes) for normal installs.", releaseAgeSnippetFor("pnpm"), 0, "minimumReleaseAge")}
		}
		if age < recommendedMinimumReleaseAgeMinutes {
			return []finding.Finding{releaseAgeFinding(doc, fmt.Sprintf("pnpm minimumReleaseAge is %d minutes, below AUDR's recommended 14400 minutes (10 days).", age), releaseAgeSnippetFor("pnpm"), line, "minimumReleaseAge")}
		}
		return broadBypassFindings(doc, raw, `(?s)minimumReleaseAgeExclude\s*:\s*(.*)`, "pnpm minimumReleaseAgeExclude contains a broad package bypass. Prefer exact package@version exclusions for emergency security fixes.")
	case ".yarnrc.yml":
		age, line, ok := findDurationAssignment(raw, `(?m)^\s*npmMinimalAgeGate\s*:\s*['\"]?([^'\"#\n]+)['\"]?`)
		if !ok {
			return []finding.Finding{releaseAgeFinding(doc, "Yarn npmMinimalAgeGate is missing. Configure a 10-day npm package age gate for normal installs.", releaseAgeSnippetFor("yarn"), 0, "npmMinimalAgeGate")}
		}
		if age < recommendedMinimumReleaseAgeDays {
			return []finding.Finding{releaseAgeFinding(doc, fmt.Sprintf("Yarn npmMinimalAgeGate is %d days, below AUDR's recommended 10 days.", age), releaseAgeSnippetFor("yarn"), line, "npmMinimalAgeGate")}
		}
		return broadBypassFindings(doc, raw, `(?s)npmPreapprovedPackages\s*:\s*(.*)`, "Yarn npmPreapprovedPackages contains a broad package bypass. Prefer package descriptor / exact-version preapproval for emergency security fixes.")
	case "renovate.json", "renovate.json5":
		return checkRenovate(doc)
	case "dependabot.yml", "dependabot.yaml":
		return checkDependabot(doc)
	default:
		return nil
	}
}

func releaseAgeFinding(doc *parse.Document, desc, fix string, line int, match string) finding.Finding {
	return finding.New(finding.Args{
		RuleID:       "dependency-minimum-release-age-missing",
		Severity:     finding.SeverityHigh,
		Taxonomy:     finding.TaxAdvisory,
		Title:        "Dependency updates should wait at least 10 days before installing new releases",
		Description:  desc,
		Path:         doc.Path,
		Line:         line,
		Match:        match,
		SuggestedFix: fix,
		Tags:         []string{"supply-chain", "dependency", "minimum-release-age", "hardening"},
	})
}

func releaseAgeSnippetFor(tool string) string {
	switch tool {
	case "bun":
		return "bunfig.toml:\n[install]\nminimumReleaseAge = 864000\n# For emergency security fixes, use the narrowest package exclusion and document advisory, approver, and expiry."
	case "npm":
		return ".npmrc:\nmin-release-age=10\n# For emergency security fixes, use a documented one-off install/update with explicit approval rather than permanently setting this to 0."
	case "pnpm":
		return "pnpm-workspace.yaml:\nminimumReleaseAge: 14400\n# Emergency bypasses should prefer exact package@version entries in minimumReleaseAgeExclude."
	case "yarn":
		return ".yarnrc.yml:\nnpmMinimalAgeGate: \"10d\"\n# Emergency bypasses should prefer exact package descriptors in npmPreapprovedPackages."
	case "uv":
		return "pyproject.toml:\n[tool.uv]\nexclude-newer = \"10d\"\n# Emergency bypasses should use exclude-newer-package with package-specific evidence and review date."
	case "renovate":
		return "renovate.json:\n{\n  \"minimumReleaseAge\": \"10 days\",\n  \"description\": \"Security updates may bypass cooldown; emergency exceptions must be package-scoped with advisory, approver, and expiry.\"\n}"
	case "dependabot":
		return ".github/dependabot.yml:\nupdates:\n  - package-ecosystem: npm\n    directory: /\n    schedule:\n      interval: daily\n    cooldown:\n      default-days: 10\n# Dependabot security updates bypass cooldown; keep normal updates delayed."
	default:
		return "Configure a native package-manager or dependency-bot minimum release age of at least 10 days, with narrow documented emergency bypasses."
	}
}

func packageJSONHasDependencies(pkg *parse.PackageJSON) bool {
	return len(pkg.Dependencies)+len(pkg.DevDependencies)+len(pkg.OptionalDependencies)+len(pkg.PeerDependencies) > 0
}

func uvReleaseAgeOK(raw []byte) (bool, int, int) {
	age, line, ok := findDurationAssignment(string(raw), `(?m)^\s*exclude-newer\s*=\s*['\"]([^'\"]+)['\"]`)
	return ok, age, line
}

func checkRenovate(doc *parse.Document) []finding.Finding {
	raw := string(doc.Raw)
	if regexp.MustCompile(`(?i)"minimumReleaseAge"\s*:\s*(null|"0\s*(?:day|days|d)?")`).MatchString(raw) {
		line := releaseAgeFindLineContaining(raw, "minimumReleaseAge")
		return []finding.Finding{releaseAgeFinding(doc, "Renovate minimumReleaseAge is disabled globally or in a package rule. Keep release-age bypasses narrow, package-scoped, and documented with advisory URL, approver, and expiry.", releaseAgeSnippetFor("renovate"), line, "minimumReleaseAge")}
	}
	ages := regexp.MustCompile(`(?i)"minimumReleaseAge"\s*:\s*"([^"]+)"`).FindAllStringSubmatch(raw, -1)
	best := 0
	for _, m := range ages {
		if d, ok := parseAgeDays(m[1]); ok && d > best {
			best = d
		}
	}
	if best >= recommendedMinimumReleaseAgeDays {
		return nil
	}
	if best > 0 {
		line := releaseAgeFindLineContaining(raw, "minimumReleaseAge")
		return []finding.Finding{releaseAgeFinding(doc, fmt.Sprintf("Renovate minimumReleaseAge is %d days, below AUDR's recommended 10 days.", best), releaseAgeSnippetFor("renovate"), line, "minimumReleaseAge")}
	}
	return []finding.Finding{releaseAgeFinding(doc, "Renovate is configured without minimumReleaseAge. Add a 10-day cooldown for normal updates; Renovate security updates can still bypass the cooldown.", releaseAgeSnippetFor("renovate"), 0, "minimumReleaseAge")}
}

func checkDependabot(doc *parse.Document) []finding.Finding {
	var top map[string]any
	if err := yaml.Unmarshal(doc.Raw, &top); err != nil {
		return nil
	}
	best := maxDependabotCooldownDays(top)
	if best >= recommendedMinimumReleaseAgeDays {
		return nil
	}
	if best > 0 {
		line := releaseAgeFindLineContaining(string(doc.Raw), "cooldown")
		return []finding.Finding{releaseAgeFinding(doc, fmt.Sprintf("Dependabot cooldown is %d days, below AUDR's recommended 10 days for normal version updates.", best), releaseAgeSnippetFor("dependabot"), line, "cooldown")}
	}
	return []finding.Finding{releaseAgeFinding(doc, "Dependabot is configured without cooldown. Add a 10-day cooldown for normal version updates; Dependabot security updates bypass cooldown by design.", releaseAgeSnippetFor("dependabot"), 0, "cooldown")}
}

func maxDependabotCooldownDays(v any) int {
	max := 0
	walkAny(v, func(key string, val any) {
		if !strings.HasSuffix(key, "days") {
			return
		}
		if n := numericAny(val); n > max {
			max = n
		}
	})
	return max
}

func walkAny(v any, visit func(string, any)) {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			visit(k, v)
			walkAny(v, visit)
		}
	case []any:
		for _, v := range x {
			walkAny(v, visit)
		}
	}
}

func numericAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func broadBypassFindings(doc *parse.Document, raw, expr, desc string) []finding.Finding {
	re := regexp.MustCompile(expr)
	m := re.FindStringSubmatch(raw)
	if len(m) == 0 {
		return nil
	}
	body := m[len(m)-1]
	if hasBroadBypass(body) {
		return []finding.Finding{releaseAgeFinding(doc, desc, "Replace broad release-age bypasses (for example '*' or '@scope/*') with exact package@version exceptions and include advisory URL, approver, and expiry/review date.", releaseAgeFindLineContaining(raw, strings.TrimSpace(strings.Split(m[0], "\n")[0])), strings.TrimSpace(truncate(m[0], 120)))}
	}
	return nil
}

func hasBroadBypass(s string) bool {
	for _, pat := range []string{"\"*\"", "'*'", "@*/*", "/*", "*"} {
		if strings.Contains(s, pat) {
			return true
		}
	}
	return regexp.MustCompile(`@[A-Za-z0-9_.-]+/\*`).MatchString(s)
}

func findIntAssignment(raw, expr string) (int, int, bool) {
	re := regexp.MustCompile(expr)
	loc := re.FindStringSubmatchIndex(raw)
	if loc == nil {
		return 0, 0, false
	}
	value := raw[loc[2]:loc[3]]
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, 0, false
	}
	return n, strings.Count(raw[:loc[0]], "\n") + 1, true
}

func findDurationAssignment(raw, expr string) (int, int, bool) {
	re := regexp.MustCompile(expr)
	loc := re.FindStringSubmatchIndex(raw)
	if loc == nil {
		return 0, 0, false
	}
	value := strings.TrimSpace(raw[loc[2]:loc[3]])
	days, ok := parseAgeDays(value)
	return days, strings.Count(raw[:loc[0]], "\n") + 1, ok
}

func parseAgeDays(s string) (int, bool) {
	s = strings.ToLower(strings.TrimSpace(strings.Trim(s, `"'`)))
	re := regexp.MustCompile(`([0-9]+)\s*(days?|d|weeks?|w|hours?|h|minutes?|m)?`)
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	unit := m[2]
	switch {
	case strings.HasPrefix(unit, "week") || unit == "w":
		return n * 7, true
	case strings.HasPrefix(unit, "hour") || unit == "h":
		return n / 24, true
	case strings.HasPrefix(unit, "minute") || unit == "m":
		return n / (24 * 60), true
	default:
		return n, true
	}
}

func releaseAgeFindLineContaining(raw, needle string) int {
	idx := strings.Index(raw, needle)
	if idx < 0 {
		return 0
	}
	return strings.Count(raw[:idx], "\n") + 1
}

func normalizePathSlashes(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}
