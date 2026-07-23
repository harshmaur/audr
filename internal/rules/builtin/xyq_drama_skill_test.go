package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
	"github.com/harshmaur/audr/internal/rules"
)

func TestRule_XYQDramaSkillDroppedLogHelper(t *testing.T) {
	doc := parse.Parse("/home/alice/.log-helper", []byte("synthetic recovered executable"))
	if !fired(doc, "xyq-drama-skill-log-helper-ioc") {
		t.Fatalf("xyq-drama-skill drop-path rule did not fire; format=%q findings=%v", doc.Format, applyRule(doc))
	}
}

func TestRule_XYQDramaSkillSetupDownloadAndDetachedLaunch(t *testing.T) {
	raw := []byte(`
from pathlib import Path
import subprocess
HELPER_URL = "https://douyin-cloud.tos-cn-beijing.volces.com/obj/hosts/log-helper"
target = Path.home() / ".log-helper"
subprocess.Popen([str(target)], start_new_session=True)
`)
	doc := parse.Parse("/tmp/xyq-drama-skill-0.3.0/setup.py", raw)
	if !fired(doc, "xyq-drama-skill-log-helper-ioc") {
		t.Fatalf("xyq-drama-skill setup.py rule did not fire; format=%q findings=%v", doc.Format, applyRule(doc))
	}
}

func TestRule_XYQDramaSkillHelperDownloadAndSetsidLaunch(t *testing.T) {
	raw := []byte(`
HELPER_URL = "https://douyin-cloud.tos-cn-beijing.volces.com/obj/hosts/log-helper"
target = os.path.expanduser("~/.log-helper")
subprocess.Popen(["setsid", target, "-w"])
`)
	doc := parse.Parse("/tmp/xyq-drama-skill/xyq_drama_skill/_helper.py", raw)
	if !fired(doc, "xyq-drama-skill-log-helper-ioc") {
		t.Fatalf("xyq-drama-skill _helper.py rule did not fire; format=%q findings=%v", doc.Format, applyRule(doc))
	}
}

func TestRule_XYQDramaSkillKnownSourceHashUsesActualBytes(t *testing.T) {
	original := xyqDramaSkillKnownSourceSHA256
	xyqDramaSkillKnownSourceSHA256 = map[string]string{
		"/setup.py": "649b220af63ccab38278514ea04bbcaf6fc9cfa4cbe4991d8fe400200a45ab11",
	}
	defer func() { xyqDramaSkillKnownSourceSHA256 = original }()

	doc := parse.Parse("/tmp/xyq-drama-skill/setup.py", []byte("synthetic known-hash fixture"))
	if !fired(doc, "xyq-drama-skill-log-helper-ioc") {
		t.Fatalf("known source hash did not fire through normal rule application; findings=%v", applyRule(doc))
	}
}

func TestRule_XYQDramaSkillBoundsFalsePositives(t *testing.T) {
	tests := []struct {
		path string
		raw  string
	}{
		{"/repo/README.md", "Threat report: https://douyin-cloud.tos-cn-beijing.volces.com/obj/hosts/log-helper"},
		{"/repo/setup.py", "from setuptools import setup\nsetup(name='clean-package')"},
		{"/repo/setup.py", "HELPER_URL='https://douyin-cloud.tos-cn-beijing.volces.com/obj/hosts/log-helper'\ntarget='~/.log-helper'\ncmdclass={'install': Install}"},
		{"/repo/other/_helper.py", "HELPER_URL='https://douyin-cloud.tos-cn-beijing.volces.com/obj/hosts/log-helper'"},
		{"/repo/.log-helper", "synthetic unrelated project helper"},
		{".log-helper", "synthetic unrelated working-directory helper"},
		{"/home/alice/.log-helper.txt", "synthetic recovered executable"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			if fired(doc, "xyq-drama-skill-log-helper-ioc") {
				t.Fatalf("xyq-drama-skill rule fired outside bounded evidence for %s: %v", tc.path, applyRule(doc))
			}
		})
	}
}

func TestRule_XYQDramaSkillFindingRedactsSourceContent(t *testing.T) {
	doc := parse.Parse("/tmp/xyq-drama-skill/setup.py", []byte(`
secret = "ghp_example_secret"
HELPER_URL = "https://douyin-cloud.tos-cn-beijing.volces.com/obj/hosts/log-helper"
target = "~/.log-helper"
subprocess.Popen([target], start_new_session=True)
`))
	for _, rule := range rules.All() {
		if rule.ID() != "xyq-drama-skill-log-helper-ioc" {
			continue
		}
		for _, result := range rule.Apply(doc) {
			if strings.Contains(result.Match, "ghp_example_secret") || strings.Contains(result.Description, "ghp_example_secret") {
				t.Fatalf("finding leaked source content: %+v", result)
			}
			return
		}
	}
	t.Fatal("expected xyq-drama-skill-log-helper-ioc finding")
}
