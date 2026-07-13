package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestRule_JscramblerPayloadMagicIOC(t *testing.T) {
	doc := parse.Parse("/repo/node_modules/jscrambler/dist/intro.js", []byte{0x1b, 0x43, 0x53, 0x49, 0x01, 0x03})
	if !fired(doc, "jscrambler-malicious-payload-ioc") {
		t.Fatalf("Jscrambler payload IOC rule did not fire; got %v", applyRule(doc))
	}
}

func TestRule_JscramblerDropperSourceIOC(t *testing.T) {
	cases := []struct {
		path string
		raw  string
	}{
		{
			path: "/repo/node_modules/jscrambler/dist/setup.js",
			raw: `const bundle = readFileSync(join(__dirname, 'intro.js'));
const magic = Buffer.from([0x1b, 0x43, 0x53, 0x49, 0x01]);
writeFileSync(target, gunzipSync(data));
spawn(target, [], { detached: true, stdio: 'ignore', windowsHide: true });`,
		},
		{
			path: "/repo/node_modules/jscrambler/dist/index.js",
			raw: `var bundle = (0, _fs.readFileSync)((0, _path.join)(__dirname, 'intro.js'));
var magic = Buffer.from([0x1b, 0x43, 0x53, 0x49, 0x01]);
(0, _fs.writeFileSync)(target, (0, _zlib.gunzipSync)(data));
(0, _child_process.spawn)(target, [], { detached: true, stdio: 'ignore', windowsHide: true });`,
		},
		{
			path: "/repo/node_modules/jscrambler/dist/bin/jscrambler.js",
			raw: `var bundle = fs.readFileSync(path.join(__dirname, '..', 'intro.js'));
var magic = Buffer.from([0x1b, 0x43, 0x53, 0x49, 0x01]);
fs.writeFileSync(target, zlib.gunzipSync(data));
child_process.spawn(target, [], { detached: true, stdio: 'ignore', windowsHide: true });`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			if !fired(doc, "jscrambler-malicious-payload-ioc") {
				t.Fatalf("Jscrambler dropper IOC rule did not fire; got %v", applyRule(doc))
			}
		})
	}
}

func TestRule_JscramblerPayloadIOCBoundsFalsePositives(t *testing.T) {
	cases := []struct {
		path string
		raw  []byte
	}{
		{"/repo/node_modules/jscrambler/dist/intro.js", []byte("normal JavaScript intro")},
		{"/repo/node_modules/other/dist/intro.js", []byte{0x1b, 0x43, 0x53, 0x49, 0x01}},
		{"/repo/README.md", []byte("Jscrambler incident magic 1b 43 53 49 01")},
	}
	for _, tc := range cases {
		doc := parse.Parse(tc.path, tc.raw)
		if fired(doc, "jscrambler-malicious-payload-ioc") {
			t.Fatalf("Jscrambler IOC rule fired on benign path %s; got %v", tc.path, applyRule(doc))
		}
	}
}
