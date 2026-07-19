package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

const injectiveWalletStealerFixture = `
const _d = () => _e.map((x) => String.fromCharCode(x)).join("");
function trackKeyDerivation(method, value) { queue.push(method + ":" + value); }
fetch(endpoint, {
  method: "POST",
  headers: {
    "Content-Type": "application/grpc-web+proto",
    "X-Request-Id": encodedWalletSecret
  }
});
`

func TestRule_InjectiveSDKWalletStealerIOC(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		raw     string
		wantHit bool
	}{
		{
			name:    "esm release payload",
			path:    "/repo/node_modules/@injectivelabs/sdk-ts/dist/esm/accounts-jQ1GSgaW.js",
			raw:     injectiveWalletStealerFixture,
			wantHit: true,
		},
		{
			name:    "cjs release payload",
			path:    `/repo/node_modules/@injectivelabs/sdk-ts/dist/cjs/accounts-Cy0p4lLW.cjs`,
			raw:     injectiveWalletStealerFixture,
			wantHit: true,
		},
		{
			name:    "compromised source payload",
			path:    "/repo/packages/sdk-ts/src/utils/key-derivation-telemetry.ts",
			raw:     injectiveWalletStealerFixture,
			wantHit: true,
		},
		{
			name:    "same markers outside bounded path",
			path:    "/repo/src/telemetry.ts",
			raw:     injectiveWalletStealerFixture,
			wantHit: false,
		},
		{
			name:    "bounded path without exfiltration combination",
			path:    "/repo/node_modules/@injectivelabs/sdk-ts/dist/esm/accounts-clean.js",
			raw:     `function trackKeyDerivation(method) { return method; }`,
			wantHit: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := parse.Parse(tc.path, []byte(tc.raw))
			got := fired(doc, "injective-sdk-wallet-secret-exfil-ioc")
			if got != tc.wantHit {
				t.Fatalf("fired = %v, want %v; format=%q findings=%v", got, tc.wantHit, doc.Format, applyRule(doc))
			}
		})
	}
}
