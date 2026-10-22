package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestHumanColorsPreserveTextAndEvidence(t *testing.T) {
	r := Report{SchemaVersion: "1.0", Warnings: []string{"Docker coverage incomplete"}, Targets: []TargetReport{{
		Target: Target{Kind: "container", Name: "php\x1b[35m"},
		Findings: []Finding{
			{Status: VulnerableStore, Method: "store", Path: "/problem", Evidence: Evidence{Detail: "accepted"}},
			{Status: Rejected, Method: "store", Path: "/passed", Evidence: Evidence{Detail: "rejected"}},
			{Status: Potential, Method: "material", Path: "/review"},
			{Status: Inconclusive, Method: "live", Client: "curl"},
			{Status: NotSupported, Method: "store", Path: "/cacerts"},
		},
		TrustStores: []TrustStore{{Path: "/etc/ssl/cert.pem", Status: Rejected, Rejected: 14, Expected: 14}},
		Coverage:    Coverage{Clients: []ClientCoverage{{Name: "curl", Discovered: true, Expected: 14}}},
	}}}
	r.Summarize()
	before, _ := json.Marshal(r)
	var plain, colored bytes.Buffer
	if e := Terminal(&plain, r, true); e != nil {
		t.Fatal(e)
	}
	if e := TerminalWithOptions(&colored, r, TerminalOptions{Verbose: true, Color: true}); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"\x1b[32mPASSED", "\x1b[31mPROBLEM", "\x1b[33mNOT VERIFIED", "\x1b[33mREVIEW", "\x1b[90mUNSUPPORTED", "\x1b[33mPARTIAL", "\x1b[1mCONTAINER", "\x1b[33mWarning:"} {
		if !strings.Contains(colored.String(), want) {
			t.Fatalf("missing %q in %q", want, colored.String())
		}
	}
	stripped := colored.String()
	for _, sequence := range []string{"\x1b[0m", "\x1b[1m", "\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[90m"} {
		stripped = strings.ReplaceAll(stripped, sequence, "")
	}
	if stripped != plain.String() || strings.Contains(stripped, "\x1b") {
		t.Fatalf("color changed content or preserved injected escape: %q", stripped)
	}
	after, _ := json.Marshal(r)
	if !bytes.Equal(before, after) || !json.Valid(after) || !bytes.Contains(after, []byte(`"status":"VULNERABLE_STORE"`)) {
		t.Fatal("human colors changed machine evidence")
	}
}
