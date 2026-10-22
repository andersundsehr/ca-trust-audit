package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSummaryAndExitCodes(t *testing.T) {
	r := Report{SchemaVersion: "1.0", Targets: []TargetReport{{Target: Target{Kind: "host"}, Coverage: Coverage{Complete: true}}}}
	r.Summarize()
	if r.ExitCode(true) != 0 {
		t.Fatal("complete scan")
	}
	r.Targets[0].Coverage.Complete = false
	r.Summarize()
	if r.ExitCode(false) != 0 || r.ExitCode(true) != 3 {
		t.Fatal("strict incomplete")
	}
	r.Targets[0].Findings = []Finding{{Status: VulnerableClient, Client: "curl"}, {Status: VulnerableClient, Client: "curl"}, {Status: VulnerableStore, Path: "/bundle"}}
	r.Summarize()
	if r.ExitCode(true) != 1 || r.Summary.VulnerableClients != 1 || r.Summary.VulnerableStores != 1 {
		t.Fatal(r.Summary)
	}
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(b, []byte(`"status":"VULNERABLE_CLIENT"`)) {
		t.Fatal("machine status changed", string(b))
	}
	var decoded Report
	if e = json.Unmarshal(b, &decoded); e != nil {
		t.Fatal(e)
	}
	if decoded.Summary != r.Summary || !bytes.Contains(b, []byte(`"schema_version":"1.0"`)) {
		t.Fatal(string(b))
	}
	var terminal bytes.Buffer
	if e = Terminal(&terminal, r, false); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(terminal.String(), "PROBLEM") {
		t.Fatal(terminal.String())
	}
}

func TestPlainLanguageStaticAndLiveSeparation(t *testing.T) {
	r := Report{Targets: []TargetReport{{Target: Target{Kind: "container", Name: "php"}, TrustStores: []TrustStore{{Path: "/etc/ssl/cert.pem", Status: Rejected, Expected: 14, Rejected: 14}}, Coverage: Coverage{Clients: []ClientCoverage{{Name: "PHP cURL", Discovered: true, Expected: 14, Reason: "offline: live validation not run"}}}}}}
	var b bytes.Buffer
	if e := Terminal(&b, r, false); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"CA FILES: PASSED", "LIVE CLIENTS: NOT VERIFIED", "live checks were not run"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing clear explanation %q: %s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "all applications are safe") {
		t.Fatal("false assurance")
	}
}
