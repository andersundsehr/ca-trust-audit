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

func TestSummaryHighlightsAffectedTargets(t *testing.T) {
	r := Report{Warnings: []string{"Docker discovery incomplete"}, Targets: []TargetReport{
		{Target: Target{Kind: "host", Name: "local filesystem"}, Findings: []Finding{{Status: VulnerableClient, Client: "curl"}}},
		{Target: Target{Kind: "container", Name: "webapp", ID: "1234567890abcdef"}, Findings: []Finding{
			{Status: VulnerableClient, Client: "PHP cURL", Chain: "first"},
			{Status: VulnerableClient, Client: "PHP cURL", Chain: "second"},
			{Status: VulnerableStore, Path: "/opt/app/ca.pem", Chain: "first"},
			{Status: VulnerableStore, Path: "/opt/app/ca.pem", Chain: "second"},
		}},
		{Target: Target{Kind: "container", Name: "worker"}, Findings: []Finding{{Status: VulnerableClient, Client: "Python ssl"}}},
		{Target: Target{Kind: "container", Name: "passed"}, Coverage: Coverage{Complete: true}, Findings: []Finding{{Status: Rejected}}},
		{Target: Target{Kind: "container", Name: "review"}, Findings: []Finding{{Status: Potential}, {Status: Potential}}},
	}}
	r.Summarize()
	var b bytes.Buffer
	if e := Terminal(&b, r, false); e != nil {
		t.Fatal(e)
	}
	_, summary, found := strings.Cut(b.String(), "\nSUMMARY\n")
	if !found {
		t.Fatal("summary missing")
	}
	for _, want := range []string{
		"Targets: 5 (hosts=1, containers=4)",
		"PROBLEM confirmed: clients=3, CA files=1",
		"PROBLEM host local filesystem\n    Clients: curl",
		"PROBLEM container webapp (1234567890ab)\n    Clients: PHP cURL\n    CA files: /opt/app/ca.pem",
		"PROBLEM container worker\n    Clients: Python ssl",
		"NOT VERIFIED incomplete coverage: targets=4, scan warnings=1",
		"REVIEW targets with potential findings: 1",
		"Action: update",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("missing %q in summary: %s", want, summary)
		}
	}
	if strings.Contains(summary, "PROBLEM container passed") || strings.Contains(summary, "PROBLEM container review") || strings.Count(summary, "PHP cURL") != 1 || strings.Count(summary, "/opt/app/ca.pem") != 1 {
		t.Fatalf("summary duplicates evidence or mislabels targets: %s", summary)
	}
}

func TestNoConfirmedProblemsStillShowsCoverageWarning(t *testing.T) {
	r := Report{Targets: []TargetReport{{Target: Target{Kind: "container", Name: "unknown"}}}}
	r.Summarize()
	var b bytes.Buffer
	if e := Terminal(&b, r, false); e != nil {
		t.Fatal(e)
	}
	_, summary, _ := strings.Cut(b.String(), "\nSUMMARY\n")
	if !strings.Contains(summary, "Confirmed problems: none detected.") || !strings.Contains(summary, "NOT VERIFIED incomplete coverage: targets=1") || strings.Contains(summary, "PROBLEM ") {
		t.Fatal(summary)
	}
}
