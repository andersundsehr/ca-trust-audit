package audit

import (
	"context"
	"testing"

	"github.com/andersundsehr/ca-trust-audit/internal/testcert"
	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

func TestTargetProgressStagesAndCancellation(t *testing.T) {
	f := testcert.Make(t)
	for _, cancelDuringRead := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		var events []Progress
		target := report.Target{Kind: "container", Name: "fixture", ID: "123"}
		ScanTarget(ctx, target, memoryFiles{data: map[string][]byte{"/etc/ssl/cert.pem": testcert.PEM(f.Root)}}, missingRunner{}, nil, f.Incident, Options{
			PositiveControl: "https://control.invalid/",
			Probes:          []probes.Probe{fakeProbe{control: probes.Result{Status: report.VulnerableClient}, incident: probes.Result{Status: report.Rejected, Category: "certificate_validation"}}},
			Progress: func(p Progress) {
				events = append(events, p)
				if cancelDuringRead && p.Phase == PhaseStores && p.Completed == 1 {
					cancel()
				}
			},
		})
		cancel()
		wantLast := PhaseTargetCompleted
		if cancelDuringRead {
			wantLast = PhaseTargetCanceled
		}
		if len(events) < 3 || events[0].Phase != PhaseTargetStarted || events[len(events)-1].Phase != wantLast {
			t.Fatalf("unexpected lifecycle: %+v", events)
		}
		phases := map[Phase]bool{}
		for _, p := range events {
			if p.Target != target || p.Completed < 0 || p.Completed > p.Total {
				t.Fatalf("invalid progress payload: %+v", p)
			}
			phases[p.Phase] = true
		}
		if !cancelDuringRead {
			for _, phase := range []Phase{PhaseConfiguration, PhaseStores, PhaseClientDiscovery, PhasePositiveControl, PhaseTLS} {
				if !phases[phase] {
					t.Fatalf("missing %s: %+v", phase, events)
				}
			}
			finishedChains := false
			for _, p := range events {
				if p.Phase == PhaseTLS && p.Completed == len(f.Incident.Chains) && p.Total == p.Completed {
					finishedChains = true
				}
			}
			if !finishedChains {
				t.Fatal("live chain progress never completed")
			}
		}
	}
}
