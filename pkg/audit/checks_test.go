package audit

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andersundsehr/ca-trust-audit/internal/testcert"
	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

type gatedProbe struct {
	active, peak, calls atomic.Int32
	entered             chan struct{}
	release             chan struct{}
	leaf                string
	controlFails        bool
}

func (*gatedProbe) Name() string                                 { return "gated client" }
func (*gatedProbe) Discover(context.Context, probes.Runner) bool { return true }
func (p *gatedProbe) Check(ctx context.Context, _ probes.Runner, endpoint string) probes.Result {
	if strings.Contains(endpoint, "control.invalid") {
		if p.controlFails {
			return probes.Result{Status: report.Inconclusive, Category: "dns"}
		}
		return probes.Result{Status: report.VulnerableClient}
	}
	p.calls.Add(1)
	active := p.active.Add(1)
	defer p.active.Add(-1)
	for peak := p.peak.Load(); active > peak; peak = p.peak.Load() {
		if p.peak.CompareAndSwap(peak, active) {
			break
		}
	}
	p.entered <- struct{}{}
	select {
	case <-p.release:
		if strings.Contains(endpoint, "chain-0.") {
			return probes.Result{Status: report.VulnerableClient, Category: "tls_accepted", LeafSHA256: p.leaf}
		}
		return probes.Result{Status: report.Rejected, Category: "certificate_validation"}
	case <-ctx.Done():
		return probes.Result{Status: report.Inconclusive, Category: "timeout_or_canceled"}
	}
}

func TestChainChecksParallelWithSharedLimitAndStableEvidence(t *testing.T) {
	fixture := testcert.Make(t)
	incident := fixture.Incident
	incident.Chains = nil
	for i := 0; i < 6; i++ {
		chain := fixture.Incident.Chains[0]
		chain.ID = fmt.Sprintf("chain-%d", i)
		chain.Host = chain.ID + ".invalid"
		incident.Chains = append(incident.Chains, chain)
	}
	for _, workers := range []int{1, 3} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			p := &gatedProbe{entered: make(chan struct{}, 12), release: make(chan struct{}), leaf: certificates.SHA256(fixture.Leaf.Raw)}
			var mu sync.Mutex
			completed := map[string]int{}
			o := Options{Workers: workers, PositiveControl: "https://control.invalid/", Probes: []probes.Probe{p}, Progress: func(event Progress) {
				if event.Phase == PhaseTLS {
					mu.Lock()
					defer mu.Unlock()
					if event.Completed < completed[event.Target.Name] {
						t.Error("parallel completion progress moved backwards")
					}
					completed[event.Target.Name] = event.Completed
				}
			}}
			if err := normalize(&o); err != nil {
				t.Fatal(err)
			}
			finished := make(chan report.TargetReport, 2)
			for _, name := range []string{"web", "worker"} {
				go func(name string) {
					finished <- ScanTarget(ctx, report.Target{Kind: "container", Name: name}, memoryFiles{}, missingRunner{}, nil, incident, o)
				}(name)
			}
			// Hold requests until all available slots are occupied: this proves
			// actual overlap without a timing-based performance assertion.
			for i := 0; i < workers; i++ {
				select {
				case <-p.entered:
				case <-ctx.Done():
					t.Fatal("checks failed to occupy the configured parallel slots")
				}
			}
			close(p.release)
			for n := 0; n < 2; n++ {
				select {
				case result := <-finished:
					if len(result.Findings) != 6 || countStatus(result, report.VulnerableClient) != 1 || countStatus(result, report.Rejected) != 5 {
						t.Fatalf("incorrect mixed-chain evidence: %+v", result)
					}
					if result.Coverage.Clients[1].Tested != 6 {
						t.Fatal("parallel client coverage incomplete", result.Coverage.Clients)
					}
					for i, finding := range result.Findings {
						if finding.Chain != incident.Chains[i].ID {
							t.Fatalf("report order or chain identity changed: %+v", result.Findings)
						}
					}
				case <-ctx.Done():
					t.Fatal("parallel scan did not finish")
				}
			}
			if p.peak.Load() != int32(workers) || p.calls.Load() != 12 {
				t.Fatalf("peak=%d calls=%d, want shared limit %d and all 12 checks", p.peak.Load(), p.calls.Load(), workers)
			}
			mu.Lock()
			defer mu.Unlock()
			if completed["web"] != 6 || completed["worker"] != 6 {
				t.Fatal("missing per-target completion progress", completed)
			}
		})
	}
}

func TestParallelChecksCancelActiveAndQueuedRequests(t *testing.T) {
	f := testcert.Make(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &gatedProbe{entered: make(chan struct{}, 4), release: make(chan struct{})}
	o := Options{Workers: 1, PositiveControl: "https://control.invalid/", Probes: []probes.Probe{p}}
	if err := normalize(&o); err != nil {
		t.Fatal(err)
	}
	finished := make(chan report.TargetReport, 2)
	for _, name := range []string{"web", "worker"} {
		go func(name string) {
			finished <- ScanTarget(ctx, report.Target{Kind: "container", Name: name}, memoryFiles{}, missingRunner{}, nil, f.Incident, o)
		}(name)
	}
	select {
	case <-p.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no request started")
	}
	cancel()
	for n := 0; n < 2; n++ {
		select {
		case result := <-finished:
			if result.Coverage.Complete || countStatus(result, report.Rejected) > 0 || countStatus(result, report.VulnerableClient) > 0 {
				t.Fatalf("cancellation incorrectly established TLS safety: %+v", result)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancellation did not release active/queued checks")
		}
	}
	if p.calls.Load() != 1 || len(o.probeSlots) != 0 {
		t.Fatal("started checks after cancellation or leaked a shared slot")
	}
}

func TestFailedControlNeverStartsParallelIncidentRequests(t *testing.T) {
	f := testcert.Make(t)
	p := &gatedProbe{controlFails: true}
	result := ScanTarget(context.Background(), report.Target{Kind: "container"}, memoryFiles{}, missingRunner{}, nil, f.Incident, Options{Workers: 4, PositiveControl: "https://control.invalid/", Probes: []probes.Probe{p}})
	if p.calls.Load() != 0 || countStatus(result, report.Inconclusive) != len(f.Incident.Chains) {
		t.Fatal("failed control still ran incident requests or established safety")
	}
	for _, finding := range result.Findings {
		if finding.Evidence.Attempted == nil || *finding.Evidence.Attempted {
			t.Fatal("skipped request marked as attempted")
		}
	}
}
