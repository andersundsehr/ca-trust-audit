package probes

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/andersundsehr/ca-trust-audit/internal/incidents/emudhra"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

func TestPublishedEndpoints(t *testing.T) {
	if os.Getenv("CA_TRUST_AUDIT_NETWORK_TESTS") != "1" {
		t.Skip("set CA_TRUST_AUDIT_NETWORK_TESTS=1 to contact published endpoints (privacy: IP/user-agent disclosed)")
	}
	incident, e := emudhra.Load()
	if e != nil {
		t.Fatal(e)
	}
	p := Native{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	control := p.Check(ctx, nil, "https://example.com/")
	cancel()
	if control.Status != report.VulnerableClient {
		t.Fatalf("positive control: %+v", control)
	}
	for _, chain := range incident.Chains {
		t.Run(chain.ID, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			f := EvidenceFor(p.Check(ctx, nil, "https://"+chain.Host+"/"), chain, p.Name())
			if f.Status != report.Rejected && f.Status != report.VulnerableClient {
				t.Fatalf("inconclusive live endpoint: %+v", f.Evidence)
			}
		})
	}
}
