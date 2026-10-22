package emudhra

import (
	"crypto/x509"
	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"strings"
	"testing"
	"time"
)

func TestSnapshot(t *testing.T) {
	i, e := Load()
	if e != nil {
		t.Fatal(e)
	}
	if len(i.Chains) != 14 {
		t.Fatalf("chains=%d", len(i.Chains))
	}
	keys := map[string]int{}
	cs := map[string]bool{}
	for _, id := range i.Identities {
		if id.Usage == "tls" {
			keys[id.SPKISHA256]++
		} else if id.Usage == "code-signing" {
			cs[id.SPKISHA256] = true
		}
	}
	if len(keys) != 6 || len(cs) != 2 {
		t.Fatalf("TLS keys=%d code-signing keys=%d", len(keys), len(cs))
	}
	for _, n := range keys {
		if n != 2 {
			t.Fatal("missing cross-sign")
		}
	}
	for _, c := range i.Chains {
		if !strings.EqualFold(certificates.SHA256(c.Certificates[1].Raw), c.Intermediate.SHA256) {
			t.Fatal("wrong intermediate")
		}
		// Validate public fixture signatures against the published root set. Current
		// Go incident-specific distrust may intentionally reject compromised paths.
		for n := 0; n < len(c.Certificates)-1; n++ {
			if e := c.Certificates[n].CheckSignatureFrom(c.Certificates[n+1]); e != nil {
				t.Fatal(e)
			}
		}
	}
}

// TestPublishedChainsExplicitModel ensures scanner Go incident distrust cannot
// accidentally turn a still-trusting PEM bundle into an apparent safe result.
func TestPublishedChainsExplicitModel(t *testing.T) {
	i, e := Load()
	if e != nil {
		t.Fatal(e)
	}
	var roots []*x509.Certificate
	for _, id := range i.Roots {
		cs, e := certificates.ParsePEM([]byte(id.PEM))
		if e != nil {
			t.Fatal(e)
		}
		roots = append(roots, cs...)
	}
	for _, chain := range i.Chains {
		t.Run(chain.ID, func(t *testing.T) {
			path, e := certificates.Evaluate(chain, roots, certificates.Policy{Time: time.Date(2026, 10, 22, 16, 0, 0, 0, time.UTC)})
			if e != nil || len(path) < 3 {
				t.Fatalf("known trusting PEM bundle must accept actual incident chain: %v", e)
			}
			if _, e := certificates.Evaluate(chain, nil, certificates.Policy{Time: time.Date(2026, 10, 22, 16, 0, 0, 0, time.UTC)}); e == nil {
				t.Fatal("empty corrected store accepted chain")
			}
		})
	}
}
