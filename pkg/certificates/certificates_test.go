package certificates_test

import (
	"crypto/rand"
	"crypto/x509"
	"github.com/andersundsehr/ca-trust-audit/internal/testcert"
	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"math/big"
	"testing"
	"time"
)

func TestTrustAndCrossSign(t *testing.T) {
	f := testcert.Make(t)
	cases := []struct {
		name   string
		chain  certificates.Chain
		roots  []*x509.Certificate
		policy certificates.Policy
		want   bool
	}{
		{"accept", f.Chain, []*x509.Certificate{f.Root}, certificates.Policy{}, true},
		{"reject", f.Chain, []*x509.Certificate{f.Other}, certificates.Policy{}, false},
		{"empty", f.Chain, nil, certificates.Policy{}, false},
		{"cross signed", f.Alternate, []*x509.Certificate{f.Other}, certificates.Policy{}, true},
		{"cross wrong root", f.Alternate, []*x509.Certificate{f.Root}, certificates.Policy{}, false},
		{"denied fingerprint", f.Chain, []*x509.Certificate{f.Root}, certificates.Policy{DeniedSHA256: map[string]bool{certificates.SHA256(f.Intermediate.Raw): true}}, false},
		{"denied shared key", f.Alternate, []*x509.Certificate{f.Other}, certificates.Policy{DeniedSPKI: map[string]bool{certificates.SPKI(f.Intermediate): true}}, false},
		{"expired", f.Chain, []*x509.Certificate{f.Root}, certificates.Policy{Time: time.Now().Add(48 * time.Hour)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, e := certificates.Evaluate(c.chain, c.roots, c.policy)
			if (e == nil) != c.want {
				t.Fatalf("err=%v want accepted=%v", e, c.want)
			}
		})
	}
}
func TestSignedRevocation(t *testing.T) {
	f := testcert.Make(t)
	now := time.Now()
	der, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: f.Intermediate.SerialNumber, RevocationTime: now.Add(-time.Minute)}}}, f.Root, f.RootKey)
	if e != nil {
		t.Fatal(e)
	}
	crl, e := x509.ParseRevocationList(der)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = certificates.Evaluate(f.Chain, []*x509.Certificate{f.Root}, certificates.Policy{CRLs: []*x509.RevocationList{crl}}); e == nil {
		t.Fatal("revoked intermediate accepted")
	}
	if _, e = certificates.Evaluate(f.Chain, []*x509.Certificate{f.Root}, certificates.Policy{}); e != nil {
		t.Fatal("implicit revocation unexpectedly enabled", e)
	}
}
func TestParse(t *testing.T) {
	f := testcert.Make(t)
	for _, b := range [][]byte{nil, {}, []byte("garbage"), []byte("-----BEGIN CERTIFICATE-----\nwrong\n-----END CERTIFICATE-----"), []byte("-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----"), make([]byte, certificates.MaxBundleBytes+1)} {
		if _, e := certificates.ParsePEM(b); e == nil {
			t.Fatal("invalid PEM accepted")
		}
	}
	if cs, e := certificates.ParsePEM(testcert.PEM(f.Root, f.Other)); e != nil || len(cs) != 2 {
		t.Fatal("valid PEM rejected", e)
	}
}
