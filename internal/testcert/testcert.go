// Package testcert creates synthetic certificates; it contains no real CA keys.
package testcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"math/big"
	"testing"
	"time"
)

type Fixture struct {
	Root, Other, Intermediate, Cross, Leaf *x509.Certificate
	RootKey                                *ecdsa.PrivateKey
	Chain, Alternate                       certificates.Chain
	Incident                               certificates.Incident
	LeafKey                                *ecdsa.PrivateKey
}

func Make(t testing.TB) Fixture {
	t.Helper()
	now := time.Now()
	serial := int64(0)
	key := func() *ecdsa.PrivateKey {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	}
	issue := func(name string, isCA bool, k *ecdsa.PrivateKey, parent *x509.Certificate, pk *ecdsa.PrivateKey) *x509.Certificate {
		serial++
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: []byte{byte(serial), 2, 3}}
		if isCA {
			template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			template.DNSNames = []string{"localhost", "tls-fixture.test"}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		if parent == nil {
			parent = template
			pk = k
		}
		der, e := x509.CreateCertificate(rand.Reader, template, parent, &k.PublicKey, pk)
		if e != nil {
			t.Fatal(e)
		}
		c, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	rk, ok, ik, lk := key(), key(), key(), key()
	root := issue("root", true, rk, nil, nil)
	other := issue("other", true, ok, nil, nil)
	inter := issue("compromised", true, ik, root, rk)
	cross := issue("compromised", true, ik, other, ok)
	leaf := issue("localhost", false, lk, inter, ik)
	id := certificates.Identity{Name: "synthetic compromised", Usage: "tls", SHA256: certificates.SHA256(inter.Raw), SPKISHA256: certificates.SPKI(inter), IssuedBy: "root"}
	chain := certificates.Chain{ID: "synthetic", Host: "localhost", Certificates: []*x509.Certificate{leaf, inter}, Intermediate: id}
	alt := chain
	alt.Certificates = []*x509.Certificate{leaf, cross}
	alt.ID = "cross"
	return Fixture{root, other, inter, cross, leaf, rk, chain, alt, certificates.Incident{ID: "synthetic", Chains: []certificates.Chain{chain, alt}, Identities: []certificates.Identity{id}}, lk}
}
func PEM(cs ...*x509.Certificate) []byte {
	var b []byte
	for _, c := range cs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return b
}
