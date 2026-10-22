// Package certificates implements bounded certificate parsing, incident identities,
// and explicit PEM trust evaluation. It never consults the machine's system roots.
package certificates

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"strings"
	"time"
)

const MaxBundleBytes = 8 << 20

func SHA256(der []byte) string        { v := sha256.Sum256(der); return hex.EncodeToString(v[:]) }
func SPKI(c *x509.Certificate) string { return SHA256(c.RawSubjectPublicKeyInfo) }

// Identity includes certificate and public key identities; cross-signs share SPKI.
type Identity struct {
	Name       string `json:"name"`
	Usage      string `json:"usage"`
	SHA256     string `json:"sha256"`
	SPKISHA256 string `json:"spki_sha256"`
	IssuedBy   string `json:"issued_by"`
	PEM        string `json:"pem,omitempty"`
}
type Chain struct {
	ID           string
	Host         string
	Certificates []*x509.Certificate // leaf first; never add these to the roots pool
	Intermediate Identity
}
type Incident struct {
	ID         string
	Source     string
	Chains     []Chain
	Identities []Identity
	Roots      []Identity
}

// ParsePEM rejects empty, malformed, mixed/private-key and OpenSSL AUX trusted PEM.
// No secret data is returned in errors.
func ParsePEM(data []byte) ([]*x509.Certificate, error) {
	if len(data) > MaxBundleBytes {
		return nil, errors.New("certificate bundle exceeds 8 MiB")
	}
	var out []*x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		// Permit ordinary bundle comments, but never silently accept a damaged PEM block.
		p := bytes.Index(data, []byte("-----BEGIN "))
		if p < 0 {
			if len(out) == 0 || bytes.Contains(data, []byte("-----")) {
				return nil, errors.New("invalid PEM data")
			}
			break
		}
		block, rest := pem.Decode(data[p:])
		if block == nil {
			return nil, errors.New("malformed PEM block")
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("unsupported PEM block type (only plain CERTIFICATE supported)")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("invalid X.509 certificate")
		}
		out = append(out, c)
		data = rest
	}
	if len(out) == 0 {
		return nil, errors.New("empty certificate bundle")
	}
	return out, nil
}

// Policy is an explicit offline policy supplied by the caller. No network CRL/OCSP
// requests occur. Denied hashes apply to every certificate in a verified path.
type Policy struct {
	Time         time.Time
	DeniedSHA256 map[string]bool
	DeniedSPKI   map[string]bool
	CRLs         []*x509.RevocationList
}

// Evaluate validates the published leaf, DNS name, signatures, validity and server
// EKU. Revocation is NOT implicit: signed, current supplied CRLs and explicit
// denies are honored. This models explicit PEM trust using the CT Go X.509 verifier, not NSS/p11-kit/Java policy.
func Evaluate(chain Chain, roots []*x509.Certificate, policy Policy) ([]*x509.Certificate, error) {
	if len(chain.Certificates) < 2 {
		return nil, errors.New("chain requires leaf and intermediate")
	}
	// This offline verifier is deliberately independent of the scanner runtime's
	// built-in incident denylist. It still checks the real, unmodified DER,
	// signatures, constraints, DNS name, validity and serverAuth usage. Live TLS
	// continues to use each actual client's fully enabled validation policy.
	pool := ctx509.NewCertPool()
	parse := func(c *x509.Certificate) (*ctx509.Certificate, error) {
		if c == nil || len(c.Raw) == 0 {
			return nil, ErrEvaluationUnsupported
		}
		return ctx509.ParseCertificate(c.Raw)
	}
	for _, c := range roots {
		parsed, e := parse(c)
		if e != nil {
			return nil, fmt.Errorf("%w: root parser", ErrEvaluationUnsupported)
		}
		pool.AddCert(parsed)
	}
	inter := ctx509.NewCertPool()
	for _, c := range chain.Certificates[1:] {
		parsed, e := parse(c)
		if e != nil {
			return nil, fmt.Errorf("%w: chain parser", ErrEvaluationUnsupported)
		}
		inter.AddCert(parsed)
	}
	leaf, e := parse(chain.Certificates[0])
	if e != nil {
		return nil, ErrEvaluationUnsupported
	}
	now := policy.Time
	if now.IsZero() {
		now = time.Now()
	}
	ctpaths, err := leaf.Verify(ctx509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: chain.Host, CurrentTime: now, KeyUsages: []ctx509.ExtKeyUsage{ctx509.ExtKeyUsageServerAuth}})
	if err != nil {
		return nil, err
	}
	paths := make([][]*x509.Certificate, 0, len(ctpaths))
	for _, ctpath := range ctpaths {
		var path []*x509.Certificate
		for _, c := range ctpath {
			parsed, e := x509.ParseCertificate(c.Raw)
			if e != nil {
				return nil, e
			}
			path = append(path, parsed)
		}
		paths = append(paths, path)
	}
	for _, path := range paths {
		denied := false
		for n, c := range path {
			if policy.DeniedSHA256[SHA256(c.Raw)] || policy.DeniedSPKI[SPKI(c)] {
				denied = true
			}
			if n+1 < len(path) {
				for _, crl := range policy.CRLs {
					if crl.CheckSignatureFrom(path[n+1]) != nil {
						continue
					}
					if now.Before(crl.ThisUpdate) || !now.Before(crl.NextUpdate) {
						return nil, ErrPolicyUnavailable
					}
					for _, e := range crl.RevokedCertificateEntries {
						if e.SerialNumber.Cmp(c.SerialNumber) == 0 {
							denied = true
						}
					}
				}
			}
		}
		if !denied {
			return path, nil
		}
	}
	return nil, fmt.Errorf("all verified paths rejected by explicit distrust or supplied CRL")
}

// ErrPolicyUnavailable means a requested policy could not be evaluated; it must
// never be presented as proof that a compromised chain was rejected.
var ErrEvaluationUnsupported = errors.New("offline X.509 parser does not support this certificate")

var ErrPolicyUnavailable = errors.New("supplied CRL is not current")

// RejectionCategory normalizes public certificate errors without retaining raw
// certificate subjects or unrelated filesystem/credential information.
func RejectionCategory(err error) string {
	if errors.Is(err, ErrEvaluationUnsupported) {
		return "unsupported_certificate"
	}
	if errors.Is(err, ErrPolicyUnavailable) {
		return "policy_unavailable"
	}
	var ctUnknown ctx509.UnknownAuthorityError
	if errors.As(err, &ctUnknown) {
		return "untrusted_issuer"
	}
	var ctInvalid ctx509.CertificateInvalidError
	if errors.As(err, &ctInvalid) {
		if ctInvalid.Reason == ctx509.Expired {
			return "expired_or_not_yet_valid"
		}
		return "certificate_policy"
	}
	var ctHost ctx509.HostnameError
	if errors.As(err, &ctHost) {
		return "hostname"
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return "untrusted_issuer"
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		if strings.Contains(err.Error(), "no valid chains") {
			return "verifier_policy"
		}
		if invalid.Reason == x509.Expired {
			return "expired_or_not_yet_valid"
		}
		return "certificate_policy"
	}
	var host x509.HostnameError
	if errors.As(err, &host) {
		return "hostname"
	}
	if strings.Contains(err.Error(), "explicit distrust") {
		return "explicit_distrust_or_revocation"
	}
	return "certificate_validation"
}
