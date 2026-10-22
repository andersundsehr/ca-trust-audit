// Package emudhra contains a pinned, integrity-checked snapshot of public incident data.
package emudhra

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
)

//go:embed data SHA256SUMS
var files embed.FS

// Load checks bundled file hashes, every published certificate fingerprint and
// SPKI, and all chain signatures. It never downloads executable or incident data.
func Load() (certificates.Incident, error) {
	var out certificates.Incident
	sums, _ := files.ReadFile("SHA256SUMS")
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			return out, fmt.Errorf("invalid fixture manifest")
		}
		data, err := files.ReadFile(f[1])
		if err != nil {
			return out, err
		}
		if certificates.SHA256(data) != f[0] {
			return out, fmt.Errorf("fixture integrity failure: %s", f[1])
		}
	}
	out.ID = "eMudhra / CVE-2026-111943"
	out.Source = "https://github.com/galadran/we-have-a-problem.com/tree/2086d67fb486982ab58aab2c965855aadf4c4a24"
	for _, v := range []struct {
		name string
		dst  *[]certificates.Identity
	}{{"impacted-intermediates.json", &out.Identities}, {"roots.json", &out.Roots}} {
		data, _ := files.ReadFile("data/" + v.name)
		if err := json.Unmarshal(data, v.dst); err != nil {
			return out, err
		}
		for _, id := range *v.dst {
			cs, err := certificates.ParsePEM([]byte(id.PEM))
			if err != nil || len(cs) != 1 {
				return out, fmt.Errorf("invalid identity certificate %s", id.Name)
			}
			if !strings.EqualFold(certificates.SHA256(cs[0].Raw), id.SHA256) || !strings.EqualFold(certificates.SPKI(cs[0]), id.SPKISHA256) {
				return out, fmt.Errorf("published identity mismatch %s", id.Name)
			}
		}
	}
	entries, _ := files.ReadDir("data/chains")
	for _, e := range entries {
		data, _ := files.ReadFile("data/chains/" + e.Name())
		cs, err := certificates.ParsePEM(data)
		if err != nil {
			return out, err
		}
		if len(cs) < 2 {
			return out, fmt.Errorf("short fixture chain")
		}
		var id certificates.Identity
		for _, candidate := range out.Identities {
			if strings.EqualFold(candidate.SHA256, certificates.SHA256(cs[1].Raw)) {
				id = candidate
			}
		}
		if id.Name == "" || id.Usage != "tls" {
			return out, fmt.Errorf("unknown compromised intermediate in %s", e.Name())
		}
		for n := 0; n < len(cs)-1; n++ {
			if err := cs[n].CheckSignatureFrom(cs[n+1]); err != nil {
				return out, fmt.Errorf("fixture signature: %w", err)
			}
		}
		host := strings.TrimSuffix(path.Base(e.Name()), ".pem")
		if err := cs[0].VerifyHostname(host); err != nil {
			return out, fmt.Errorf("fixture hostname: %w", err)
		}
		out.Chains = append(out.Chains, certificates.Chain{ID: host, Host: host, Certificates: cs, Intermediate: id})
	}
	if len(out.Chains) != 14 || len(out.Identities) != 16 {
		return out, fmt.Errorf("incomplete incident snapshot")
	}
	return out, nil
}
