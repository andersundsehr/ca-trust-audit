// Package audit orchestrates incident scans of the local Linux filesystem and
// running Docker containers. Its zero Options selects host, containers and online
// checks; use Offline or HostOnly for explicit restrictions.
package audit

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andersundsehr/ca-trust-audit/internal/incidents/emudhra"
	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"github.com/andersundsehr/ca-trust-audit/pkg/docker"
	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

// Options controls selection and bounds. IncludeHost/IncludeContainers, when
// either is true, form an explicit target selection; both false defaults to both.
// Online is retained for readable call sites; Offline overrides it.
type Options struct {
	CADirectories     []string // additional certificate-only directories
	IncludeHost       bool
	IncludeContainers bool
	Online            bool
	Offline           bool
	HostOnly          bool
	ContainersOnly    bool
	Container         string
	Timeout           time.Duration
	Workers           int
	CAPaths           []string // additional exact PEM files, evaluated in each selected target
	Incident          *certificates.Incident
	Probes            []probes.Probe // nil uses built-ins; empty disables external probes
	PositiveControl   string         // defaults to https://example.com/
	Policy            certificates.Policy
}

// DefaultIncident returns the verified embedded incident snapshot.
func DefaultIncident() (certificates.Incident, error) { return emudhra.Load() }
func normalize(o *Options) error {
	if o.HostOnly && o.ContainersOnly {
		return errors.New("host-only and containers-only are mutually exclusive")
	}
	if o.Container != "" && o.HostOnly {
		return errors.New("container and host-only are mutually exclusive")
	}
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Timeout < time.Millisecond || o.Timeout > 5*time.Minute {
		return errors.New("timeout must be between 1ms and 5m")
	}
	if o.Workers == 0 {
		o.Workers = 4
	}
	if o.Workers < 1 || o.Workers > 64 {
		return errors.New("workers must be between 1 and 64")
	}
	if o.PositiveControl == "" {
		o.PositiveControl = "https://example.com/"
	}
	if !strings.HasPrefix(o.PositiveControl, "https://") {
		return errors.New("positive control must use HTTPS")
	}
	if o.Probes == nil {
		o.Probes = probes.Defaults()
	}
	for _, p := range append(append([]string{}, o.CAPaths...), o.CADirectories...) {
		if !safePath(p) {
			return errors.New("CA paths must be absolute filesystem paths without control characters")
		}
	}
	return nil
}
func safePath(p string) bool {
	return filepath.IsAbs(p) && !strings.ContainsAny(p, "\r\n\x00") && len(p) < 4096
}

// Scan performs bounded target scans. Discovery failures preserve a valid host
// report and mark Docker coverage incomplete. Fatal errors are returned separately.
func Scan(ctx context.Context, o Options) (report.Report, error) {
	r := report.Report{SchemaVersion: "1.0", GeneratedAt: time.Now().UTC(), Targets: []report.TargetReport{}, Warnings: []string{}}
	if err := normalize(&o); err != nil {
		return r, err
	}
	incident, err := DefaultIncident()
	if o.Incident != nil {
		incident = *o.Incident
		err = nil
	}
	if err != nil {
		return r, fmt.Errorf("load incident: %w", err)
	}
	if len(incident.Chains) == 0 {
		return r, errors.New("incident has no TLS chains")
	}
	for _, c := range incident.Chains {
		if len(c.Certificates) < 2 {
			return r, errors.New("incident has an incomplete TLS chain")
		}
	}
	r.Incident = incident.ID
	host, containers := o.IncludeHost, o.IncludeContainers
	if !host && !containers {
		host = true
		containers = true
	}
	if o.HostOnly {
		host = true
		containers = false
	}
	if o.ContainersOnly || o.Container != "" {
		host = false
		containers = true
	}
	if host {
		env := map[string]string{}
		for k := range docker.CAKeys {
			if v, ok := os.LookupEnv(k); ok {
				env[k] = v
			}
		}
		r.Targets = append(r.Targets, ScanTarget(ctx, report.Target{Kind: "host", Name: "local filesystem"}, HostFiles{}, probes.HostRunner{}, env, incident, o))
	}
	if containers {
		discovery, cancel := context.WithTimeout(ctx, o.Timeout)
		client, e := docker.New(discovery)
		if e != nil {
			cancel()
			if errors.Is(e, docker.ErrUnavailable) && o.Container == "" && !o.ContainersOnly {
				r.Warnings = append(r.Warnings, "Docker unavailable: host-only coverage")
			} else {
				r.Warnings = append(r.Warnings, "Docker discovery incomplete: "+e.Error())
			}
		} else {
			defer client.Close()
			list, e := client.Running(discovery)
			cancel()
			if e != nil {
				r.Warnings = append(r.Warnings, "Docker discovery incomplete: "+e.Error())
			} else {
				sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
				if o.Container != "" {
					var matches []docker.Container
					for _, c := range list {
						match := c.ID == o.Container || strings.HasPrefix(c.ID, o.Container)
						for _, n := range c.Names {
							match = match || strings.TrimPrefix(n, "/") == o.Container
						}
						if match {
							matches = append(matches, c)
						}
					}
					if len(matches) != 1 {
						return r, errors.New("container selection must match exactly one running container")
					}
					list = matches
				}
				results := make([]report.TargetReport, len(list))
				jobs := make(chan int)
				var wg sync.WaitGroup
				workers := o.Workers
				if workers > len(list) {
					workers = len(list)
				}
				for w := 0; w < workers; w++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for n := range jobs {
							c := list[n]
							name := c.ID
							if len(c.Names) > 0 {
								name = strings.TrimPrefix(c.Names[0], "/")
							}
							tc, cancel := context.WithTimeout(ctx, o.Timeout)
							env, e := client.CAEnvironment(tc, c.ID)
							cancel()
							t := ScanTarget(ctx, report.Target{Kind: "container", Name: name, ID: c.ID, Image: c.Image}, containerFiles{client, c.ID}, docker.Runner{Client: client, ID: c.ID}, env, incident, o)
							if e != nil {
								t.Coverage.Complete = false
								t.Coverage.Limitations = append(t.Coverage.Limitations, "container CA environment unavailable")
							}
							results[n] = t
						}
					}()
				}
				for n := range list {
					jobs <- n
				}
				close(jobs)
				wg.Wait()
				r.Targets = append(r.Targets, results...)
			}
		}
	}
	r.Summarize()
	if len(r.Targets) == 0 && len(r.Warnings) > 0 {
		return r, errors.New("no selected targets could be scanned; " + strings.Join(r.Warnings, "; "))
	}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	return r, nil
}

// ScanTarget enables embedded, deterministic and custom-filesystem scans. Options
// are normalized locally; invalid options produce an incomplete target report.
func ScanTarget(ctx context.Context, target report.Target, files Files, runner probes.Runner, env map[string]string, incident certificates.Incident, o Options) report.TargetReport {
	t := report.TargetReport{Target: target, Findings: []report.Finding{}, Coverage: report.Coverage{Complete: true, Clients: []report.ClientCoverage{}, Limitations: []string{}}}
	if err := normalize(&o); err != nil {
		t.Coverage.Complete = false
		t.Coverage.Limitations = append(t.Coverage.Limitations, err.Error())
		return t
	}
	for _, chain := range incident.Chains {
		if len(chain.Certificates) < 2 {
			t.Coverage.Complete = false
			t.Coverage.Limitations = append(t.Coverage.Limitations, "invalid incident: incomplete chain")
			return t
		}
	}
	paths := []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt", "/etc/ssl/certs/java/cacerts", "/etc/pki/java/cacerts", "/etc/pki/nssdb/cert9.db", "/etc/ssl/cert9.db"}
	paths = append(paths, o.CAPaths...)
	configured := map[string]bool{}
	clientPaths := map[string][]string{}
	directories := append([]string{}, o.CADirectories...)
	for key, val := range env {
		if key == "JAVA_TOOL_OPTIONS" || key == "JDK_JAVA_OPTIONS" || key == "_JAVA_OPTIONS" {
			for _, word := range strings.Fields(val) {
				if p, ok := strings.CutPrefix(word, "-Djavax.net.ssl.trustStore="); ok {
					p = strings.Trim(p, "\"'")
					if safePath(p) {
						paths = append(paths, p)
						configured[p] = true
					}
				}
			}
			continue
		}
		if key == "JAVA_HOME" {
			if safePath(val) {
				paths = append(paths, filepath.Join(val, "lib/security/cacerts"))
			}
			continue
		}
		if key == "SSL_CERT_DIR" {
			for _, d := range strings.Split(val, ":") {
				if safePath(d) {
					directories = append(directories, d)
				}
			}
			continue
		}
		if safePath(val) {
			paths = append(paths, val)
			configured[val] = true
		}
	}
	// Ask installed clients only for narrow public CA configuration, not phpinfo,
	// environment dumps, site files, full JVM options or application directories.
	if runner != nil {
		metadata := []struct {
			exe     string
			clients []string
			args    []string
		}{
			{"python3", []string{"Python ssl/urllib"}, []string{"-B", "-c", `import ssl,json;v=ssl.get_default_verify_paths();print(json.dumps({'files':[v.cafile],'dirs':[v.capath]}))`}},
			{"python3", []string{"Python requests/certifi"}, []string{"-B", "-c", `import certifi,json;print(json.dumps({'files':[certifi.where()]}))`}},
			{"php", []string{"PHP OpenSSL streams"}, []string{"-r", `$v=openssl_get_cert_locations();echo json_encode(['files'=>[ini_get('openssl.cafile'),$v['default_cert_file']??null],'dirs'=>[ini_get('openssl.capath'),$v['default_cert_dir']??null]]);`}},
			{"php", []string{"PHP cURL"}, []string{"-r", `$v=[ini_get('curl.cainfo')];if(extension_loaded('curl')&&defined('CURLINFO_CAINFO')){$h=curl_init();$v[]=curl_getinfo($h,CURLINFO_CAINFO);}echo json_encode(['files'=>$v]);`}},
		}
		for _, m := range metadata {
			c, cancel := context.WithTimeout(ctx, o.Timeout)
			b, e := runner.Run(c, m.exe, m.args...)
			cancel()
			if e != nil {
				continue
			}
			var ps struct {
				Files []string
				Dirs  []string
			}
			if json.Unmarshal(b, &ps) != nil {
				continue
			}
			for _, p := range ps.Files {
				if safePath(p) {
					paths = append(paths, p)
					configured[p] = true
					for _, client := range m.clients {
						clientPaths[client] = append(clientPaths[client], p)
					}
				}
			}
			for _, p := range ps.Dirs {
				if safePath(p) {
					directories = append(directories, p)
					for _, client := range m.clients {
						clientPaths[client] = append(clientPaths[client], p)
					}
				}
			}
		}

	}
	directories = append(directories, "/etc/ssl/certs", "/usr/local/share/ca-certificates", "/etc/pki/ca-trust/source/anchors")
	for _, dir := range unique(directories) {
		c, cancel := context.WithTimeout(ctx, o.Timeout)
		ps, e := files.CAFiles(c, dir)
		cancel()
		if e != nil {
			if !errors.Is(e, fs.ErrNotExist) {
				t.Coverage.Complete = false
				t.Coverage.Limitations = append(t.Coverage.Limitations, "could not enumerate CA directory: "+dir)
			}
			continue
		}
		paths = append(paths, ps...)
	}
	count := 0
	for _, p := range unique(paths) {
		if ctx.Err() != nil {
			t.Coverage.Complete = false
			break
		}
		count++
		if count > 2048 {
			t.Coverage.Complete = false
			t.Coverage.Limitations = append(t.Coverage.Limitations, "CA path limit exceeded")
			break
		}
		c, cancel := context.WithTimeout(ctx, o.Timeout)
		b, e := files.ReadFile(c, p)
		cancel()
		if e != nil {
			if !errors.Is(e, fs.ErrNotExist) || configured[p] || contains(o.CAPaths, p) {
				t.Coverage.Complete = false
				t.Findings = append(t.Findings, report.Finding{Status: report.Inconclusive, Method: "store", Path: p, Usage: "tls", Evidence: report.Evidence{Model: "PEM/CT Go x509", Category: "file_unavailable", Detail: "CA file unavailable, unreadable, not regular or exceeds limits"}})
			}
			continue
		}
		if strings.HasSuffix(p, "cacerts") || strings.HasSuffix(p, ".jks") || strings.HasSuffix(p, ".p12") || strings.HasSuffix(p, ".pfx") || strings.HasSuffix(p, ".db") {
			t.Coverage.Complete = false
			t.Findings = append(t.Findings, report.Finding{Status: report.NotSupported, Method: "store", Path: p, Usage: "tls", Evidence: report.Evidence{Model: "unsupported", Detail: "Java/JKS/PKCS#12/NSS policy validation is not supported"}})
			continue
		}
		roots, e := certificates.ParsePEM(b)
		if e != nil {
			t.Coverage.Complete = false
			t.Findings = append(t.Findings, report.Finding{Status: report.NotSupported, Method: "store", Path: p, Usage: "tls", Evidence: report.Evidence{Model: "PEM/CT Go x509", Detail: e.Error()}})
			continue
		}
		t.Coverage.Stores++
		for _, chain := range incident.Chains {
			verified, e := certificates.Evaluate(chain, roots, o.Policy)
			f := report.Finding{Status: report.Rejected, Method: "store", Path: p, Usage: "tls", Chain: chain.ID, Intermediate: chain.Intermediate.Name, Root: chain.Intermediate.IssuedBy, Evidence: report.Evidence{Model: "CT Go x509, explicit PEM anchors, serverAuth, DNS and current time; no implicit CRL/OCSP or external distrust", IntermediateSHA256: strings.ToLower(chain.Intermediate.SHA256), SPKISHA256: strings.ToLower(chain.Intermediate.SPKISHA256), LeafSHA256: certificates.SHA256(chain.Certificates[0].Raw), Detail: "published chain rejected by explicit PEM model"}}
			if e != nil {
				f.Evidence.Category = certificates.RejectionCategory(e)
				f.Evidence.Detail += " (" + f.Evidence.Category + ")"
				if f.Evidence.Category == "verifier_policy" {
					f.Status = report.Potential
					f.Evidence.Detail = "scanner Go verifier rejected all candidate paths; built-in distrust may mask the PEM bundle policy; effective application trust remains unestablished"
					t.Coverage.Complete = false
				}
				if errors.Is(e, certificates.ErrEvaluationUnsupported) {
					f.Status = report.NotSupported
					t.Coverage.Complete = false
				}
				if errors.Is(e, certificates.ErrPolicyUnavailable) {
					f.Status = report.Inconclusive
					t.Coverage.Complete = false
				}
			}
			if e == nil {
				f.Status = report.VulnerableStore
				f.Evidence.Detail = "explicit PEM model accepted the published leaf and compromised chain"
				if len(verified) > 0 {
					root := verified[len(verified)-1]
					f.Root = root.Subject.CommonName
					f.Evidence.RootSHA256 = certificates.SHA256(root.Raw)
				}
				f.Remediation = "Update this CA bundle and consuming runtimes using vendor incident guidance; verify effective distrust with live clients."
			}
			t.Findings = append(t.Findings, f)
		}
		t.Findings = append(t.Findings, materialFindings(roots, p, incident)...)
	}
	if t.Coverage.Stores == 0 {
		t.Coverage.Complete = false
		t.Coverage.Limitations = append(t.Coverage.Limitations, "no supported PEM trust stores could be evaluated")
	}
	clients := append([]probes.Probe{}, o.Probes...)
	if target.Kind == "host" {
		clients = append([]probes.Probe{probes.Native{}}, clients...)
	} else {
		t.Coverage.Clients = append(t.Coverage.Clients, report.ClientCoverage{Name: "Go applications in container", Reason: "cannot infer application TLS policy from scanner Go stack"})
	}
	testedClients := 0
	for _, client := range clients {
		if runner == nil {
			break
		}
		c, cancel := context.WithTimeout(ctx, o.Timeout)
		found := client.Discover(c, runner)
		cancel()
		cv := report.ClientCoverage{Name: client.Name(), Discovered: found, Expected: len(incident.Chains)}
		if !found {
			if scripted, ok := client.(probes.Script); ok {
				c, cancel := context.WithTimeout(ctx, o.Timeout)
				present := probes.Exists(c, runner, scripted.Executable, "--version")
				cancel()
				if present {
					cv.Discovered = true
					t.Coverage.Complete = false
					cv.Reason = "runtime installed; required module or discovery unavailable"
				}
			}
			if cv.Reason == "" {
				cv.Reason = "not installed or discovery failed"
			}
			t.Coverage.Clients = append(t.Coverage.Clients, cv)
			continue
		}
		for _, k := range clientCAKeys(client.Name()) {
			if v := env[k]; safePath(v) {
				cv.CAPaths = append(cv.CAPaths, v)
			}
		}
		cv.CAPaths = unique(append(cv.CAPaths, clientPaths[client.Name()]...))
		if o.Offline {
			cv.Reason = "offline: live validation not run"
			t.Coverage.Complete = false
			t.Coverage.Clients = append(t.Coverage.Clients, cv)
			continue
		}
		c, cancel = context.WithTimeout(ctx, o.Timeout)
		control := client.Check(c, runner, o.PositiveControl)
		cancel()
		if control.Status != report.VulnerableClient {
			cv.Reason = "positive control failed: " + control.Category
		}
		for _, chain := range incident.Chains {
			result := probes.Result{Status: report.Inconclusive, Category: "positive_control_failed"}
			if control.Status == report.VulnerableClient {
				c, cancel = context.WithTimeout(ctx, o.Timeout)
				result = client.Check(c, runner, "https://"+chain.Host+"/")
				cancel()
			}
			f := probes.EvidenceFor(result, chain, client.Name())
			if control.Status != report.VulnerableClient {
				f.Status = report.Inconclusive
				f.Evidence.Category = "positive_control_failed"
				attempted := false
				f.Evidence.Attempted = &attempted
				f.Evidence.Detail = "incident request not attempted: positive control failed: " + control.Category + "; restore verified connectivity and rerun"
				f.Remediation = "Restore verified HTTPS connectivity for this client and rerun."
			}
			if f.Status == report.Rejected || f.Status == report.VulnerableClient {
				cv.Tested++
			} else {
				t.Coverage.Complete = false
			}
			t.Findings = append(t.Findings, f)
		}
		if cv.Tested == len(incident.Chains) {
			testedClients++
		}
		t.Coverage.Clients = append(t.Coverage.Clients, cv)
	}
	if testedClients == 0 {
		t.Coverage.Complete = false
		t.Coverage.Limitations = append(t.Coverage.Limitations, "no client completed all live chain tests")
	}
	if runner != nil {
		c, cancel := context.WithTimeout(ctx, o.Timeout)
		java := probes.Exists(c, runner, "java", "-version")
		cancel()
		t.Coverage.Clients = append(t.Coverage.Clients, report.ClientCoverage{Name: "Java JSSE", Discovered: java, Reason: "NOT_SUPPORTED: no portable read-only inline JSSE probe"})
		if java {
			t.Coverage.Complete = false
		}
	}
	t.TrustStores = storeSummaries(t.Findings, len(incident.Chains))
	t.Coverage.Limitations = append(t.Coverage.Limitations, "Code-signing policy NOT_SUPPORTED; CA material detection only. Custom application stores and external distrust/revocation policies may differ.")
	return t
}
func materialFindings(cs []*x509.Certificate, p string, i certificates.Incident) []report.Finding {
	var out []report.Finding
	for _, c := range cs {
		for _, id := range append(append([]certificates.Identity{}, i.Identities...), i.Roots...) {
			if strings.EqualFold(certificates.SPKI(c), id.SPKISHA256) {
				usage := id.Usage
				if usage == "" {
					usage = "ca-material"
				}
				out = append(out, report.Finding{Status: report.Potential, Method: "material", Path: p, Usage: usage, Intermediate: id.Name, Evidence: report.Evidence{Model: "certificate/SPKI identity only", Detail: "incident-related CA key present; presence alone does not establish effective TLS or code-signing trust", IntermediateSHA256: certificates.SHA256(c.Raw), SPKISHA256: certificates.SPKI(c)}, Remediation: "Review vendor distrust guidance and applications consuming this path."})
				break
			}
		}
	}
	return out
}
func unique(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, p := range in {
		if !m[p] {
			m[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func clientCAKeys(name string) []string {
	switch name {
	case "Go TLS (scanner)", "Python ssl/urllib", "Ruby HTTPS":
		return []string{"SSL_CERT_FILE", "SSL_CERT_DIR"}
	case "curl":
		return []string{"CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"}
	case "Python requests/certifi":
		return []string{"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"}
	case "Node.js HTTPS":
		return []string{"NODE_EXTRA_CA_CERTS"}
	case "PHP OpenSSL streams", "PHP cURL":
		return nil
	}
	return nil
}

func storeSummaries(findings []report.Finding, expected int) []report.TrustStore {
	stores := map[string]*report.TrustStore{}
	for _, f := range findings {
		if f.Method != "store" {
			continue
		}
		s := stores[f.Path]
		if s == nil {
			s = &report.TrustStore{Path: f.Path, Format: "PEM", Model: f.Evidence.Model, Expected: expected, Status: report.Rejected}
			stores[f.Path] = s
		}
		switch f.Status {
		case report.VulnerableStore:
			s.Accepted++
			s.Status = report.VulnerableStore
		case report.Rejected:
			s.Rejected++
		default:
			s.Other++
			if s.Status != report.VulnerableStore {
				s.Status = f.Status
			}
		}
	}
	var out []report.TrustStore
	for _, s := range stores {
		if s.Accepted+s.Rejected == 0 {
			s.Format = "unavailable_or_unsupported"
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
