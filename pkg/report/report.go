// Package report defines the versioned public report schema and terminal renderer.
package report

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
)

type Status string

const (
	VulnerableClient Status = "VULNERABLE_CLIENT"
	VulnerableStore  Status = "VULNERABLE_STORE"
	Potential        Status = "POTENTIAL"
	Rejected         Status = "REJECTED"
	Inconclusive     Status = "INCONCLUSIVE"
	NotSupported     Status = "NOT_SUPPORTED"
)

// Target identifies a local filesystem or a running container.
type Target struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	ID    string `json:"id,omitempty"`
	Image string `json:"image,omitempty"`
}
type Evidence struct {
	Attempted          *bool  `json:"attempted,omitempty"` // Live chain request attempted; absent for static evidence.
	Model              string `json:"model"`
	Detail             string `json:"detail"`
	Category           string `json:"category,omitempty"`
	LeafSHA256         string `json:"leaf_sha256,omitempty"`
	IntermediateSHA256 string `json:"intermediate_sha256,omitempty"`
	SPKISHA256         string `json:"spki_sha256,omitempty"`
	RootSHA256         string `json:"root_sha256,omitempty"`
}
type Finding struct {
	Status       Status   `json:"status"`
	Method       string   `json:"method"`
	Client       string   `json:"client,omitempty"`
	Path         string   `json:"path,omitempty"`
	Usage        string   `json:"usage"`
	Chain        string   `json:"chain,omitempty"`
	Intermediate string   `json:"intermediate,omitempty"`
	Root         string   `json:"root,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
	Evidence     Evidence `json:"evidence"`
	Remediation  string   `json:"remediation,omitempty"`
}
type ClientCoverage struct {
	Name       string   `json:"name"`
	Discovered bool     `json:"discovered"`
	Tested     int      `json:"tested"`
	Expected   int      `json:"expected"`
	Reason     string   `json:"reason,omitempty"`
	CAPaths    []string `json:"ca_paths,omitempty"`
}
type Coverage struct {
	Complete    bool             `json:"complete"` // Scoped to supported TLS checks, never all applications.
	Stores      int              `json:"stores"`
	Clients     []ClientCoverage `json:"clients"`
	Limitations []string         `json:"limitations"`
}

// TrustStore summarizes explicit static validation at one exact filesystem path.
type TrustStore struct {
	Path     string `json:"path"`
	Format   string `json:"format"`
	Model    string `json:"model"`
	Status   Status `json:"status"`
	Expected int    `json:"expected"`
	Accepted int    `json:"accepted"`
	Rejected int    `json:"rejected"`
	Other    int    `json:"other"`
}
type TargetReport struct {
	TrustStores []TrustStore `json:"trust_stores"`
	Target      Target       `json:"target"`
	Findings    []Finding    `json:"findings"`
	Coverage    Coverage     `json:"coverage"`
}
type Summary struct {
	Targets           int `json:"targets"`
	Hosts             int `json:"hosts"`
	Containers        int `json:"containers"`
	VulnerableClients int `json:"vulnerable_clients"` // distinct target/client pairs
	VulnerableStores  int `json:"vulnerable_stores"`  // distinct target/path pairs
	IncompleteTargets int `json:"incomplete_targets"`
}
type Report struct {
	SchemaVersion string         `json:"schema_version"`
	Incident      string         `json:"incident"`
	GeneratedAt   time.Time      `json:"generated_at"`
	Targets       []TargetReport `json:"targets"`
	Warnings      []string       `json:"warnings"`
	Summary       Summary        `json:"summary"`
}

// Summarize recalculates counters. Evidence is never merged between clients and stores.
func (r *Report) Summarize() {
	r.Summary = Summary{Targets: len(r.Targets)}
	for _, t := range r.Targets {
		if t.Target.Kind == "host" {
			r.Summary.Hosts++
		} else {
			r.Summary.Containers++
		}
		if !t.Coverage.Complete {
			r.Summary.IncompleteTargets++
		}
		clients, stores := map[string]bool{}, map[string]bool{}
		for _, f := range t.Findings {
			if f.Status == VulnerableClient {
				clients[f.Client] = true
			}
			if f.Status == VulnerableStore {
				stores[f.Path] = true
			}
		}
		r.Summary.VulnerableClients += len(clients)
		r.Summary.VulnerableStores += len(stores)
	}
}

// ExitCode gives vulnerabilities precedence over incomplete coverage.
func (r Report) ExitCode(strict bool) int {
	if r.Summary.VulnerableClients+r.Summary.VulnerableStores > 0 {
		return 1
	}
	if strict && (r.Summary.IncompleteTargets > 0 || len(r.Warnings) > 0) {
		return 3
	}
	return 0
}
func Terminal(w io.Writer, r Report, verbose bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CA Trust Audit\nIncident: %s\n", r.Incident)
	for _, t := range r.Targets {
		fmt.Fprintf(&b, "\n%s %s", strings.ToUpper(t.Target.Kind), t.Target.Name)
		if t.Target.ID != "" {
			fmt.Fprintf(&b, " (%s) image=%s", t.Target.ID, t.Target.Image)
		}
		fmt.Fprintln(&b)
		explainTarget(&b, t)
		counts := map[Status]int{}
		shown := map[string]bool{}
		for _, f := range t.Findings {
			counts[f.Status]++
			if !verbose && (f.Status == Rejected || f.Status == NotSupported) {
				continue
			}
			key := string(f.Status) + "/" + f.Method + "/" + f.Client + "/" + f.Path
			if !verbose && shown[key] {
				continue
			}
			shown[key] = true
			fmt.Fprintf(&b, "  %s %s %s\n", terminalLabel(f.Status), f.Client, f.Path)
			if f.Chain != "" || f.Intermediate != "" {
				fmt.Fprintf(&b, "    %s / %s\n", f.Intermediate, f.Root)
			}
			fmt.Fprintf(&b, "    %s\n", terminalDetail(f.Evidence.Detail))
			if f.Remediation != "" {
				fmt.Fprintf(&b, "    Action: %s\n", f.Remediation)
			}
		}
		fmt.Fprintf(&b, "  Checks: passed=%d problems=%d review=%d not-verified=%d unsupported=%d\n", counts[Rejected], counts[VulnerableClient]+counts[VulnerableStore], counts[Potential], counts[Inconclusive], counts[NotSupported])
		for _, s := range t.TrustStores {
			if strings.Contains(s.Path, "ca-certificates.crt") || s.Path == "/etc/ssl/cert.pem" || strings.Contains(s.Path, "ca-bundle") || strings.Contains(s.Path, "cacert.pem") {
				fmt.Fprintf(&b, "  Store %s: %s (%d/%d chains rejected; accepted=%d; unresolved=%d)\n", s.Path, terminalLabel(s.Status), s.Rejected, s.Expected, s.Accepted, s.Other)
			}
		}
		for _, c := range t.Coverage.Clients {
			if c.Discovered || verbose {
				fmt.Fprintf(&b, "  Client %s: %s (%d/%d chains tested) %s\n", c.Name, clientLabel(c, t.Findings), c.Tested, c.Expected, terminalDetail(c.Reason))
			}
		}
		coverage := "PARTIAL"
		if t.Coverage.Complete {
			coverage = "COMPLETE"
		}
		fmt.Fprintf(&b, "  Coverage: %s; CA files evaluated: %d\n", coverage, t.Coverage.Stores)
		for _, l := range t.Coverage.Limitations {
			fmt.Fprintf(&b, "  Coverage: %s\n", terminalDetail(l))
		}
	}
	for _, s := range r.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", s)
	}
	fmt.Fprintf(&b, "\nSUMMARY targets=%d hosts=%d containers=%d problem-clients=%d problem-stores=%d targets-with-incomplete-coverage=%d\n", r.Summary.Targets, r.Summary.Hosts, r.Summary.Containers, r.Summary.VulnerableClients, r.Summary.VulnerableStores, r.Summary.IncompleteTargets)
	fmt.Fprintln(&b, "Results describe the evaluated models and clients; they do not establish safety of all applications or code signing.")
	_, err := io.WriteString(w, strings.Map(func(r rune) rune {
		if r != '\n' && r != '\t' && unicode.IsControl(r) {
			return '?'
		}
		return r
	}, b.String()))
	return err
}

// explainTarget gives an administrator the actionable conclusion before detail.
func explainTarget(w io.Writer, t TargetReport) {
	accepted, other, rejected := 0, 0, 0
	for _, s := range t.TrustStores {
		accepted += s.Accepted
		other += s.Other
		rejected += s.Rejected
	}
	switch {
	case accepted > 0:
		fmt.Fprintln(w, "  CA FILES: PROBLEM — a checked CA file accepts a compromised chain under the documented PEM validation model. Update the listed bundles and consuming applications.")
	case rejected > 0 && other == 0:
		fmt.Fprintln(w, "  CA FILES: PASSED — the checked CA files rejected all incident test chains under the documented PEM validation model.")
	default:
		fmt.Fprintln(w, "  CA FILES: NOT VERIFIED — the available checks could not determine whether all selected stores reject the compromised chains.")
	}
	liveVulnerable := false
	for _, f := range t.Findings {
		if f.Status == VulnerableClient {
			liveVulnerable = true
		}
	}
	offline := false
	complete := true
	discovered := 0
	tested := 0
	for _, c := range t.Coverage.Clients {
		if !c.Discovered {
			continue
		}
		discovered++
		tested += c.Tested
		if strings.Contains(c.Reason, "offline:") {
			offline = true
		}
		if c.Expected == 0 || c.Tested < c.Expected {
			complete = false
		}
	}
	switch {
	case liveVulnerable:
		fmt.Fprintln(w, "  LIVE CLIENTS: PROBLEM — a validating client accepted a known compromised test certificate. Update that runtime and its trust configuration, then retest.")
	case offline:
		fmt.Fprintln(w, "  LIVE CLIENTS: NOT VERIFIED — offline mode; live checks were not run.")
	case discovered > 0 && complete:
		fmt.Fprintln(w, "  LIVE CLIENTS: PASSED — the listed clients rejected all incident endpoints and passed their HTTPS positive controls. Other applications are outside this result.")
	case tested > 0:
		fmt.Fprintln(w, "  LIVE CLIENTS: NOT VERIFIED — some checks completed, but additional clients or chains remain unverified.")
	default:
		fmt.Fprintln(w, "  LIVE CLIENTS: NOT VERIFIED — live checks could not establish a complete result. Network or positive-control failures require a retry; they do not establish protection or vulnerability.")
	}
}

// terminalLabel keeps administrator wording independent of the stable JSON enums.
func terminalLabel(s Status) string {
	switch s {
	case Rejected:
		return "PASSED"
	case VulnerableClient, VulnerableStore:
		return "PROBLEM"
	case Potential:
		return "REVIEW"
	case NotSupported:
		return "UNSUPPORTED"
	default:
		return "NOT VERIFIED"
	}
}
func terminalDetail(detail string) string {
	// Some normalized evidence begins with a machine status. Preserve the evidence
	// in JSON while using the same human-readable vocabulary throughout the terminal.
	for _, s := range []Status{VulnerableClient, VulnerableStore, NotSupported, Inconclusive, Rejected, Potential} {
		detail = strings.ReplaceAll(detail, string(s), terminalLabel(s))
	}
	return detail
}
func clientLabel(c ClientCoverage, findings []Finding) string {
	for _, f := range findings {
		if f.Method == "live" && f.Client == c.Name && f.Status == VulnerableClient {
			return "PROBLEM"
		}
	}
	if !c.Discovered {
		return "UNAVAILABLE"
	}
	if c.Expected == 0 {
		return "UNSUPPORTED"
	}
	if c.Tested == c.Expected {
		return "PASSED"
	}
	return "NOT VERIFIED"
}
