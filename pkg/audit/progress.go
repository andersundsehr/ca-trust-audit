package audit

import "github.com/andersundsehr/ca-trust-audit/pkg/report"

// Phase describes work in progress, never its security outcome.
type Phase string

const (
	PhaseDockerDiscovery   Phase = "docker_discovery"
	PhaseTargetsDiscovered Phase = "targets_discovered"
	PhaseContainerInspect  Phase = "container_inspect"
	PhaseTargetStarted     Phase = "target_started"
	PhaseConfiguration     Phase = "configuration"
	PhaseStores            Phase = "stores"
	PhaseClientDiscovery   Phase = "client_discovery"
	PhasePositiveControl   Phase = "positive_control"
	PhaseTLS               Phase = "tls"
	PhaseTargetCompleted   Phase = "target_completed"
	PhaseTargetCanceled    Phase = "target_canceled"
)

// Progress is an ephemeral scan notification, separate from report evidence.
// Completed/Total count work in the current phase. For PhaseTargetsDiscovered,
// Total is the final selected target count; it is unknown before Docker discovery.
// Security checks may still be inconclusive when a target finishes processing.
type Progress struct {
	Phase     Phase
	Target    report.Target
	Client    string
	Completed int
	Total     int
}

func notify(o Options, p Progress) {
	if o.Progress != nil {
		o.Progress(p)
	}
}
