package audit

import (
	"context"
	"sync"

	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

// Waiting for a shared slot does not consume a request's network deadline.
func checkClient(ctx context.Context, o Options, client probes.Probe, runner probes.Runner, endpoint string) probes.Result {
	if ctx.Err() != nil {
		return probes.Result{Status: report.Inconclusive, Category: "canceled"}
	}
	select {
	case o.probeSlots <- struct{}{}:
		defer func() { <-o.probeSlots }()
	case <-ctx.Done():
		return probes.Result{Status: report.Inconclusive, Category: "canceled"}
	}
	if ctx.Err() != nil {
		return probes.Result{Status: report.Inconclusive, Category: "canceled"}
	}
	c, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	return client.Check(c, runner, endpoint)
}

// Results retain incident order even when checks finish out of order. Only this
// calling goroutine emits progress, keeping completion counts monotonic and
// preserving serialized callbacks for direct ScanTarget calls.
func checkChains(ctx context.Context, o Options, target report.Target, client probes.Probe, runner probes.Runner, chains []certificates.Chain, controlOK bool) []probes.Result {
	results := make([]probes.Result, len(chains))
	progress := Progress{Phase: PhaseTLS, Target: target, Client: client.Name(), Total: len(chains)}
	notify(o, progress)
	if !controlOK {
		for i := range results {
			if ctx.Err() != nil {
				break
			}
			results[i] = probes.Result{Status: report.Inconclusive, Category: "positive_control_failed"}
			progress.Completed++
			notify(o, progress)
		}
		return results
	}
	jobs := make(chan int, len(chains))
	for i := range chains {
		jobs <- i
	}
	close(jobs)
	type completedCheck struct {
		index  int
		result probes.Result
	}
	completed := make(chan completedCheck, min(o.Workers, len(chains)))
	var wg sync.WaitGroup
	for w := 0; w < min(o.Workers, len(chains)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				result := checkClient(ctx, o, client, runner, "https://"+chains[i].Host+"/")
				completed <- completedCheck{i, result}
			}
		}()
	}
	go func() { wg.Wait(); close(completed) }()
	for check := range completed {
		results[check.index] = check.result
		progress.Completed++
		notify(o, progress)
	}
	return results
}
