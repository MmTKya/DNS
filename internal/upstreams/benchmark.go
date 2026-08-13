package upstreams

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/MmTKya/DNS/internal/store"
	"github.com/miekg/dns"
)

// isPlain reports whether an address is a bare resolver rather than an
// encrypted URL or a domain-specific rule.
func isPlain(address string) bool {
	return !strings.Contains(address, "://") && !strings.HasPrefix(address, "[/")
}

func splitHostPort(address string) (host, port string, err error) {
	return net.SplitHostPort(address)
}

// Candidates are the resolvers a benchmark tries when it is not given a list.
//
// Deliberately a short list of well-known public resolvers plus whatever the
// node is already using. A longer one would take longer to measure and would
// not change the answer: the winner is almost always the one with a server
// nearest the line, and there are only so many operators with one.
var Candidates = []string{
	"1.1.1.1",
	"8.8.8.8",
	"9.9.9.9",
	"208.67.222.222",
	"94.140.14.14",
}

// probes are the names a candidate has to resolve to be considered usable.
//
// The regional one is the point. A resolver can be fast, reachable and
// perfectly healthy and still fail to reach a country's nameservers — which
// is not a hypothetical: the resolver shipped as the default here answers in
// 139 ms and cannot resolve gib.gov.tr at all, while slower ones can. Speed
// measured without correctness would have recommended it.
var probes = []string{
	"www.google.com",
	"github.com",
	"gib.gov.tr",
	"wikipedia.org",
}

// Result is how one candidate performed.
type Result struct {
	// Error is why the resolver was rejected, empty when it was not.
	Error string `json:"error,omitempty"`

	Address string `json:"address"`

	// Median latency over the probes that answered.
	MedianMS int `json:"median_ms"`

	// Resolved and Probes say how much of the test it passed. A resolver that
	// answers three names out of four is not a faster resolver, it is a
	// broken one.
	Resolved int `json:"resolved"`
	Probes   int `json:"probes"`

	// Usable is true only when every probe resolved. The panel sorts on this
	// before it sorts on speed.
	Usable bool `json:"usable"`
}

// Benchmark measures candidates and returns them best first.
//
// "Best" means usable first, then fastest — in that order, never the other
// way round. A resolver that cannot answer for a country is not a candidate
// no matter what its median looks like.
func Benchmark(ctx context.Context, candidates []string, perQuery time.Duration) (results []Result, err error) {
	if len(candidates) == 0 {
		candidates = Candidates
	}
	if perQuery <= 0 {
		perQuery = 2 * time.Second
	}

	type outcome struct {
		result Result
		index  int
	}

	done := make(chan outcome, len(candidates))

	for i, address := range candidates {
		go func() {
			done <- outcome{result: measure(ctx, address, perQuery), index: i}
		}()
	}

	results = make([]Result, len(candidates))
	for range candidates {
		select {
		case out := <-done:
			results[out.index] = out.result
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Usable != results[j].Usable {
			return results[i].Usable
		}
		if results[i].Resolved != results[j].Resolved {
			return results[i].Resolved > results[j].Resolved
		}

		return results[i].MedianMS < results[j].MedianMS
	})

	return results, nil
}

// measure times one resolver against every probe.
func measure(ctx context.Context, address string, perQuery time.Duration) Result {
	result := Result{Address: address, Probes: len(probes)}

	normalised, err := Validate(address)
	if err != nil {
		result.Error = err.Error()

		return result
	}

	// Encrypted transports need the proxy's own client, which is more than
	// this measurement is for. They are still selectable by hand.
	if !isPlain(normalised) {
		result.Error = "only plain resolvers can be measured from here"

		return result
	}

	server := normalised
	if _, _, splitErr := splitHostPort(server); splitErr != nil {
		server += ":53"
	}

	client := &dns.Client{Timeout: perQuery}
	latencies := make([]int, 0, len(probes))

	for _, name := range probes {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), dns.TypeA)
		msg.RecursionDesired = true

		reply, rtt, exchangeErr := client.ExchangeContext(ctx, msg, server)
		if exchangeErr != nil {
			if result.Error == "" {
				result.Error = fmt.Sprintf("%s: %s", name, exchangeErr)
			}

			continue
		}

		// SERVFAIL is the failure that matters here: the resolver answered,
		// which a reachability check would call success, and it answered that
		// it cannot resolve the name.
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) == 0 {
			if result.Error == "" {
				result.Error = fmt.Sprintf("%s: %s", name, dns.RcodeToString[reply.Rcode])
			}

			continue
		}

		result.Resolved++
		latencies = append(latencies, int(rtt.Milliseconds()))
	}

	if len(latencies) > 0 {
		sort.Ints(latencies)
		result.MedianMS = latencies[len(latencies)/2]
	}

	result.Usable = result.Resolved == result.Probes
	if result.Usable {
		result.Error = ""
	}

	return result
}

// ErrNoUsableResolver means every candidate failed a probe.
var ErrNoUsableResolver = errors.New("no candidate resolved every probe")

// Adopt replaces the stored resolvers with the two best from a benchmark.
//
// Two, not one: a single resolver is a single point of failure, and the
// runner-up costs nothing until the first one is slow. Anything already
// configured is removed, because a half-replaced list is neither the old
// choice nor the new one.
func Adopt(ctx context.Context, db *store.DB, results []Result) (adopted []string, err error) {
	for _, result := range results {
		if result.Usable {
			adopted = append(adopted, result.Address)
		}
		if len(adopted) == 2 {
			break
		}
	}

	if len(adopted) == 0 {
		return nil, ErrNoUsableResolver
	}

	if _, err = db.Writer().ExecContext(ctx, `DELETE FROM upstreams`); err != nil {
		return nil, fmt.Errorf("clearing the previous resolvers: %w", err)
	}

	for _, address := range adopted {
		if _, err = Add(ctx, db, address, RolePrimary, "chosen by measurement"); err != nil {
			return nil, err
		}
	}

	return adopted, nil
}
