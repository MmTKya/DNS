// Package metrics exposes the node to Prometheus.
//
// The numbers here are the ones an operator would graph or alert on, not every
// counter the process happens to have. A metrics endpoint that exports
// everything is a metrics endpoint nobody reads.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Snapshot is what the node reports at scrape time.
type Snapshot struct {
	QueriesTotal   uint64
	QueriesBlocked uint64
	QueriesCached  uint64
	QueriesErrors  uint64
	AvgLatencyMS   float64

	FilterRules     int
	FilterBytes     int
	SuggestionsOpen int
	ClientsKnown    int
	VPNPeersOnline  int

	ResolverUp bool
	ClusterUp  bool
}

// Provider returns the current snapshot.
type Provider func() Snapshot

// collector turns a Snapshot into Prometheus metrics.
//
// Collected on demand rather than mirrored into package-level counters: the
// node already keeps these numbers, and a second copy updated on the hot path
// would be both slower and a chance to disagree.
type collector struct {
	provider Provider

	queriesTotal   *prometheus.Desc
	queriesBlocked *prometheus.Desc
	queriesCached  *prometheus.Desc
	queriesErrors  *prometheus.Desc
	latency        *prometheus.Desc
	rules          *prometheus.Desc
	ruleBytes      *prometheus.Desc
	suggestions    *prometheus.Desc
	clients        *prometheus.Desc
	vpnPeers       *prometheus.Desc
	resolverUp     *prometheus.Desc
	clusterUp      *prometheus.Desc
}

func newCollector(provider Provider) *collector {
	return &collector{
		provider: provider,
		queriesTotal: prometheus.NewDesc(
			"seddns_queries_total", "DNS queries handled since start.", nil, nil),
		queriesBlocked: prometheus.NewDesc(
			"seddns_queries_blocked_total", "Queries answered by a filtering rule.", nil, nil),
		queriesCached: prometheus.NewDesc(
			"seddns_queries_cached_total", "Queries answered from cache.", nil, nil),
		queriesErrors: prometheus.NewDesc(
			"seddns_queries_errors_total", "Queries that failed to resolve.", nil, nil),
		latency: prometheus.NewDesc(
			"seddns_query_latency_ms", "Mean time to answer a query, in milliseconds.", nil, nil),
		rules: prometheus.NewDesc(
			"seddns_filter_rules", "Rules in the compiled ruleset.", nil, nil),
		ruleBytes: prometheus.NewDesc(
			"seddns_filter_bytes", "Approximate memory held by the ruleset.", nil, nil),
		suggestions: prometheus.NewDesc(
			"seddns_suggestions_pending", "Names waiting for a block-or-allow decision.", nil, nil),
		clients: prometheus.NewDesc(
			"seddns_clients_known", "Devices seen by this node.", nil, nil),
		vpnPeers: prometheus.NewDesc(
			"seddns_vpn_peers_online", "WireGuard peers that handshaked recently.", nil, nil),
		resolverUp: prometheus.NewDesc(
			"seddns_resolver_up", "1 when the resolver answers its own health query.", nil, nil),
		clusterUp: prometheus.NewDesc(
			"seddns_cluster_primary_reachable", "1 when a primary is reachable.", nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		c.queriesTotal, c.queriesBlocked, c.queriesCached, c.queriesErrors,
		c.latency, c.rules, c.ruleBytes, c.suggestions, c.clients, c.vpnPeers,
		c.resolverUp, c.clusterUp,
	} {
		ch <- desc
	}
}

// Collect implements prometheus.Collector.
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	s := c.provider()

	counter := func(desc *prometheus.Desc, value float64) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, value)
	}
	gauge := func(desc *prometheus.Desc, value float64) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value)
	}

	counter(c.queriesTotal, float64(s.QueriesTotal))
	counter(c.queriesBlocked, float64(s.QueriesBlocked))
	counter(c.queriesCached, float64(s.QueriesCached))
	counter(c.queriesErrors, float64(s.QueriesErrors))

	gauge(c.latency, s.AvgLatencyMS)
	gauge(c.rules, float64(s.FilterRules))
	gauge(c.ruleBytes, float64(s.FilterBytes))
	gauge(c.suggestions, float64(s.SuggestionsOpen))
	gauge(c.clients, float64(s.ClientsKnown))
	gauge(c.vpnPeers, float64(s.VPNPeersOnline))
	gauge(c.resolverUp, boolValue(s.ResolverUp))
	gauge(c.clusterUp, boolValue(s.ClusterUp))
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}

	return 0
}

// Handler returns the /metrics handler.
//
// The Go runtime collectors come along because "is the node about to run out
// of memory" is a question a Raspberry Pi owner genuinely needs answered.
func Handler(provider Provider) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(
		newCollector(provider),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
}
