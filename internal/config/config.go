// Package config holds the single source of truth for AegisDNS node settings.
//
// The control plane owns a Config value; the datapath is rebuilt from an
// immutable snapshot of it.  Nothing in this package may import the resolver,
// the store or the API, so that later phases (cluster replication, backup and
// restore) can serialise a node's whole configuration without pulling in the
// runtime.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DeploymentMode selects how AegisDNS is wired into the network.  It gates
// which capabilities the node can honestly offer: a DNS-only node observes
// queries, a gateway node observes packets.  Features must consult the mode
// instead of pretending both deployments are equivalent.
type DeploymentMode string

const (
	// ModeDNSOnly is the default: the node is only a DNS server.  Real
	// bandwidth accounting, real dwell time and real internet cut-off are not
	// available; anything derived from query logs must be labelled as an
	// estimate in the UI.
	ModeDNSOnly DeploymentMode = "dns-only"

	// ModeGateway means all client traffic is routed through the node, so
	// per-client byte counters, live connections and enforceable blocking
	// become possible.  Implemented from phase 3 onwards.
	ModeGateway DeploymentMode = "gateway"
)

// Valid reports whether m is a mode the node knows how to run.
func (m DeploymentMode) Valid() bool {
	return m == ModeDNSOnly || m == ModeGateway
}

// Upstream selection strategies, mirroring dnsproxy's upstream modes.  They are
// kept as plain strings here so that this package stays free of datapath
// dependencies; internal/resolver maps them onto proxy.UpstreamMode.
const (
	UpstreamModeLoadBalance = "load_balance"
	UpstreamModeParallel    = "parallel"
	UpstreamModeFastestAddr = "fastest_addr"
)

// DefaultPath is where a packaged installation keeps its configuration.
const DefaultPath = "/etc/aegisdns/aegisdns.yaml"

// Duration is a time.Duration that reads as "10s" or "1h30m" in YAML.
type Duration time.Duration

// Duration returns the wrapped standard library duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String implements fmt.Stringer.
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"10s\": %w", err)
	}

	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parsing duration %q: %w", s, err)
	}

	*d = Duration(parsed)

	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// Config is the complete node configuration.
//
// What belongs here is what an operator sets once and what the node needs
// before it can serve anything: listeners, upstreams, storage.  What the panel
// manages at runtime — feeds, per-client rules, users — lives in SQLite
// instead, because editing a YAML file from a web form and reloading the
// process is a worse experience than a transaction.
type Config struct {
	// Mode is the deployment mode.  See DeploymentMode.
	Mode DeploymentMode `yaml:"mode"`

	Log       LogConfig       `yaml:"log"`
	DNS       DNSConfig       `yaml:"dns"`
	VPN       VPNConfig       `yaml:"vpn"`
	Filtering FilteringConfig `yaml:"filtering"`
	QueryLog  QueryLogConfig  `yaml:"querylog"`
	HTTP      HTTPConfig      `yaml:"http"`
	Store     StoreConfig     `yaml:"store"`
	Cluster   ClusterConfig   `yaml:"cluster"`
}

// ClusterConfig pairs this node with another one.
//
// Two nodes, not a consensus protocol. Raft on two machines has no quorum:
// losing either one stops the cluster, which is the opposite of why a second
// resolver was added. So one node is primary and owns the configuration, the
// other follows it, and a replica that has not heard from the primary for
// three heartbeats promotes itself.
type ClusterConfig struct {
	// Enabled turns replication on. A node with this off still reports its
	// own state, so the panel can show a cluster of one honestly.
	Enabled bool `yaml:"enabled"`

	// Role is "primary" or "replica". The primary is where configuration is
	// edited; a replica's own edits are overwritten at the next sync.
	Role string `yaml:"role"`

	// Token is the shared secret. Every snapshot is signed with it, and a
	// replica refuses one that does not verify — otherwise anything that can
	// reach the replication port could install a configuration that turns
	// filtering off.
	Token string `yaml:"token"`

	// Peers are the other nodes' panel URLs, e.g. "http://192.168.1.11:8080".
	Peers []string `yaml:"peers"`
}

// LogConfig controls process logging.
type LogConfig struct {
	// Level is one of debug, info, warn, error.
	Level string `yaml:"level"`
	// Format is either "text" (human readable) or "json" (for log shipping).
	Format string `yaml:"format"`
}

// DNSConfig configures the datapath.
type DNSConfig struct {
	// Listen is the set of "host:port" addresses to serve plain DNS on, over
	// both UDP and TCP.  Encrypted transports arrive in phase 1.
	Listen []string `yaml:"listen"`

	// Upstreams are resolvers to forward to, in dnsproxy syntax.  Plain
	// addresses ("9.9.9.9"), encrypted URLs ("https://dns.quad9.net/dns-query")
	// and domain-specific forms ("[/corp.lan/]192.168.1.1") are all accepted.
	Upstreams []string `yaml:"upstreams"`

	// Bootstrap resolvers translate the hostnames of encrypted upstreams into
	// addresses.  They must be plain IPs, otherwise resolution deadlocks.
	Bootstrap []string `yaml:"bootstrap"`

	// UpstreamMode is one of load_balance, parallel or fastest_addr.
	UpstreamMode string `yaml:"upstream_mode"`

	// UpstreamTimeout bounds a single upstream exchange.
	UpstreamTimeout Duration `yaml:"upstream_timeout"`

	// CacheEnabled turns on the response cache.
	CacheEnabled bool `yaml:"cache_enabled"`

	// CacheSizeBytes is the cache budget.  Note this is a byte budget, not an
	// entry count.
	CacheSizeBytes int `yaml:"cache_size_bytes"`

	// RefuseAny makes the resolver refuse ANY queries, which are mostly used
	// for reflection amplification.
	RefuseAny bool `yaml:"refuse_any"`

	// Fallbacks are used only when every upstream has failed.  They are a
	// separate layer from Upstreams so that a plain, always-reachable resolver
	// can back a set of encrypted ones without being load-balanced into
	// normal traffic.
	Fallbacks []string `yaml:"fallbacks"`

	// ServeStale keeps answering from expired cache entries while a refresh
	// runs in the background (RFC 8767).  This is the single largest
	// availability win available to a home resolver: when the upstream
	// flickers, the internet keeps working instead of failing for everyone at
	// once.
	ServeStale bool `yaml:"serve_stale"`

	// ServeStaleMaxAge bounds how long an expired entry may still be served.
	ServeStaleMaxAge Duration `yaml:"serve_stale_max_age"`

	// CacheMinTTL raises very short TTLs, which some ad networks use to defeat
	// caching.  Zero leaves TTLs alone.
	CacheMinTTL uint32 `yaml:"cache_min_ttl"`

	// CacheMaxTTL caps long TTLs so a stale answer cannot linger for days.
	CacheMaxTTL uint32 `yaml:"cache_max_ttl"`

	// DNSSEC sets the DO bit on upstream queries, so a validating upstream
	// reports failures instead of silently returning forged data.
	DNSSEC bool `yaml:"dnssec"`

	// TLS configures the encrypted listeners.  Without a certificate they stay
	// switched off.
	TLS TLSConfig `yaml:"tls"`
}

// TLSConfig configures DNS-over-TLS, DNS-over-HTTPS and DNS-over-QUIC.
//
// These matter for two reasons: devices on the LAN can encrypt their queries
// to the node, and — more importantly for this product — a phone on mobile
// data can reach its own filtered resolver over DoH without a VPN.
type TLSConfig struct {
	// CertFile and KeyFile are PEM paths.  Both are required to enable any
	// encrypted listener.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	// TLSListen serves DNS-over-TLS (port 853 by convention).
	TLSListen []string `yaml:"tls_listen"`

	// HTTPSListen serves DNS-over-HTTPS.
	HTTPSListen []string `yaml:"https_listen"`

	// QUICListen serves DNS-over-QUIC.
	QUICListen []string `yaml:"quic_listen"`
}

// Enabled reports whether an encrypted listener is both configured and
// possible.
func (c TLSConfig) Enabled() bool {
	return c.CertFile != "" && c.KeyFile != "" &&
		(len(c.TLSListen) > 0 || len(c.HTTPSListen) > 0 || len(c.QUICListen) > 0)
}

// Blocking modes decide what a client is told when a name is blocked.
const (
	// BlockingModeNullIP answers with 0.0.0.0 and ::.  Browsers fail fast on
	// it, which is why it is the default.
	BlockingModeNullIP = "null_ip"

	// BlockingModeNXDOMAIN claims the name does not exist.  Some clients
	// retry other resolvers when they see this.
	BlockingModeNXDOMAIN = "nxdomain"

	// BlockingModeRefused refuses the query outright.
	BlockingModeRefused = "refused"

	// BlockingModeCustomIP points blocked names at an address of your own,
	// typically a local page explaining the block.
	BlockingModeCustomIP = "custom_ip"
)

// FilteringConfig configures what happens to a query that matches a rule.
//
// The list of feeds is not here: feeds are managed from the panel and stored
// in the database, because they change far more often than this file does.
type FilteringConfig struct {
	// Enabled turns filtering off without unloading the rules.
	Enabled bool `yaml:"enabled"`

	// BlockingMode is one of null_ip, nxdomain, refused or custom_ip.
	BlockingMode string `yaml:"blocking_mode"`

	// BlockingIPv4 and BlockingIPv6 are the answers for custom_ip mode.
	BlockingIPv4 string `yaml:"blocking_ipv4"`
	BlockingIPv6 string `yaml:"blocking_ipv6"`

	// BlockedTTL is the TTL on a blocked answer.  It is short on purpose: an
	// unblock made in the panel should take effect in seconds, not hours.
	BlockedTTL uint32 `yaml:"blocked_ttl"`

	// UpdateInterval is how often enabled feeds are refreshed.
	UpdateInterval Duration `yaml:"update_interval"`
}

// Query log modes, in decreasing order of what they retain.
const (
	// QueryLogFull keeps the client address and the queried name.
	QueryLogFull = "full"

	// QueryLogAnonymized keeps the name but truncates client addresses, so
	// per-client attribution is lost and the statistics survive.
	QueryLogAnonymized = "anonymized"

	// QueryLogRAM keeps the live ring buffer only and never writes to disk.
	// This is the setting for an SD-card install, and for anyone who does not
	// want a browsing history on the device at all.
	QueryLogRAM = "ram"

	// QueryLogOff records nothing beyond counters.
	QueryLogOff = "off"
)

// QueryLogConfig configures query recording.
type QueryLogConfig struct {
	// Mode is one of full, anonymized, ram or off.
	Mode string `yaml:"mode"`

	// RingSize is how many recent queries the live dashboard can show.  These
	// are held in memory and cost no writes.
	RingSize int `yaml:"ring_size"`

	// FlushInterval is how often buffered rows are written to SQLite.  Longer
	// intervals mean fewer, larger writes, which is what keeps an SD card
	// alive; the cost is losing at most this much history on a hard reset.
	FlushInterval Duration `yaml:"flush_interval"`

	// Retention is how long individual rows are kept before being rolled up
	// into hourly aggregates.
	Retention Duration `yaml:"retention"`
}

// VPNConfig configures the WireGuard tunnel.
//
// The tunnel exists so a device carries the household's filtering with it: a
// phone on mobile data resolves through this node rather than through whatever
// its carrier hands out.
type VPNConfig struct {
	// Enabled brings the interface up.  Off by default: it needs a forwarded
	// port and a reachable endpoint, which is a deliberate step.
	Enabled bool `yaml:"enabled"`

	// Interface is the tunnel device name.
	Interface string `yaml:"interface"`

	// ListenPort is the UDP port peers dial.  This is the one thing that has
	// to be reachable from outside.
	ListenPort int `yaml:"listen_port"`

	// Subnet is the address range handed out inside the tunnel.  It must not
	// overlap the home network, or a connected device cannot reach either.
	Subnet string `yaml:"subnet"`

	// Address is this node's address inside the tunnel, and what peers use for
	// DNS.
	Address string `yaml:"address"`

	// Endpoint is the "host:port" written into client configurations — a
	// dynamic DNS name, or a static address.
	Endpoint string `yaml:"endpoint"`

	// MTU of the tunnel.  1420 is the usual safe value over a 1500-byte path.
	MTU int `yaml:"mtu"`

	// KeepAlive holds a NAT mapping open from the client side.
	KeepAlive int `yaml:"keepalive"`
}

// HTTPConfig configures the admin API and panel listener.
type HTTPConfig struct {
	// Listen is the "host:port" the admin interface binds to.
	Listen string `yaml:"listen"`

	// SessionTTL is how long a panel login lasts.
	SessionTTL Duration `yaml:"session_ttl"`
}

// StoreConfig configures persistence.
type StoreConfig struct {
	// Path is the SQLite database file.  Its parent directory is created on
	// startup if missing.
	Path string `yaml:"path"`
}

// Default returns the built-in configuration.  A node started with no config
// file at all runs with exactly these settings.
func Default() *Config {
	return &Config{
		Mode: ModeDNSOnly,
		Cluster: ClusterConfig{
			// Off, but with a role already chosen: someone who switches
			// clustering on without saying which node this is gets the
			// answer that is safe for the node they are standing at.
			Role: RolePrimary,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "text",
		},
		DNS: DNSConfig{
			Listen: []string{"0.0.0.0:53"},
			// Quad9 filters known-malicious domains upstream, which is a
			// sensible floor before AegisDNS' own filtering lands in phase 1.
			Upstreams:       []string{"9.9.9.9", "149.112.112.112"},
			Bootstrap:       []string{"9.9.9.9", "149.112.112.112"},
			UpstreamMode:    UpstreamModeLoadBalance,
			UpstreamTimeout: Duration(10 * time.Second),
			CacheEnabled:    true,
			CacheSizeBytes:  4 * 1024 * 1024,
			RefuseAny:       true,
			ServeStale:      true,
			// Long enough to ride out an upstream outage or a router reboot,
			// short enough that a genuinely changed record is not served for
			// days.
			ServeStaleMaxAge: Duration(24 * time.Hour),
			CacheMinTTL:      0,
			CacheMaxTTL:      86400,
			DNSSEC:           true,
		},
		VPN: VPNConfig{
			Enabled:    false,
			Interface:  "wg0",
			ListenPort: 51820,
			// A range unlikely to clash with a home network, which usually
			// sits on 192.168.x or 10.0.x.
			Subnet:    "10.6.0.0/24",
			Address:   "10.6.0.1",
			MTU:       1420,
			KeepAlive: 25,
		},
		Filtering: FilteringConfig{
			Enabled:        true,
			BlockingMode:   BlockingModeNullIP,
			BlockedTTL:     10,
			UpdateInterval: Duration(24 * time.Hour),
		},
		QueryLog: QueryLogConfig{
			Mode:     QueryLogFull,
			RingSize: 50_000,
			// One write per minute rather than per query is the difference
			// between an SD card lasting years and lasting months.
			FlushInterval: Duration(time.Minute),
			Retention:     Duration(7 * 24 * time.Hour),
		},
		HTTP: HTTPConfig{
			Listen:     "0.0.0.0:8080",
			SessionTTL: Duration(7 * 24 * time.Hour),
		},
		Store: StoreConfig{
			Path: "/var/lib/aegisdns/aegisdns.db",
		},
	}
}

// Load reads the YAML file at path on top of Default, so an operator only has
// to write down what they want to change.  Unknown keys are rejected rather
// than silently ignored: a typo in a security setting must not fail open.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer func() { _ = f.Close() }()

	cfg := Default()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	if err = dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}

	if err = cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config %s: %w", path, err)
	}

	return cfg, nil
}

// Validate checks the cluster settings.
//
// Enabling replication without a token or a peer is the kind of half-finished
// setup that looks like it is working: the panel shows a cluster, and nothing
// ever syncs.
func (c ClusterConfig) validate() (errs []error) {
	if !c.Enabled {
		return nil
	}

	switch c.Role {
	case RolePrimary, RoleReplica:
	default:
		errs = append(errs, fmt.Errorf("cluster.role: must be %q or %q, got %q", RolePrimary, RoleReplica, c.Role))
	}

	// 32 hex characters is what the panel generates. Shorter is allowed but
	// worth refusing outright below that: this is the only thing standing
	// between the replication port and a hostile configuration.
	if len(c.Token) < 16 {
		errs = append(errs, errors.New("cluster.token: needs at least 16 characters; generate one with `openssl rand -hex 32`"))
	}

	if len(c.Peers) == 0 {
		errs = append(errs, errors.New("cluster.peers: at least one peer URL is required when clustering is on"))
	}
	for _, peer := range c.Peers {
		parsed, err := url.Parse(peer)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			errs = append(errs, fmt.Errorf("cluster.peers: %q is not a URL like http://192.168.1.11:8080", peer))
		}
	}

	return errs
}

// Cluster roles.
const (
	RolePrimary = "primary"
	RoleReplica = "replica"
)

// Validate reports every problem it can find at once, so a misconfigured node
// does not have to be fixed one restart at a time.
func (c *Config) Validate() error {
	var errs []error

	if !c.Mode.Valid() {
		errs = append(errs, fmt.Errorf("mode: %q is not one of %q, %q", c.Mode, ModeDNSOnly, ModeGateway))
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level: %q is not one of debug, info, warn, error", c.Log.Level))
	}

	switch c.Log.Format {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("log.format: %q is not one of text, json", c.Log.Format))
	}

	if len(c.DNS.Listen) == 0 {
		errs = append(errs, errors.New("dns.listen: at least one address is required"))
	}
	for _, addr := range c.DNS.Listen {
		if _, err := net.ResolveUDPAddr("udp", addr); err != nil {
			errs = append(errs, fmt.Errorf("dns.listen: %q is not a valid host:port: %w", addr, err))
		}
	}

	if len(c.DNS.Upstreams) == 0 {
		errs = append(errs, errors.New("dns.upstreams: at least one upstream is required"))
	}

	// A hostname here cannot be resolved without already having DNS, so this
	// is a deadlock rather than a slow start.
	for _, b := range c.DNS.Bootstrap {
		host := b
		if h, _, err := net.SplitHostPort(b); err == nil {
			host = h
		}
		if net.ParseIP(host) == nil {
			errs = append(errs, fmt.Errorf("dns.bootstrap: %q must be a plain IP address, not a hostname", b))
		}
	}

	switch c.DNS.UpstreamMode {
	case UpstreamModeLoadBalance, UpstreamModeParallel, UpstreamModeFastestAddr:
	default:
		errs = append(errs, fmt.Errorf("dns.upstream_mode: %q is not one of %s, %s, %s",
			c.DNS.UpstreamMode, UpstreamModeLoadBalance, UpstreamModeParallel, UpstreamModeFastestAddr))
	}

	if c.DNS.UpstreamTimeout <= 0 {
		errs = append(errs, errors.New("dns.upstream_timeout: must be positive"))
	}

	if c.DNS.CacheEnabled && c.DNS.CacheSizeBytes <= 0 {
		errs = append(errs, errors.New("dns.cache_size_bytes: must be positive when the cache is enabled"))
	}

	if c.DNS.ServeStale && c.DNS.ServeStaleMaxAge <= 0 {
		errs = append(errs, errors.New("dns.serve_stale_max_age: must be positive when serve_stale is on"))
	}

	if c.DNS.CacheMaxTTL > 0 && c.DNS.CacheMinTTL > c.DNS.CacheMaxTTL {
		errs = append(errs, fmt.Errorf("dns.cache_min_ttl (%d) is above dns.cache_max_ttl (%d)",
			c.DNS.CacheMinTTL, c.DNS.CacheMaxTTL))
	}

	errs = append(errs, c.VPN.validate()...)
	errs = append(errs, c.DNS.TLS.validate()...)
	errs = append(errs, c.Filtering.validate()...)
	errs = append(errs, c.QueryLog.validate()...)
	errs = append(errs, c.Cluster.validate()...)

	if strings.TrimSpace(c.HTTP.Listen) == "" {
		errs = append(errs, errors.New("http.listen: is required"))
	} else if _, err := net.ResolveTCPAddr("tcp", c.HTTP.Listen); err != nil {
		errs = append(errs, fmt.Errorf("http.listen: %q is not a valid host:port: %w", c.HTTP.Listen, err))
	}

	if c.HTTP.SessionTTL <= 0 {
		errs = append(errs, errors.New("http.session_ttl: must be positive"))
	}

	if strings.TrimSpace(c.Store.Path) == "" {
		errs = append(errs, errors.New("store.path: is required"))
	}

	return errors.Join(errs...)
}

// validate checks the encrypted listener settings.  A half-configured listener
// is reported rather than quietly ignored: an operator who wrote down a DoH
// port expects DoH to be reachable, and silence would look like it is.
func (c TLSConfig) validate() (errs []error) {
	hasListener := len(c.TLSListen) > 0 || len(c.HTTPSListen) > 0 || len(c.QUICListen) > 0
	hasCert := c.CertFile != "" && c.KeyFile != ""

	if hasListener && !hasCert {
		errs = append(errs, errors.New("dns.tls: an encrypted listener needs both cert_file and key_file"))
	}
	if hasCert && !hasListener {
		errs = append(errs, errors.New("dns.tls: a certificate is configured but no encrypted listener is"))
	}

	for name, addrs := range map[string][]string{
		"tls_listen":   c.TLSListen,
		"https_listen": c.HTTPSListen,
		"quic_listen":  c.QUICListen,
	} {
		for _, addr := range addrs {
			if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
				errs = append(errs, fmt.Errorf("dns.tls.%s: %q is not a valid host:port: %w", name, addr, err))
			}
		}
	}

	return errs
}

func (c VPNConfig) validate() (errs []error) {
	if !c.Enabled {
		return nil
	}

	if strings.TrimSpace(c.Interface) == "" {
		errs = append(errs, errors.New("vpn.interface: is required"))
	}
	if c.ListenPort <= 0 || c.ListenPort > 65535 {
		errs = append(errs, errors.New("vpn.listen_port: must be between 1 and 65535"))
	}

	subnet, err := netip.ParsePrefix(c.Subnet)
	if err != nil {
		errs = append(errs, fmt.Errorf("vpn.subnet: %q is not a valid CIDR: %w", c.Subnet, err))
	}

	addr, err := netip.ParseAddr(c.Address)
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("vpn.address: %q is not a valid address: %w", c.Address, err))
	case subnet.IsValid() && !subnet.Contains(addr):
		// An address outside its own subnet produces a tunnel that comes up
		// and carries nothing, with no error anywhere.
		errs = append(errs, fmt.Errorf("vpn.address: %s is not inside vpn.subnet %s", addr, subnet))
	}

	if strings.TrimSpace(c.Endpoint) == "" {
		// Without it, generated client configurations have nothing to dial.
		errs = append(errs, errors.New("vpn.endpoint: is required when the tunnel is enabled (the host:port your devices dial)"))
	}

	return errs
}

func (c FilteringConfig) validate() (errs []error) {
	switch c.BlockingMode {
	case BlockingModeNullIP, BlockingModeNXDOMAIN, BlockingModeRefused:
	case BlockingModeCustomIP:
		if c.BlockingIPv4 == "" && c.BlockingIPv6 == "" {
			errs = append(errs, errors.New("filtering.blocking_ipv4 or blocking_ipv6: required in custom_ip mode"))
		}
	default:
		errs = append(errs, fmt.Errorf("filtering.blocking_mode: %q is not one of %s, %s, %s, %s",
			c.BlockingMode, BlockingModeNullIP, BlockingModeNXDOMAIN, BlockingModeRefused, BlockingModeCustomIP))
	}

	for name, value := range map[string]string{
		"blocking_ipv4": c.BlockingIPv4,
		"blocking_ipv6": c.BlockingIPv6,
	} {
		if value != "" && net.ParseIP(value) == nil {
			errs = append(errs, fmt.Errorf("filtering.%s: %q is not an IP address", name, value))
		}
	}

	if c.UpdateInterval <= 0 {
		errs = append(errs, errors.New("filtering.update_interval: must be positive"))
	}

	return errs
}

func (c QueryLogConfig) validate() (errs []error) {
	switch c.Mode {
	case QueryLogFull, QueryLogAnonymized, QueryLogRAM, QueryLogOff:
	default:
		errs = append(errs, fmt.Errorf("querylog.mode: %q is not one of %s, %s, %s, %s",
			c.Mode, QueryLogFull, QueryLogAnonymized, QueryLogRAM, QueryLogOff))
	}

	if c.RingSize < 0 {
		errs = append(errs, errors.New("querylog.ring_size: must not be negative"))
	}

	if c.Persists() {
		if c.FlushInterval <= 0 {
			errs = append(errs, errors.New("querylog.flush_interval: must be positive"))
		}
		if c.Retention <= 0 {
			errs = append(errs, errors.New("querylog.retention: must be positive"))
		}
	}

	return errs
}

// Persists reports whether the query log is written to disk in this mode.
func (c QueryLogConfig) Persists() bool {
	return c.Mode == QueryLogFull || c.Mode == QueryLogAnonymized
}

// Records reports whether queries are recorded at all, in memory or on disk.
func (c QueryLogConfig) Records() bool { return c.Mode != QueryLogOff }

// SlogLevel maps the configured level onto slog's level type.
func (c *Config) SlogLevel() slog.Level {
	switch c.Log.Level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// UDPAddrs returns dns.listen parsed as UDP addresses.
func (c *Config) UDPAddrs() ([]*net.UDPAddr, error) {
	addrs := make([]*net.UDPAddr, 0, len(c.DNS.Listen))
	for _, a := range c.DNS.Listen {
		udp, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			return nil, fmt.Errorf("resolving udp listen address %q: %w", a, err)
		}
		addrs = append(addrs, udp)
	}

	return addrs, nil
}

// TCPAddrs returns dns.listen parsed as TCP addresses.  DNS needs TCP for
// responses that do not fit in a datagram, so both are always bound together.
func (c *Config) TCPAddrs() ([]*net.TCPAddr, error) {
	addrs := make([]*net.TCPAddr, 0, len(c.DNS.Listen))
	for _, a := range c.DNS.Listen {
		tcp, err := net.ResolveTCPAddr("tcp", a)
		if err != nil {
			return nil, fmt.Errorf("resolving tcp listen address %q: %w", a, err)
		}
		addrs = append(addrs, tcp)
	}

	return addrs, nil
}

// Write saves the configuration to path, creating the parent directory.  It is
// used by the installer and, later, by the panel when settings change.
func (c *Config) Write(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	out, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}

	if err = os.WriteFile(path, out, 0o640); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}
