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
type Config struct {
	// Mode is the deployment mode.  See DeploymentMode.
	Mode DeploymentMode `yaml:"mode"`

	Log   LogConfig   `yaml:"log"`
	DNS   DNSConfig   `yaml:"dns"`
	HTTP  HTTPConfig  `yaml:"http"`
	Store StoreConfig `yaml:"store"`
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
}

// HTTPConfig configures the admin API and panel listener.
type HTTPConfig struct {
	// Listen is the "host:port" the admin interface binds to.
	Listen string `yaml:"listen"`
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
		},
		HTTP: HTTPConfig{
			Listen: "0.0.0.0:8080",
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

	if strings.TrimSpace(c.HTTP.Listen) == "" {
		errs = append(errs, errors.New("http.listen: is required"))
	} else if _, err := net.ResolveTCPAddr("tcp", c.HTTP.Listen); err != nil {
		errs = append(errs, fmt.Errorf("http.listen: %q is not a valid host:port: %w", c.HTTP.Listen, err))
	}

	if strings.TrimSpace(c.Store.Path) == "" {
		errs = append(errs, errors.New("store.path: is required"))
	}

	return errors.Join(errs...)
}

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
