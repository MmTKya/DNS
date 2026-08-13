package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/config"
)

func TestDefaultIsValid(t *testing.T) {
	t.Parallel()

	if err := config.Default().Validate(); err != nil {
		t.Fatalf("default config must be valid, got: %v", err)
	}
}

func TestLoadMergesOntoDefaults(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "seddns.yaml")
	const partial = `
mode: gateway
dns:
  listen:
    - "127.0.0.1:5353"
  upstream_timeout: 3s
`
	if err := os.WriteFile(path, []byte(partial), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Mode != config.ModeGateway {
		t.Errorf("mode = %q, want %q", cfg.Mode, config.ModeGateway)
	}
	if got, want := cfg.DNS.UpstreamTimeout.Duration(), 3*time.Second; got != want {
		t.Errorf("upstream_timeout = %v, want %v", got, want)
	}
	if len(cfg.DNS.Listen) != 1 || cfg.DNS.Listen[0] != "127.0.0.1:5353" {
		t.Errorf("listen = %v, want [127.0.0.1:5353]", cfg.DNS.Listen)
	}

	// Untouched keys must keep their defaults.
	if !cfg.DNS.CacheEnabled {
		t.Error("cache_enabled should have kept its default of true")
	}
	if len(cfg.DNS.Upstreams) == 0 {
		t.Error("upstreams should have kept their defaults")
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "seddns.yaml")
	if err := os.WriteFile(path, []byte("dns:\n  cach_enabled: true\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	if _, err := config.Load(path); err == nil {
		t.Fatal("a typo in a config key must be an error, not a silent default")
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{{
		name:    "unknown mode",
		mutate:  func(c *config.Config) { c.Mode = "bridge" },
		wantErr: "mode",
	}, {
		name:    "no listen address",
		mutate:  func(c *config.Config) { c.DNS.Listen = nil },
		wantErr: "dns.listen",
	}, {
		name:    "malformed listen address",
		mutate:  func(c *config.Config) { c.DNS.Listen = []string{"0.0.0.0"} },
		wantErr: "dns.listen",
	}, {
		name:    "no upstreams",
		mutate:  func(c *config.Config) { c.DNS.Upstreams = nil },
		wantErr: "dns.upstreams",
	}, {
		name:    "hostname bootstrap deadlocks",
		mutate:  func(c *config.Config) { c.DNS.Bootstrap = []string{"dns.quad9.net"} },
		wantErr: "dns.bootstrap",
	}, {
		name:    "unknown upstream mode",
		mutate:  func(c *config.Config) { c.DNS.UpstreamMode = "roundrobin" },
		wantErr: "dns.upstream_mode",
	}, {
		name:    "non-positive timeout",
		mutate:  func(c *config.Config) { c.DNS.UpstreamTimeout = 0 },
		wantErr: "dns.upstream_timeout",
	}, {
		name:    "empty store path",
		mutate:  func(c *config.Config) { c.Store.Path = "  " },
		wantErr: "store.path",
	}, {
		name:    "serve-stale without a window",
		mutate:  func(c *config.Config) { c.DNS.ServeStaleMaxAge = 0 },
		wantErr: "dns.serve_stale_max_age",
	}, {
		name:    "min ttl above max ttl",
		mutate:  func(c *config.Config) { c.DNS.CacheMinTTL = 100; c.DNS.CacheMaxTTL = 50 },
		wantErr: "cache_min_ttl",
	}, {
		name:    "encrypted listener without a certificate",
		mutate:  func(c *config.Config) { c.DNS.TLS.TLSListen = []string{"0.0.0.0:853"} },
		wantErr: "dns.tls",
	}, {
		name: "certificate without a listener",
		mutate: func(c *config.Config) {
			c.DNS.TLS.CertFile = "/etc/seddns/cert.pem"
			c.DNS.TLS.KeyFile = "/etc/seddns/key.pem"
		},
		wantErr: "dns.tls",
	}, {
		name:    "unknown blocking mode",
		mutate:  func(c *config.Config) { c.Filtering.BlockingMode = "teapot" },
		wantErr: "filtering.blocking_mode",
	}, {
		name:    "custom_ip mode without an address",
		mutate:  func(c *config.Config) { c.Filtering.BlockingMode = config.BlockingModeCustomIP },
		wantErr: "filtering.blocking_ipv4",
	}, {
		name:    "unknown query log mode",
		mutate:  func(c *config.Config) { c.QueryLog.Mode = "verbose" },
		wantErr: "querylog.mode",
	}, {
		name:    "persisted query log without a flush interval",
		mutate:  func(c *config.Config) { c.QueryLog.FlushInterval = 0 },
		wantErr: "querylog.flush_interval",
	}, {
		name:    "non-positive session ttl",
		mutate:  func(c *config.Config) { c.HTTP.SessionTTL = 0 },
		wantErr: "http.session_ttl",
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Default()
			tc.mutate(cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatalf("want an error mentioning %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Mode = "bridge"
	cfg.DNS.Upstreams = nil
	cfg.Store.Path = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("want an error")
	}

	for _, want := range []string{"mode", "dns.upstreams", "store.path"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q; validation should not stop at the first problem", err, want)
		}
	}
}

func TestWriteRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sub", "seddns.yaml")

	want := config.Default()
	want.DNS.Listen = []string{"127.0.0.1:5353"}
	want.DNS.UpstreamTimeout = config.Duration(2500 * time.Millisecond)

	if err := want.Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got.DNS.UpstreamTimeout != want.DNS.UpstreamTimeout {
		t.Errorf("upstream_timeout = %v, want %v", got.DNS.UpstreamTimeout, want.DNS.UpstreamTimeout)
	}
	if got.DNS.Listen[0] != want.DNS.Listen[0] {
		t.Errorf("listen = %v, want %v", got.DNS.Listen, want.DNS.Listen)
	}
}

func TestAddrParsing(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.DNS.Listen = []string{"127.0.0.1:5353", "127.0.0.2:5354"}

	udp, err := cfg.UDPAddrs()
	if err != nil {
		t.Fatalf("UDPAddrs: %v", err)
	}
	tcp, err := cfg.TCPAddrs()
	if err != nil {
		t.Fatalf("TCPAddrs: %v", err)
	}

	if len(udp) != 2 || len(tcp) != 2 {
		t.Fatalf("got %d udp and %d tcp addresses, want 2 each", len(udp), len(tcp))
	}
	if udp[0].Port != 5353 || tcp[1].Port != 5354 {
		t.Errorf("ports parsed incorrectly: udp=%v tcp=%v", udp, tcp)
	}
}

func TestQueryLogModeSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		mode         string
		wantRecords  bool
		wantPersists bool
	}{
		{config.QueryLogFull, true, true},
		{config.QueryLogAnonymized, true, true},
		// RAM mode is the SD-card setting: the live dashboard still works,
		// but nothing is written to disk.
		{config.QueryLogRAM, true, false},
		{config.QueryLogOff, false, false},
	}

	for _, tc := range tests {
		cfg := config.QueryLogConfig{Mode: tc.mode}
		if got := cfg.Records(); got != tc.wantRecords {
			t.Errorf("%s: Records() = %t, want %t", tc.mode, got, tc.wantRecords)
		}
		if got := cfg.Persists(); got != tc.wantPersists {
			t.Errorf("%s: Persists() = %t, want %t", tc.mode, got, tc.wantPersists)
		}
	}
}

func TestTLSEnabled(t *testing.T) {
	t.Parallel()

	full := config.TLSConfig{
		CertFile:  "/c.pem",
		KeyFile:   "/k.pem",
		TLSListen: []string{"0.0.0.0:853"},
	}
	if !full.Enabled() {
		t.Error("a fully configured TLS block should be enabled")
	}

	// A listener without a certificate must never count as enabled: starting
	// it would fail at bind time, long after the config was accepted.
	noCert := config.TLSConfig{TLSListen: []string{"0.0.0.0:853"}}
	if noCert.Enabled() {
		t.Error("a listener without a certificate must not be enabled")
	}
}
