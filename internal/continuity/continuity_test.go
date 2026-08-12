package continuity_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/continuity"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeServiceManager listens on a unix datagram socket the way systemd does.
type fakeServiceManager struct {
	conn     *net.UnixConn
	messages chan string
}

func newFakeServiceManager(t *testing.T) *fakeServiceManager {
	t.Helper()

	// Short path: unix socket names are limited to about 100 bytes, and
	// t.TempDir() is already long.
	dir, err := os.MkdirTemp("", "sd")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	m := &fakeServiceManager{conn: conn, messages: make(chan string, 64)}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, readErr := conn.Read(buf)
			if readErr != nil {
				return
			}
			select {
			case m.messages <- string(buf[:n]):
			default:
			}
		}
	}()

	t.Setenv("NOTIFY_SOCKET", path)

	return m
}

func (m *fakeServiceManager) await(t *testing.T, want string, within time.Duration) {
	t.Helper()

	deadline := time.After(within)
	for {
		select {
		case msg := <-m.messages:
			if strings.Contains(msg, want) {
				return
			}
		case <-deadline:
			t.Fatalf("never received %q", want)
		}
	}
}

func (m *fakeServiceManager) count(within time.Duration, want string) int {
	deadline := time.After(within)
	seen := 0
	for {
		select {
		case msg := <-m.messages:
			if strings.Contains(msg, want) {
				seen++
			}
		case <-deadline:
			return seen
		}
	}
}

func TestNotifierSpeaksToTheServiceManager(t *testing.T) {
	manager := newFakeServiceManager(t)

	notifier, enabled := continuity.NewNotifier()
	if !enabled {
		t.Fatal("the notifier should be enabled when NOTIFY_SOCKET is set")
	}

	if err := notifier.Ready(); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	manager.await(t, "READY=1", 2*time.Second)

	if err := notifier.Status("serving"); err != nil {
		t.Fatalf("Status: %v", err)
	}
	manager.await(t, "STATUS=serving", 2*time.Second)

	if err := notifier.Stopping(); err != nil {
		t.Fatalf("Stopping: %v", err)
	}
	manager.await(t, "STOPPING=1", 2*time.Second)
}

func TestNotifierIsANoOpOutsideSystemd(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")

	notifier, enabled := continuity.NewNotifier()
	if enabled {
		t.Error("the notifier should be disabled without NOTIFY_SOCKET")
	}

	// Running the binary by hand must not error on every notification.
	if err := notifier.Ready(); err != nil {
		t.Errorf("Ready outside systemd: %v", err)
	}
}

func TestWatchdogFeedsWhileHealthy(t *testing.T) {
	manager := newFakeServiceManager(t)

	notifier, _ := continuity.NewNotifier()
	watchdog := continuity.NewWatchdog(notifier, func(context.Context) error { return nil },
		50*time.Millisecond, discard())

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	go watchdog.Run(ctx)

	if got := manager.count(500*time.Millisecond, "WATCHDOG=1"); got < 3 {
		t.Errorf("received %d pings, want the watchdog to be fed regularly", got)
	}
}

func TestWatchdogStopsFeedingWhenUnhealthy(t *testing.T) {
	manager := newFakeServiceManager(t)

	var healthy atomic.Bool
	healthy.Store(true)

	notifier, _ := continuity.NewNotifier()
	watchdog := continuity.NewWatchdog(notifier, func(context.Context) error {
		if healthy.Load() {
			return nil
		}

		return errors.New("cannot resolve through my own listener")
	}, 50*time.Millisecond, discard())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go watchdog.Run(ctx)

	manager.await(t, "WATCHDOG=1", time.Second)

	// A process can be alive and useless. Withholding the ping is what gets it
	// restarted, and is the whole point of checking rather than just breathing.
	healthy.Store(false)
	drain(manager, 300*time.Millisecond)

	if got := manager.count(400*time.Millisecond, "WATCHDOG=1"); got > 0 {
		t.Errorf("the watchdog was fed %d times while the node was unhealthy", got)
	}
}

func TestWatchdogToleratesOneBadCheck(t *testing.T) {
	manager := newFakeServiceManager(t)

	var calls atomic.Int64
	notifier, _ := continuity.NewNotifier()
	watchdog := continuity.NewWatchdog(notifier, func(context.Context) error {
		// Fail exactly once: a single slow moment is not a reason to restart a
		// node the whole house depends on.
		if calls.Add(1) == 2 {
			return errors.New("one slow moment")
		}

		return nil
	}, 50*time.Millisecond, discard())

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go watchdog.Run(ctx)

	if got := manager.count(600*time.Millisecond, "WATCHDOG=1"); got < 4 {
		t.Errorf("received %d pings; a single failure should not stop the feeding", got)
	}
}

func drain(m *fakeServiceManager, d time.Duration) {
	deadline := time.After(d)
	for {
		select {
		case <-m.messages:
		case <-deadline:
			return
		}
	}
}

func TestWatchdogIntervalFromSystemd(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "30000000")
	t.Setenv("WATCHDOG_PID", "")

	interval, enabled := continuity.WatchdogInterval()
	if !enabled {
		t.Fatal("the interval should come from the environment")
	}
	// Half of what systemd asked for, leaving room for one late ping.
	if interval != 15*time.Second {
		t.Errorf("interval = %v, want 15s", interval)
	}
}

func TestWatchdogIntervalIgnoresOtherProcesses(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "30000000")
	t.Setenv("WATCHDOG_PID", "1")

	// The variable is inherited by children; answering for a parent would let
	// a forked helper keep a dead service alive.
	if _, enabled := continuity.WatchdogInterval(); enabled {
		t.Error("a watchdog addressed to another pid must be ignored")
	}
}

func TestRenderKeepalived(t *testing.T) {
	t.Parallel()

	cfg := continuity.VRRPConfig{
		Interface:      "eth0",
		VirtualAddress: netip.MustParseAddr("192.168.1.2"),
		RouterID:       51,
		Priority:       150,
		SelfAddress:    netip.MustParseAddr("192.168.1.10"),
		Peers:          []netip.Addr{netip.MustParseAddr("192.168.1.11")},
		Password:       "aegis",
	}

	out, err := continuity.RenderKeepalived(cfg, "/usr/local/lib/aegisdns/check.sh")
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}

	for _, want := range []string{
		"virtual_router_id 51",
		"priority 150",
		"state MASTER",
		"192.168.1.2 dev eth0",
		"unicast_peer",
		"192.168.1.11",
		"track_script",
		"chk_aegisdns",
		// Without nopreempt, a recovering node interrupts service a second
		// time to take an address it does not need back.
		"nopreempt",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("configuration is missing %q:\n%s", want, out)
		}
	}
}

func TestVRRPValidation(t *testing.T) {
	t.Parallel()

	base := continuity.VRRPConfig{
		Interface:      "eth0",
		VirtualAddress: netip.MustParseAddr("192.168.1.2"),
		RouterID:       51,
		Priority:       150,
		Peers:          []netip.Addr{netip.MustParseAddr("192.168.1.11")},
	}

	if err := base.Validate(); err != nil {
		t.Fatalf("a complete configuration should validate: %v", err)
	}

	tests := map[string]func(*continuity.VRRPConfig){
		"interface": func(c *continuity.VRRPConfig) { c.Interface = "" },
		"router id": func(c *continuity.VRRPConfig) { c.RouterID = 0 },
		"priority":  func(c *continuity.VRRPConfig) { c.Priority = 500 },
		"peer":      func(c *continuity.VRRPConfig) { c.Peers = nil },
		// VRRP truncates a longer password silently, leaving a pair that never
		// agrees and no clue why.
		"password": func(c *continuity.VRRPConfig) { c.Password = "far-too-long-for-vrrp" },
	}

	for name, mutate := range tests {
		cfg := base
		mutate(&cfg)

		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: expected validation to fail", name)
		}
	}
}

func TestCheckScriptResolvesRatherThanPings(t *testing.T) {
	t.Parallel()

	script := continuity.RenderCheckScript(5353, "")

	// A port or process check passes on a resolver that has stopped answering,
	// which is the exact failure this arrangement exists to survive.
	if !strings.Contains(script, "dig") {
		t.Errorf("the health script must resolve a name:\n%s", script)
	}
	if !strings.Contains(script, "-p 5353") {
		t.Errorf("the health script must query the configured port:\n%s", script)
	}
	if !strings.HasPrefix(script, "#!/bin/sh") {
		t.Errorf("the health script needs an interpreter line:\n%s", script)
	}
}
