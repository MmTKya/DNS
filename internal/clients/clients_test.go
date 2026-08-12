package clients_test

import (
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/clients"
	"github.com/MmTKya/DNS/internal/store"
)

func newRegistry(t *testing.T) (*clients.Registry, *store.DB) {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg, err := clients.New(t.Context(), db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("creating registry: %v", err)
	}

	return reg, db
}

func TestIdentifyUnknownDeviceIsFilteredByDefault(t *testing.T) {
	t.Parallel()

	reg, _ := newRegistry(t)

	client := reg.Identify(netip.MustParseAddr("192.168.1.42"), "")

	if client.Key != "192.168.1.42" {
		t.Errorf("key = %q, want the address", client.Key)
	}
	// An unknown device on the network is the one you least want unfiltered.
	if !client.FilteringEnabled {
		t.Error("an unconfigured device must be filtered by default")
	}
	if client.Known {
		t.Error("an unconfigured device must not be reported as known")
	}
}

func TestClientIDBeatsAddress(t *testing.T) {
	t.Parallel()

	reg, _ := newRegistry(t)
	ctx := t.Context()

	name := "Kids tablet"
	if _, err := reg.Update(ctx, "kids-tablet", clients.Update{Name: &name}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	byAddress := "Living room"
	if _, err := reg.Update(ctx, "192.168.1.42", clients.Update{Name: &byAddress}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// A device that names itself keeps its identity wherever it is, so the id
	// has to win over whatever address it happens to be using.
	client := reg.Identify(netip.MustParseAddr("192.168.1.42"), "kids-tablet")
	if client.Name != name {
		t.Errorf("name = %q, want %q", client.Name, name)
	}
}

func TestSubnetMatchAndSpecificity(t *testing.T) {
	t.Parallel()

	reg, _ := newRegistry(t)
	ctx := t.Context()

	lan := "LAN"
	filtering := false
	if _, err := reg.Update(ctx, "192.168.1.0/24", clients.Update{Name: &lan, FilteringEnabled: &filtering}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	guest := "Guest range"
	if _, err := reg.Update(ctx, "192.168.1.128/25", clients.Update{Name: &guest}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if client := reg.Identify(netip.MustParseAddr("192.168.1.10"), ""); client.Name != lan {
		t.Errorf("name = %q, want %q", client.Name, lan)
	}

	// The narrower subnet has to win, or a rule for a guest range would be
	// swallowed by the rule for the whole LAN.
	if client := reg.Identify(netip.MustParseAddr("192.168.1.200"), ""); client.Name != guest {
		t.Errorf("name = %q, want %q", client.Name, guest)
	}
}

func TestExactAddressBeatsSubnet(t *testing.T) {
	t.Parallel()

	reg, _ := newRegistry(t)
	ctx := t.Context()

	lan := "LAN"
	if _, err := reg.Update(ctx, "192.168.1.0/24", clients.Update{Name: &lan}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	printer := "Printer"
	if _, err := reg.Update(ctx, "192.168.1.5", clients.Update{Name: &printer}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if client := reg.Identify(netip.MustParseAddr("192.168.1.5"), ""); client.Name != printer {
		t.Errorf("name = %q, want %q", client.Name, printer)
	}
}

func TestSightingsBecomeListedClients(t *testing.T) {
	t.Parallel()

	reg, _ := newRegistry(t)
	ctx := t.Context()

	for range 3 {
		reg.Identify(netip.MustParseAddr("192.168.1.77"), "")
	}

	// A device that has only been seen still has to appear in the panel, so it
	// can be named instead of staying an address.
	list, err := reg.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	var found bool
	for _, c := range list {
		if c.Key == "192.168.1.77" {
			found = true
			if c.QueryCount < 3 {
				t.Errorf("query count = %d, want at least 3", c.QueryCount)
			}
			if c.LastSeen.IsZero() {
				t.Error("last seen should be recorded")
			}
		}
	}
	if !found {
		t.Error("a device that has been seen should be listed")
	}
}

func TestUpdateAndDelete(t *testing.T) {
	t.Parallel()

	reg, _ := newRegistry(t)
	ctx := t.Context()

	name := "Office laptop"
	paused := true
	client, err := reg.Update(ctx, "192.168.1.20", clients.Update{Name: &name, Paused: &paused})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if client.Name != name || !client.Paused {
		t.Errorf("client = %+v, want it named and paused", client)
	}

	// Identify has to see the change immediately: a pause taking a minute to
	// apply would be reported as a bug.
	if got := reg.Identify(netip.MustParseAddr("192.168.1.20"), ""); !got.Paused {
		t.Error("Identify should reflect the pause straight away")
	}

	if err = reg.Delete(ctx, "192.168.1.20"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := reg.Identify(netip.MustParseAddr("192.168.1.20"), ""); got.Paused {
		t.Error("a deleted client must lose its settings")
	}
}

func TestStale(t *testing.T) {
	t.Parallel()

	reg, db := newRegistry(t)
	ctx := t.Context()

	name := "Old tablet"
	if _, err := reg.Update(ctx, "192.168.1.30", clients.Update{Name: &name}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Backdate it: a device retired months ago is exactly what the stale view
	// is for.
	old := time.Now().Add(-90 * 24 * time.Hour).Unix()
	if _, err := db.Writer().ExecContext(ctx,
		`UPDATE clients SET last_seen = ? WHERE key = ?`, old, "192.168.1.30"); err != nil {
		t.Fatalf("backdating: %v", err)
	}

	stale, err := reg.Stale(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Stale: %v", err)
	}

	var found bool
	for _, c := range stale {
		if c.Key == "192.168.1.30" {
			found = true
		}
	}
	if !found {
		t.Error("a device unseen for 90 days should be reported as stale")
	}
}

func TestSeenMapIsBounded(t *testing.T) {
	t.Parallel()

	reg, _ := newRegistry(t)

	// A scanned or spoofed network must not be able to mint unbounded state on
	// the hot path.
	for i := range 10_000 {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		reg.Identify(addr, "")
	}

	list, err := reg.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) > 5000 {
		t.Errorf("registry grew to %d clients; the sighting map should be bounded", len(list))
	}
}
