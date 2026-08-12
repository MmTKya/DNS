package neigh

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The kernel's format, including the cases that matter: an incomplete entry
// and a zero hardware address.
const fixture = `IP address       HW type     Flags       HW address            Mask     Device
192.168.68.69    0x1         0x2         80:32:53:3a:a7:82     *        ens34
192.168.68.62    0x1         0x2         48:55:19:73:81:d9     *        ens34
192.168.68.9     0x1         0x0         00:00:00:00:00:00     *        ens34
192.168.68.1     0x1         0x2         A8:42:A1:61:B0:E8     *        ens34
`

func TestReadFrom(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "arp")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	table, err := readFrom(path)
	if err != nil {
		t.Fatalf("readFrom: %v", err)
	}

	// The incomplete entry must be dropped: its all-zero address would
	// attribute every unresolved neighbour to one imaginary device.
	if len(table) != 3 {
		t.Fatalf("got %d entries, want 3", len(table))
	}
	if _, found := table.Lookup(netip.MustParseAddr("192.168.68.9")); found {
		t.Error("an incomplete entry was kept")
	}

	mac, found := table.Lookup(netip.MustParseAddr("192.168.68.69"))
	if !found || mac != "80:32:53:3a:a7:82" {
		t.Errorf("lookup = %q, %t; want the hardware address", mac, found)
	}

	// Case is normalised, so a lookup never depends on how the kernel spelled it.
	if mac, _ = table.Lookup(netip.MustParseAddr("192.168.68.1")); mac != "a8:42:a1:61:b0:e8" {
		t.Errorf("lookup = %q, want it lowercased", mac)
	}
}

func TestReadFromMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := readFrom(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("a missing neighbour table should be an error, not an empty answer")
	}
}

func TestWatcherKeepsPreviousTableOnFailure(t *testing.T) {
	t.Parallel()

	w := NewWatcher(time.Hour)

	// Whatever this machine has, the call must not panic and must return a
	// usable map.
	first := w.Table()
	if first == nil {
		t.Fatal("Table returned nil")
	}

	// Cached: a second call inside the ttl must not re-read.
	if second := w.Table(); len(second) != len(first) {
		t.Errorf("cached table changed size: %d then %d", len(first), len(second))
	}
}

func TestReadsThisMachine(t *testing.T) {
	t.Parallel()

	if !Available() {
		t.Skip("no neighbour table on this system")
	}

	table, err := Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	// Not asserting a count — a machine may legitimately have none — but every
	// entry that is there has to be well formed.
	for addr, entry := range table {
		if !addr.IsValid() {
			t.Errorf("entry has an invalid address: %+v", entry)
		}
		if len(entry.MAC) != 17 {
			t.Errorf("entry %v has a malformed hardware address %q", addr, entry.MAC)
		}
		if entry.Interface == "" {
			t.Errorf("entry %v has no interface", addr)
		}
	}
}
