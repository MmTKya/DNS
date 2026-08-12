// Package neigh reads the kernel's neighbour table to learn which hardware
// address is behind which IP address.
//
// This works in DNS-only mode, which is the point: the node is on the same
// network segment as its clients, so it already knows their hardware addresses
// without any traffic having to pass through it. That is what turns
// "192.168.1.74" in a device list into "Samsung tablet".
//
// It is read-only, needs no privileges, and is deliberately not authoritative:
// an entry can be stale, absent, or a randomised address that means nothing.
// Callers must treat a missing answer as normal.
package neigh

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// procPath is the kernel's IPv4 neighbour table.
//
// Only IPv4 is read here. IPv6 neighbours live in the netlink table with no
// procfs equivalent, so covering them means a netlink dependency; until then
// an IPv6-only client simply has no hardware address, which the caller already
// has to handle.
const procPath = "/proc/net/arp"

// Flag bits in /proc/net/arp.
const (
	flagComplete = 0x2
)

// Entry is one neighbour.
type Entry struct {
	Addr      netip.Addr
	MAC       string
	Interface string
}

// Table maps addresses to hardware addresses.
type Table map[netip.Addr]Entry

// Read returns the current neighbour table.
func Read() (table Table, err error) {
	return readFrom(procPath)
}

// Available reports whether the neighbour table can be read at all, so the
// panel can say "not available here" rather than showing empty vendors.
func Available() bool {
	_, err := os.Stat(procPath)

	return err == nil
}

func readFrom(path string) (table Table, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening neighbour table: %w", err)
	}
	defer func() { _ = f.Close() }()

	table = Table{}

	scanner := bufio.NewScanner(f)
	// The header line names the columns; the format is fixed, so it is skipped
	// rather than parsed.
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		addr, parseErr := netip.ParseAddr(fields[0])
		if parseErr != nil {
			continue
		}

		flags, flagErr := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		if flagErr != nil {
			continue
		}

		// An incomplete entry carries 00:00:00:00:00:00, which would attribute
		// every unresolved neighbour to the same imaginary device.
		if flags&flagComplete == 0 {
			continue
		}

		mac := strings.ToLower(fields[3])
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}

		table[addr] = Entry{Addr: addr, MAC: mac, Interface: fields[5]}
	}

	if err = scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading neighbour table: %w", err)
	}

	return table, nil
}

// Lookup returns the hardware address for an address.
func (t Table) Lookup(addr netip.Addr) (mac string, found bool) {
	entry, ok := t[addr.Unmap()]
	if !ok {
		return "", false
	}

	return entry.MAC, true
}

// Watcher keeps a recent copy of the neighbour table.
//
// The table is polled rather than watched: it changes only when a device joins
// or its entry expires, and a netlink subscription for that is a dependency and
// a privileged socket for information that is fine a minute late.
type Watcher struct {
	table  Table
	loaded time.Time
	ttl    time.Duration
}

// NewWatcher returns a watcher that refreshes at most every ttl.
func NewWatcher(ttl time.Duration) *Watcher {
	if ttl <= 0 {
		ttl = time.Minute
	}

	return &Watcher{ttl: ttl}
}

// Table returns the cached table, refreshing it when stale.
//
// A read failure keeps the previous copy: losing every device's vendor because
// one read failed would be a worse outcome than showing slightly old data.
func (w *Watcher) Table() Table {
	if time.Since(w.loaded) < w.ttl && w.table != nil {
		return w.table
	}

	table, err := Read()
	if err != nil {
		if w.table != nil {
			return w.table
		}

		return Table{}
	}

	w.table = table
	w.loaded = time.Now()

	return table
}
