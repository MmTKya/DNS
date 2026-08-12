// Package clients tracks the devices asking this resolver questions.
//
// Identity is the hard part.  An address identifies a device only while it
// stays on this network and keeps its lease; a phone that leaves the house has
// a different one every hour.  So three keys are supported, matched from most
// to least specific: a self-declared id carried in a DoH path or DoT server
// name, an exact address, and a subnet.  Only the first survives roaming, which
// is why the encrypted transports matter for per-device policy.
package clients

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MmTKya/DNS/internal/neigh"
	"github.com/MmTKya/DNS/internal/oui"
	"github.com/MmTKya/DNS/internal/store"
)

// Key types.
const (
	KeyClientID = "client_id"
	KeyIP       = "ip"
	KeyCIDR     = "cidr"
)

// Client is a device, or a group of them.
type Client struct {
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen,omitzero"`

	Key     string `json:"key"`
	KeyType string `json:"key_type"`
	Name    string `json:"name"`
	Tags    string `json:"tags,omitempty"`

	// MAC and Vendor come from the kernel's neighbour table and the IEEE
	// registry.  They are empty for a device that has never been seen on this
	// segment, and for one behind a router.
	MAC    string `json:"mac,omitempty"`
	Vendor string `json:"vendor,omitempty"`

	// MACRandomised marks a locally-administered address.  Modern phones
	// rotate these, so the address identifies the device only for as long as
	// it stays joined — the panel must not offer it as a stable handle.
	MACRandomised bool `json:"mac_randomised,omitempty"`

	ID         int64  `json:"id"`
	QueryCount uint64 `json:"query_count"`

	FilteringEnabled bool `json:"filtering_enabled"`
	Paused           bool `json:"paused"`

	// Known is false for a device that has been seen but never configured.
	// The panel shows these so they can be named rather than staying an
	// address.
	Known bool `json:"known"`
}

// DisplayName is what the panel shows.
func (c Client) DisplayName() string {
	if c.Name != "" {
		return c.Name
	}

	return c.Key
}

// Registry resolves queries to clients and keeps their state.
//
// Lookups happen on every query, so configured clients are held in memory and
// the database is only touched when something changes.
type Registry struct {
	db     *store.DB
	logger *slog.Logger

	// neighbours maps addresses to hardware addresses.  It is polled, because
	// it changes only when a device joins or an entry expires.
	neighbours *neigh.Watcher

	mu sync.RWMutex

	byClientID map[string]*Client
	byIP       map[netip.Addr]*Client
	byCIDR     []cidrClient

	// seen tracks devices that have no configured record, so the panel can
	// offer to name them.  Kept in memory and persisted on a timer.
	seen map[string]*sighting
}

type cidrClient struct {
	client *Client
	prefix netip.Prefix
}

type sighting struct {
	lastSeen time.Time
	count    uint64
	dirty    bool
}

// maxSeen bounds the auto-discovery map.  A scanned or spoofed network could
// otherwise mint an unbounded number of entries.
const maxSeen = 4096

// New creates a registry and loads the configured clients.
func New(ctx context.Context, db *store.DB, logger *slog.Logger) (*Registry, error) {
	if logger == nil {
		logger = slog.Default()
	}

	r := &Registry{
		db:         db,
		logger:     logger.With("component", "clients"),
		seen:       map[string]*sighting{},
		neighbours: neigh.NewWatcher(time.Minute),
	}

	if err := r.Reload(ctx); err != nil {
		return nil, err
	}

	return r, nil
}

// Reload rebuilds the in-memory index from the database.
func (r *Registry) Reload(ctx context.Context) error {
	list, err := r.load(ctx)
	if err != nil {
		return err
	}

	byClientID := make(map[string]*Client, len(list))
	byIP := make(map[netip.Addr]*Client, len(list))
	var byCIDR []cidrClient

	for i := range list {
		c := &list[i]

		switch c.KeyType {
		case KeyClientID:
			byClientID[c.Key] = c

		case KeyIP:
			if addr, parseErr := netip.ParseAddr(c.Key); parseErr == nil {
				byIP[addr] = c
			} else {
				r.logger.WarnContext(ctx, "client has an unparseable address", "key", c.Key)
			}

		case KeyCIDR:
			if prefix, parseErr := netip.ParsePrefix(c.Key); parseErr == nil {
				byCIDR = append(byCIDR, cidrClient{prefix: prefix, client: c})
			} else {
				r.logger.WarnContext(ctx, "client has an unparseable subnet", "key", c.Key)
			}
		}
	}

	// The narrowest subnet wins, so a rule for one /32 beats a rule for the
	// whole LAN.
	sort.Slice(byCIDR, func(i, j int) bool {
		return byCIDR[i].prefix.Bits() > byCIDR[j].prefix.Bits()
	})

	r.mu.Lock()
	defer r.mu.Unlock()

	r.byClientID = byClientID
	r.byIP = byIP
	r.byCIDR = byCIDR

	return nil
}

// Identify resolves a query's source to a client, recording the sighting.
//
// It never fails: a device with no configured record still gets a usable
// Client so that policy has something to consult and the panel can show it.
func (r *Registry) Identify(addr netip.Addr, clientID string) Client {
	r.mu.RLock()

	var found *Client
	switch {
	case clientID != "":
		found = r.byClientID[clientID]
	default:
	}

	if found == nil && addr.IsValid() {
		found = r.byIP[addr.Unmap()]

		if found == nil {
			for _, entry := range r.byCIDR {
				if entry.prefix.Contains(addr.Unmap()) {
					found = entry.client

					break
				}
			}
		}
	}

	r.mu.RUnlock()

	key := clientID
	if key == "" && addr.IsValid() {
		key = addr.String()
	}

	if found != nil {
		r.touch(found.Key)

		return *found
	}

	r.touch(key)

	// An unconfigured device is filtered by default: an unknown thing on the
	// network is the one you least want unfiltered.
	return Client{
		Key:              key,
		KeyType:          keyTypeFor(clientID, addr),
		FilteringEnabled: true,
	}
}

func keyTypeFor(clientID string, addr netip.Addr) string {
	if clientID != "" {
		return KeyClientID
	}
	if addr.IsValid() {
		return KeyIP
	}

	return KeyIP
}

// touch records that a client was seen.  It only writes to memory; the
// database is updated by Run on a timer.
func (r *Registry) touch(key string) {
	if key == "" {
		return
	}

	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	if s, ok := r.seen[key]; ok {
		s.lastSeen = now
		s.count++
		s.dirty = true

		return
	}

	if len(r.seen) >= maxSeen {
		return
	}

	r.seen[key] = &sighting{lastSeen: now, count: 1, dirty: true}
}

// Run persists sightings until ctx is cancelled.
func (r *Registry) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.persistSightings(context.WithoutCancel(ctx))

			return
		case <-ticker.C:
			r.persistSightings(ctx)
		}
	}
}

func (r *Registry) persistSightings(ctx context.Context) {
	r.mu.Lock()
	pending := make(map[string]sighting, len(r.seen))
	for key, s := range r.seen {
		if s.dirty {
			pending[key] = *s
			s.dirty = false
		}
	}
	r.mu.Unlock()

	// Hardware identity is refreshed even when nothing was seen: a device that
	// is quiet, or one added from the panel, still has a hardware address on
	// this segment, and its vendor should not depend on it making a query.
	defer func() {
		r.refreshHardware(ctx)

		if err := r.Reload(ctx); err != nil {
			r.logger.ErrorContext(ctx, "reloading clients", "err", err)
		}
	}()

	if len(pending) == 0 {
		return
	}

	for key, s := range pending {
		// A device that has never been configured gets a row on first sight,
		// so the panel can list it; the row carries the defaults until someone
		// names it.
		if _, err := r.db.Writer().ExecContext(ctx, `
			INSERT INTO clients (key, key_type, name, filtering_enabled, paused, created_at, last_seen, query_count)
			VALUES (?, ?, '', 1, 0, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET
				last_seen   = excluded.last_seen,
				query_count = query_count + excluded.query_count
		`, key, keyTypeForKey(key), time.Now().Unix(), s.lastSeen.Unix(), s.count); err != nil {
			r.logger.ErrorContext(ctx, "recording client sighting", "client", key, "err", err)

			return
		}
	}
}

// refreshHardware fills in the hardware address and vendor for clients keyed on
// an address.
//
// A device that has gone quiet drops out of the neighbour table, so a known
// address is never cleared — only filled in. Losing a device's name because it
// was asleep would be a worse answer than a slightly stale one.
func (r *Registry) refreshHardware(ctx context.Context) {
	table := r.neighbours.Table()
	if len(table) == 0 {
		return
	}

	r.mu.RLock()
	known := make([]*Client, 0, len(r.byIP))
	for _, c := range r.byIP {
		known = append(known, c)
	}
	r.mu.RUnlock()

	for _, client := range known {
		addr, err := netip.ParseAddr(client.Key)
		if err != nil {
			continue
		}

		mac, found := table.Lookup(addr)
		if !found || mac == client.MAC {
			continue
		}

		vendor := ""
		if !oui.Randomised(mac) {
			vendor, _ = oui.Lookup(mac)
		}

		if _, err = r.db.Writer().ExecContext(ctx,
			`UPDATE clients SET mac = ?, vendor = ? WHERE key = ?`,
			mac, vendor, client.Key,
		); err != nil {
			r.logger.ErrorContext(ctx, "recording client hardware", "client", client.Key, "err", err)
		}
	}
}

func keyTypeForKey(key string) string {
	if _, err := netip.ParseAddr(key); err == nil {
		return KeyIP
	}
	if _, err := netip.ParsePrefix(key); err == nil {
		return KeyCIDR
	}

	return KeyClientID
}

// List returns every known client, most recently seen first.
func (r *Registry) List(ctx context.Context) ([]Client, error) {
	// Sightings buffered in memory would otherwise make the panel look stale.
	r.persistSightings(ctx)

	return r.load(ctx)
}

func (r *Registry) load(ctx context.Context) (list []Client, err error) {
	rows, err := r.db.Reader().QueryContext(ctx, `
		SELECT id, key, key_type, name, tags, filtering_enabled, paused,
		       created_at, last_seen, query_count, mac, vendor
		FROM clients
		ORDER BY last_seen DESC, id
	`)
	if err != nil {
		return nil, fmt.Errorf("listing clients: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			c                  Client
			filtering, paused  int
			createdAt, lastSee int64
		)

		if err = rows.Scan(&c.ID, &c.Key, &c.KeyType, &c.Name, &c.Tags,
			&filtering, &paused, &createdAt, &lastSee, &c.QueryCount,
			&c.MAC, &c.Vendor,
		); err != nil {
			return nil, fmt.Errorf("scanning client: %w", err)
		}

		c.MACRandomised = c.MAC != "" && oui.Randomised(c.MAC)
		c.FilteringEnabled = filtering != 0
		c.Paused = paused != 0
		c.Known = true
		c.CreatedAt = time.Unix(createdAt, 0)
		if lastSee > 0 {
			c.LastSeen = time.Unix(lastSee, 0)
		}

		list = append(list, c)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating clients: %w", err)
	}

	return list, nil
}

// Update changes a client's settings.
type Update struct {
	Name             *string
	Tags             *string
	FilteringEnabled *bool
	Paused           *bool
}

// Update applies changes to a client, creating its row if the device has been
// seen but never configured.
func (r *Registry) Update(ctx context.Context, key string, u Update) (client Client, err error) {
	if strings.TrimSpace(key) == "" {
		return Client{}, fmt.Errorf("a client key is required")
	}

	if _, err = r.db.Writer().ExecContext(ctx, `
		INSERT INTO clients (key, key_type, created_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO NOTHING
	`, key, keyTypeForKey(key), time.Now().Unix()); err != nil {
		return Client{}, fmt.Errorf("creating client %s: %w", key, err)
	}

	var (
		sets []string
		args []any
	)
	if u.Name != nil {
		sets = append(sets, "name = ?")
		args = append(args, *u.Name)
	}
	if u.Tags != nil {
		sets = append(sets, "tags = ?")
		args = append(args, *u.Tags)
	}
	if u.FilteringEnabled != nil {
		sets = append(sets, "filtering_enabled = ?")
		args = append(args, boolToInt(*u.FilteringEnabled))
	}
	if u.Paused != nil {
		sets = append(sets, "paused = ?")
		args = append(args, boolToInt(*u.Paused))
	}

	if len(sets) > 0 {
		args = append(args, key)
		if _, err = r.db.Writer().ExecContext(ctx,
			`UPDATE clients SET `+strings.Join(sets, ", ")+` WHERE key = ?`, args...,
		); err != nil {
			return Client{}, fmt.Errorf("updating client %s: %w", key, err)
		}
	}

	if err = r.Reload(ctx); err != nil {
		return Client{}, err
	}

	return r.Get(ctx, key)
}

// Get returns one client.
func (r *Registry) Get(ctx context.Context, key string) (client Client, err error) {
	list, err := r.load(ctx)
	if err != nil {
		return Client{}, err
	}

	for _, c := range list {
		if c.Key == key {
			return c, nil
		}
	}

	return Client{}, fmt.Errorf("no client with key %q", key)
}

// Delete forgets a client.  It reappears if the device asks again.
func (r *Registry) Delete(ctx context.Context, key string) error {
	if _, err := r.db.Writer().ExecContext(ctx, `DELETE FROM clients WHERE key = ?`, key); err != nil {
		return fmt.Errorf("deleting client %s: %w", key, err)
	}

	r.mu.Lock()
	delete(r.seen, key)
	r.mu.Unlock()

	return r.Reload(ctx)
}

// Stale returns clients not seen for longer than age, which is how the panel
// offers to clean up retired hardware and expired leases.
func (r *Registry) Stale(ctx context.Context, age time.Duration) (list []Client, err error) {
	all, err := r.load(ctx)
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().Add(-age)
	for _, c := range all {
		if c.LastSeen.IsZero() || c.LastSeen.Before(cutoff) {
			list = append(list, c)
		}
	}

	return list, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}

	return 0
}
