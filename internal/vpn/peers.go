package vpn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/MmTKya/DNS/internal/store"
	qrcode "github.com/skip2/go-qrcode"
)

// Peer is a device that connects through the tunnel.
type Peer struct {
	CreatedAt     time.Time `json:"created_at"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`

	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`

	ID      int64 `json:"id"`
	RxBytes int64 `json:"rx_bytes"`
	TxBytes int64 `json:"tx_bytes"`

	Enabled bool `json:"enabled"`

	// HasPresharedKey is reported instead of the key itself.  The panel needs
	// to know it exists; nobody needs to read it back.
	HasPresharedKey bool `json:"has_preshared_key"`
}

// Online reports whether the peer has handshaked recently.
//
// WireGuard is connectionless: a peer that has nothing to say is silent, and a
// silent peer is not the same as a disconnected one. Three minutes is a little
// over two keepalive intervals, which is the shortest window that does not
// flicker.
func (p Peer) Online() bool {
	return !p.LastHandshake.IsZero() && time.Since(p.LastHandshake) < 3*time.Minute
}

// ServerConfig describes this node's side of the tunnel.
type ServerConfig struct {
	// Subnet is the address range handed out inside the tunnel.
	Subnet netip.Prefix

	// Address is this node's address inside the tunnel, and — crucially — what
	// peers are told to use for DNS.
	Address netip.Addr

	// Endpoint is the host:port clients dial from outside.
	Endpoint string

	// PublicKey is this node's tunnel identity.
	PublicKey string

	// KeepAlive keeps a NAT mapping open from the client side.
	KeepAlive int

	// MTU of the tunnel interface.  1420 is the usual safe value over an
	// ordinary 1500-byte path.
	MTU int
}

// ErrPoolExhausted means the tunnel subnet has no free addresses.
var ErrPoolExhausted = errors.New("no free addresses left in the tunnel subnet")

// AllocateAddress returns the lowest unused address in the subnet.
//
// Addresses are handed out in order and reused once a peer is deleted, so a
// household adding and removing devices does not march up the range forever.
func AllocateAddress(subnet netip.Prefix, serverAddr netip.Addr, taken []string) (addr netip.Addr, err error) {
	used := map[netip.Addr]struct{}{}
	for _, raw := range taken {
		if parsed, parseErr := parseAddress(raw); parseErr == nil {
			used[parsed] = struct{}{}
		}
	}
	if serverAddr.IsValid() {
		used[serverAddr] = struct{}{}
	}

	candidate := subnet.Addr()
	// The network address itself is never handed out.
	candidate = candidate.Next()

	for subnet.Contains(candidate) {
		if _, clash := used[candidate]; !clash {
			return candidate, nil
		}
		candidate = candidate.Next()
	}

	return netip.Addr{}, ErrPoolExhausted
}

// parseAddress accepts both "10.6.0.2" and "10.6.0.2/32".
func parseAddress(raw string) (addr netip.Addr, err error) {
	raw = strings.TrimSpace(raw)
	if prefix, prefixErr := netip.ParsePrefix(raw); prefixErr == nil {
		return prefix.Addr(), nil
	}

	return netip.ParseAddr(raw)
}

// ClientConfig is what a new device is given.
type ClientConfig struct {
	// Config is the wg-quick file contents.
	Config string `json:"config"`

	// PrivateKey is returned once, here, and never stored.
	PrivateKey string `json:"private_key"`

	Peer Peer `json:"peer"`
}

// RenderClientConfig builds the configuration a device imports.
//
// The DNS line is the whole point: without it the phone keeps using whatever
// resolver its carrier handed out, the tunnel carries traffic but filters
// nothing, and the feature quietly does not work.
func RenderClientConfig(server ServerConfig, peer Peer, privateKey Key, presharedKey Key, fullTunnel bool) string {
	var b strings.Builder

	keepAlive := server.KeepAlive
	if keepAlive <= 0 {
		keepAlive = 25
	}

	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + privateKey.String() + "\n")
	b.WriteString("Address = " + peer.Address + "\n")
	b.WriteString("DNS = " + server.Address.String() + "\n")
	if server.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", server.MTU)
	}

	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = " + server.PublicKey + "\n")
	if !presharedKey.IsZero() {
		b.WriteString("PresharedKey = " + presharedKey.String() + "\n")
	}
	b.WriteString("Endpoint = " + server.Endpoint + "\n")

	if fullTunnel {
		// Everything through the tunnel: the device's whole connection is
		// filtered, at the cost of its bandwidth going through the house.
		b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	} else {
		// DNS and the home network only. The device keeps its own path to the
		// internet, which is what most phones want, and still resolves here.
		b.WriteString("AllowedIPs = " + server.Address.String() + "/32, " + server.Subnet.String() + "\n")
	}

	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", keepAlive)

	return b.String()
}

// RenderQR encodes a client configuration as a PNG QR code.
//
// Typing a 44-character key on a phone keyboard is how people give up on
// setting up a VPN.
func RenderQR(config string, size int) (png []byte, err error) {
	if size <= 0 {
		size = 512
	}

	// Medium recovery: a configuration is long enough that high recovery makes
	// the code dense enough to be hard to scan on a screen.
	png, err = qrcode.Encode(config, qrcode.Medium, size)
	if err != nil {
		return nil, fmt.Errorf("encoding qr code: %w", err)
	}

	return png, nil
}

// RenderServerConfig produces a wg-quick file for this node.
//
// The node normally programs the interface directly through netlink; this
// exists for operators who prefer to manage it themselves, and for support.
func RenderServerConfig(server ServerConfig, privateKey Key, port int, peers []Peer, presharedKeys map[string]string) string {
	var b strings.Builder

	b.WriteString("# Generated by SedDNS.\n")
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + privateKey.String() + "\n")
	b.WriteString("Address = " + server.Address.String() + "/" + fmt.Sprint(server.Subnet.Bits()) + "\n")
	fmt.Fprintf(&b, "ListenPort = %d\n", port)
	if server.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", server.MTU)
	}

	for _, peer := range peers {
		if !peer.Enabled {
			continue
		}

		b.WriteString("\n[Peer]\n")
		b.WriteString("# " + peer.Name + "\n")
		b.WriteString("PublicKey = " + peer.PublicKey + "\n")
		if psk, ok := presharedKeys[peer.PublicKey]; ok && psk != "" {
			b.WriteString("PresharedKey = " + psk + "\n")
		}
		b.WriteString("AllowedIPs = " + peer.Address + "\n")
	}

	return b.String()
}

// --- storage ---

// List returns every peer.
func List(ctx context.Context, db *store.DB) (peers []Peer, err error) {
	rows, err := db.Reader().QueryContext(ctx, `
		SELECT id, name, public_key, preshared_key, address, enabled,
		       created_at, last_handshake, rx_bytes, tx_bytes
		FROM vpn_peers ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("listing peers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			p                    Peer
			preshared            string
			enabled              int
			createdAt, handshake int64
		)

		if err = rows.Scan(&p.ID, &p.Name, &p.PublicKey, &preshared, &p.Address,
			&enabled, &createdAt, &handshake, &p.RxBytes, &p.TxBytes,
		); err != nil {
			return nil, fmt.Errorf("scanning peer: %w", err)
		}

		p.Enabled = enabled != 0
		p.HasPresharedKey = preshared != ""
		p.CreatedAt = time.Unix(createdAt, 0)
		if handshake > 0 {
			p.LastHandshake = time.Unix(handshake, 0)
		}

		peers = append(peers, p)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating peers: %w", err)
	}

	return peers, nil
}

// PresharedKeys returns the stored symmetric keys, which the interface needs
// when it is programmed.
func PresharedKeys(ctx context.Context, db *store.DB) (keys map[string]string, err error) {
	rows, err := db.Reader().QueryContext(ctx,
		`SELECT public_key, preshared_key FROM vpn_peers WHERE preshared_key != ''`)
	if err != nil {
		return nil, fmt.Errorf("reading preshared keys: %w", err)
	}
	defer func() { _ = rows.Close() }()

	keys = map[string]string{}
	for rows.Next() {
		var public, preshared string
		if err = rows.Scan(&public, &preshared); err != nil {
			return nil, fmt.Errorf("scanning preshared key: %w", err)
		}
		keys[public] = preshared
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating preshared keys: %w", err)
	}

	return keys, nil
}

// AddPeer creates a peer and returns the configuration for the device.
//
// The private key is generated here, handed back once, and never stored: a
// node holding every device's private key would be one theft away from
// impersonating all of them.
func AddPeer(ctx context.Context, db *store.DB, server ServerConfig, name string, fullTunnel bool) (cfg ClientConfig, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ClientConfig{}, errors.New("a name is required")
	}

	existing, err := List(ctx, db)
	if err != nil {
		return ClientConfig{}, err
	}

	taken := make([]string, 0, len(existing))
	for _, p := range existing {
		taken = append(taken, p.Address)
	}

	addr, err := AllocateAddress(server.Subnet, server.Address, taken)
	if err != nil {
		return ClientConfig{}, err
	}

	pair, err := GenerateKeyPair()
	if err != nil {
		return ClientConfig{}, err
	}

	preshared, err := GeneratePresharedKey()
	if err != nil {
		return ClientConfig{}, err
	}

	peer := Peer{
		Name:            name,
		PublicKey:       pair.Public.String(),
		Address:         addr.String() + "/32",
		Enabled:         true,
		CreatedAt:       time.Now(),
		HasPresharedKey: true,
	}

	res, err := db.Writer().ExecContext(ctx, `
		INSERT INTO vpn_peers (name, public_key, preshared_key, address, enabled, created_at)
		VALUES (?, ?, ?, ?, 1, ?)
	`, peer.Name, peer.PublicKey, preshared.String(), peer.Address, peer.CreatedAt.Unix())
	if err != nil {
		return ClientConfig{}, fmt.Errorf("storing peer: %w", err)
	}

	if peer.ID, err = res.LastInsertId(); err != nil {
		return ClientConfig{}, fmt.Errorf("reading peer id: %w", err)
	}

	return ClientConfig{
		Config:     RenderClientConfig(server, peer, pair.Private, preshared, fullTunnel),
		PrivateKey: pair.Private.String(),
		Peer:       peer,
	}, nil
}

// SetEnabled switches a peer on or off without deleting it.
func SetEnabled(ctx context.Context, db *store.DB, id int64, enabled bool) (found bool, err error) {
	value := 0
	if enabled {
		value = 1
	}

	res, err := db.Writer().ExecContext(ctx,
		`UPDATE vpn_peers SET enabled = ? WHERE id = ?`, value, id)
	if err != nil {
		return false, fmt.Errorf("updating peer: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("checking update: %w", err)
	}

	return affected > 0, nil
}

// DeletePeer removes a peer and frees its address.
func DeletePeer(ctx context.Context, db *store.DB, id int64) (found bool, err error) {
	res, err := db.Writer().ExecContext(ctx, `DELETE FROM vpn_peers WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("deleting peer: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("checking deletion: %w", err)
	}

	return affected > 0, nil
}

// RecordStats stores what the kernel reports about a peer.
func RecordStats(ctx context.Context, db *store.DB, publicKey string, handshake time.Time, rx, tx int64) error {
	var ts int64
	if !handshake.IsZero() {
		ts = handshake.Unix()
	}

	if _, err := db.Writer().ExecContext(ctx, `
		UPDATE vpn_peers SET last_handshake = ?, rx_bytes = ?, tx_bytes = ? WHERE public_key = ?
	`, ts, rx, tx, publicKey); err != nil {
		return fmt.Errorf("recording peer stats: %w", err)
	}

	return nil
}

// SortPeers orders peers for display: online first, then by name.
func SortPeers(peers []Peer) {
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Online() != peers[j].Online() {
			return peers[i].Online()
		}

		return peers[i].Name < peers[j].Name
	})
}
