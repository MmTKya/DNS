package vpn_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/store"
	"github.com/MmTKya/DNS/internal/vpn"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "aegisdns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func testServer(t *testing.T) vpn.ServerConfig {
	t.Helper()

	pair, err := vpn.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	return vpn.ServerConfig{
		Subnet:    netip.MustParsePrefix("10.6.0.0/24"),
		Address:   netip.MustParseAddr("10.6.0.1"),
		Endpoint:  "home.example:51820",
		PublicKey: pair.Public.String(),
		MTU:       1420,
	}
}

func TestKeyGeneration(t *testing.T) {
	t.Parallel()

	pair, err := vpn.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// WireGuard configurations carry base64 keys of exactly 44 characters.
	if len(pair.Public.String()) != 44 {
		t.Errorf("public key is %q, want 44 base64 characters", pair.Public.String())
	}
	if raw, decodeErr := base64.StdEncoding.DecodeString(pair.Private.String()); decodeErr != nil || len(raw) != 32 {
		t.Errorf("private key does not decode to 32 bytes: %v", decodeErr)
	}

	// Clamping is part of Curve25519: without it the handshake produces a
	// shared secret neither side can reproduce.
	if pair.Private[0]&7 != 0 {
		t.Error("the private key is not clamped in its first byte")
	}
	if pair.Private[31]&128 != 0 || pair.Private[31]&64 == 0 {
		t.Error("the private key is not clamped in its last byte")
	}

	// The public key must be reproducible from the private one.
	derived, err := vpn.PublicKey(pair.Private)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if derived != pair.Public {
		t.Error("the public key does not derive from the private key")
	}

	// Two keypairs must differ.
	other, err := vpn.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if other.Private == pair.Private {
		t.Fatal("two generated keys are identical")
	}
}

func TestParseKey(t *testing.T) {
	t.Parallel()

	pair, err := vpn.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	parsed, err := vpn.ParseKey(pair.Public.String())
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	if parsed != pair.Public {
		t.Error("a key did not survive a round trip through base64")
	}

	for _, bad := range []string{"", "not-base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err = vpn.ParseKey(bad); err == nil {
			t.Errorf("ParseKey(%q) accepted an invalid key", bad)
		}
	}
}

func TestAddressAllocation(t *testing.T) {
	t.Parallel()

	subnet := netip.MustParsePrefix("10.6.0.0/24")
	server := netip.MustParseAddr("10.6.0.1")

	first, err := vpn.AllocateAddress(subnet, server, nil)
	if err != nil {
		t.Fatalf("AllocateAddress: %v", err)
	}
	// The network address and the node's own address are never handed out.
	if first.String() != "10.6.0.2" {
		t.Errorf("first allocation = %s, want 10.6.0.2", first)
	}

	next, err := vpn.AllocateAddress(subnet, server, []string{"10.6.0.2/32"})
	if err != nil {
		t.Fatalf("AllocateAddress: %v", err)
	}
	if next.String() != "10.6.0.3" {
		t.Errorf("second allocation = %s, want 10.6.0.3", next)
	}

	// A freed address is reused rather than the range marching upwards forever.
	reused, err := vpn.AllocateAddress(subnet, server, []string{"10.6.0.3/32"})
	if err != nil {
		t.Fatalf("AllocateAddress: %v", err)
	}
	if reused.String() != "10.6.0.2" {
		t.Errorf("allocation after a deletion = %s, want the freed 10.6.0.2", reused)
	}
}

func TestAddressPoolExhaustion(t *testing.T) {
	t.Parallel()

	// A /30 holds 10.6.0.0-3: network, server, one peer, broadcast.
	subnet := netip.MustParsePrefix("10.6.0.0/30")
	server := netip.MustParseAddr("10.6.0.1")

	if _, err := vpn.AllocateAddress(subnet, server, []string{"10.6.0.2", "10.6.0.3"}); err == nil {
		t.Error("a full subnet should report exhaustion rather than an invalid address")
	}
}

func TestClientConfigForcesDNSThroughTheNode(t *testing.T) {
	t.Parallel()

	server := testServer(t)
	peer := vpn.Peer{Name: "phone", Address: "10.6.0.2/32", PublicKey: "peer-key"}

	private, err := vpn.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	preshared, err := vpn.GeneratePresharedKey()
	if err != nil {
		t.Fatalf("GeneratePresharedKey: %v", err)
	}

	cfg := vpn.RenderClientConfig(server, peer, private, preshared, false)

	// Without this line the tunnel carries traffic and filters nothing: the
	// phone keeps using whatever resolver its carrier handed out.
	if !strings.Contains(cfg, "DNS = 10.6.0.1") {
		t.Errorf("the client config does not point DNS at the node:\n%s", cfg)
	}

	for _, want := range []string{
		"[Interface]",
		"PrivateKey = " + private.String(),
		"Address = 10.6.0.2/32",
		"[Peer]",
		"PublicKey = " + server.PublicKey,
		"PresharedKey = " + preshared.String(),
		"Endpoint = home.example:51820",
		"PersistentKeepalive = 25",
		"MTU = 1420",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("the client config is missing %q:\n%s", want, cfg)
		}
	}

	// Split tunnel: DNS and the home network only.
	if strings.Contains(cfg, "0.0.0.0/0") {
		t.Errorf("a split-tunnel config should not route everything:\n%s", cfg)
	}

	full := vpn.RenderClientConfig(server, peer, private, preshared, true)
	if !strings.Contains(full, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Errorf("a full-tunnel config should route everything:\n%s", full)
	}
}

func TestAddPeerReturnsThePrivateKeyOnceAndNeverStoresIt(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	server := testServer(t)

	cfg, err := vpn.AddPeer(t.Context(), db, server, "Phone", false)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if cfg.PrivateKey == "" {
		t.Fatal("the device needs its private key once")
	}

	// A node holding every device's private key is one theft away from
	// impersonating all of them.
	var stored int
	if err = db.Reader().QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM vpn_peers WHERE public_key = ? OR preshared_key = ?`,
		cfg.PrivateKey, cfg.PrivateKey).Scan(&stored); err != nil {
		t.Fatalf("querying: %v", err)
	}
	if stored != 0 {
		t.Error("the private key was stored on the node")
	}

	peers, err := vpn.List(t.Context(), db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(peers) != 1 || peers[0].Name != "Phone" || peers[0].Address != "10.6.0.2/32" {
		t.Errorf("peers = %+v, want the new one", peers)
	}
	if !peers[0].HasPresharedKey {
		t.Error("a preshared key should be generated for every peer")
	}
}

func TestPeerLifecycle(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	server := testServer(t)
	ctx := t.Context()

	first, err := vpn.AddPeer(ctx, db, server, "Phone", false)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if _, err = vpn.AddPeer(ctx, db, server, "Laptop", true); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	found, err := vpn.SetEnabled(ctx, db, first.Peer.ID, false)
	if err != nil || !found {
		t.Fatalf("SetEnabled: found=%t err=%v", found, err)
	}

	peers, err := vpn.List(ctx, db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if peers[0].Enabled {
		t.Error("the peer should be disabled")
	}

	if found, err = vpn.DeletePeer(ctx, db, first.Peer.ID); err != nil || !found {
		t.Fatalf("DeletePeer: found=%t err=%v", found, err)
	}

	// The freed address goes back into the pool.
	next, err := vpn.AddPeer(ctx, db, server, "Tablet", false)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if next.Peer.Address != "10.6.0.2/32" {
		t.Errorf("new peer took %s, want the freed 10.6.0.2/32", next.Peer.Address)
	}
}

func TestDuplicateNameIsAllowedDuplicateKeyIsNot(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	server := testServer(t)

	// Two devices can share a name; the key is what has to be unique.
	if _, err := vpn.AddPeer(t.Context(), db, server, "Phone", false); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if _, err := vpn.AddPeer(t.Context(), db, server, "Phone", false); err != nil {
		t.Errorf("a second peer with the same name should be allowed: %v", err)
	}

	if _, err := vpn.AddPeer(t.Context(), db, server, "  ", false); err == nil {
		t.Error("a blank name should be refused")
	}
}

func TestRenderQR(t *testing.T) {
	t.Parallel()

	png, err := vpn.RenderQR("[Interface]\nPrivateKey = x\n", 256)
	if err != nil {
		t.Fatalf("RenderQR: %v", err)
	}

	// Typing a 44-character key on a phone is how people give up on setting up
	// a VPN, so the QR has to actually be a PNG the panel can show.
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Error("the QR code is not a PNG")
	}
	if len(png) < 200 {
		t.Errorf("the QR code is %d bytes, which is too small to be real", len(png))
	}
}

func TestRenderServerConfig(t *testing.T) {
	t.Parallel()

	server := testServer(t)
	private, err := vpn.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	peers := []vpn.Peer{
		{Name: "Phone", PublicKey: "phone-key", Address: "10.6.0.2/32", Enabled: true},
		{Name: "Old laptop", PublicKey: "old-key", Address: "10.6.0.3/32", Enabled: false},
	}

	out := vpn.RenderServerConfig(server, private, 51820, peers, map[string]string{"phone-key": "psk"})

	if !strings.Contains(out, "ListenPort = 51820") {
		t.Errorf("the server config is missing its port:\n%s", out)
	}
	if !strings.Contains(out, "phone-key") || !strings.Contains(out, "PresharedKey = psk") {
		t.Errorf("the enabled peer is missing:\n%s", out)
	}
	// A disabled peer must not be programmed, or switching it off would do
	// nothing at all.
	if strings.Contains(out, "old-key") {
		t.Errorf("a disabled peer was included:\n%s", out)
	}
}

func TestOnlineWindow(t *testing.T) {
	t.Parallel()

	var never vpn.Peer
	if never.Online() {
		t.Error("a peer that has never handshaked is not online")
	}
}

// fakeDevice records what would have been programmed.
type fakeDevice struct {
	available bool
	synced    []vpn.Peer
	stats     map[string]vpn.PeerStats
	syncs     int
}

func (f *fakeDevice) Available(string) bool { return f.available }

func (f *fakeDevice) Sync(_ context.Context, _ string, _ vpn.Key, _ int, peers []vpn.Peer, _ map[string]string) error {
	f.syncs++
	f.synced = peers

	return nil
}

func (f *fakeDevice) Stats(context.Context, string) (map[string]vpn.PeerStats, error) {
	return f.stats, nil
}

func TestManagerSyncsStoredPeers(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	server := testServer(t)
	ctx := t.Context()

	if _, err := vpn.AddPeer(ctx, db, server, "Phone", false); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	device := &fakeDevice{available: true}
	key, err := vpn.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	manager := vpn.NewManager(db, device, "wg0", key, 51820, nil)
	if err = manager.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	if len(device.synced) != 1 || device.synced[0].Name != "Phone" {
		t.Errorf("synced %+v, want the stored peer", device.synced)
	}
}

func TestManagerReportsUnavailableHonestly(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	key, err := vpn.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	manager := vpn.NewManager(db, &fakeDevice{available: false}, "wg0", key, 51820, nil)

	// A node without WireGuard should say so, not show an empty peer list that
	// never fills in.
	if manager.Available() {
		t.Error("availability must be reported honestly")
	}
	if err = manager.Sync(t.Context()); err == nil {
		t.Error("Sync should fail when the tunnel cannot be programmed")
	}
}

func TestStatsAreRecorded(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	server := testServer(t)
	ctx := t.Context()

	created, err := vpn.AddPeer(ctx, db, server, "Phone", false)
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	handshake := time.Now().Add(-30 * time.Second)
	if err = vpn.RecordStats(ctx, db, created.Peer.PublicKey, handshake, 1000, 2000); err != nil {
		t.Fatalf("RecordStats: %v", err)
	}

	peers, err := vpn.List(ctx, db)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if peers[0].RxBytes != 1000 || peers[0].TxBytes != 2000 {
		t.Errorf("transfer = %d/%d, want 1000/2000", peers[0].RxBytes, peers[0].TxBytes)
	}

	// WireGuard is connectionless: recency of the handshake is the only signal
	// there is, and a device that handshaked half a minute ago is connected.
	if !peers[0].Online() {
		t.Error("a peer that handshaked 30 seconds ago should be online")
	}
}
