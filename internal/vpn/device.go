package vpn

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/MmTKya/DNS/internal/store"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Device programs the kernel's WireGuard interface.
//
// It is an interface so that peer management, address allocation and
// configuration rendering can be developed and tested without a kernel module,
// a privileged socket or root — which is most of the work, and all of the part
// that is easy to get wrong.
type Device interface {
	// Available reports whether the named interface exists and can be
	// programmed.  Opening the control socket is not enough: it succeeds on a
	// machine with no WireGuard at all, which would have the panel showing a
	// peer list that can never connect.
	Available(name string) bool

	// Sync makes the interface match the given peers exactly.
	Sync(ctx context.Context, name string, privateKey Key, port int, peers []Peer, preshared map[string]string) error

	// Stats reports what the kernel knows about each peer.
	Stats(ctx context.Context, name string) (map[string]PeerStats, error)
}

// PeerStats is the kernel's view of a peer.
type PeerStats struct {
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// KernelDevice programs a real interface through netlink.
type KernelDevice struct{}

// Available implements Device.
//
// The interface has to already exist: creating it is the job of wg-quick or
// systemd-networkd, and a node that cannot see it will never carry a peer no
// matter how many are configured.
func (KernelDevice) Available(name string) bool {
	client, err := wgctrl.New()
	if err != nil {
		return false
	}
	defer func() { _ = client.Close() }()

	_, err = client.Device(name)

	return err == nil
}

// Sync implements Device.
//
// ReplacePeers is used rather than incremental changes: reconciling to a
// desired state cannot drift, while adding and removing peers one at a time
// eventually leaves a device connected that the panel says was revoked.
func (KernelDevice) Sync(
	_ context.Context,
	name string,
	privateKey Key,
	port int,
	peers []Peer,
	preshared map[string]string,
) error {
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("opening the wireguard control socket: %w", err)
	}
	defer func() { _ = client.Close() }()

	key, err := wgtypes.NewKey(privateKey[:])
	if err != nil {
		return fmt.Errorf("converting the private key: %w", err)
	}

	configured := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, peer := range peers {
		if !peer.Enabled {
			// A disabled peer is simply absent from the desired state, which
			// is what makes switching it off take effect immediately.
			continue
		}

		publicKey, keyErr := wgtypes.ParseKey(peer.PublicKey)
		if keyErr != nil {
			return fmt.Errorf("parsing the public key of %q: %w", peer.Name, keyErr)
		}

		_, allowed, netErr := net.ParseCIDR(peer.Address)
		if netErr != nil {
			return fmt.Errorf("parsing the address of %q: %w", peer.Name, netErr)
		}

		config := wgtypes.PeerConfig{
			PublicKey:         publicKey,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{*allowed},
		}

		if raw, ok := preshared[peer.PublicKey]; ok && raw != "" {
			psk, pskErr := wgtypes.ParseKey(raw)
			if pskErr != nil {
				return fmt.Errorf("parsing the preshared key of %q: %w", peer.Name, pskErr)
			}
			config.PresharedKey = &psk
		}

		configured = append(configured, config)
	}

	if err = client.ConfigureDevice(name, wgtypes.Config{
		PrivateKey:   &key,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers:        configured,
	}); err != nil {
		return fmt.Errorf("configuring %s: %w", name, err)
	}

	return nil
}

// Stats implements Device.
func (KernelDevice) Stats(_ context.Context, name string) (stats map[string]PeerStats, err error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("opening the wireguard control socket: %w", err)
	}
	defer func() { _ = client.Close() }()

	device, err := client.Device(name)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}

	stats = make(map[string]PeerStats, len(device.Peers))
	for _, peer := range device.Peers {
		stats[peer.PublicKey.String()] = PeerStats{
			LastHandshake: peer.LastHandshakeTime,
			RxBytes:       peer.ReceiveBytes,
			TxBytes:       peer.TransmitBytes,
		}
	}

	return stats, nil
}

// Manager keeps the interface in step with the stored peers.
type Manager struct {
	db     *store.DB
	device Device
	logger *slog.Logger

	name       string
	privateKey Key
	port       int
}

// NewManager creates a manager for the named interface.
func NewManager(db *store.DB, device Device, name string, privateKey Key, port int, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	if device == nil {
		device = KernelDevice{}
	}

	return &Manager{
		db:         db,
		device:     device,
		logger:     logger.With("component", "vpn"),
		name:       name,
		privateKey: privateKey,
		port:       port,
	}
}

// Available reports whether the tunnel can be programmed here.
func (m *Manager) Available() bool { return m.device.Available(m.name) }

// Sync pushes the stored peers onto the interface.
func (m *Manager) Sync(ctx context.Context) error {
	if !m.device.Available(m.name) {
		return fmt.Errorf("the wireguard interface %s does not exist; bring it up with wg-quick or systemd-networkd first", m.name)
	}

	peers, err := List(ctx, m.db)
	if err != nil {
		return err
	}

	preshared, err := PresharedKeys(ctx, m.db)
	if err != nil {
		return err
	}

	return m.device.Sync(ctx, m.name, m.privateKey, m.port, peers, preshared)
}

// Run keeps the interface and the recorded statistics up to date.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	if !m.device.Available(m.name) {
		// Nothing to do on a node without WireGuard. The panel says so rather
		// than showing an empty peer list that never fills in.
		<-ctx.Done()

		return
	}

	if interval <= 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := m.refreshStats(ctx); err != nil && ctx.Err() == nil {
			m.logger.DebugContext(ctx, "reading tunnel statistics", "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *Manager) refreshStats(ctx context.Context) error {
	stats, err := m.device.Stats(ctx, m.name)
	if err != nil {
		return err
	}

	for publicKey, s := range stats {
		if err = RecordStats(ctx, m.db, publicKey, s.LastHandshake, s.RxBytes, s.TxBytes); err != nil {
			return err
		}
	}

	return nil
}
