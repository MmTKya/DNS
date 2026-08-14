package clients

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
)

// Devices announce their own name when they ask for an address.
//
// This is the source that works when the others do not. A modern phone or
// laptop randomises its hardware address, so there is no manufacturer to look
// up; many of them answer nothing on multicast; and plenty of routers, this
// household's included, will not say what they handed an address to. But every
// device on the network asks for an address, and most put their name in the
// request — option 12, in the clear, broadcast to the whole subnet.
//
// Listening costs nothing and changes nothing: the node does not answer, does
// not hand out addresses, and the router carries on as the only DHCP server.
// It is the one place a device volunteers what it calls itself.

// dhcpPort is the server port. Requests are broadcast to it, so a second
// listener sees them without being the server.
const dhcpPort = 67

// optionHostname is DHCP option 12.
const optionHostname = 12

// dhcpMagic marks the start of the options section.
var dhcpMagic = [4]byte{99, 130, 83, 99}

// dhcpListener watches for devices naming themselves.
type dhcpListener struct {
	logger *slog.Logger

	mu    sync.RWMutex
	names map[string]string // hardware address -> name
}

func newDHCPListener(logger *slog.Logger) *dhcpListener {
	return &dhcpListener{
		logger: logger.With("component", "dhcp-names"),
		names:  map[string]string{},
	}
}

// nameFor returns what a device called itself, by hardware address.
func (d *dhcpListener) nameFor(mac string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.names[strings.ToLower(mac)]
}

// Run listens until the context is cancelled.
//
// A failure to bind is not fatal and barely worth a warning: something else
// holding port 67 means the machine is already running a DHCP server, and
// device names are the least of what that changes.
func (d *dhcpListener) Run(ctx context.Context) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: dhcpPort})
	if err != nil {
		d.logger.InfoContext(ctx, "not listening for device names; something else holds the DHCP port",
			"err", err)

		return
	}

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	d.logger.InfoContext(ctx, "listening for devices naming themselves")

	buf := make([]byte, 1500)
	for {
		n, _, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			if ctx.Err() != nil {
				return
			}

			continue
		}

		mac, name, ok := parseDHCP(buf[:n])
		if !ok || name == "" {
			continue
		}

		d.mu.Lock()
		changed := d.names[mac] != name
		d.names[mac] = name
		d.mu.Unlock()

		if changed {
			d.logger.InfoContext(ctx, "a device named itself", "mac", mac, "name", name)
		}
	}
}

// parseDHCP pulls the hardware address and the hostname out of a request.
//
// Deliberately hand-rolled and narrow: this reads two fields from a broadcast
// packet, and a full DHCP implementation would be a dependency that can also
// hand out addresses — which is exactly what this must never do.
func parseDHCP(packet []byte) (mac, name string, ok bool) {
	// Fixed header is 236 bytes, then the magic cookie, then options.
	const headerLen = 236
	if len(packet) < headerLen+len(dhcpMagic) {
		return "", "", false
	}

	// op 1 is a request from a client; op 2 is the server replying, and a
	// server does not name the device.
	if packet[0] != 1 {
		return "", "", false
	}

	// hlen at offset 2, hardware address from offset 28.
	hlen := int(packet[2])
	if hlen == 0 || hlen > 16 || headerLen < 28+hlen {
		return "", "", false
	}

	hw := make([]string, 0, hlen)
	for _, b := range packet[28 : 28+hlen] {
		hw = append(hw, hexByte(b))
	}
	mac = strings.Join(hw, ":")

	rest := packet[headerLen:]
	if rest[0] != dhcpMagic[0] || rest[1] != dhcpMagic[1] || rest[2] != dhcpMagic[2] || rest[3] != dhcpMagic[3] {
		return "", "", false
	}
	rest = rest[4:]

	for len(rest) >= 2 {
		option := rest[0]

		// 0 is padding, 255 ends the options.
		if option == 0 {
			rest = rest[1:]

			continue
		}
		if option == 255 {
			break
		}

		length := int(rest[1])
		if len(rest) < 2+length {
			break
		}

		if option == optionHostname {
			name = tidyDHCPName(string(rest[2 : 2+length]))

			return mac, name, true
		}

		rest = rest[2+length:]
	}

	// A request with no name is still a valid packet; it just has nothing to
	// contribute.
	return mac, "", true
}

func hexByte(b byte) string {
	const digits = "0123456789abcdef"

	return string([]byte{digits[b>>4], digits[b&0x0f]})
}

// tidyDHCPName keeps what a person would recognise and drops the rest.
func tidyDHCPName(raw string) string {
	name := strings.TrimSpace(strings.Trim(raw, "\x00"))

	// Some devices send a fully qualified name; the domain is the router's.
	if host, _, found := strings.Cut(name, "."); found && host != "" {
		name = host
	}

	// Anything unprintable is a malformed packet or something trying to be
	// clever, and this string ends up on a screen.
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}

	if len(name) > 63 {
		name = name[:63]
	}

	return name
}
