package clients

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// A device's own name is the one thing on the panel that makes a list of
// addresses into a list of things in the house. Nobody knows which of their
// devices is .79; everybody knows which one is the kitchen tablet.
//
// It is asked of the router, because the router is what handed out the address
// and knows the name the device gave when it asked for one. There is no other
// source: DHCP happens between the device and the router, and this node is not
// in that conversation.

// hostnameTTL is how long a discovered name is trusted.
//
// Long, because these change when someone renames a laptop, and short enough
// that a reused address does not carry the previous device's name for a week.
const hostnameTTL = 6 * time.Hour

// resolveTimeout bounds a single lookup. A router that does not answer PTR at
// all is the common case, and it must cost a fraction of a second once rather
// than a stall on every new device.
const resolveTimeout = 1500 * time.Millisecond

// hostnames discovers what devices call themselves.
type hostnames struct {
	servers []string

	mu    sync.Mutex
	cache map[string]entry
}

type entry struct {
	name string
	at   time.Time
}

func newHostnames(servers []string) *hostnames {
	return &hostnames{servers: servers, cache: map[string]entry{}}
}

// lookup returns the name a device gave the router, or empty.
//
// Empty is a normal answer, not a failure: plenty of routers do not answer
// PTR for their own clients, and plenty of devices never offer a name.
func (h *hostnames) lookup(ctx context.Context, address string) string {
	addr, err := netip.ParseAddr(address)
	if err != nil || !addr.Is4() || !isLocal(addr) {
		return ""
	}

	h.mu.Lock()
	cached, ok := h.cache[address]
	h.mu.Unlock()

	if ok && time.Since(cached.at) < hostnameTTL {
		return cached.name
	}

	name := h.ask(ctx, addr)

	h.mu.Lock()
	// Cached even when empty, so a router that does not answer is asked once
	// rather than on every query from every device that has no name.
	h.cache[address] = entry{name: name, at: time.Now()}
	h.mu.Unlock()

	return name
}

func (h *hostnames) ask(ctx context.Context, addr netip.Addr) string {
	arpa, err := dns.ReverseAddr(addr.String())
	if err != nil {
		return ""
	}

	// The device itself first. Anything running Bonjour or Avahi — Apple
	// hardware, Android, printers, most Linux — answers for its own address,
	// and it answers with the name its owner chose rather than whatever the
	// router filed it under. Measured on a real network before being relied
	// on: the router there answers nothing and the devices answer this.
	if name := h.askMDNS(ctx, arpa); name != "" {
		return name
	}

	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetQuestion(arpa, dns.TypePTR)
	msg.RecursionDesired = true

	client := &dns.Client{Timeout: resolveTimeout}

	for _, server := range h.servers {
		if ctx.Err() != nil {
			return ""
		}

		reply, _, exchangeErr := client.ExchangeContext(ctx, msg, server)
		if exchangeErr != nil || reply == nil || reply.Rcode != dns.RcodeSuccess {
			continue
		}

		for _, rr := range reply.Answer {
			ptr, ok := rr.(*dns.PTR)
			if !ok {
				continue
			}

			if name := tidy(ptr.Ptr); name != "" {
				return name
			}
		}
	}

	return ""
}

// askMDNS asks the network, rather than any one server.
//
// Multicast, so the device that owns the address is the one that replies. A
// short wait: this runs while a device is being catalogued, not while anyone
// is waiting for a page.
func (h *hostnames) askMDNS(ctx context.Context, arpa string) string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()

	msg := new(dns.Msg)
	msg.SetQuestion(arpa, dns.TypePTR)
	// Multicast DNS has no recursion: every responder speaks only for itself.
	msg.RecursionDesired = false

	raw, err := msg.Pack()
	if err != nil {
		return ""
	}

	if _, err = conn.WriteToUDP(raw, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}); err != nil {
		return ""
	}

	deadline := time.Now().Add(mdnsWait)
	if until, ok := ctx.Deadline(); ok && until.Before(deadline) {
		deadline = until
	}
	_ = conn.SetReadDeadline(deadline)

	buf := make([]byte, 4096)
	for {
		n, _, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			return ""
		}

		reply := new(dns.Msg)
		if reply.Unpack(buf[:n]) != nil {
			continue
		}

		for _, rr := range reply.Answer {
			ptr, ok := rr.(*dns.PTR)
			if !ok {
				continue
			}

			if name := tidy(ptr.Ptr); name != "" {
				return name
			}
		}
	}
}

// mdnsWait is how long to listen for a device to speak up.
//
// Multicast answers arrive in tens of milliseconds on a home network; the rest
// is allowance for a device that was asleep.
const mdnsWait = 900 * time.Millisecond

// tidy turns a PTR record into something worth showing.
//
// Routers answer with the DHCP name plus their own domain — "kitchen-tablet.lan"
// or "MacBook-Pro.home". The suffix is the router's, not the device's, and
// repeating it on every row is noise.
func tidy(ptr string) string {
	name := strings.TrimSuffix(ptr, ".")
	if name == "" {
		return ""
	}

	if host, _, found := strings.Cut(name, "."); found && host != "" {
		name = host
	}

	// A router with nothing better to say answers with the address written
	// back at you, which is not a name.
	if strings.Count(name, "-") == 3 && strings.Trim(name, "0123456789-") == "" {
		return ""
	}

	return name
}

// isLocal reports whether an address belongs to this side of the router.
//
// Asking the router about a public address would be a reverse lookup of the
// internet, which is neither useful here nor free.
func isLocal(addr netip.Addr) bool {
	return addr.IsPrivate() || addr.IsLinkLocalUnicast()
}
