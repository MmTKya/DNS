package resolver

import (
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// localSuffixes are names whose answers are none of this code's business.
//
// A private address is the expected answer for all of these, and dropping it
// would break the ordinary case of a router, a NAS or a printer having a name.
var localSuffixes = []string{
	".local.",
	".lan.",
	".home.",
	".home.arpa.",
	".internal.",
	".localdomain.",
	".in-addr.arpa.",
	".ip6.arpa.",
}

// isLocalName reports whether a name belongs to the household rather than the
// internet.
//
// Single-label names count: "nas" or "router" typed into a browser is a local
// lookup by definition, and a public name cannot be a single label.
func isLocalName(name string) bool {
	name = strings.ToLower(dns.Fqdn(name))

	if name == "." {
		return true
	}
	if strings.Count(name, ".") == 1 {
		return true
	}

	for _, suffix := range localSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}

	return false
}

// isInternalAddr reports whether an address belongs to this side of the
// router.
func isInternalAddr(addr netip.Addr) bool {
	return addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsUnspecified()
}

// rebindHit describes an answer that pointed inside the network.
type rebindHit struct {
	Name    string
	Address string
}

// checkRebind reports whether a response to a public name carries an address
// inside the household's own network.
//
// This is the DNS half of a rebinding attack: a page loaded from the internet
// asks for a name its author controls, the answer points at 192.168.1.1, and
// the browser — which believes it is still talking to the same origin — starts
// making requests to the router. A resolver is the only place this can be
// caught, because by the time the browser acts, everything looks legitimate.
//
// Deliberately narrow. Local names are exempt entirely, and a blocking answer
// this node produced itself uses 0.0.0.0, which is unspecified and would
// otherwise be caught by its own protection.
func checkRebind(res *dns.Msg, blockingAddrs []netip.Addr) (hit rebindHit, found bool) {
	if res == nil || len(res.Question) == 0 {
		return rebindHit{}, false
	}

	name := res.Question[0].Name
	if isLocalName(name) {
		return rebindHit{}, false
	}

	for _, rr := range res.Answer {
		var addr netip.Addr

		switch record := rr.(type) {
		case *dns.A:
			addr, _ = netip.AddrFromSlice(record.A.To4())
		case *dns.AAAA:
			addr, _ = netip.AddrFromSlice(record.AAAA)
		default:
			continue
		}

		if !addr.IsValid() || !isInternalAddr(addr) {
			continue
		}

		// The node's own blocking answer is an internal address on purpose.
		if isBlockingAddr(addr, blockingAddrs) {
			continue
		}

		return rebindHit{Name: strings.TrimSuffix(name, "."), Address: addr.String()}, true
	}

	return rebindHit{}, false
}

func isBlockingAddr(addr netip.Addr, blocking []netip.Addr) bool {
	if addr.IsUnspecified() {
		return true
	}

	for _, b := range blocking {
		if b.IsValid() && b == addr {
			return true
		}
	}

	return false
}
