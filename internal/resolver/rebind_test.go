package resolver

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func answer(t *testing.T, name, ip string) *dns.Msg {
	t.Helper()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip),
	})

	return msg
}

// The attack: a name the attacker controls, answered with an address on the
// household's own network, so a browser starts talking to the router while
// believing it is still on the attacker's site.
func TestRebindCaughtForPublicNames(t *testing.T) {
	t.Parallel()

	for _, ip := range []string{"192.168.1.1", "10.0.0.5", "172.16.4.4", "127.0.0.1", "169.254.1.1"} {
		hit, found := checkRebind(answer(t, "evil.example.com", ip), nil)
		if !found {
			t.Errorf("an answer pointing at %s was allowed through", ip)
		}
		if found && hit.Address != ip {
			t.Errorf("hit.Address = %q, want %q", hit.Address, ip)
		}
	}
}

// The constraint that matters more than the protection: a household's own
// devices have names, and they resolve to private addresses. Breaking those
// would be a self-inflicted outage.
func TestLocalNamesAreNeverTouched(t *testing.T) {
	t.Parallel()

	local := []string{
		"nas.local",
		"printer.lan",
		"router.home.arpa",
		"fileserver.internal",
		"1.1.168.192.in-addr.arpa",
		"router",
	}

	for _, name := range local {
		if _, found := checkRebind(answer(t, name, "192.168.1.50"), nil); found {
			t.Errorf("the local name %q was treated as a rebinding attempt", name)
		}
	}
}

// A public name answered with a public address is the ordinary case and must
// pass untouched.
func TestPublicAnswersPassThrough(t *testing.T) {
	t.Parallel()

	for _, ip := range []string{"140.82.121.4", "1.1.1.1", "212.133.164.6"} {
		if _, found := checkRebind(answer(t, "github.com", ip), nil); found {
			t.Errorf("a normal answer of %s was dropped", ip)
		}
	}
}

// This node blocks by answering 0.0.0.0, and a custom blocking address may be
// a real private one. Either would otherwise be caught by its own protection,
// turning every blocked name into a warning.
func TestOwnBlockingAnswersAreNotRebinding(t *testing.T) {
	t.Parallel()

	if _, found := checkRebind(answer(t, "ads.example.com", "0.0.0.0"), nil); found {
		t.Error("the node's own 0.0.0.0 block was reported as a rebinding attempt")
	}

	custom := []netip.Addr{netip.MustParseAddr("192.168.1.2")}
	if _, found := checkRebind(answer(t, "ads.example.com", "192.168.1.2"), custom); found {
		t.Error("a configured block page address was reported as a rebinding attempt")
	}
}
