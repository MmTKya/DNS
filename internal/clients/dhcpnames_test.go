package clients

import (
	"strings"
	"testing"
)

// build makes a DHCP request carrying a hardware address and, optionally, the
// name the device calls itself.
func build(op byte, mac []byte, hostname string) []byte {
	p := make([]byte, 236)
	p[0] = op
	p[1] = 1
	p[2] = byte(len(mac))
	copy(p[28:], mac)

	p = append(p, dhcpMagic[:]...)

	// Message type first, as a real client sends it, so the parser has to
	// walk past an option rather than finding its one at the front.
	p = append(p, 53, 1, 3)

	if hostname != "" {
		p = append(p, optionHostname, byte(len(hostname)))
		p = append(p, hostname...)
	}

	return append(p, 255)
}

// The whole point: a phone with a randomised hardware address has no
// manufacturer to look up and may answer nothing on multicast, but it still
// says what it is called when it asks for an address.
func TestHostnameIsReadFromARequest(t *testing.T) {
	t.Parallel()

	packet := build(1, []byte{0x9e, 0xae, 0xaf, 0xac, 0x46, 0xab}, "mehmet-laptop")

	mac, name, ok := parseDHCP(packet)
	if !ok {
		t.Fatal("a valid request was rejected")
	}
	if mac != "9e:ae:af:ac:46:ab" {
		t.Errorf("mac = %q, want the client's", mac)
	}
	if name != "mehmet-laptop" {
		t.Errorf("name = %q, want mehmet-laptop", name)
	}
}

// A server's reply does not name the device, and reading one as though it did
// would file the router's idea of a name against the wrong machine.
func TestServerRepliesAreIgnored(t *testing.T) {
	t.Parallel()

	if _, _, ok := parseDHCP(build(2, []byte{1, 2, 3, 4, 5, 6}, "router-says-this")); ok {
		t.Error("a server reply was parsed as a client request")
	}
}

// Plenty of devices never send a name. That is a valid packet with nothing to
// contribute, not a parse failure.
func TestARequestWithoutANameIsStillValid(t *testing.T) {
	t.Parallel()

	mac, name, ok := parseDHCP(build(1, []byte{1, 2, 3, 4, 5, 6}, ""))
	if !ok {
		t.Fatal("a request with no hostname was rejected outright")
	}
	if mac == "" {
		t.Error("the hardware address was not read")
	}
	if name != "" {
		t.Errorf("name = %q, want empty", name)
	}
}

// This string is put on a screen, and it arrives from anything on the network
// that can send a broadcast.
func TestNamesAreCleanedBeforeTheyAreShown(t *testing.T) {
	t.Parallel()

	if got := tidyDHCPName("kitchen-tablet.lan"); got != "kitchen-tablet" {
		t.Errorf("tidyDHCPName() = %q, want the first label", got)
	}
	if got := tidyDHCPName("laptop\x00\x00"); got != "laptop" {
		t.Errorf("trailing padding survived: %q", got)
	}
	if got := tidyDHCPName("bad\x07name"); got != "" {
		t.Errorf("an unprintable character was kept: %q", got)
	}
	if got := tidyDHCPName(strings.Repeat("a", 200)); len(got) > 63 {
		t.Errorf("an over-long name was not bounded: %d characters", len(got))
	}
}

// Malformed and truncated packets arrive on any network; none of them should
// panic a resolver.
func TestMalformedPacketsAreSurvived(t *testing.T) {
	t.Parallel()

	cases := [][]byte{
		nil,
		{},
		make([]byte, 10),
		make([]byte, 236),
		append(make([]byte, 236), 1, 2, 3),
	}

	for i, packet := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			_, _, _ = parseDHCP(packet)
		}()
	}
}
