// Package gateway reports whether this machine could route the household's
// traffic, and what is missing.
//
// Gateway mode is the difference between seeing names and seeing packets: only
// a node on the path can count what a device downloaded, or actually cut it
// off rather than declining to look up an address for it. It is also the
// difference between a failure that stops DNS and one that stops the internet,
// which is why nothing here switches it on.
//
// What this does is check the machine in front of it and say plainly what is
// not ready. The alternative — a settings screen that accepts a configuration
// the machine cannot run — is how someone ends up with a household offline and
// no idea which of six requirements they missed.
package gateway

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Check is one requirement, and what to do when it is not met.
type Check struct {
	// Name is what is being checked, in the words of the person reading it.
	Name string `json:"name"`

	// Detail is what was actually found on this machine.
	Detail string `json:"detail"`

	// Remedy is the next step when Passed is false. Empty when it passed.
	Remedy string `json:"remedy,omitempty"`

	// Passed reports whether this requirement is already met.
	Passed bool `json:"passed"`

	// Blocking marks a requirement that cannot be worked around. A missing
	// second network port is not a setting; it is a trip to a shop.
	Blocking bool `json:"blocking"`
}

// Readiness is the whole picture.
type Readiness struct {
	Interfaces []Interface `json:"interfaces"`
	Checks     []Check     `json:"checks"`

	// Ready is true only when every check passed. The panel refuses to offer
	// the switch until then, because a half-met requirement list is how the
	// internet goes down for a reason nobody can see.
	Ready bool `json:"ready"`
}

// Interface is a network port the node could use.
type Interface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses,omitempty"`
	Kind      string   `json:"kind"`
	Up        bool     `json:"up"`
}

// Inspect examines the machine.
func Inspect(ctx context.Context) Readiness {
	r := Readiness{Interfaces: interfaces()}

	r.Checks = append(r.Checks,
		checkTwoPorts(r.Interfaces),
		checkForwarding(),
		checkNftables(),
		checkPrivileges(),
		checkDHCP(ctx),
	)

	r.Ready = true
	for _, c := range r.Checks {
		if !c.Passed {
			r.Ready = false

			break
		}
	}

	return r
}

func interfaces() []Interface {
	list, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var out []Interface
	for _, iface := range list {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		item := Interface{
			Name: iface.Name,
			Up:   iface.Flags&net.FlagUp != 0,
			Kind: kindOf(iface.Name),
		}

		if addrs, addrErr := iface.Addrs(); addrErr == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					item.Addresses = append(item.Addresses, ipnet.String())
				}
			}
		}

		out = append(out, item)
	}

	return out
}

// kindOf guesses what a port is from its name.
//
// Wireless is called out because using it as one side of a gateway routes the
// whole household over wifi, which is both slower and less reliable than the
// cable it would be replacing.
func kindOf(name string) string {
	switch {
	case strings.HasPrefix(name, "wl"), strings.HasPrefix(name, "wlan"):
		return "wireless"
	case strings.HasPrefix(name, "wg"), strings.HasPrefix(name, "tun"), strings.HasPrefix(name, "tap"):
		return "tunnel"
	case strings.HasPrefix(name, "docker"), strings.HasPrefix(name, "br-"), strings.HasPrefix(name, "veth"):
		return "virtual"
	default:
		return "wired"
	}
}

// checkTwoPorts is the requirement that cannot be configured around.
func checkTwoPorts(list []Interface) Check {
	var wired []string
	for _, i := range list {
		if i.Kind == "wired" {
			wired = append(wired, i.Name)
		}
	}

	c := Check{
		Name:     "Two wired network ports",
		Detail:   fmt.Sprintf("found %d: %s", len(wired), strings.Join(wired, ", ")),
		Blocking: true,
	}
	if len(wired) >= 2 {
		c.Passed = true

		return c
	}

	c.Remedy = "A gateway needs one port facing the modem and one facing the house. " +
		"Add a USB 3.0 gigabit adapter — using wifi as the second side would put every " +
		"device's traffic over the air."

	return c
}

func checkForwarding() Check {
	c := Check{Name: "Packet forwarding"}

	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		c.Detail = "could not be read"
		c.Remedy = "Check that /proc is mounted."

		return c
	}

	if strings.TrimSpace(string(raw)) == "1" {
		c.Detail = "on"
		c.Passed = true

		return c
	}

	c.Detail = "off"
	c.Remedy = "Enable it: echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-seddns-gateway.conf " +
		"&& sudo sysctl -p /etc/sysctl.d/99-seddns-gateway.conf"

	return c
}

func checkNftables() Check {
	c := Check{Name: "Firewall tooling"}

	if _, err := exec.LookPath("nft"); err != nil {
		c.Detail = "nft not installed"
		c.Remedy = "Install it: sudo apt install nftables"

		return c
	}

	c.Detail = "nft available"
	c.Passed = true

	return c
}

// checkPrivileges is the one people are most surprised by.
//
// The node runs unprivileged on purpose — it is the process exposed to the
// network — and an unprivileged process cannot install firewall rules or hand
// out addresses. Gateway mode is a deliberate trade of that hardening for
// capability, not an oversight to be patched around quietly.
func checkPrivileges() Check {
	c := Check{Name: "Permission to change the network"}

	if os.Geteuid() == 0 {
		c.Detail = "running as root"
		c.Passed = true

		return c
	}

	if caps, err := os.ReadFile("/proc/self/status"); err == nil {
		for line := range strings.Lines(string(caps)) {
			if !strings.HasPrefix(line, "CapEff:") {
				continue
			}

			// CAP_NET_ADMIN is bit 12.
			var eff uint64
			if _, scanErr := fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), "%x", &eff); scanErr == nil {
				if eff&(1<<12) != 0 {
					c.Detail = "has CAP_NET_ADMIN"
					c.Passed = true

					return c
				}
			}
		}
	}

	c.Detail = "unprivileged, and deliberately so"
	c.Remedy = "Gateway mode needs CAP_NET_ADMIN in the service unit. That is a real reduction " +
		"in how contained this process is: it is the part exposed to the network, and it " +
		"would gain the ability to reconfigure the network it is exposed to."

	return c
}

// checkDHCP looks for something to hand out addresses.
//
// Whatever is the gateway has to answer DHCP, and this node does not: it holds
// port 53 and nothing else. dnsmasq run with port=0 does addresses only and
// stays out of the way.
func checkDHCP(ctx context.Context) Check {
	c := Check{Name: "Address server"}

	if _, err := exec.LookPath("dnsmasq"); err != nil {
		c.Detail = "dnsmasq not installed"
		c.Remedy = "Install it: sudo apt install dnsmasq. It must be configured with port=0 so it " +
			"hands out addresses without answering DNS, which this node already does."

		return c
	}

	// Installed and also answering DNS would fight for port 53.
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", "dnsmasq").Output()
	state := strings.TrimSpace(string(out))
	if err == nil && state == "active" {
		c.Detail = "dnsmasq installed and running"
	} else {
		c.Detail = "dnsmasq installed, not running"
	}
	c.Passed = true

	return c
}

// ScanRoutes returns the current default route, so the panel can say which
// port faces the modem today.
func ScanRoutes() (iface, gateway string) {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return "", ""
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}

		var b [4]byte
		if _, scanErr := fmt.Sscanf(fields[2], "%02x%02x%02x%02x", &b[3], &b[2], &b[1], &b[0]); scanErr != nil {
			continue
		}

		return fields[0], net.IPv4(b[0], b[1], b[2], b[3]).String()
	}

	return "", ""
}
