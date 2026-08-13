package clients

import "testing"

// Routers answer with their own domain attached, and repeating ".lan" on every
// row of the panel is noise. What people recognise is the first label.
func TestTidyKeepsTheNameAndDropsTheRouterDomain(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"kitchen-tablet.lan.": "kitchen-tablet",
		"MacBook-Pro.home.":   "MacBook-Pro",
		"mehmet-laptop.":      "mehmet-laptop",
		"nas.home.arpa.":      "nas",
		"":                    "",
		".":                   "",
	}

	for ptr, want := range cases {
		if got := tidy(ptr); got != want {
			t.Errorf("tidy(%q) = %q, want %q", ptr, got, want)
		}
	}
}

// Some routers answer a PTR with the address written back as a name, which
// looks like a hostname and tells you nothing you did not already have.
func TestTidyRejectsAnAddressPretendingToBeAName(t *testing.T) {
	t.Parallel()

	for _, ptr := range []string{"192-168-68-79.lan.", "10-0-0-5."} {
		if got := tidy(ptr); got != "" {
			t.Errorf("tidy(%q) = %q, want it discarded", ptr, got)
		}
	}
}

// Asking the router about a public address is a reverse lookup of the
// internet: not useful here, and not free.
func TestOnlyLocalAddressesAreLookedUp(t *testing.T) {
	t.Parallel()

	h := newHostnames([]string{"192.0.2.1:53"})

	if got := h.lookup(t.Context(), "140.82.121.4"); got != "" {
		t.Errorf("a public address was looked up and returned %q", got)
	}
	if got := h.lookup(t.Context(), "not-an-address"); got != "" {
		t.Errorf("a malformed address returned %q", got)
	}
}
