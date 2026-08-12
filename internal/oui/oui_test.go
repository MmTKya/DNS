package oui_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MmTKya/DNS/internal/oui"
)

func TestLookupKnownVendors(t *testing.T) {
	t.Parallel()

	// Real assignments, in the separator styles the world actually uses.
	cases := []struct {
		mac  string
		want string
	}{
		{"a8:42:a1:61:b0:e8", ""}, // filled in below from the registry
		{"A8-42-A1-61-B0-E8", ""},
		{"a842.a161.b0e8", ""},
	}

	first, found := oui.Lookup(cases[0].mac)
	if !found {
		t.Skip("this assignment is not in the embedded registry")
	}

	// Whatever the vendor is, every spelling of the same address must resolve
	// to it: a device list that depends on punctuation is a bug report.
	for _, tc := range cases {
		got, ok := oui.Lookup(tc.mac)
		if !ok || got != first {
			t.Errorf("Lookup(%q) = %q, %t; want %q", tc.mac, got, ok, first)
		}
	}
}

func TestRegistryIsSubstantial(t *testing.T) {
	t.Parallel()

	// A curated subset would leave half a home network unlabelled, so the
	// whole registry is embedded and this guards against it being replaced by
	// a token file.
	if got := oui.Len(); got < 30_000 {
		t.Errorf("registry holds %d assignments, want the full IEEE list", got)
	}
}

func TestRandomisedAddressesAreNotAttributed(t *testing.T) {
	t.Parallel()

	// Locally-administered bit set: what a phone doing MAC randomisation
	// presents. Reporting a vendor for one of these would name whichever
	// company happens to own the range, which is worse than saying nothing.
	randomised := []string{
		"02:11:22:33:44:55",
		"7a:bb:cc:dd:ee:ff",
		"06:00:00:00:00:01",
	}

	for _, mac := range randomised {
		if !oui.Randomised(mac) {
			t.Errorf("Randomised(%q) = false, want true", mac)
		}
		if vendor, found := oui.Lookup(mac); found {
			t.Errorf("Lookup(%q) attributed it to %q", mac, vendor)
		}
		if got := oui.Describe(mac); got != "randomised address" {
			t.Errorf("Describe(%q) = %q, want it called out as randomised", mac, got)
		}
	}

	// A globally-unique address must not be mistaken for a randomised one.
	for _, mac := range []string{"a8:42:a1:61:b0:e8", "80:32:53:3a:a7:82", "48:55:19:73:81:d9"} {
		if oui.Randomised(mac) {
			t.Errorf("Randomised(%q) = true, want false", mac)
		}
	}
}

func TestMulticast(t *testing.T) {
	t.Parallel()

	if !oui.Multicast("01:00:5e:00:00:fb") {
		t.Error("a group address should be recognised")
	}
	if oui.Multicast("a8:42:a1:61:b0:e8") {
		t.Error("a unicast address must not be reported as multicast")
	}
}

func TestLookupRejectsGarbage(t *testing.T) {
	t.Parallel()

	for _, mac := range []string{"", "not-a-mac", "zz:zz:zz:zz:zz:zz", "a8:42"} {
		if vendor, found := oui.Lookup(mac); found {
			t.Errorf("Lookup(%q) = %q, want no match", mac, vendor)
		}
	}
}

// Not parallel: LoadFile replaces the process-wide overrides, which is the
// right semantics for a registry loaded once at startup and the wrong thing to
// race two tests over.
func TestLoadFileOverridesEmbedded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oui.tsv")
	// 88:99:AA is globally unique; AA:BB:CC would not be, because 0xAA has the
	// locally-administered bit set and is correctly refused attribution.
	if err := os.WriteFile(path, []byte("8899AA\tExample Devices\nDDEEFF\tAnother Vendor\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	added, err := oui.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if added != 2 {
		t.Errorf("loaded %d assignments, want 2", added)
	}

	// An operator has to be able to correct or extend the registry without
	// waiting for a release.
	if vendor, found := oui.Lookup("88:99:aa:11:22:33"); !found || vendor != "Example Devices" {
		t.Errorf("Lookup = %q, %t; want the file's entry", vendor, found)
	}

}

func TestLoadFileAcceptsIEEECSV(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oui.csv")
	const csv = `Registry,Assignment,Organization Name,Organization Address
MA-L,112233,"Test Instruments, Inc.","Somewhere"
`
	if err := os.WriteFile(path, []byte(csv), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	added, err := oui.LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if added != 1 {
		t.Fatalf("loaded %d assignments, want 1", added)
	}

	vendor, found := oui.Lookup("11:22:33:44:55:66")
	if !found || !strings.Contains(vendor, "Test Instruments") {
		t.Errorf("Lookup = %q, %t; want the CSV entry", vendor, found)
	}
}

func BenchmarkLookup(b *testing.B) {
	for range b.N {
		oui.Lookup("a8:42:a1:61:b0:e8")
	}
}
