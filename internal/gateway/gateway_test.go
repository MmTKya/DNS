package gateway

import "testing"

// The requirement that decides everything: a gateway needs a port facing the
// modem and one facing the house. Wifi does not count — using it as one side
// puts every device's traffic over the air, which is slower and less reliable
// than the cable it replaces.
func TestTwoPortsRequiresTwoWiredOnes(t *testing.T) {
	t.Parallel()

	oneWired := []Interface{
		{Name: "eth0", Kind: "wired"},
		{Name: "wlan0", Kind: "wireless"},
		{Name: "docker0", Kind: "virtual"},
		{Name: "wg0", Kind: "tunnel"},
	}

	c := checkTwoPorts(oneWired)
	if c.Passed {
		t.Error("one wired port and a wifi card was accepted as two ports")
	}
	if !c.Blocking {
		t.Error("a missing network port must be marked blocking: no setting adds one")
	}
	if c.Remedy == "" {
		t.Error("the check did not say what to do about it")
	}

	twoWired := append(oneWired, Interface{Name: "eth1", Kind: "wired"})
	if !checkTwoPorts(twoWired).Passed {
		t.Error("two wired ports were not accepted")
	}
}

// The names a Raspberry Pi and a USB adapter actually use.
func TestKindOfRecognisesRealNames(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"eth0":         "wired",
		"eth1":         "wired",
		"enx00e04c":    "wired",
		"wlan0":        "wireless",
		"wlp2s0":       "wireless",
		"wg0":          "tunnel",
		"docker0":      "virtual",
		"br-0a1e7f5dc": "virtual",
	}

	for name, want := range cases {
		if got := kindOf(name); got != want {
			t.Errorf("kindOf(%q) = %q, want %q", name, got, want)
		}
	}
}

// Every failed check has to carry its next step, or the screen is a list of
// complaints.
func TestFailedChecksCarryARemedy(t *testing.T) {
	t.Parallel()

	r := Inspect(t.Context())

	if len(r.Checks) == 0 {
		t.Fatal("Inspect() returned no checks")
	}
	for _, c := range r.Checks {
		if !c.Passed && c.Remedy == "" {
			t.Errorf("%q failed without saying what to do", c.Name)
		}
		if c.Detail == "" {
			t.Errorf("%q did not say what it found on this machine", c.Name)
		}
	}
}
