package clients

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// interfaces writes a fake /sys/class/net so a cable can be pulled in a test.
func interfaces(t *testing.T, state map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for name, carrier := range state {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if carrier == "" {
			// An interface that is administratively down refuses the read.
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "carrier"), []byte(carrier+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

func watcher(t *testing.T, root string) (*linkWatcher, *[]LinkEvent) {
	t.Helper()

	var seen []LinkEvent
	w := newLinkWatcher(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(e LinkEvent) { seen = append(seen, e) },
	)
	w.root = root

	return w, &seen
}

func TestAnInterruptionIsReportedWithHowLongItLasted(t *testing.T) {
	// The case this was written for: the cable dropped for twenty-five
	// seconds, the whole house lost DNS, and answering "what happened" took a
	// shell session and a journal.
	root := interfaces(t, map[string]string{"eth0": "1"})
	w, seen := watcher(t, root)

	start := time.Now()
	w.poll(start)

	// The cable comes out.
	if err := os.WriteFile(filepath.Join(root, "eth0", "carrier"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.poll(start.Add(1 * time.Second))

	// Nothing is reported while it is still down: the duration is the useful
	// part and it is not known yet.
	if len(*seen) != 0 {
		t.Fatalf("reported %d events during the outage, want none", len(*seen))
	}

	// And back.
	if err := os.WriteFile(filepath.Join(root, "eth0", "carrier"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.poll(start.Add(26 * time.Second))

	if len(*seen) != 1 {
		t.Fatalf("reported %d events, want 1", len(*seen))
	}

	event := (*seen)[0]
	if event.Interface != "eth0" {
		t.Fatalf("interface = %q", event.Interface)
	}
	if event.Duration != 25*time.Second {
		t.Fatalf("duration = %s, want 25s", event.Duration)
	}
}

func TestABriefFlapIsNotAnOutage(t *testing.T) {
	// Interfaces bounce on startup and during an ordinary address renewal.
	// Reporting those would bury the real ones.
	root := interfaces(t, map[string]string{"eth0": "1"})
	w, seen := watcher(t, root)

	start := time.Now()
	w.poll(start)

	_ = os.WriteFile(filepath.Join(root, "eth0", "carrier"), []byte("0\n"), 0o644)
	w.poll(start.Add(500 * time.Millisecond))

	_ = os.WriteFile(filepath.Join(root, "eth0", "carrier"), []byte("1\n"), 0o644)
	w.poll(start.Add(1500 * time.Millisecond))

	if len(*seen) != 0 {
		t.Fatalf("reported %v, want nothing for a one-second flap", *seen)
	}
}

func TestEachInterfaceIsTrackedSeparately(t *testing.T) {
	// The node has a cable and a radio. One going down while the other holds
	// is the case where the house stays online, and conflating them would
	// report an outage that nobody experienced.
	root := interfaces(t, map[string]string{"eth0": "1", "wlan0": "1"})
	w, seen := watcher(t, root)

	start := time.Now()
	w.poll(start)

	_ = os.WriteFile(filepath.Join(root, "eth0", "carrier"), []byte("0\n"), 0o644)
	w.poll(start.Add(time.Second))
	w.poll(start.Add(10 * time.Second))

	_ = os.WriteFile(filepath.Join(root, "eth0", "carrier"), []byte("1\n"), 0o644)
	w.poll(start.Add(20 * time.Second))

	if len(*seen) != 1 || (*seen)[0].Interface != "eth0" {
		t.Fatalf("got %v, want one event for eth0", *seen)
	}
}

func TestInventedInterfacesAreIgnored(t *testing.T) {
	// A container bridge or a tunnel going up and down is not the household
	// losing its network, and there can be dozens of them.
	root := interfaces(t, map[string]string{
		"eth0": "1", "docker0": "1", "veth1234": "1", "wg0": "1", "br-abc": "1", "lo": "1",
	})
	w, _ := watcher(t, root)

	states := w.states()

	if _, found := states["eth0"]; !found {
		t.Fatal("the real port was skipped")
	}
	if len(states) != 1 {
		t.Fatalf("watching %v, want only the real port", states)
	}
}

func TestAnInterfaceThatIsSwitchedOffIsNotAnOutage(t *testing.T) {
	// Reading carrier on an administratively down interface fails. Nobody
	// expects it to carry anything, so it is not an interruption.
	root := interfaces(t, map[string]string{"eth0": "1", "wlan0": ""})
	w, seen := watcher(t, root)

	start := time.Now()
	w.poll(start)
	w.poll(start.Add(time.Minute))

	if len(*seen) != 0 {
		t.Fatalf("reported %v for an interface nobody switched on", *seen)
	}
}
