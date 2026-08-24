package panelport

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeListener stands in for a bound port.
type fakeListener struct {
	mu     sync.Mutex
	closed bool
}

func (f *fakeListener) Accept() (net.Conn, error) { select {} }
func (f *fakeListener) Addr() net.Addr            { return nil }
func (f *fakeListener) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true

	return nil
}

func (f *fakeListener) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.closed
}

type harness struct {
	mover     *Mover
	listeners map[int]*fakeListener
	stored    []int
	taken     map[int]bool
	mu        sync.Mutex
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	h := &harness{listeners: map[int]*fakeListener{}, taken: map[int]bool{}}

	h.mover = &Mover{
		serve: func(net.Listener) {},
		persist: func(port int) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.stored = append(h.stored, port)

			return nil
		},
		now: time.Now,
		listen: func(port int) (net.Listener, error) {
			h.mu.Lock()
			defer h.mu.Unlock()

			if h.taken[port] {
				return nil, errors.New("address already in use")
			}

			l := &fakeListener{}
			h.listeners[port] = l

			return l, nil
		},
	}

	return h
}

func (h *harness) persisted() []int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return append([]int(nil), h.stored...)
}

func TestNothingIsStoredUntilTheNewPortIsProvenToWork(t *testing.T) {
	// The whole design. Everything before the confirmation is reversible by
	// walking away, so a change that turns out to be unreachable leaves the
	// node coming back on the port that was known to work.
	h := newHarness(t)

	if _, err := h.mover.Begin(8081); err != nil {
		t.Fatal(err)
	}

	if got := h.persisted(); len(got) != 0 {
		t.Fatalf("stored %v before anyone confirmed anything", got)
	}

	if err := h.mover.Confirm(8081); err != nil {
		t.Fatal(err)
	}

	if got := h.persisted(); len(got) != 1 || got[0] != 8081 {
		t.Fatalf("stored %v, want [8081]", got)
	}
}

func TestAConfirmationFromTheOldPortIsRefused(t *testing.T) {
	// The attack on this design is confirming without ever having reached the
	// new port — which is exactly the case where the change locks you out.
	// A request on the old port proves nothing about the new one.
	h := newHarness(t)

	if _, err := h.mover.Begin(8081); err != nil {
		t.Fatal(err)
	}

	if err := h.mover.Confirm(8080); !errors.Is(err, ErrWrongPort) {
		t.Fatalf("err = %v, want %v", err, ErrWrongPort)
	}
	if got := h.persisted(); len(got) != 0 {
		t.Fatalf("stored %v on a confirmation that proved nothing", got)
	}

	// And the real one still works afterwards.
	if err := h.mover.Confirm(8081); err != nil {
		t.Fatal(err)
	}
}

func TestAnAbandonedChangeClosesItsOwnPort(t *testing.T) {
	// Someone who closes the tab should not leave a second panel listening on
	// a port they have forgotten about.
	h := newHarness(t)

	// A window short enough to observe.
	h.mover.listen = func(port int) (net.Listener, error) {
		l := &fakeListener{}
		h.mu.Lock()
		h.listeners[port] = l
		h.mu.Unlock()

		return l, nil
	}

	if _, err := h.mover.Begin(8081); err != nil {
		t.Fatal(err)
	}

	h.mover.abandon(8081)

	h.mu.Lock()
	l := h.listeners[8081]
	h.mu.Unlock()

	if !l.isClosed() {
		t.Fatal("the abandoned port was left open")
	}
	if _, _, waiting := h.mover.Pending(); waiting {
		t.Fatal("the abandoned change is still pending")
	}
	if got := h.persisted(); len(got) != 0 {
		t.Fatalf("stored %v for a change nobody confirmed", got)
	}
}

func TestAPortSomethingElseHoldsIsRefusedBeforeAnythingChanges(t *testing.T) {
	// The second machine in this household was already running a web server on
	// 8080. Moving onto an occupied port has to fail while the old panel is
	// still up, not after.
	h := newHarness(t)
	h.taken[8080] = true

	if _, err := h.mover.Begin(8080); !errors.Is(err, ErrInUse) {
		t.Fatalf("err = %v, want %v", err, ErrInUse)
	}
	if _, _, waiting := h.mover.Pending(); waiting {
		t.Fatal("a failed attempt left a pending change behind")
	}
}

func TestOnlyOneChangeAtATime(t *testing.T) {
	h := newHarness(t)

	if _, err := h.mover.Begin(8081); err != nil {
		t.Fatal(err)
	}
	if _, err := h.mover.Begin(8082); !errors.Is(err, ErrPending) {
		t.Fatalf("err = %v, want %v", err, ErrPending)
	}
}

func TestCancellingReleasesThePort(t *testing.T) {
	h := newHarness(t)

	if _, err := h.mover.Begin(8081); err != nil {
		t.Fatal(err)
	}
	if err := h.mover.Cancel(); err != nil {
		t.Fatal(err)
	}

	h.mu.Lock()
	l := h.listeners[8081]
	h.mu.Unlock()

	if !l.isClosed() {
		t.Fatal("cancelling left the port open")
	}

	// And the port is free to try again.
	if _, err := h.mover.Begin(8082); err != nil {
		t.Fatal(err)
	}
}

func TestPrivilegedPortsAreRefusedWithTheReason(t *testing.T) {
	// The node is unprivileged deliberately and holds one capability, for port
	// 53. A panel on 80 would need another, which is a bigger decision than a
	// number in a form.
	if err := Validate(80); !errors.Is(err, ErrUnprivileged) {
		t.Fatalf("err = %v, want %v", err, ErrUnprivileged)
	}
	if err := Validate(443); !errors.Is(err, ErrUnprivileged) {
		t.Fatalf("err = %v, want %v", err, ErrUnprivileged)
	}

	for _, port := range []int{0, -1, 70000} {
		if Validate(port) == nil {
			t.Errorf("%d was accepted as a port", port)
		}
	}

	for _, port := range []int{1024, 8080, 8443, 65535} {
		if err := Validate(port); err != nil {
			t.Errorf("%d was refused: %v", port, err)
		}
	}
}

func TestConfirmingNothingSaysSo(t *testing.T) {
	h := newHarness(t)

	if err := h.mover.Confirm(8081); !errors.Is(err, ErrNothing) {
		t.Fatalf("err = %v, want %v", err, ErrNothing)
	}
}

func TestTheMovedPortIsOneSomeoneWouldGuess(t *testing.T) {
	// A panel that lands on a random free port is not a setting, it is a
	// puzzle. Someone hunting for a moved panel tries 8081 long before 44317.
	busy := map[string]bool{"0.0.0.0:8080": true}

	got, err := listenNearbyWith("0.0.0.0:8080", func(_, addr string) (net.Listener, error) {
		if busy[addr] {
			return nil, errors.New("address already in use")
		}

		return &fakeListener{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("no listener")
	}

	// Every candidate has to stay within reach of the original.
	for _, offset := range nearbyOffsets {
		if offset > 1000 {
			t.Errorf("offset %d is too far from the port anyone would try", offset)
		}
	}
}

func TestAMachineWithNothingFreeNearbySaysSoRatherThanWandering(t *testing.T) {
	_, err := listenNearbyWith("0.0.0.0:8080", func(_, _ string) (net.Listener, error) {
		return nil, errors.New("address already in use")
	})
	if err == nil {
		t.Fatal("a machine with no free port nearby reported success")
	}
}

func TestAPortNearTheTopDoesNotOverflow(t *testing.T) {
	// base+1000 from 65000 is past the end of the range, and asking the kernel
	// for port 66000 is a confusing error rather than a useful one.
	var tried []string

	_, _ = listenNearbyWith("0.0.0.0:65000", func(_, addr string) (net.Listener, error) {
		tried = append(tried, addr)

		return nil, errors.New("address already in use")
	})

	for _, addr := range tried {
		_, port, _ := net.SplitHostPort(addr)
		if n, _ := strconv.Atoi(port); n > 65535 {
			t.Errorf("tried port %d, which does not exist", n)
		}
	}
}
