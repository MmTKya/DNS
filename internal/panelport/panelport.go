// Package panelport moves the admin interface to a different port without
// letting anyone lock themselves out of it.
//
// Changing the panel's own address from the panel is the one setting that can
// destroy the thing editing it. Get it wrong and the way back is a keyboard
// attached to the machine — which for a box in a cupboard means taking it out
// of the cupboard.
//
// So the change is made in two halves, the way network equipment has done it
// for decades. The first half opens the new port and changes nothing else: the
// old one keeps working, and nothing is written down. The second half is a
// confirmation that has to arrive *on the new port*, which is only possible if
// the new port actually works from where the person is sitting. Until that
// arrives, the stored setting is untouched, so a restart comes back on the
// port that was known to work.
//
// Nothing here decides that the new port is reachable by inspecting it. The
// only evidence that counts is a request that came in on it.
package panelport

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// ConfirmWindow is how long the new port stays open unconfirmed.
//
// Long enough to switch browser tabs, type an address and log in; short enough
// that an abandoned attempt does not leave a second panel listening.
const ConfirmWindow = 2 * time.Minute

// Errors a caller has to tell apart.
var (
	ErrInUse        = errors.New("something is already listening on that port")
	ErrPending      = errors.New("a port change is already waiting to be confirmed")
	ErrNothing      = errors.New("no port change is waiting")
	ErrWrongPort    = errors.New("the confirmation did not arrive on the new port")
	ErrUnprivileged = errors.New("ports below 1024 need privileges this node does not have")
)

// Serve starts serving the panel on a listener. It returns when the listener
// closes.
type Serve func(net.Listener)

// Persist records the confirmed port, so a restart uses it.
type Persist func(port int) error

// Mover owns the pending change.
type Mover struct {
	serve   Serve
	persist Persist
	now     func() time.Time

	// listen is swappable so the rules can be tested without binding
	// anything.
	listen func(port int) (net.Listener, error)

	mu      sync.Mutex
	pending *pending
}

type pending struct {
	port     int
	listener net.Listener
	deadline time.Time
	timer    *time.Timer
}

// New creates a mover.
func New(serve Serve, persist Persist) *Mover {
	return &Mover{
		serve:   serve,
		persist: persist,
		now:     time.Now,
		listen: func(port int) (net.Listener, error) {
			return net.Listen("tcp", fmt.Sprintf(":%d", port))
		},
	}
}

// Validate reports whether a port is one this node may move to.
//
// The lower bound is not arbitrary: the node runs unprivileged on purpose, and
// the one capability it holds is for port 53. A panel on port 80 would need a
// second one, which is a larger decision than a form on a settings screen.
func Validate(port int) error {
	if port < 1024 {
		if port < 1 {
			return errors.New("that is not a port number")
		}

		return ErrUnprivileged
	}
	if port > 65535 {
		return errors.New("that is not a port number")
	}

	return nil
}

// Begin opens the new port. Nothing is stored and the old port keeps working.
func (m *Mover) Begin(port int) (deadline time.Time, err error) {
	if err = Validate(port); err != nil {
		return time.Time{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pending != nil {
		return time.Time{}, ErrPending
	}

	listener, err := m.listen(port)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrInUse, err)
	}

	deadline = m.now().Add(ConfirmWindow)
	p := &pending{port: port, listener: listener, deadline: deadline}

	// Abandoning the attempt has to clean up by itself. Someone who closes the
	// tab should not be left with a second panel open on a port they have
	// forgotten about.
	p.timer = time.AfterFunc(ConfirmWindow, func() { m.abandon(port) })

	m.pending = p

	go m.serve(listener)

	return deadline, nil
}

// Confirm accepts the change, but only from a request that arrived on the new
// port.
//
// arrivedOn is the local address the request was accepted on. It is the whole
// mechanism: a browser that can reach the new port proves the port works from
// where the person actually is, which is the only claim worth anything here.
func (m *Mover) Confirm(arrivedOn int) error {
	m.mu.Lock()

	p := m.pending
	if p == nil {
		m.mu.Unlock()

		return ErrNothing
	}
	if arrivedOn != p.port {
		m.mu.Unlock()

		return ErrWrongPort
	}

	m.pending = nil
	p.timer.Stop()
	m.mu.Unlock()

	// Stored only now. Everything before this point is reversible by walking
	// away, and that is the point.
	if err := m.persist(p.port); err != nil {
		return fmt.Errorf("storing the new port: %w", err)
	}

	return nil
}

// Cancel gives up on a pending change.
func (m *Mover) Cancel() error {
	m.mu.Lock()
	p := m.pending
	m.pending = nil
	m.mu.Unlock()

	if p == nil {
		return ErrNothing
	}

	p.timer.Stop()

	return p.listener.Close()
}

// abandon closes an unconfirmed listener when its window expires.
func (m *Mover) abandon(port int) {
	m.mu.Lock()
	p := m.pending
	if p == nil || p.port != port {
		m.mu.Unlock()

		return
	}
	m.pending = nil
	m.mu.Unlock()

	_ = p.listener.Close()
}

// Pending reports the port awaiting confirmation, if any.
func (m *Mover) Pending() (port int, deadline time.Time, waiting bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.pending == nil {
		return 0, time.Time{}, false
	}

	return m.pending.port, m.pending.deadline, true
}

// ListenNearby finds a free port close to the one that was wanted.
//
// Used when something else already holds the panel's port at startup. The node
// moves rather than refusing to run: it answers names for a whole household,
// and giving that up because a web server got to 8080 first trades the
// important job for the convenient one.
//
// Deliberately a short, adjacent list rather than "any free port". Someone
// looking for a panel that moved will try 8081 long before 44317, and a port
// that lands somewhere different on every restart is not a setting, it is a
// puzzle.
func ListenNearby(wanted string) (net.Listener, error) {
	return listenNearbyWith(wanted, net.Listen)
}

// nearbyOffsets is the search order.
var nearbyOffsets = []int{1, 2, 10, 1000}

func listenNearbyWith(wanted string, listen func(network, addr string) (net.Listener, error)) (net.Listener, error) {
	host, port, err := net.SplitHostPort(wanted)
	if err != nil {
		return nil, err
	}

	base, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	for _, offset := range nearbyOffsets {
		candidate := base + offset
		if candidate > 65535 {
			continue
		}

		listener, listenErr := listen("tcp", net.JoinHostPort(host, strconv.Itoa(candidate)))
		if listenErr == nil {
			return listener, nil
		}
	}

	return nil, fmt.Errorf("no free port near %s", wanted)
}
