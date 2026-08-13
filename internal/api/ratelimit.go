package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Password verification is deliberately expensive — 19 MiB and two passes of
// argon2id per attempt — which is what makes a stolen hash costly to attack.
// Unauthenticated and unbounded, that same cost is a way to take the resolver
// down: a hundred concurrent login attempts is nearly two gigabytes of
// allocation and all of the CPU, on a machine whose actual job is answering
// DNS for a household.
//
// Two limits, because they stop different things. The per-address one stops
// someone guessing passwords. The global one bounds memory no matter how many
// addresses the attempts come from, which matters on a LAN where an address is
// not an identity.
const (
	loginAttemptsPerMinute = 10
	loginWindow            = time.Minute

	// Concurrent password verifications. Four is enough that a household
	// logging in together never notices, and caps the damage at 76 MiB.
	maxConcurrentVerifications = 4
)

// loginLimiter throttles the endpoints that verify a password.
type loginLimiter struct {
	slots chan struct{}

	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	resetAt  time.Time
	attempts int
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		slots:   make(chan struct{}, maxConcurrentVerifications),
		windows: make(map[string]*window),
	}
}

// allow reports whether an address may make another attempt.
func (l *loginLimiter) allow(addr string, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Cheap enough to do inline, and it keeps a node that has been probed for
	// a week from holding a map entry per source address.
	for key, w := range l.windows {
		if now.After(w.resetAt) {
			delete(l.windows, key)
		}
	}

	w, seen := l.windows[addr]
	if !seen || now.After(w.resetAt) {
		l.windows[addr] = &window{attempts: 1, resetAt: now.Add(loginWindow)}

		return true, 0
	}

	if w.attempts >= loginAttemptsPerMinute {
		return false, time.Until(w.resetAt)
	}

	w.attempts++

	return true, 0
}

// throttle limits attempts per address and bounds how many run at once.
//
// The queue is what keeps this from being a denial of service in its own
// right: a legitimate login during a flood waits its turn rather than being
// refused.
func (s *Server) throttle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		addr := clientAddr(r)

		if ok, retryAfter := s.limiter.allow(addr, time.Now()); !ok {
			seconds := int(retryAfter.Seconds()) + 1
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			s.writeError(w, r, http.StatusTooManyRequests,
				"too many attempts; wait "+strconv.Itoa(seconds)+" seconds")

			return
		}

		select {
		case s.limiter.slots <- struct{}{}:
			defer func() { <-s.limiter.slots }()
		case <-r.Context().Done():
			return
		case <-time.After(15 * time.Second):
			// Every slot busy for fifteen seconds means something is hammering
			// this endpoint. Shedding the request protects the resolver, which
			// is the part of this machine that must not stop.
			w.Header().Set("Retry-After", "30")
			s.writeError(w, r, http.StatusServiceUnavailable, "the node is busy; try again shortly")

			return
		}

		next.ServeHTTP(w, r)
	})
}

// clientAddr is the address attempts are counted against.
//
// RealIP has already applied X-Forwarded-For where a proxy set it; falling
// back to the raw address means a direct connection is still counted rather
// than every direct attempt sharing one bucket.
func clientAddr(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}

	return r.RemoteAddr
}
