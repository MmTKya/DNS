package api

import (
	"testing"
	"time"
)

// Guessing passwords has to become slow. Argon2id already makes each attempt
// cost something; this makes the number of attempts finite.
func TestLoginLimiterStopsRepeatedAttempts(t *testing.T) {
	t.Parallel()

	limiter := newLoginLimiter()
	now := time.Now()

	for i := range loginAttemptsPerMinute {
		if ok, _ := limiter.allow("192.0.2.10", now); !ok {
			t.Fatalf("attempt %d was refused inside the allowance", i+1)
		}
	}

	ok, retryAfter := limiter.allow("192.0.2.10", now)
	if ok {
		t.Error("an eleventh attempt in the same minute was allowed")
	}
	if retryAfter <= 0 {
		t.Error("the refusal did not say how long to wait")
	}
}

// One noisy address must not lock out the rest of the household.
func TestLoginLimiterIsPerAddress(t *testing.T) {
	t.Parallel()

	limiter := newLoginLimiter()
	now := time.Now()

	for range loginAttemptsPerMinute + 5 {
		limiter.allow("192.0.2.10", now)
	}

	if ok, _ := limiter.allow("192.0.2.11", now); !ok {
		t.Error("a different address was refused because of someone else's attempts")
	}
}

// Someone who waits gets to try again: this is a brake, not a ban.
func TestLoginLimiterRecoversAfterTheWindow(t *testing.T) {
	t.Parallel()

	limiter := newLoginLimiter()
	now := time.Now()

	for range loginAttemptsPerMinute + 1 {
		limiter.allow("192.0.2.10", now)
	}

	if ok, _ := limiter.allow("192.0.2.10", now.Add(loginWindow+time.Second)); !ok {
		t.Error("the address was still refused after the window had passed")
	}
}

// Entries must not accumulate for every address that ever probed the node.
func TestLoginLimiterForgetsOldAddresses(t *testing.T) {
	t.Parallel()

	limiter := newLoginLimiter()
	now := time.Now()

	limiter.allow("192.0.2.10", now)
	limiter.allow("192.0.2.11", now)

	// A later attempt sweeps anything whose window has closed.
	limiter.allow("192.0.2.12", now.Add(2*loginWindow))

	limiter.mu.Lock()
	remaining := len(limiter.windows)
	limiter.mu.Unlock()

	if remaining != 1 {
		t.Errorf("the limiter is holding %d addresses, want only the current one", remaining)
	}
}

// The reason the concurrency cap exists: each verification allocates 19 MiB,
// so an unbounded flood is a way to starve the resolver of memory on the
// machine whose actual job is answering DNS.
func TestConcurrentVerificationsAreBounded(t *testing.T) {
	t.Parallel()

	limiter := newLoginLimiter()

	for i := range maxConcurrentVerifications {
		select {
		case limiter.slots <- struct{}{}:
		default:
			t.Fatalf("slot %d was unavailable inside the cap", i+1)
		}
	}

	select {
	case limiter.slots <- struct{}{}:
		t.Error("more verifications ran at once than the cap allows")
	default:
	}
}
