// Package continuity keeps the node serving, and gets it restarted when it
// stops.
//
// The watchdog is the part that matters. A process can be alive and useless:
// the goroutines are parked on a lock, the listener is bound, systemd sees a
// running PID, and every device in the house has lost DNS. So the watchdog is
// only fed after the node proves it can still answer a question — a real query
// against its own listener. Feeding it unconditionally would turn systemd's
// health check into a liveness check for the scheduler, which is a thing
// nobody needs.
package continuity

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"
)

// Notifier speaks systemd's notification protocol.
//
// The protocol is three lines of text over a unix datagram socket, so it is
// implemented here rather than pulling in a dependency for it.
type Notifier struct {
	socket string
}

// NewNotifier returns a notifier, and reports whether systemd is listening.
//
// Outside systemd — a developer running the binary by hand, a container — the
// address is empty and every call becomes a no-op.
func NewNotifier() (notifier *Notifier, enabled bool) {
	socket := os.Getenv("NOTIFY_SOCKET")

	return &Notifier{socket: socket}, socket != ""
}

// Notify sends a raw status line.
func (n *Notifier) Notify(state string) error {
	if n.socket == "" {
		return nil
	}

	address := n.socket
	// A leading '@' means an abstract socket, which Go expresses with a NUL.
	if address[0] == '@' {
		address = "\x00" + address[1:]
	}

	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("connecting to the service manager: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err = conn.Write([]byte(state)); err != nil {
		return fmt.Errorf("notifying the service manager: %w", err)
	}

	return nil
}

// Ready announces that startup finished.
func (n *Notifier) Ready() error { return n.Notify("READY=1") }

// Stopping announces a clean shutdown, so systemd does not treat the exit as a
// crash and count it towards the restart limit.
func (n *Notifier) Stopping() error { return n.Notify("STOPPING=1") }

// Status sets the one-line status shown by `systemctl status`.
func (n *Notifier) Status(text string) error { return n.Notify("STATUS=" + text) }

// Ping feeds the watchdog.
func (n *Notifier) Ping() error { return n.Notify("WATCHDOG=1") }

// WatchdogInterval returns how often the watchdog must be fed, derived from
// what systemd asked for.
//
// It returns half of WatchdogSec, which is the documented convention: it
// leaves room for one late ping before the service manager gives up.
func WatchdogInterval() (interval time.Duration, enabled bool) {
	raw := os.Getenv("WATCHDOG_USEC")
	if raw == "" {
		return 0, false
	}

	// WATCHDOG_PID exists so a forked child does not answer for its parent.
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" {
		if want, err := strconv.Atoi(pid); err == nil && want != os.Getpid() {
			return 0, false
		}
	}

	usec, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || usec <= 0 {
		return 0, false
	}

	return time.Duration(usec) * time.Microsecond / 2, true
}

// HealthCheck reports whether the node is genuinely working.
type HealthCheck func(ctx context.Context) error

// Watchdog feeds the service manager for as long as the node is healthy.
type Watchdog struct {
	notifier *Notifier
	check    HealthCheck
	logger   *slog.Logger
	interval time.Duration

	// failures counts consecutive unhealthy checks, so one slow moment does
	// not restart a node that is about to recover.
	tolerate int
}

// NewWatchdog creates a watchdog.  interval of zero uses what systemd asked
// for; a check of nil means the process is fed unconditionally, which is only
// appropriate when there is nothing to check.
func NewWatchdog(notifier *Notifier, check HealthCheck, interval time.Duration, logger *slog.Logger) *Watchdog {
	if logger == nil {
		logger = slog.Default()
	}

	if interval <= 0 {
		if fromSystemd, ok := WatchdogInterval(); ok {
			interval = fromSystemd
		} else {
			interval = 15 * time.Second
		}
	}

	return &Watchdog{
		notifier: notifier,
		check:    check,
		logger:   logger.With("component", "watchdog"),
		interval: interval,
		tolerate: 2,
	}
}

// Run feeds the watchdog until ctx is cancelled.
//
// When the health check fails, the ping is withheld rather than the process
// killed: letting the service manager time out is what produces a restart with
// the configured backoff, the journal entry, and — in a cluster — the address
// failover that goes with it.
func (w *Watchdog) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	consecutive := 0

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			if w.check == nil {
				_ = w.notifier.Ping()

				continue
			}

			checkCtx, cancel := context.WithTimeout(ctx, w.interval)
			err := w.check(checkCtx)
			cancel()

			if err == nil {
				if consecutive > 0 {
					w.logger.InfoContext(ctx, "node is healthy again", "after_failures", consecutive)
				}
				consecutive = 0

				if pingErr := w.notifier.Ping(); pingErr != nil {
					w.logger.WarnContext(ctx, "feeding the watchdog", "err", pingErr)
				}

				continue
			}

			consecutive++
			w.logger.ErrorContext(ctx, "health check failed",
				"consecutive", consecutive, "err", err)

			if consecutive < w.tolerate {
				// Still within tolerance: feed it, and hope the next check is
				// better. A single slow moment is not a reason to restart.
				_ = w.notifier.Ping()

				continue
			}

			// Deliberately not fed. The service manager will restart us.
			_ = w.notifier.Status(fmt.Sprintf("unhealthy: %v", err))
			w.logger.ErrorContext(ctx, "withholding the watchdog ping; the service manager will restart this node")
		}
	}
}
