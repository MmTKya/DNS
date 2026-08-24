package clients

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A node cannot answer anything while its own cable is unplugged, and it is
// the one thing that never appeared anywhere on the screen.
//
// The household experience of a link that drops for twenty seconds is the same
// as the experience of a crash: no internet. The two need completely different
// responses — one is a cable, the other is a bug — and telling them apart took
// a shell session and a journal, which is exactly what this product exists to
// avoid.
//
// The kernel already tracks it. Reading a file every couple of seconds costs
// nothing and turns "it died and I do not know why" into a line with a time
// and a duration on it.

// LinkEvent is one interruption, after it has ended.
type LinkEvent struct {
	Interface string
	Down      time.Time
	Duration  time.Duration
}

// linkWatcher notices interfaces losing and regaining their connection.
type linkWatcher struct {
	root   string
	logger *slog.Logger

	// report is called once per interruption, when it ends. Reporting on the
	// way back up rather than on the way down is deliberate: the duration is
	// the useful part, and a node with no network cannot write anywhere
	// useful at the moment it matters anyway.
	report func(LinkEvent)

	// down holds when each interface went down, for those currently down.
	down map[string]time.Time
}

// linkPollInterval is short enough to catch the brief drops that a failing
// cable produces — those are the ones nothing else records — and long enough
// that the watching is free.
const linkPollInterval = 2 * time.Second

// minReportable filters the flap that happens on the node's own startup and
// during a normal address renewal, which is noise rather than an outage.
const minReportable = 3 * time.Second

func newLinkWatcher(logger *slog.Logger, report func(LinkEvent)) *linkWatcher {
	return &linkWatcher{
		root:   "/sys/class/net",
		logger: logger.With("component", "link-watch"),
		report: report,
		down:   map[string]time.Time{},
	}
}

// Run watches until the context is cancelled.
func (w *linkWatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(linkPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.poll(time.Now())
		}
	}
}

// poll compares every interface against what it was last time.
func (w *linkWatcher) poll(now time.Time) {
	for name, up := range w.states() {
		wentDown, wasDown := w.down[name]

		switch {
		case !up && !wasDown:
			w.down[name] = now

		case up && wasDown:
			delete(w.down, name)

			outage := now.Sub(wentDown)
			if outage < minReportable {
				continue
			}

			w.logger.Warn("the network connection dropped and came back",
				"interface", name, "seconds", outage.Seconds())

			if w.report != nil {
				w.report(LinkEvent{Interface: name, Down: wentDown, Duration: outage})
			}
		}
	}
}

// states reads whether each real interface currently has a connection.
//
// Loopback and virtual interfaces are skipped: they are always up, and a
// tunnel going up and down is its own thing rather than the house losing its
// network.
func (w *linkWatcher) states() map[string]bool {
	entries, err := os.ReadDir(w.root)
	if err != nil {
		return nil
	}

	states := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "lo" || !physical(name) {
			continue
		}

		raw, readErr := os.ReadFile(filepath.Join(w.root, name, "carrier"))
		if readErr != nil {
			// An interface that is administratively down refuses this read.
			// That is not an outage — nobody is expecting it to carry
			// anything — so it is left out rather than reported as one.
			continue
		}

		states[name] = strings.TrimSpace(string(raw)) == "1"
	}

	return states
}

// physical reports whether a name is a real port rather than something the
// machine made up.
func physical(name string) bool {
	for _, prefix := range []string{"veth", "docker", "br-", "virbr", "wg", "tun", "tap", "dummy", "bond"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}

	return true
}
