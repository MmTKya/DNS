package notify_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/MmTKya/DNS/internal/notify"
	"github.com/MmTKya/DNS/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "seddns.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// webhookServer records what arrives.
type webhookServer struct {
	server   *httptest.Server
	received atomic.Int64
	last     atomic.Value
}

func newWebhookServer(t *testing.T) *webhookServer {
	t.Helper()

	w := &webhookServer{}
	w.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.received.Add(1)

		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.last.Store(payload)

		rw.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(w.server.Close)

	return w
}

func addWebhook(t *testing.T, db *store.DB, url, minSeverity string) int64 {
	t.Helper()

	id, err := notify.AddChannel(t.Context(), db, notify.KindWebhook, "test", minSeverity,
		map[string]any{"url": url})
	if err != nil {
		t.Fatalf("AddChannel: %v", err)
	}

	return id
}

func TestWebhookDelivery(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	hook := newWebhookServer(t)
	addWebhook(t, db, hook.server.URL, notify.SeverityWarning)

	n := notify.New(db, discard())

	delivered, suppressed, err := n.Send(t.Context(), notify.Alert{
		Key:      "feed-failed:hagezi-pro",
		Severity: notify.SeverityWarning,
		Title:    "A blocklist failed to update",
		Body:     "HaGeZi Pro has not updated for two days.",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if suppressed || delivered != 1 {
		t.Fatalf("delivered=%d suppressed=%t, want one delivery", delivered, suppressed)
	}

	payload, _ := hook.last.Load().(map[string]any)
	if payload["title"] != "A blocklist failed to update" {
		t.Errorf("payload = %+v, want the alert", payload)
	}
	if payload["severity"] != notify.SeverityWarning {
		t.Errorf("severity = %v, want warning", payload["severity"])
	}
}

func TestRepeatedAlertIsSuppressed(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	hook := newWebhookServer(t)
	addWebhook(t, db, hook.server.URL, notify.SeverityWarning)

	n := notify.New(db, discard())
	alert := notify.Alert{
		Key:      "upstream-down",
		Severity: notify.SeverityWarning,
		Title:    "Upstream unreachable",
	}

	for range 10 {
		if _, _, err := n.Send(t.Context(), alert); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}

	// An alert that arrives every minute for an hour gets muted, and then the
	// one that mattered arrives into a muted channel.
	if got := hook.received.Load(); got != 1 {
		t.Errorf("the destination received %d copies of the same condition, want 1", got)
	}

	// A different condition still gets through.
	if _, suppressed, err := n.Send(t.Context(), notify.Alert{
		Key: "disk-full", Severity: notify.SeverityWarning, Title: "Disk nearly full",
	}); err != nil || suppressed {
		t.Errorf("a different alert was suppressed (err=%v)", err)
	}
	if got := hook.received.Load(); got != 2 {
		t.Errorf("received %d alerts, want 2", got)
	}
}

func TestSeverityThreshold(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	hook := newWebhookServer(t)

	// This destination only wants the serious ones.
	addWebhook(t, db, hook.server.URL, notify.SeverityCritical)

	n := notify.New(db, discard())

	if _, _, err := n.Send(t.Context(), notify.Alert{
		Key: "info", Severity: notify.SeverityInfo, Title: "A feed updated",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := hook.received.Load(); got != 0 {
		t.Errorf("an informational alert reached a critical-only destination")
	}

	if _, _, err := n.Send(t.Context(), notify.Alert{
		Key: "critical", Severity: notify.SeverityCritical, Title: "The resolver stopped",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := hook.received.Load(); got != 1 {
		t.Errorf("a critical alert did not reach the destination")
	}
}

func TestDisabledChannelIsSkipped(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	hook := newWebhookServer(t)
	id := addWebhook(t, db, hook.server.URL, notify.SeverityInfo)

	if found, err := notify.SetChannelEnabled(t.Context(), db, id, false); err != nil || !found {
		t.Fatalf("SetChannelEnabled: found=%t err=%v", found, err)
	}

	n := notify.New(db, discard())
	if _, _, err := n.Send(t.Context(), notify.Alert{
		Key: "x", Severity: notify.SeverityCritical, Title: "Something",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got := hook.received.Load(); got != 0 {
		t.Error("a disabled destination received an alert")
	}
}

func TestTestButtonBypassesSuppression(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	hook := newWebhookServer(t)
	id := addWebhook(t, db, hook.server.URL, notify.SeverityInfo)

	n := notify.New(db, discard())

	// A test button that silently does nothing because the same test was sent
	// an hour ago is worse than no test button.
	for range 3 {
		if err := n.Test(t.Context(), id); err != nil {
			t.Fatalf("Test: %v", err)
		}
	}

	if got := hook.received.Load(); got != 3 {
		t.Errorf("the destination received %d tests, want 3", got)
	}
}

func TestSecretsAreRedactedOnRead(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	if _, err := notify.AddChannel(t.Context(), db, notify.KindSMTP, "mail", notify.SeverityWarning,
		map[string]any{
			"host": "smtp.example.com", "from": "a@example.com", "to": "b@example.com",
			"username": "a@example.com", "password": "hunter2",
		}); err != nil {
		t.Fatalf("AddChannel: %v", err)
	}

	shown, err := notify.ListChannelsForDisplay(t.Context(), db)
	if err != nil {
		t.Fatalf("ListChannelsForDisplay: %v", err)
	}
	// A borrowed panel session should not walk away with the household's mail
	// password.
	if shown[0].Config["password"] == "hunter2" {
		t.Error("the password was returned to the panel")
	}
	if shown[0].Config["host"] != "smtp.example.com" {
		t.Error("a non-secret setting was redacted")
	}

	// The notifier still needs the real value.
	internal, err := notify.ListChannels(t.Context(), db)
	if err != nil {
		t.Fatalf("ListChannels: %v", err)
	}
	if internal[0].Config["password"] != "hunter2" {
		t.Error("the notifier cannot read the password it needs to send mail")
	}
}

func TestUnknownChannelKindIsRefused(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	if _, err := notify.AddChannel(t.Context(), db, "carrier-pigeon", "x", "", nil); err == nil {
		t.Error("an unknown channel kind should be refused")
	}
	if _, err := notify.AddChannel(t.Context(), db, notify.KindWebhook, "", "", nil); err == nil {
		t.Error("a channel without a name should be refused")
	}
}

func TestDeliveryFailureIsRecordedButDoesNotStopOthers(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()

	working := newWebhookServer(t)

	addWebhook(t, db, broken.URL, notify.SeverityInfo)
	addWebhook(t, db, working.server.URL, notify.SeverityInfo)

	n := notify.New(db, discard())

	delivered, _, err := n.Send(t.Context(), notify.Alert{
		Key: "x", Severity: notify.SeverityCritical, Title: "Something",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	// One destination being down must not deny the others.
	if delivered != 1 {
		t.Errorf("delivered to %d destinations, want 1", delivered)
	}
	if got := working.received.Load(); got != 1 {
		t.Errorf("the working destination received %d alerts, want 1", got)
	}

	channels, err := notify.ListChannelsForDisplay(t.Context(), db)
	if err != nil {
		t.Fatalf("ListChannelsForDisplay: %v", err)
	}
	if channels[0].LastError == "" {
		t.Error("the failure should be visible in the panel")
	}
}

func TestAlertHistory(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	n := notify.New(db, discard())

	if _, _, err := n.Send(t.Context(), notify.Alert{
		Key: "x", Severity: notify.SeverityWarning, Title: "Recorded",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	history, err := notify.RecentAlerts(t.Context(), db, 10)
	if err != nil {
		t.Fatalf("RecentAlerts: %v", err)
	}
	// Even with nowhere to send it, the alert is recorded: the panel is a
	// destination too.
	if len(history) != 1 || history[0].Title != "Recorded" {
		t.Errorf("history = %+v, want the alert", history)
	}
}
