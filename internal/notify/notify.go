// Package notify tells someone when the node needs attention.
//
// The hard part is not delivery, it is restraint. An alert that arrives every
// minute for an hour stops being an alert: people mute the channel, and then
// the one that mattered arrives into a muted channel. So every alert carries a
// key, the same key is not re-sent within its cooldown, and severity decides
// which destinations hear about it at all.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MmTKya/DNS/internal/store"
	"github.com/wneessen/go-mail"
)

// Severities, in increasing order of how much they should interrupt someone.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Channel kinds.
const (
	KindSMTP     = "smtp"
	KindWebhook  = "webhook"
	KindNtfy     = "ntfy"
	KindTelegram = "telegram"
	KindDiscord  = "discord"
)

// Cooldowns by severity.
//
// A critical alert repeats sooner because it is likely to need action; an
// informational one waits a long time because nobody wants to be told twice
// that a feed updated.
var cooldowns = map[string]time.Duration{
	SeverityInfo:     24 * time.Hour,
	SeverityWarning:  6 * time.Hour,
	SeverityCritical: time.Hour,
}

// Alert is something worth telling a person about.
type Alert struct {
	// Key identifies the condition, not the occurrence: "feed-failed:hagezi-pro"
	// rather than a timestamp. It is what deduplication works on.
	Key string

	Severity string
	Title    string
	Body     string

	// URL points at the panel page where the problem can be dealt with.
	URL string
}

// severityRank orders severities for the per-channel threshold.
func severityRank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	default:
		return 1
	}
}

// Channel is a configured destination.
type Channel struct {
	CreatedAt   time.Time      `json:"created_at"`
	LastSent    time.Time      `json:"last_sent,omitzero"`
	Kind        string         `json:"kind"`
	Name        string         `json:"name"`
	MinSeverity string         `json:"min_severity"`
	LastError   string         `json:"last_error,omitempty"`
	Config      map[string]any `json:"config"`
	ID          int64          `json:"id"`
	Enabled     bool           `json:"enabled"`
}

// Notifier delivers alerts to the configured channels.
type Notifier struct {
	db     *store.DB
	logger *slog.Logger
	client *http.Client

	// mu guards the in-memory dedup cache, which spares the database a read on
	// every alert.
	mu   sync.Mutex
	sent map[string]time.Time
}

// New creates a notifier.
func New(db *store.DB, logger *slog.Logger) *Notifier {
	if logger == nil {
		logger = slog.Default()
	}

	return &Notifier{
		db:     db,
		logger: logger.With("component", "notify"),
		client: &http.Client{Timeout: 15 * time.Second},
		sent:   map[string]time.Time{},
	}
}

// Send delivers an alert to every channel that wants it.
//
// Suppression is not an error: a caller reporting a condition every minute is
// behaving correctly, and it is this function's job to be quiet about it.
func (n *Notifier) Send(ctx context.Context, alert Alert) (delivered int, suppressed bool, err error) {
	if alert.Key == "" || alert.Title == "" {
		return 0, false, fmt.Errorf("an alert needs a key and a title")
	}
	if alert.Severity == "" {
		alert.Severity = SeverityWarning
	}

	if n.suppress(alert) {
		return 0, true, nil
	}

	channels, err := ListChannels(ctx, n.db)
	if err != nil {
		return 0, false, err
	}

	minRank := severityRank(alert.Severity)

	for _, channel := range channels {
		if !channel.Enabled || severityRank(channel.MinSeverity) > minRank {
			continue
		}

		if sendErr := n.deliver(ctx, channel, alert); sendErr != nil {
			n.logger.ErrorContext(ctx, "delivering an alert",
				"channel", channel.Name, "kind", channel.Kind, "err", sendErr)
			n.recordChannelResult(ctx, channel.ID, sendErr)

			continue
		}

		n.recordChannelResult(ctx, channel.ID, nil)
		delivered++
	}

	n.record(ctx, alert, delivered)

	return delivered, false, nil
}

// suppress reports whether this alert is still within its cooldown.
func (n *Notifier) suppress(alert Alert) bool {
	cooldown, ok := cooldowns[alert.Severity]
	if !ok {
		cooldown = cooldowns[SeverityWarning]
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	if last, seen := n.sent[alert.Key]; seen && time.Since(last) < cooldown {
		return true
	}

	n.sent[alert.Key] = time.Now()

	// The map is bounded by the number of distinct conditions, which is small,
	// but a compromised or buggy caller could still invent keys.
	if len(n.sent) > 1000 {
		cutoff := time.Now().Add(-24 * time.Hour)
		for key, at := range n.sent {
			if at.Before(cutoff) {
				delete(n.sent, key)
			}
		}
	}

	return false
}

// Test sends a sample alert to one channel, bypassing deduplication.
//
// A test button that silently does nothing because the same test was sent an
// hour ago is worse than no test button.
func (n *Notifier) Test(ctx context.Context, channelID int64) error {
	channel, found, err := GetChannel(ctx, n.db, channelID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no such channel")
	}

	alert := Alert{
		Key:      fmt.Sprintf("test:%d:%d", channelID, time.Now().UnixNano()),
		Severity: SeverityInfo,
		Title:    "SedDNS test notification",
		Body:     "If you are reading this, alerts from your DNS node will reach you here.",
	}

	if err = n.deliver(ctx, channel, alert); err != nil {
		n.recordChannelResult(ctx, channelID, err)

		return err
	}

	n.recordChannelResult(ctx, channelID, nil)

	return nil
}

func (n *Notifier) deliver(ctx context.Context, channel Channel, alert Alert) error {
	switch channel.Kind {
	case KindSMTP:
		return n.sendMail(ctx, channel, alert)
	case KindWebhook:
		return n.sendWebhook(ctx, channel, alert)
	case KindNtfy:
		return n.sendNtfy(ctx, channel, alert)
	case KindTelegram:
		return n.sendTelegram(ctx, channel, alert)
	case KindDiscord:
		return n.sendDiscord(ctx, channel, alert)
	default:
		return fmt.Errorf("unknown channel kind %q", channel.Kind)
	}
}

func (n *Notifier) sendMail(_ context.Context, channel Channel, alert Alert) error {
	host := configString(channel.Config, "host")
	from := configString(channel.Config, "from")
	to := configString(channel.Config, "to")

	if host == "" || from == "" || to == "" {
		return fmt.Errorf("smtp channel needs host, from and to")
	}

	port := configInt(channel.Config, "port", 587)

	msg := mail.NewMsg()
	if err := msg.From(from); err != nil {
		return fmt.Errorf("invalid from address: %w", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("invalid to address: %w", err)
	}

	msg.Subject("[SedDNS] " + alert.Title)
	msg.SetBodyString(mail.TypeTextPlain, formatBody(alert))

	opts := []mail.Option{mail.WithPort(port), mail.WithTimeout(20 * time.Second)}

	if username := configString(channel.Config, "username"); username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
			mail.WithUsername(username),
			mail.WithPassword(configString(channel.Config, "password")),
		)
	} else {
		// A relay on the LAN that takes no credentials is a normal setup, and
		// go-mail otherwise insists on authenticating.
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthNoAuth))
	}

	switch strings.ToLower(configString(channel.Config, "encryption")) {
	case "none":
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	case "ssl", "tls":
		opts = append(opts, mail.WithSSL())
	default:
		// Opportunistic STARTTLS: encrypt when the server offers it rather
		// than failing against a relay that does not.
		opts = append(opts, mail.WithTLSPolicy(mail.TLSOpportunistic))
	}

	client, err := mail.NewClient(host, opts...)
	if err != nil {
		return fmt.Errorf("configuring the mail client: %w", err)
	}

	if err = client.DialAndSend(msg); err != nil {
		return fmt.Errorf("sending mail: %w", err)
	}

	return nil
}

func (n *Notifier) sendWebhook(ctx context.Context, channel Channel, alert Alert) error {
	url := configString(channel.Config, "url")
	if url == "" {
		return fmt.Errorf("webhook channel needs a url")
	}

	payload, err := json.Marshal(map[string]any{
		"key":      alert.Key,
		"severity": alert.Severity,
		"title":    alert.Title,
		"body":     alert.Body,
		"url":      alert.URL,
		"source":   "aegisdns",
		"at":       time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}

	return n.post(ctx, url, "application/json", payload, map[string]string{
		"Authorization": configString(channel.Config, "authorization"),
	})
}

func (n *Notifier) sendNtfy(ctx context.Context, channel Channel, alert Alert) error {
	server := configString(channel.Config, "server")
	if server == "" {
		server = "https://ntfy.sh"
	}

	topic := configString(channel.Config, "topic")
	if topic == "" {
		return fmt.Errorf("ntfy channel needs a topic")
	}

	priority := "default"
	tags := "warning"
	switch alert.Severity {
	case SeverityCritical:
		priority, tags = "urgent", "rotating_light"
	case SeverityInfo:
		priority, tags = "low", "information_source"
	}

	headers := map[string]string{
		"Title":    alert.Title,
		"Priority": priority,
		"Tags":     tags,
	}
	if token := configString(channel.Config, "token"); token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	if alert.URL != "" {
		headers["Click"] = alert.URL
	}

	return n.post(ctx, strings.TrimSuffix(server, "/")+"/"+topic, "text/plain",
		[]byte(alert.Body), headers)
}

func (n *Notifier) sendTelegram(ctx context.Context, channel Channel, alert Alert) error {
	token := configString(channel.Config, "token")
	chatID := configString(channel.Config, "chat_id")

	if token == "" || chatID == "" {
		return fmt.Errorf("telegram channel needs a token and a chat id")
	}

	base := configString(channel.Config, "api_base")
	if base == "" {
		base = "https://api.telegram.org"
	}

	payload, err := json.Marshal(map[string]any{
		"chat_id": chatID,
		"text":    alert.Title + "\n\n" + formatBody(alert),
	})
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}

	return n.post(ctx, strings.TrimSuffix(base, "/")+"/bot"+token+"/sendMessage",
		"application/json", payload, nil)
}

func (n *Notifier) sendDiscord(ctx context.Context, channel Channel, alert Alert) error {
	url := configString(channel.Config, "url")
	if url == "" {
		return fmt.Errorf("discord channel needs a webhook url")
	}

	payload, err := json.Marshal(map[string]any{
		"content":  "**" + alert.Title + "**\n" + formatBody(alert),
		"username": "SedDNS",
	})
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}

	return n.post(ctx, url, "application/json", payload, nil)
}

func (n *Notifier) post(ctx context.Context, url, contentType string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "SedDNS")
	for key, value := range headers {
		if value != "" {
			req.Header.Set(key, value)
		}
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("destination returned %s", resp.Status)
	}

	return nil
}

func formatBody(alert Alert) string {
	body := alert.Body
	if alert.URL != "" {
		body += "\n\n" + alert.URL
	}

	return body
}

func configString(config map[string]any, key string) string {
	value, _ := config[key].(string)

	return strings.TrimSpace(value)
}

func configInt(config map[string]any, key string, fallback int) int {
	switch value := config[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		return fallback
	}
}

func (n *Notifier) record(ctx context.Context, alert Alert, delivered int) {
	if _, err := n.db.Writer().ExecContext(ctx, `
		INSERT INTO notify_history (key, severity, title, body, sent_at, delivered)
		VALUES (?, ?, ?, ?, ?, ?)
	`, alert.Key, alert.Severity, alert.Title, alert.Body, time.Now().Unix(), delivered); err != nil {
		n.logger.ErrorContext(ctx, "recording an alert", "err", err)
	}
}

func (n *Notifier) recordChannelResult(ctx context.Context, id int64, sendErr error) {
	message := ""
	if sendErr != nil {
		message = sendErr.Error()
	}

	if _, err := n.db.Writer().ExecContext(ctx,
		`UPDATE notify_channels SET last_sent = ?, last_error = ? WHERE id = ?`,
		time.Now().Unix(), message, id); err != nil {
		n.logger.ErrorContext(ctx, "recording a channel result", "err", err)
	}
}
