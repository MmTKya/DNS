package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/MmTKya/DNS/internal/store"
)

// secretKeys are redacted when a channel is read back.
//
// They have to be stored to be usable, but nothing needs to read them out
// again: a borrowed panel session should not walk away with the household's
// mail password.
var secretKeys = map[string]struct{}{
	"password":      {},
	"token":         {},
	"authorization": {},
}

// ListChannels returns the configured destinations with their secrets intact,
// for internal use by the notifier.
func ListChannels(ctx context.Context, db *store.DB) (channels []Channel, err error) {
	return listChannels(ctx, db, false)
}

// ListChannelsForDisplay returns the destinations with secrets redacted.
func ListChannelsForDisplay(ctx context.Context, db *store.DB) (channels []Channel, err error) {
	return listChannels(ctx, db, true)
}

func listChannels(ctx context.Context, db *store.DB, redact bool) (channels []Channel, err error) {
	rows, err := db.Reader().QueryContext(ctx, `
		SELECT id, kind, name, config, min_severity, enabled, created_at, last_sent, last_error
		FROM notify_channels ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("listing channels: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			c                   Channel
			raw                 string
			enabled             int
			createdAt, lastSent int64
		)

		if err = rows.Scan(&c.ID, &c.Kind, &c.Name, &raw, &c.MinSeverity,
			&enabled, &createdAt, &lastSent, &c.LastError,
		); err != nil {
			return nil, fmt.Errorf("scanning channel: %w", err)
		}

		c.Enabled = enabled != 0
		c.CreatedAt = time.Unix(createdAt, 0)
		if lastSent > 0 {
			c.LastSent = time.Unix(lastSent, 0)
		}

		if err = json.Unmarshal([]byte(raw), &c.Config); err != nil {
			c.Config = map[string]any{}
		}

		if redact {
			for key := range c.Config {
				if _, secret := secretKeys[key]; secret {
					c.Config[key] = "••••••••"
				}
			}
		}

		channels = append(channels, c)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating channels: %w", err)
	}

	return channels, nil
}

// GetChannel returns one destination, secrets included.
func GetChannel(ctx context.Context, db *store.DB, id int64) (channel Channel, found bool, err error) {
	channels, err := listChannels(ctx, db, false)
	if err != nil {
		return Channel{}, false, err
	}

	for _, c := range channels {
		if c.ID == id {
			return c, true, nil
		}
	}

	return Channel{}, false, nil
}

// AddChannel stores a destination.
func AddChannel(ctx context.Context, db *store.DB, kind, name, minSeverity string, config map[string]any) (id int64, err error) {
	kind = strings.TrimSpace(kind)
	switch kind {
	case KindSMTP, KindWebhook, KindNtfy, KindTelegram, KindDiscord:
	default:
		return 0, fmt.Errorf("unknown channel kind %q", kind)
	}

	if strings.TrimSpace(name) == "" {
		return 0, fmt.Errorf("a name is required")
	}

	switch minSeverity {
	case SeverityInfo, SeverityWarning, SeverityCritical:
	case "":
		minSeverity = SeverityWarning
	default:
		return 0, fmt.Errorf("unknown severity %q", minSeverity)
	}

	if config == nil {
		config = map[string]any{}
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		return 0, fmt.Errorf("encoding channel config: %w", err)
	}

	res, err := db.Writer().ExecContext(ctx, `
		INSERT INTO notify_channels (kind, name, config, min_severity, enabled, created_at)
		VALUES (?, ?, ?, ?, 1, ?)
	`, kind, name, string(encoded), minSeverity, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("storing channel: %w", err)
	}

	if id, err = res.LastInsertId(); err != nil {
		return 0, fmt.Errorf("reading channel id: %w", err)
	}

	return id, nil
}

// SetChannelEnabled switches a destination on or off.
func SetChannelEnabled(ctx context.Context, db *store.DB, id int64, enabled bool) (found bool, err error) {
	value := 0
	if enabled {
		value = 1
	}

	res, err := db.Writer().ExecContext(ctx,
		`UPDATE notify_channels SET enabled = ? WHERE id = ?`, value, id)
	if err != nil {
		return false, fmt.Errorf("updating channel: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("checking update: %w", err)
	}

	return affected > 0, nil
}

// DeleteChannel removes a destination.
func DeleteChannel(ctx context.Context, db *store.DB, id int64) (found bool, err error) {
	res, err := db.Writer().ExecContext(ctx, `DELETE FROM notify_channels WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("deleting channel: %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("checking deletion: %w", err)
	}

	return affected > 0, nil
}

// History is a previously sent alert.
type History struct {
	SentAt    time.Time `json:"sent_at"`
	Key       string    `json:"key"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	Body      string    `json:"body,omitempty"`
	Delivered int       `json:"delivered"`
}

// RecentAlerts returns what has been sent lately.
func RecentAlerts(ctx context.Context, db *store.DB, limit int) (history []History, err error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	rows, err := db.Reader().QueryContext(ctx, `
		SELECT key, severity, title, body, sent_at, delivered
		FROM notify_history ORDER BY sent_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("reading alert history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			h      History
			sentAt int64
		)
		if err = rows.Scan(&h.Key, &h.Severity, &h.Title, &h.Body, &sentAt, &h.Delivered); err != nil {
			return nil, fmt.Errorf("scanning alert: %w", err)
		}

		h.SentAt = time.Unix(sentAt, 0)
		history = append(history, h)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating alerts: %w", err)
	}

	return history, nil
}
