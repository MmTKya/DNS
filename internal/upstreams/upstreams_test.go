package upstreams_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/MmTKya/DNS/internal/store"
	"github.com/MmTKya/DNS/internal/upstreams"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()

	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

// The rule the whole design rests on: nothing configured means the resolvers
// that shipped stay in use. Returning an empty list here instead would leave a
// node with nowhere to forward to.
func TestEffectiveIsNilUntilSomethingIsConfigured(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	primary, fallback, err := upstreams.Effective(t.Context(), db)
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if primary != nil || fallback != nil {
		t.Errorf("Effective() = %v, %v; want nil, nil so the defaults apply", primary, fallback)
	}
}

// Deleting the last one has to be a way back to the defaults, not a way to
// break resolution. Someone who tries an upstream and dislikes it must be able
// to undo that from the same screen.
func TestDeletingTheLastUpstreamRestoresTheDefaults(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	id, err := upstreams.Add(t.Context(), db, "8.8.8.8", upstreams.RolePrimary, "")
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	primary, _, err := upstreams.Effective(t.Context(), db)
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if len(primary) != 1 || primary[0] != "8.8.8.8" {
		t.Fatalf("Effective() primary = %v, want [8.8.8.8]", primary)
	}

	if err = upstreams.Delete(t.Context(), db, id); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	primary, _, err = upstreams.Effective(t.Context(), db)
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if primary != nil {
		t.Errorf("after deleting the last upstream Effective() = %v, want nil", primary)
	}
}

// Fallbacks alone are not a configuration: there would be nothing to ask
// first. Treating that as "no choice made" keeps the node resolving instead of
// sending every query down the path meant for an outage.
func TestFallbacksAloneDoNotReplaceTheDefaults(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	if _, err := upstreams.Add(t.Context(), db, "1.1.1.1", upstreams.RoleFallback, ""); err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	primary, fallback, err := upstreams.Effective(t.Context(), db)
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if primary != nil || fallback != nil {
		t.Errorf("Effective() = %v, %v; want nil, nil", primary, fallback)
	}
}

// A disabled upstream must not be handed to the resolver, but must survive so
// it can be switched back on.
func TestDisabledUpstreamsAreNotUsed(t *testing.T) {
	t.Parallel()

	db := openDB(t)

	id, err := upstreams.Add(t.Context(), db, "8.8.8.8", upstreams.RolePrimary, "")
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if _, err = upstreams.Add(t.Context(), db, "1.1.1.1", upstreams.RolePrimary, ""); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err = upstreams.SetEnabled(t.Context(), db, id, false); err != nil {
		t.Fatalf("SetEnabled() error = %v", err)
	}

	primary, _, err := upstreams.Effective(t.Context(), db)
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if len(primary) != 1 || primary[0] != "1.1.1.1" {
		t.Errorf("Effective() primary = %v, want [1.1.1.1]", primary)
	}

	list, err := upstreams.List(t.Context(), db)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 2 {
		t.Errorf("List() returned %d upstreams, want 2: a disabled one is still remembered", len(list))
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	valid := []string{
		"9.9.9.9",
		"8.8.8.8:53",
		"2620:fe::fe",
		"tls://dns.quad9.net",
		"https://dns.quad9.net/dns-query",
		"quic://dns.adguard-dns.com",
		"[/home.lan/]192.168.1.1",
	}
	for _, address := range valid {
		if _, err := upstreams.Validate(address); err != nil {
			t.Errorf("Validate(%q) = %v, want no error", address, err)
		}
	}

	invalid := []string{
		"",
		"not a resolver",
		// A bare hostname cannot be resolved without already having DNS,
		// which is the problem it would be configured to solve.
		"dns.quad9.net",
		"[/home.lan 192.168.1.1",
	}
	for _, address := range invalid {
		if _, err := upstreams.Validate(address); !errors.Is(err, upstreams.ErrInvalid) {
			t.Errorf("Validate(%q) = %v, want ErrInvalid", address, err)
		}
	}
}
