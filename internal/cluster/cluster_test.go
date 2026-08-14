package cluster_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MmTKya/DNS/internal/cluster"
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

// fakePeer serves the replication endpoints the way a real node does.
type fakePeer struct {
	server   *httptest.Server
	state    atomic.Pointer[cluster.State]
	archive  []byte
	signer   func([]byte) string
	requests atomic.Int64
	down     atomic.Bool
}

func newFakePeer(t *testing.T, state cluster.State, archive []byte, signer func([]byte) string) *fakePeer {
	t.Helper()

	p := &fakePeer{archive: archive, signer: signer}
	p.state.Store(&state)

	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.requests.Add(1)

		if p.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		switch r.URL.Path {
		case "/api/cluster/state":
			_ = json.NewEncoder(w).Encode(p.state.Load())
		case "/api/cluster/snapshot":
			if p.signer != nil {
				w.Header().Set("X-SedDNS-Signature", p.signer(p.archive))
			}
			_, _ = w.Write(p.archive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(p.server.Close)

	return p
}

func (p *fakePeer) setState(state cluster.State) { p.state.Store(&state) }

func TestReplicaPullsFromPrimary(t *testing.T) {
	t.Parallel()

	const token = "shared-token"
	archive := []byte("pretend-this-is-an-archive")

	// The signer stands in for the primary, which signs with the same token.
	signer := func(body []byte) string {
		signing := cluster.New(openDB(t), cluster.Config{NodeID: "primary", Token: token}, discard())

		return signing.SignSnapshot(body)
	}

	peer := newFakePeer(t, cluster.State{
		NodeID: "primary", Role: cluster.RolePrimary, Revision: 7, Hash: "abc", Healthy: true,
	}, archive, signer)

	var applied atomic.Value
	replica := cluster.New(openDB(t), cluster.Config{
		NodeID: "replica",
		Token:  token,
		Role:   cluster.RoleReplica,
		Peers:  []string{peer.server.URL},
		Apply: func(_ context.Context, data []byte) error {
			applied.Store(string(data))

			return nil
		},
	}, discard())

	runFor(t, replica, 2*cluster.HeartbeatInterval)

	if got, _ := applied.Load().(string); got != string(archive) {
		t.Errorf("applied %q, want the primary's snapshot", got)
	}

	status := replica.Status(t.Context())
	if !status.PrimaryReachable {
		t.Error("the primary should be reported as reachable")
	}
	if status.LastSync.IsZero() {
		t.Error("a successful sync should be recorded")
	}
	if revision, hash := replica.Snapshot(); revision != 7 || hash != "abc" {
		t.Errorf("snapshot = %d/%s, want the primary's 7/abc", revision, hash)
	}
}

func TestReplicaRefusesAnUnsignedSnapshot(t *testing.T) {
	t.Parallel()

	// A peer that cannot produce a valid signature must not be able to install
	// configuration — that would let anyone who reaches the port turn
	// filtering off.
	peer := newFakePeer(t, cluster.State{
		NodeID: "primary", Role: cluster.RolePrimary, Revision: 2, Hash: "xyz", Healthy: true,
	}, []byte("malicious-archive"), func([]byte) string { return "not-the-right-signature" })

	var applied atomic.Bool
	replica := cluster.New(openDB(t), cluster.Config{
		NodeID: "replica",
		Token:  "shared-token",
		Role:   cluster.RoleReplica,
		Peers:  []string{peer.server.URL},
		Apply: func(context.Context, []byte) error {
			applied.Store(true)

			return nil
		},
	}, discard())

	runFor(t, replica, 2*cluster.HeartbeatInterval)

	if applied.Load() {
		t.Fatal("a snapshot with a bad signature was applied")
	}
	if status := replica.Status(t.Context()); status.LastSyncError == "" {
		t.Error("the refusal should be visible as a sync error")
	}
}

func TestNoResyncWhenNothingChanged(t *testing.T) {
	t.Parallel()

	const token = "shared-token"
	archive := []byte("archive")
	signer := func(body []byte) string {
		signing := cluster.New(openDB(t), cluster.Config{NodeID: "primary", Token: token}, discard())

		return signing.SignSnapshot(body)
	}

	peer := newFakePeer(t, cluster.State{
		NodeID: "primary", Role: cluster.RolePrimary, Revision: 3, Hash: "same", Healthy: true,
	}, archive, signer)

	var applies atomic.Int64
	replica := cluster.New(openDB(t), cluster.Config{
		NodeID: "replica",
		Token:  token,
		Role:   cluster.RoleReplica,
		Peers:  []string{peer.server.URL},
		Apply: func(context.Context, []byte) error {
			applies.Add(1)

			return nil
		},
	}, discard())

	runFor(t, replica, 4*cluster.HeartbeatInterval)

	// Reinstalling an unchanged configuration on every heartbeat would rebuild
	// a million-rule index every five seconds.
	if got := applies.Load(); got != 1 {
		t.Errorf("applied the snapshot %d times, want once", got)
	}
}

func TestReplicaPromotesWhenPrimaryDies(t *testing.T) {
	t.Parallel()

	peer := newFakePeer(t, cluster.State{
		NodeID: "primary", Role: cluster.RolePrimary, Revision: 1, Hash: "h", Healthy: true,
	}, []byte("archive"), nil)

	replica := cluster.New(openDB(t), cluster.Config{
		NodeID: "replica",
		Role:   cluster.RoleReplica,
		Peers:  []string{peer.server.URL},
		Apply:  func(context.Context, []byte) error { return nil },
	}, discard())

	runFor(t, replica, 2*cluster.HeartbeatInterval)
	if replica.Role() != cluster.RoleReplica {
		t.Fatal("the replica promoted itself while the primary was alive")
	}

	peer.down.Store(true)

	// Three missed beats: one is a slow network, three is a dead node.
	runFor(t, replica, cluster.FailoverAfter+2*cluster.HeartbeatInterval)

	if replica.Role() != cluster.RolePrimary {
		t.Error("the replica did not take over after the primary went away")
	}
}

func TestLowerIDWinsTheTieBreak(t *testing.T) {
	t.Parallel()

	// Another replica with a lower id is present and will promote itself, so
	// this one must stand down rather than create a second primary.
	otherReplica := newFakePeer(t, cluster.State{
		NodeID: "aaa-replica", Role: cluster.RoleReplica, Healthy: true,
	}, nil, nil)

	node := cluster.New(openDB(t), cluster.Config{
		NodeID: "zzz-replica",
		Role:   cluster.RoleReplica,
		Peers:  []string{otherReplica.server.URL},
		Apply:  func(context.Context, []byte) error { return nil },
	}, discard())

	runFor(t, node, cluster.FailoverAfter+2*cluster.HeartbeatInterval)

	if node.Role() != cluster.RoleReplica {
		t.Error("both replicas would have promoted; the tie-break did not hold")
	}
}

func TestStandaloneNodeCostsNothing(t *testing.T) {
	t.Parallel()

	node := cluster.New(openDB(t), cluster.Config{NodeID: "solo"}, discard())

	status := node.Status(t.Context())
	if status.Enabled {
		t.Error("a node with no peers should not report a cluster")
	}
	if node.Role() != cluster.RolePrimary {
		t.Error("a lone node is its own primary")
	}
}

func TestRevisionSurvivesRestart(t *testing.T) {
	t.Parallel()

	db := openDB(t)
	ctx := t.Context()

	first := cluster.New(db, cluster.Config{NodeID: "node"}, discard())
	if err := first.BumpRevision(ctx, "hash-1"); err != nil {
		t.Fatalf("BumpRevision: %v", err)
	}
	if err := first.BumpRevision(ctx, "hash-2"); err != nil {
		t.Fatalf("BumpRevision: %v", err)
	}

	second := cluster.New(db, cluster.Config{NodeID: "node"}, discard())
	if err := second.Load(ctx); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// A revision that resets on restart would make a replica think the primary
	// had gone backwards and re-sync for no reason.
	if revision, _ := second.Snapshot(); revision != 2 {
		t.Errorf("revision after restart = %d, want 2", revision)
	}
}

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	node := cluster.New(openDB(t), cluster.Config{NodeID: "node", Token: "secret"}, discard())
	body := []byte("payload")

	if !node.Authenticate(node.SignSnapshot(body), body) {
		t.Error("a correctly signed body should authenticate")
	}
	if node.Authenticate("deadbeef", body) {
		t.Error("a wrong signature must not authenticate")
	}
	if node.Authenticate(node.SignSnapshot([]byte("other")), body) {
		t.Error("a signature over different content must not authenticate")
	}
}

// runFor runs a node's loop for the given duration.
func runFor(t *testing.T, node *cluster.Node, d time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		node.Run(ctx)
	}()

	<-done
}
