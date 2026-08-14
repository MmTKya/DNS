// Package cluster keeps two or three nodes carrying the same configuration.
//
// There is no Raft here, and that is a decision rather than an omission. A
// two-node Raft cluster has no quorum: losing either member makes the survivor
// read-only, which is the exact opposite of what a household wants when the
// DNS server they depend on has just died. An election protocol that cannot
// make progress alone is worse than no election protocol.
//
// What is here instead: one node is primary, the others replicate its
// configuration, and a replica promotes itself if the primary stops
// heartbeating. Configuration is small and changes rarely, so a whole snapshot
// is sent rather than a log — there is nothing to replay and nothing to
// compact. Data-plane failover is a virtual address (see vrrp.go); this layer
// only agrees on what the nodes should be serving.
package cluster

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/MmTKya/DNS/internal/backup"
	"github.com/MmTKya/DNS/internal/store"
)

// Roles a node can hold.
const (
	RolePrimary = "primary"
	RoleReplica = "replica"
)

// Settings keys.
const (
	SettingNodeID   = "cluster.node_id"
	SettingRole     = "cluster.role"
	SettingToken    = "cluster.token"
	SettingRevision = "cluster.revision"
)

// Timing.
//
// A replica waits for three missed heartbeats before promoting itself. One
// missed beat is a slow network; three is a dead node. Promoting on the first
// miss is how two nodes end up both believing they are primary.
const (
	HeartbeatInterval = 5 * time.Second
	MissedBeats       = 3
	FailoverAfter     = HeartbeatInterval * MissedBeats
	requestTimeout    = 15 * time.Second
)

// Peer is another node in the cluster.
type Peer struct {
	ID  string `json:"id"`
	URL string `json:"url"`

	LastSeen  time.Time `json:"last_seen,omitzero"`
	Reachable bool      `json:"reachable"`
	Role      string    `json:"role,omitempty"`
	Revision  int64     `json:"revision"`
	Hash      string    `json:"hash,omitempty"`
	Error     string    `json:"error,omitempty"`
	Version   string    `json:"version,omitempty"`
}

// State is what a node reports about itself.
type State struct {
	NodeID   string `json:"node_id"`
	Role     string `json:"role"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
	Version  string `json:"version"`

	// Healthy is the node's own verdict on whether it is actually serving.
	// A primary that cannot resolve should not be replicated from, and should
	// not keep a replica from taking over.
	Healthy bool `json:"healthy"`
}

// Status is the whole cluster as this node sees it.
type Status struct {
	Self    State  `json:"self"`
	Peers   []Peer `json:"peers"`
	Enabled bool   `json:"enabled"`

	// PrimaryReachable is false when a replica has lost the primary; the panel
	// shows it, because it is the moment a person cares about.
	PrimaryReachable bool      `json:"primary_reachable"`
	LastSync         time.Time `json:"last_sync,omitzero"`
	LastSyncError    string    `json:"last_sync_error,omitempty"`
}

// HealthFunc reports whether this node is actually serving.
type HealthFunc func(ctx context.Context) bool

// ApplyFunc installs a configuration snapshot received from the primary.
type ApplyFunc func(ctx context.Context, archive []byte) error

// Node participates in a cluster.
type Node struct {
	db     *store.DB
	logger *slog.Logger
	client *http.Client

	nodeID  string
	token   string
	version string

	health HealthFunc
	apply  ApplyFunc

	mu            sync.RWMutex
	role          string
	peers         []Peer
	revision      int64
	hash          string
	lastSync      time.Time
	lastSyncError string
	lastPrimaryOK time.Time
	enabled       bool
}

// Config configures a node.
type Config struct {
	NodeID  string
	Token   string
	Version string
	Role    string
	Peers   []string
	Health  HealthFunc
	Apply   ApplyFunc
}

// New creates a cluster node.  A node with no peers is a cluster of one and
// costs nothing.
func New(db *store.DB, cfg Config, logger *slog.Logger) *Node {
	if logger == nil {
		logger = slog.Default()
	}

	role := cfg.Role
	if role != RoleReplica {
		role = RolePrimary
	}

	n := &Node{
		db:      db,
		logger:  logger.With("component", "cluster"),
		client:  &http.Client{Timeout: requestTimeout},
		nodeID:  cfg.NodeID,
		token:   cfg.Token,
		version: cfg.Version,
		role:    role,
		health:  cfg.Health,
		apply:   cfg.Apply,
		enabled: len(cfg.Peers) > 0,
	}

	for _, url := range cfg.Peers {
		n.peers = append(n.peers, Peer{URL: url})
	}

	return n
}

// Role returns this node's current role.
func (n *Node) Role() string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.role
}

// Status returns the cluster as this node sees it.
func (n *Node) Status(ctx context.Context) Status {
	n.mu.RLock()
	defer n.mu.RUnlock()

	peers := make([]Peer, len(n.peers))
	copy(peers, n.peers)

	return Status{
		Enabled:          n.enabled,
		Self:             n.state(ctx),
		Peers:            peers,
		PrimaryReachable: n.role == RolePrimary || time.Since(n.lastPrimaryOK) < FailoverAfter,
		LastSync:         n.lastSync,
		LastSyncError:    n.lastSyncError,
	}
}

// state builds this node's self-report.  The caller holds the lock.
func (n *Node) state(ctx context.Context) State {
	healthy := true
	if n.health != nil {
		healthy = n.health(ctx)
	}

	return State{
		NodeID:   n.nodeID,
		Role:     n.role,
		Revision: n.revision,
		Hash:     n.hash,
		Version:  n.version,
		Healthy:  healthy,
	}
}

// SetSnapshot records the configuration state this node is serving.
//
// The revision is monotonic and the hash identifies the content, so a replica
// can tell "nothing changed" from "changed back" — a revision alone cannot.
func (n *Node) SetSnapshot(revision int64, hash string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.revision = revision
	n.hash = hash
}

// Snapshot returns the current revision and hash.
func (n *Node) Snapshot() (revision int64, hash string) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	return n.revision, n.hash
}

// BumpRevision records that the configuration changed.
func (n *Node) BumpRevision(ctx context.Context, hash string) error {
	n.mu.Lock()
	n.revision++
	n.hash = hash
	revision := n.revision
	n.mu.Unlock()

	if err := n.db.SetSetting(ctx, SettingRevision, fmt.Sprint(revision)); err != nil {
		return fmt.Errorf("recording revision: %w", err)
	}

	return nil
}

// Load restores the node's identity and revision from the database.
func (n *Node) Load(ctx context.Context) error {
	if value, ok, err := n.db.GetSetting(ctx, SettingRevision); err != nil {
		return err
	} else if ok {
		var revision int64
		if _, scanErr := fmt.Sscan(value, &revision); scanErr == nil {
			n.mu.Lock()
			n.revision = revision
			n.mu.Unlock()
		}
	}

	return nil
}

// Run keeps this node in step with its peers until ctx is cancelled.
func (n *Node) Run(ctx context.Context) {
	n.mu.RLock()
	enabled := n.enabled
	n.mu.RUnlock()

	if !enabled {
		<-ctx.Done()

		return
	}

	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.tick(ctx)
		}
	}
}

func (n *Node) tick(ctx context.Context) {
	n.mu.RLock()
	role := n.role
	peers := make([]Peer, len(n.peers))
	copy(peers, n.peers)
	n.mu.RUnlock()

	updated := make([]Peer, len(peers))

	for i, peer := range peers {
		state, err := n.probe(ctx, peer.URL)

		updated[i] = peer
		if err != nil {
			// Identity is kept from the last successful probe. Forgetting who
			// a peer was because one request timed out is how two replicas
			// both decide they are the lowest id and both promote.
			updated[i].Reachable = false
			updated[i].Error = err.Error()

			continue
		}

		updated[i] = Peer{
			ID:        state.NodeID,
			URL:       peer.URL,
			LastSeen:  time.Now(),
			Reachable: true,
			Role:      state.Role,
			Revision:  state.Revision,
			Hash:      state.Hash,
			Version:   state.Version,
		}
	}

	n.mu.Lock()
	n.peers = updated
	n.mu.Unlock()

	if role == RoleReplica {
		n.followPrimary(ctx, updated)
	}
}

// followPrimary pulls configuration from a healthy primary, and promotes this
// node if there is not one.
func (n *Node) followPrimary(ctx context.Context, peers []Peer) {
	var primary *Peer
	for i := range peers {
		// A primary that says it is unhealthy is not one to copy from, and
		// must not stop this node from taking over.
		if peers[i].Reachable && peers[i].Role == RolePrimary {
			primary = &peers[i]

			break
		}
	}

	if primary == nil {
		n.considerPromotion(ctx)

		return
	}

	n.mu.Lock()
	n.lastPrimaryOK = time.Now()
	localRevision, localHash := n.revision, n.hash
	n.mu.Unlock()

	// Nothing to do when the content matches: comparing the hash as well as
	// the revision catches a primary that was restored from a backup and is
	// now on a lower number.
	if primary.Hash == localHash && primary.Revision == localRevision {
		return
	}

	if err := n.pull(ctx, primary.URL); err != nil {
		n.mu.Lock()
		n.lastSyncError = err.Error()
		n.mu.Unlock()

		n.logger.ErrorContext(ctx, "pulling configuration from the primary",
			"peer", primary.URL, "err", err)

		return
	}

	n.mu.Lock()
	n.revision = primary.Revision
	n.hash = primary.Hash
	n.lastSync = time.Now()
	n.lastSyncError = ""
	n.mu.Unlock()

	n.logger.InfoContext(ctx, "configuration replicated from the primary",
		"peer", primary.URL, "revision", primary.Revision)
}

// considerPromotion promotes this replica when the primary has been gone long
// enough.
//
// The tie-break is the node id, so two replicas that lose the primary at the
// same moment do not both promote: the lowest id wins, and the other stays a
// replica and follows it.
func (n *Node) considerPromotion(ctx context.Context) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.lastPrimaryOK.IsZero() {
		// Never seen a primary. Start the clock rather than promoting
		// immediately on a node that has only just booted.
		n.lastPrimaryOK = time.Now()

		return
	}

	since := time.Since(n.lastPrimaryOK)
	if since < FailoverAfter {
		return
	}

	for _, peer := range n.peers {
		// Role and id come from the last successful probe, so a peer that is
		// momentarily unreachable is still known to be a lower-id replica.
		if peer.ID == "" || peer.Role != RoleReplica || peer.ID >= n.nodeID {
			continue
		}

		if peer.Reachable {
			// It is there and it will promote itself. Standing aside is what
			// keeps this from becoming a second primary.
			return
		}

		// It is not answering us either. Either it is dead — in which case
		// this node should take over — or the network is partitioned and it is
		// happily serving the other half. Waiting out a second failover window
		// gives it the chance it is owed before risking two primaries.
		if since < 2*FailoverAfter {
			return
		}
	}

	n.role = RolePrimary
	n.logger.WarnContext(ctx, "primary has been unreachable, promoting this node",
		"missed_for", time.Since(n.lastPrimaryOK).Round(time.Second))

	if err := n.db.SetSetting(ctx, SettingRole, RolePrimary); err != nil {
		n.logger.ErrorContext(ctx, "recording promotion", "err", err)
	}
}

// Demote returns this node to a replica, which is what an operator does after
// the original primary comes back.
func (n *Node) Demote(ctx context.Context) error {
	n.mu.Lock()
	n.role = RoleReplica
	n.lastPrimaryOK = time.Now()
	n.mu.Unlock()

	return n.db.SetSetting(ctx, SettingRole, RoleReplica)
}

func (n *Node) probe(ctx context.Context, url string) (state State, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/api/cluster/state", nil)
	if err != nil {
		return State{}, fmt.Errorf("building request: %w", err)
	}
	n.authorise(req, nil)

	resp, err := n.client.Do(req)
	if err != nil {
		return State{}, fmt.Errorf("contacting peer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return State{}, fmt.Errorf("peer returned %s", resp.Status)
	}

	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&state); err != nil {
		return State{}, fmt.Errorf("decoding peer state: %w", err)
	}

	return state, nil
}

func (n *Node) pull(ctx context.Context, url string) error {
	if n.apply == nil {
		return fmt.Errorf("this node cannot apply a snapshot")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/api/cluster/snapshot", nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	n.authorise(req, nil)

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("contacting peer: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer returned %s", resp.Status)
	}

	archive, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return fmt.Errorf("reading snapshot: %w", err)
	}

	// The snapshot is verified before it is applied: an attacker who can reach
	// the replication port would otherwise be able to install any
	// configuration they liked, including one that turns filtering off.
	signature := resp.Header.Get(signatureHeader)
	if !n.verify(archive, signature) {
		return fmt.Errorf("snapshot signature does not match; refusing to apply it")
	}

	return n.apply(ctx, archive)
}

// signatureHeader carries the HMAC of a snapshot.
const signatureHeader = "X-SedDNS-Signature"

// authorise signs a request with the shared token.
//
// A shared secret rather than mTLS: two nodes in a house need to be paired by
// copying one string, and a certificate authority for that is a support burden
// nobody asked for. The token never travels; only what it signs does.
func (n *Node) authorise(req *http.Request, body []byte) {
	if n.token == "" {
		return
	}

	req.Header.Set(signatureHeader, n.sign(body))
	req.Header.Set("X-SedDNS-Node", n.nodeID)
}

func (n *Node) sign(body []byte) string {
	mac := hmac.New(sha256.New, []byte(n.token))
	mac.Write(body)

	return hex.EncodeToString(mac.Sum(nil))
}

func (n *Node) verify(body []byte, signature string) bool {
	if n.token == "" {
		// Without a token there is nothing to verify, and a cluster without a
		// token is only safe on a trusted link. Configuration says so.
		return true
	}

	expected := n.sign(body)

	return hmac.Equal([]byte(expected), []byte(signature))
}

// Authenticate checks an incoming replication request.
func (n *Node) Authenticate(signature string, body []byte) bool {
	return n.verify(body, signature)
}

// SnapshotArchive builds the payload a replica receives.
func (n *Node) SnapshotArchive(ctx context.Context, configPath string) (archive []byte, manifest backup.Manifest, err error) {
	var buf bytes.Buffer

	manifest, err = backup.Export(ctx, n.db, &buf, backup.Options{
		// A replica has to be able to authenticate the same people and reach
		// the same threat sources, so secrets travel.
		IncludeSecrets: true,
		ConfigPath:     configPath,
		NodeID:         n.nodeID,
		Version:        n.version,
	})
	if err != nil {
		return nil, backup.Manifest{}, err
	}

	return buf.Bytes(), manifest, nil
}

// SignSnapshot returns the signature for an outgoing snapshot.
func (n *Node) SignSnapshot(archive []byte) string { return n.sign(archive) }
