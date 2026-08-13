// Command aegisdns runs an SedDNS node: the DNS datapath and the admin
// control plane in one process.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MmTKya/DNS/internal/api"
	"github.com/MmTKya/DNS/internal/audit"
	"github.com/MmTKya/DNS/internal/auth"
	"github.com/MmTKya/DNS/internal/backup"
	"github.com/MmTKya/DNS/internal/clients"
	"github.com/MmTKya/DNS/internal/cluster"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/continuity"
	"github.com/MmTKya/DNS/internal/enforce"
	"github.com/MmTKya/DNS/internal/events"
	"github.com/MmTKya/DNS/internal/feeds"
	"github.com/MmTKya/DNS/internal/filter"
	"github.com/MmTKya/DNS/internal/intel"
	"github.com/MmTKya/DNS/internal/metrics"
	"github.com/MmTKya/DNS/internal/notify"
	"github.com/MmTKya/DNS/internal/policy"
	"github.com/MmTKya/DNS/internal/querylog"
	"github.com/MmTKya/DNS/internal/resolver"
	"github.com/MmTKya/DNS/internal/sgb"
	"github.com/MmTKya/DNS/internal/store"
	"github.com/MmTKya/DNS/internal/update"
	"github.com/MmTKya/DNS/internal/upstreams"
	"github.com/MmTKya/DNS/internal/version"
	"github.com/MmTKya/DNS/internal/vpn"
)

// shutdownTimeout bounds how long a stop is allowed to take before the process
// exits anyway.  systemd's default TimeoutStopSec is 90s, so this stays well
// inside it.
const shutdownTimeout = 15 * time.Second

func main() {
	var (
		configPath  = flag.String("config", config.DefaultPath, "path to the configuration file")
		checkConfig = flag.Bool("check-config", false, "validate the configuration and exit")
		showVersion = flag.Bool("version", false, "print version information and exit")
		applyUpdate = flag.String("apply-update", "",
			"install a staged update from this directory and exit (run as root by aegisdns-update.service)")
	)
	flag.Parse()

	if *showVersion {
		info := version.Get()
		fmt.Printf("aegisdns %s (commit %s, built %s, %s)\n", info.Version, info.Commit, info.Date, info.GoVersion)

		return
	}

	if *applyUpdate != "" {
		if err := installStagedUpdate(*applyUpdate, *configPath); err != nil {
			fmt.Fprintf(os.Stderr, "aegisdns: %v\n", err)
			os.Exit(1)
		}

		return
	}

	if err := run(*configPath, *checkConfig); err != nil {
		// The logger may not exist yet when this fires, so report on stderr.
		fmt.Fprintf(os.Stderr, "aegisdns: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath string, checkOnly bool) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	if checkOnly {
		fmt.Printf("configuration is valid (mode: %s)\n", cfg.Mode)

		return nil
	}

	logger := newLogger(cfg)
	slog.SetDefault(logger)

	// Signals are trapped before anything binds, so a Ctrl-C during a slow
	// startup still unwinds cleanly instead of leaving sockets behind.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	info := version.Get()
	logger.Info("starting aegisdns",
		"version", info.Version,
		"commit", info.Commit,
		"mode", cfg.Mode,
		"config", configPath,
	)

	db, err := store.Open(ctx, cfg.Store.Path)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			logger.Error("closing store", "err", closeErr)
		}
	}()

	if err = feeds.Seed(ctx, db); err != nil {
		return fmt.Errorf("seeding feed catalogue: %w", err)
	}

	filterEngine := filter.NewEngine()
	feedManager := feeds.NewManager(
		db,
		feeds.NewDownloader(feedCacheDir(cfg), version.Get().Version, logger),
		filterEngine,
		logger,
	)

	clientRegistry, err := clients.New(ctx, db, logger)
	if err != nil {
		return fmt.Errorf("loading clients: %w", err)
	}

	policyEngine := policy.New(filterEngine, cfg, logger)
	policyEngine.SetClientResolver(clientAdapter{registry: clientRegistry})

	queries := querylog.New(db, cfg, logger)

	enricher := intel.New(db, logger)
	if err = enricher.Configure(ctx); err != nil {
		return fmt.Errorf("configuring threat intelligence: %w", err)
	}

	suggestions := intel.NewQueue(db, enricher, logger)
	if err = suggestions.LoadAutoBlock(ctx); err != nil {
		return fmt.Errorf("loading the automatic-blocking setting: %w", err)
	}

	// Two observers: one records every query, the other offers names it has
	// not seen before to the threat-intelligence queue.
	policyEngine.SetObserver(observers{queries, intelObserver{queue: suggestions}})

	enforcer := enforce.New(cfg.Mode, logger)

	dnsResolver := resolver.New(cfg, logger)
	dnsResolver.SetHook(policyEngine.Hook())

	if err = dnsResolver.Start(ctx); err != nil {
		return describeBindError(err, cfg.DNS.Listen)
	}

	// Feeds are refreshed in the background: the node must answer queries
	// while it downloads, not after.
	go feedManager.Run(ctx, cfg.Filtering.UpdateInterval.Duration())

	// The national threat feed is an API rather than a file, so it has its own
	// syncer. It writes the same kind of cache file the compiler reads, and
	// only runs when the operator has enabled the feed.
	sgbSyncer := sgb.NewSyncer(
		sgb.NewClient(version.Get().Version, logger),
		db,
		feedCacheDir(cfg),
		logger,
	)
	go runSGBWhenEnabled(ctx, db, sgbSyncer, feedManager, logger)

	// Sightings are accumulated in memory and written on a timer, for the same
	// reason the query log batches: one write per query would wear out an SD
	// card.
	go clientRegistry.Run(ctx, time.Minute)

	// Threat lookups happen on their own schedule, paced to keep every
	// free-tier quota intact.
	go suggestions.Run(ctx)

	// The firewall is reconciled to the paused set rather than patched, so a
	// missed update corrects itself on the next pass instead of leaving a
	// device blocked that the panel says is not.
	go reconcileEnforcement(ctx, clientRegistry, enforcer, logger)

	// Buffered query rows are written on a timer, and flushed once more when
	// this returns, so a clean stop does not lose the last minute of history.
	logDone := make(chan struct{})
	go func() {
		defer close(logDone)
		queries.Run(ctx)
	}()
	defer func() {
		<-logDone
	}()

	authManager := auth.New(db, cfg.HTTP.SessionTTL.Duration(), logger)
	go authManager.Run(ctx)

	// The watchdog is fed only when the node proves it can still answer a
	// query through its own listener. A process that is alive and mute is the
	// failure this exists to catch.
	notifier, underSystemd := continuity.NewNotifier()
	if underSystemd {
		selfTest := continuity.SelfTest(cfg.DNS.Listen[0], "")
		go continuity.NewWatchdog(notifier, selfTest, 0, logger).Run(ctx)

		if err = notifier.Ready(); err != nil {
			logger.Warn("announcing readiness to the service manager", "err", err)
		}
		defer func() { _ = notifier.Stopping() }()
	}

	if err = reportSetupState(ctx, authManager, cfg, logger); err != nil {
		return err
	}

	alerts := notify.New(db, logger)
	auditor := audit.New(db, logger)

	// Alerts are raised from the same background work that discovers the
	// problem, so a failed feed or a lost primary reaches a person without
	// anyone watching the panel.
	go raiseAlerts(ctx, db, alerts, feedManager, logger)

	vpnManager, vpnPublicKey, err := setupVPN(ctx, db, cfg, logger)
	if err != nil {
		return err
	}
	if vpnManager != nil {
		go vpnManager.Run(ctx, 30*time.Second)
	}

	// A node with no peers is a cluster of one: the machinery is present, costs
	// nothing, and is ready the moment a second node is added.
	applyStoredUpstreams(ctx, db, cfg, logger)

	// Watches whatever the node is currently forwarding to, read fresh each
	// time: adopting a measurement swaps the resolvers underneath, and a
	// monitor still timing the old ones would mislead precisely when someone
	// is looking at it to find out what is wrong.
	upstreamMonitor := upstreams.NewMonitor(func() (primary, fallback []string) {
		if stored, storedFallback, err := upstreams.Effective(ctx, db); err == nil && stored != nil {
			return stored, storedFallback
		}

		return cfg.DNS.Upstreams, cfg.DNS.Fallbacks
	})
	dnsResolver.OnRescue(upstreamMonitor.RecordRescue)
	go upstreamMonitor.Run(ctx)

	// What the node noticed, kept where someone can read it. Everything here
	// was previously only in the journal, which meant the answer to "why did
	// that page not open" was a shell session on the machine.
	eventLog := events.NewRecorder(db, logger)
	go eventLog.Run(ctx)

	dnsResolver.OnEvent(func(kind, subject, detail string) {
		severity := events.SeverityInfo
		if kind == events.KindRebindBlocked {
			// Either an attack or a misconfiguration, and both are things
			// someone needs to see rather than discover as a site that will
			// not load.
			severity = events.SeverityWarning
		}

		eventLog.Record(kind, severity, subject, detail)
	})

	// A blocklist that stops updating is protection quietly getting worse,
	// and nothing else in the panel would say so.
	feedManager.OnEvent(func(kind, subject, detail string) {
		eventLog.Record(kind, events.SeverityWarning, subject, detail)
	})

	clusterNode := cluster.New(db, cluster.Config{
		NodeID:  nodeID(ctx, db, logger),
		Version: version.Get().Version,
		Token:   cfg.Cluster.Token,
		Role:    cfg.Cluster.Role,
		Peers:   clusterPeers(cfg),
		Health: func(healthCtx context.Context) bool {
			return continuity.SelfTest(cfg.DNS.Listen[0], "")(healthCtx) == nil
		},
		Apply: applySnapshot(db, feedManager, logger),
	}, logger)
	if err = clusterNode.Load(ctx); err != nil {
		return fmt.Errorf("loading cluster state: %w", err)
	}
	go clusterNode.Run(ctx)

	httpServer, httpListener, err := newHTTPServer(ctx, apiDeps{
		config:       cfg,
		store:        db,
		resolver:     dnsResolver,
		auth:         authManager,
		feeds:        feedManager,
		filter:       filterEngine,
		clients:      clientRegistry,
		queryLog:     queries,
		intel:        enricher,
		suggestions:  suggestions,
		enforce:      enforcer,
		cluster:      clusterNode,
		configPath:   configPath,
		vpn:          vpnManager,
		vpnPublicKey: vpnPublicKey,
		notify:       alerts,
		audit:        auditor,
		update:       updateChecker(cfg, logger),
		reloadDatapath: func() {
			// The same path SIGHUP takes, so a change made in the panel and a
			// change made in the file cannot diverge in how they are applied.
			reload(ctx, configPath, db, dnsResolver, policyEngine, logger)
		},
		updateStaging: filepath.Join(filepath.Dir(cfg.Store.Path), "update"),
		metrics: metrics.Handler(func() metrics.Snapshot {
			return snapshot(ctx, queries, filterEngine, db, clientRegistry, clusterNode)
		}),
		logger: logger,
	})
	if err != nil {
		return errors.Join(err, dnsResolver.Shutdown(ctx))
	}

	// SIGHUP re-reads the configuration file.  The datapath is rebuilt from the
	// new snapshot; the HTTP listener is not moved, because doing so would drop
	// the panel session that asked for the reload.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	serverErr := make(chan error, 1)
	go func() {
		if serveErr := httpServer.Serve(httpListener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			serverErr <- serveErr
		}
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Info("shutdown requested")

			return shutdown(httpServer, dnsResolver, logger)

		case err = <-serverErr:
			return errors.Join(
				fmt.Errorf("admin http server: %w", err),
				dnsResolver.Shutdown(context.Background()),
			)

		case <-hup:
			reload(ctx, configPath, db, dnsResolver, policyEngine, logger)
		}
	}
}

// loadConfig reads the config file, tolerating a missing file only at the
// default location: a node that has never been configured should still start
// with sane defaults, but an explicitly named file that is not there is a
// mistake worth failing on.
func loadConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err == nil {
		return cfg, nil
	}

	if errors.Is(err, os.ErrNotExist) && path == config.DefaultPath {
		fmt.Fprintf(os.Stderr, "aegisdns: no config at %s, using built-in defaults\n", path)

		return config.Default(), nil
	}

	return nil, err
}

func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.SlogLevel()}

	var handler slog.Handler
	if cfg.Log.Format == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		// systemd captures stderr into the journal, which already timestamps
		// every line, but keeping the timestamp costs little and helps when
		// the binary is run by hand.
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}

// apiDeps groups what the control plane needs, so the parameter list of
// newHTTPServer does not grow a field per phase.
type apiDeps struct {
	config         *config.Config
	store          *store.DB
	resolver       *resolver.Resolver
	auth           *auth.Manager
	feeds          *feeds.Manager
	filter         *filter.Engine
	clients        *clients.Registry
	queryLog       *querylog.Log
	intel          *intel.Enricher
	suggestions    *intel.Queue
	enforce        *enforce.Enforcer
	cluster        *cluster.Node
	configPath     string
	vpn            *vpn.Manager
	vpnPublicKey   string
	notify         *notify.Notifier
	audit          *audit.Recorder
	update         *update.Checker
	upstreamHealth func() ([]upstreams.Health, uint64)
	updateStaging  string
	reloadDatapath func()
	metrics        http.Handler
	logger         *slog.Logger
}

// newHTTPServer binds the admin listener eagerly so that a port clash is
// reported at startup rather than swallowed by a background goroutine.
func newHTTPServer(ctx context.Context, d apiDeps) (*http.Server, net.Listener, error) {
	handler := api.New(api.Deps{
		Config:         d.config,
		Store:          d.store,
		Resolver:       d.resolver,
		Auth:           d.auth,
		Feeds:          d.feeds,
		Filter:         d.filter,
		Clients:        d.clients,
		QueryLog:       d.queryLog,
		Intel:          d.intel,
		Suggestions:    d.suggestions,
		Enforce:        d.enforce,
		Cluster:        d.cluster,
		ConfigPath:     d.configPath,
		VPN:            d.vpn,
		VPNPublicKey:   d.vpnPublicKey,
		Notify:         d.notify,
		Audit:          d.audit,
		Update:         d.update,
		UpdateStaging:  d.updateStaging,
		UpstreamHealth: d.upstreamHealth,
		ReloadDatapath: d.reloadDatapath,
		Metrics:        d.metrics,
		Version:        version.Get().Version,
		Logger:         d.logger,
		Started:        time.Now(),
	})

	cfg, logger := d.config, d.logger

	listener, err := net.Listen("tcp", cfg.HTTP.Listen)
	if err != nil {
		return nil, nil, fmt.Errorf("binding admin interface on %s: %w", cfg.HTTP.Listen, err)
	}

	srv := &http.Server{
		Handler: handler,
		// Generous but finite: the panel's live streams arrive in phase 1 and
		// will need their own exemption from the write timeout.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}

	logger.Info("admin interface listening", "addr", listener.Addr().String())

	return srv, listener, nil
}

func reload(
	ctx context.Context,
	configPath string,
	db *store.DB,
	dnsResolver *resolver.Resolver,
	policyEngine *policy.Engine,
	logger *slog.Logger,
) {
	logger.Info("reloading configuration", "config", configPath)

	newCfg, err := loadConfig(configPath)
	if err != nil {
		logger.Error("reload aborted, keeping the running configuration", "err", err)

		return
	}

	// The panel's resolvers are part of the running configuration, so a reload
	// that ignored them would quietly revert a change made a second earlier.
	applyStoredUpstreams(ctx, db, newCfg, logger)

	if err = dnsResolver.Reload(ctx, newCfg); err != nil {
		logger.Error("reloading datapath", "err", err)

		return
	}

	// The datapath took the new settings, so policy must follow; leaving it on
	// the old snapshot would apply the previous blocking mode to queries the
	// new listeners answer.
	policyEngine.Configure(newCfg)

	logger.Info("configuration reloaded")
}

// releasePublicKey is the Ed25519 key releases are signed with.
//
// Empty in this build: it is filled in by the release pipeline through
// -ldflags, and until then the updater verifies checksums only and says so.
var releasePublicKey = ""

// installStagedUpdate performs the privileged half of a self-update.
//
// It runs as root from a unit the service account cannot edit, which is the
// point: the resolver is exposed to the network and must not be able to
// rewrite the binary it will run next. Everything in the staging directory is
// verified again here, because that directory is writable by the very process
// this separation exists to contain.
func installStagedUpdate(dir, configPath string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	key, err := update.ParsePublicKey(releasePublicKey)
	if err != nil {
		return fmt.Errorf("the built-in release key is unusable: %w", err)
	}
	if len(key) == 0 {
		return update.ErrUnsigned
	}

	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating this binary: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	version, err := update.InstallStaged(ctx, dir, binary, configPath, key)

	// Cleared either way: a staged update that failed verification must not
	// sit there being retried every time the directory changes.
	if clearErr := update.ClearStaged(dir); clearErr != nil {
		logger.Warn("could not clear the staging directory", "err", clearErr, "dir", dir)
	}

	if err != nil {
		return fmt.Errorf("installing %s: %w", version, err)
	}

	logger.Info("update installed", "version", version, "binary", binary)

	return nil
}

// applyStoredUpstreams folds the operator's chosen resolvers into a freshly
// loaded configuration.
//
// The file keeps the defaults that shipped and the panel overrides them, which
// is what makes deleting the last one a way back rather than a way to break
// resolution: with nothing stored, this leaves the snapshot untouched.
func applyStoredUpstreams(ctx context.Context, db *store.DB, cfg *config.Config, logger *slog.Logger) {
	primary, fallback, err := upstreams.Effective(ctx, db)
	if err != nil {
		logger.WarnContext(ctx, "could not read the stored resolvers; keeping the ones in the config file", "err", err)

		return
	}
	if primary == nil {
		return
	}

	cfg.DNS.Upstreams = primary
	cfg.DNS.Fallbacks = fallback

	// Bootstrap resolves the hostnames of encrypted upstreams, so it cannot
	// point at a name. Keeping the file's plain addresses means someone who
	// switches to DoH does not have to know that.
	logger.InfoContext(ctx, "using the resolvers configured in the panel",
		"upstreams", len(primary), "fallbacks", len(fallback))
}

// clusterPeers returns the peers only when replication is switched on.
//
// A token and a peer list left in the file by someone who then turned
// clustering off should not quietly keep syncing.
func clusterPeers(cfg *config.Config) []string {
	if !cfg.Cluster.Enabled {
		return nil
	}

	return cfg.Cluster.Peers
}

// applySnapshot installs a configuration snapshot pulled from the primary.
//
// The archive has already had its signature checked against the shared token
// by the caller; this is what happens once it is trusted. The configuration
// file is deliberately not replaced: it carries the primary's listen
// addresses and its own cluster role, and writing those here would point the
// replica at itself and take it off the network.
func applySnapshot(db *store.DB, feedManager *feeds.Manager, logger *slog.Logger) cluster.ApplyFunc {
	return func(ctx context.Context, archive []byte) error {
		manifest, err := backup.Import(ctx, db, bytes.NewReader(archive), backup.ImportOptions{})
		if err != nil {
			return fmt.Errorf("importing the snapshot: %w", err)
		}

		logger.InfoContext(ctx, "snapshot applied",
			"from_node", manifest.NodeID, "from_version", manifest.Version)

		// Feeds, rules and clients all changed underneath the running node, so
		// the compiled ruleset is now describing the configuration this node
		// had a moment ago.
		if err = feedManager.Compile(ctx); err != nil {
			return fmt.Errorf("recompiling after the snapshot: %w", err)
		}

		return nil
	}
}

// updateChecker builds the self-update client, or nil when this build has no
// version to compare against.
func updateChecker(cfg *config.Config, logger *slog.Logger) *update.Checker {
	binary, err := os.Executable()
	if err != nil {
		logger.Warn("cannot locate this binary, so updates are unavailable", "err", err)

		return nil
	}

	key, err := update.ParsePublicKey(releasePublicKey)
	if err != nil {
		logger.Error("the built-in release key is unusable; updates will not be offered", "err", err)

		return nil
	}

	return update.New("MmTKya/DNS", version.Get().Version, binary, key, logger)
}

// snapshot gathers what Prometheus scrapes.
func snapshot(
	ctx context.Context,
	queries *querylog.Log,
	filterEngine *filter.Engine,
	db *store.DB,
	registry *clients.Registry,
	clusterNode *cluster.Node,
) metrics.Snapshot {
	stats := queries.Stats()
	filterStats := filterEngine.Stats()

	snap := metrics.Snapshot{
		QueriesTotal:   stats.Total,
		QueriesBlocked: stats.Blocked,
		QueriesCached:  stats.Cached,
		QueriesErrors:  stats.Errors,
		AvgLatencyMS:   stats.AvgElapsedMS,
		FilterRules:    filterStats.Rules,
		FilterBytes:    filterStats.ApproxBytes,
		ResolverUp:     true,
	}

	if pending, err := intel.PendingCount(ctx, db); err == nil {
		snap.SuggestionsOpen = pending
	}
	if list, err := registry.List(ctx); err == nil {
		snap.ClientsKnown = len(list)
	}
	if peers, err := vpn.List(ctx, db); err == nil {
		for _, peer := range peers {
			if peer.Online() {
				snap.VPNPeersOnline++
			}
		}
	}
	if clusterNode != nil {
		snap.ClusterUp = clusterNode.Status(ctx).PrimaryReachable
	}

	return snap
}

// raiseAlerts turns background problems into notifications.
//
// The conditions checked here are the ones a person can do something about. A
// node that alerts on everything trains its owner to ignore it.
func raiseAlerts(
	ctx context.Context,
	db *store.DB,
	notifier *notify.Notifier,
	feedManager *feeds.Manager,
	logger *slog.Logger,
) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		records, err := feeds.Enabled(ctx, db)
		if err != nil {
			logger.ErrorContext(ctx, "checking feeds for alerts", "err", err)

			continue
		}

		for _, record := range records {
			// A list that has not updated in two days is either broken
			// upstream or broken here, and either way it is quietly filtering
			// less than the operator thinks.
			if record.LastError == "" && (record.LastSuccessAt.IsZero() ||
				time.Since(record.LastSuccessAt) < 48*time.Hour) {
				continue
			}

			detail := record.LastError
			if detail == "" {
				detail = "it has not updated for more than two days"
			}

			if _, _, alertErr := notifier.Send(ctx, notify.Alert{
				Key:      "feed-stale:" + record.ID,
				Severity: notify.SeverityWarning,
				Title:    "Blocklist " + record.Name + " is not updating",
				Body:     detail,
			}); alertErr != nil {
				logger.ErrorContext(ctx, "raising a feed alert", "feed", record.ID, "err", alertErr)
			}
		}

		if pending, countErr := intel.PendingCount(ctx, db); countErr == nil && pending > 0 {
			if _, _, alertErr := notifier.Send(ctx, notify.Alert{
				Key:      "suggestions-pending",
				Severity: notify.SeverityInfo,
				Title:    fmt.Sprintf("%d names are waiting for your decision", pending),
				Body:     "The node found names that look malicious and would like you to decide.",
			}); alertErr != nil {
				logger.ErrorContext(ctx, "raising a suggestion alert", "err", alertErr)
			}
		}
	}
}

// vpnKeySetting is where this node's tunnel private key lives.
const vpnKeySetting = "vpn.private_key"

// setupVPN brings up the tunnel manager, generating this node's key on first
// use.
//
// The key is generated once and kept: regenerating it would invalidate every
// enrolled device, which is a surprising thing for a restart to do.
func setupVPN(
	ctx context.Context,
	db *store.DB,
	cfg *config.Config,
	logger *slog.Logger,
) (manager *vpn.Manager, publicKey string, err error) {
	if !cfg.VPN.Enabled {
		return nil, "", nil
	}

	stored, ok, err := db.GetSetting(ctx, vpnKeySetting)
	if err != nil {
		return nil, "", fmt.Errorf("reading the tunnel key: %w", err)
	}

	var private vpn.Key
	if ok && stored != "" {
		if private, err = vpn.ParseKey(stored); err != nil {
			return nil, "", fmt.Errorf("the stored tunnel key is unusable: %w", err)
		}
	} else {
		if private, err = vpn.GeneratePrivateKey(); err != nil {
			return nil, "", err
		}
		if err = db.SetSetting(ctx, vpnKeySetting, private.String()); err != nil {
			return nil, "", fmt.Errorf("storing the tunnel key: %w", err)
		}
		logger.Info("generated this node's tunnel key")
	}

	public, err := vpn.PublicKey(private)
	if err != nil {
		return nil, "", err
	}

	manager = vpn.NewManager(db, nil, cfg.VPN.Interface, private, cfg.VPN.ListenPort, logger)

	if !manager.Available() {
		// Saying so beats a peer list that never connects and no explanation.
		logger.Warn("the tunnel is enabled but its interface does not exist; "+
			"bring it up with wg-quick or systemd-networkd and restart",
			"interface", cfg.VPN.Interface)

		return manager, public.String(), nil
	}

	if err = manager.Sync(ctx); err != nil {
		logger.Error("programming the tunnel", "err", err)
	}

	return manager, public.String(), nil
}

// nodeID returns this node's stable identity, minting one on first run.
//
// It is used as the cluster tie-break, so it has to survive restarts: a node
// that reinvents itself could promote alongside its peer after a reboot.
func nodeID(ctx context.Context, db *store.DB, logger *slog.Logger) string {
	if value, ok, err := db.GetSetting(ctx, cluster.SettingNodeID); err == nil && ok && value != "" {
		return value
	}

	id, err := os.Hostname()
	if err != nil || id == "" {
		id = fmt.Sprintf("node-%d", time.Now().UnixNano())
	}

	if err = db.SetSetting(ctx, cluster.SettingNodeID, id); err != nil {
		logger.Warn("recording node id", "err", err)
	}

	return id
}

// reportSetupState tells the operator, on the console, that the node is
// waiting to be claimed.
//
// A freshly installed node has no administrator, and the panel will hand the
// first person who reaches it the keys.  Saying so in the log is what turns
// that from a surprise into a step.
func reportSetupState(ctx context.Context, authManager *auth.Manager, cfg *config.Config, logger *slog.Logger) error {
	needsSetup, err := authManager.NeedsSetup(ctx)
	if err != nil {
		return fmt.Errorf("checking for an administrator: %w", err)
	}

	if needsSetup {
		logger.Warn("this node has no administrator yet — open the panel to create one",
			"panel", "http://"+cfg.HTTP.Listen,
		)
	}

	return nil
}

// runSGBWhenEnabled syncs the national threat feed while it stays enabled.
//
// It is polled rather than wired to a switch because enabling a feed is a
// database write from the panel, and a node that was restarted with the feed
// already on has to pick it up too.
func runSGBWhenEnabled(
	ctx context.Context,
	db *store.DB,
	syncer *sgb.Syncer,
	feedManager *feeds.Manager,
	logger *slog.Logger,
) {
	const (
		// Long enough that a full sync does not compete with startup, short
		// enough that a node restarted with the feed already on picks it up
		// without a five-minute silence.
		startupDelay  = 45 * time.Second
		checkInterval = 5 * time.Minute
	)

	wait := startupDelay
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()

			return
		case <-timer.C:
		}
		wait = checkInterval

		record, found, err := feeds.Get(ctx, db, sgb.FeedID)
		if err != nil {
			logger.ErrorContext(ctx, "checking the national threat feed", "err", err)

			continue
		}
		if !found || !record.Enabled {
			continue
		}

		result, err := syncer.Sync(ctx, false)
		if err != nil {
			if ctx.Err() == nil {
				logger.ErrorContext(ctx, "syncing the national threat feed", "err", err)
			}

			continue
		}

		// Only recompile when the export actually changed; a no-op delta
		// should not rebuild a 600,000-rule index.
		if result.Added > 0 || result.Removed > 0 {
			if err = feedManager.Compile(ctx); err != nil {
				logger.ErrorContext(ctx, "recompiling after a national feed sync", "err", err)
			}
		}
	}
}

// reconcileEnforcement keeps the firewall in step with the paused devices.
//
// In DNS-only mode there is nothing to enforce and this returns immediately,
// which is the honest behaviour: pausing there is a DNS refusal and the panel
// says so.
func reconcileEnforcement(
	ctx context.Context,
	registry *clients.Registry,
	enforcer *enforce.Enforcer,
	logger *slog.Logger,
) {
	if !enforcer.Capability().Enforced {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		list, err := registry.List(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.ErrorContext(ctx, "listing clients for enforcement", "err", err)
		} else {
			var targets []enforce.Target
			for _, c := range list {
				if !c.Paused {
					continue
				}

				// The hardware address is preferred where it is known: a
				// device that renews its lease onto a new address would
				// otherwise walk out of the block by doing nothing.
				target := enforce.Target{MAC: c.MAC}
				if addr, parseErr := netip.ParseAddr(c.Key); parseErr == nil {
					target.Addr = addr
				}
				targets = append(targets, target)
			}

			if err = enforcer.Apply(ctx, targets); err != nil && !errors.Is(err, enforce.ErrNotEnforceable) {
				logger.ErrorContext(ctx, "applying firewall rules", "err", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// observers fans one query out to several sinks.
type observers []policy.Observer

// Observe implements policy.Observer.
func (o observers) Observe(event policy.Event) {
	for _, sink := range o {
		sink.Observe(event)
	}
}

// intelObserver offers resolved names to the threat-intelligence queue.
//
// Only names that were allowed are considered: something already blocked needs
// no second opinion, and spending a rate-limited lookup on it would crowd out
// the names nobody has judged yet.
type intelObserver struct {
	queue *intel.Queue
}

// Observe implements policy.Observer.
func (o intelObserver) Observe(event policy.Event) {
	if event.Verdict != policy.VerdictAllowed || event.Host == "" {
		return
	}

	client := event.ClientID
	if client == "" && event.Client.IsValid() {
		client = event.Client.String()
	}

	o.queue.Consider(event.Host, client)
}

// clientAdapter presents the client registry to the policy engine.
//
// The two packages describe a client differently on purpose: policy needs only
// what a decision depends on, and keeping the interface that narrow is what
// stops the datapath from acquiring a dependency on how identity is stored.
type clientAdapter struct {
	registry *clients.Registry
}

// Identify implements policy.ClientResolver.
func (a clientAdapter) Identify(addr netip.Addr, clientID string) policy.Client {
	c := a.registry.Identify(addr, clientID)

	return policy.Client{
		Key:              c.Key,
		Name:             c.Name,
		FilteringEnabled: c.FilteringEnabled,
		Paused:           c.Paused,
	}
}

// feedCacheDir keeps downloaded blocklists beside the database, so a single
// data directory holds everything the node accumulates.
func feedCacheDir(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Store.Path), "feeds")
}

func shutdown(httpServer *http.Server, dnsResolver *resolver.Resolver, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// DNS goes first: it is the service clients depend on, and draining it
	// while the admin interface still answers keeps the failure legible.
	err := dnsResolver.Shutdown(ctx)
	if err != nil {
		logger.Error("stopping datapath", "err", err)
	}

	if httpErr := httpServer.Shutdown(ctx); httpErr != nil {
		logger.Error("stopping admin interface", "err", httpErr)
		err = errors.Join(err, httpErr)
	}

	logger.Info("stopped")

	return err
}

// describeBindError turns the two failures every first-time installer hits —
// port 53 already taken by systemd-resolved or dnsmasq, and no permission to
// bind a privileged port — into instructions instead of an errno.
func describeBindError(err error, listen []string) error {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return fmt.Errorf("%w\n\n"+
			"Another DNS server already holds %v. On most systems this is systemd-resolved:\n"+
			"  sudo mkdir -p /etc/systemd/resolved.conf.d\n"+
			"  printf '[Resolve]\\nDNSStubListener=no\\n' | sudo tee /etc/systemd/resolved.conf.d/aegisdns.conf\n"+
			"  sudo systemctl restart systemd-resolved", err, listen)

	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fmt.Errorf("%w\n\n"+
			"Binding %v needs privileges. Run under the packaged systemd unit, which grants\n"+
			"CAP_NET_BIND_SERVICE, or use a port above 1024 for local testing.", err, listen)

	default:
		return fmt.Errorf("starting resolver: %w", err)
	}
}
