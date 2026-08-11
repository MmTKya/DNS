// Command aegisdns runs an AegisDNS node: the DNS datapath and the admin
// control plane in one process.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MmTKya/DNS/internal/api"
	"github.com/MmTKya/DNS/internal/config"
	"github.com/MmTKya/DNS/internal/resolver"
	"github.com/MmTKya/DNS/internal/store"
	"github.com/MmTKya/DNS/internal/version"
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
	)
	flag.Parse()

	if *showVersion {
		info := version.Get()
		fmt.Printf("aegisdns %s (commit %s, built %s, %s)\n", info.Version, info.Commit, info.Date, info.GoVersion)

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

	dnsResolver := resolver.New(cfg, logger)
	if err = dnsResolver.Start(ctx); err != nil {
		return describeBindError(err, cfg.DNS.Listen)
	}

	httpServer, httpListener, err := newHTTPServer(ctx, cfg, db, dnsResolver, logger)
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
			reload(ctx, configPath, dnsResolver, logger)
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

// newHTTPServer binds the admin listener eagerly so that a port clash is
// reported at startup rather than swallowed by a background goroutine.
func newHTTPServer(
	ctx context.Context,
	cfg *config.Config,
	db *store.DB,
	dnsResolver *resolver.Resolver,
	logger *slog.Logger,
) (*http.Server, net.Listener, error) {
	handler := api.New(api.Deps{
		Config:   cfg,
		Store:    db,
		Resolver: dnsResolver,
		Logger:   logger,
		Started:  time.Now(),
	})

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

func reload(ctx context.Context, configPath string, dnsResolver *resolver.Resolver, logger *slog.Logger) {
	logger.Info("reloading configuration", "config", configPath)

	newCfg, err := loadConfig(configPath)
	if err != nil {
		logger.Error("reload aborted, keeping the running configuration", "err", err)

		return
	}

	if err = dnsResolver.Reload(ctx, newCfg); err != nil {
		logger.Error("reloading datapath", "err", err)

		return
	}

	logger.Info("configuration reloaded")
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
