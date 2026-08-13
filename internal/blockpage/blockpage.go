// Package blockpage explains a block to the person who hit it.
//
// Answering a blocked name with 0.0.0.0 makes the browser fail with a
// connection error, which tells someone that something is broken but not what
// or why. Pointing the name at this node instead means the request arrives
// here and can be answered with a sentence.
//
// The honest limitation, stated here because it decides half of what this is
// worth: almost everything is HTTPS, and a browser asking for
// https://ads.example.com will be handed a certificate for something else. It
// shows a certificate warning, not this page. The page is reached on plain
// HTTP, and on the HTTPS attempts where a browser falls back. Every product
// that does this has the same limit; none of them can fix it without
// installing a certificate authority on every device in the house.
package blockpage

import (
	"context"

	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Reason is what the resolver knows about a block.
type Reason struct {
	// Host is the name that was blocked.
	Host string

	// Source is the list or rule that stopped it.
	Source string

	// MatchedDomain is the pattern that matched, when it differs from Host —
	// a subdomain blocked by a rule on its parent, most often.
	MatchedDomain string
}

// Lookup answers why a name would be blocked, or reports that it would not.
type Lookup func(host string) (reason Reason, blocked bool)

// Release adds an exception for a name.
type Release func(ctx context.Context, host string) error

// Config controls the server.
type Config struct {
	// Listen is the address to serve on, normally ":80".
	Listen string

	// AllowRelease puts a button on the page that unblocks the name.
	//
	// Off by default, and the setting says why: this page is reachable by
	// anything on the network, so a button here is an unblock that needs no
	// password. That is the right trade for one household and the wrong one
	// where the blocking is a rule for somebody rather than a preference.
	AllowRelease bool

	// PanelURL is where someone is sent to do it properly.
	PanelURL string
}

// Server answers requests for blocked names.
type Server struct {
	cfg     Config
	lookup  Lookup
	release Release
	logger  *slog.Logger
	http    *http.Server
}

// New builds the server.
func New(cfg Config, lookup Lookup, release Release, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Listen == "" {
		cfg.Listen = ":80"
	}

	s := &Server{cfg: cfg, lookup: lookup, release: release, logger: logger.With("component", "blockpage")}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	mux.HandleFunc("/__seddns/release", s.handleRelease)

	s.http = &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return s
}

// ServeHTTP exposes the routing, so the pages can be exercised without
// binding a privileged port.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.http.Handler.ServeHTTP(w, r)
}

// Run serves until the context is cancelled.
//
// A failure to bind is logged rather than fatal: port 80 is often taken, and a
// node that refused to start because it could not explain its blocks would be
// trading the thing that matters for the thing that is nice to have.
func (s *Server) Run(ctx context.Context) {
	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shutdownCtx)
	}()

	s.logger.InfoContext(ctx, "serving the block page", "listen", s.cfg.Listen)

	if err := s.http.ListenAndServe(); err != nil && ctx.Err() == nil {
		s.logger.WarnContext(ctx, "the block page is not available; blocked names will fail without explaining why",
			"listen", s.cfg.Listen, "err", err)
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r)

	reason, blocked := Reason{Host: host}, false
	if s.lookup != nil {
		reason, blocked = s.lookup(host)
	}

	// Something reached this address for a name that is not blocked — a
	// misconfiguration, or someone typing the node's own address. Saying so is
	// more useful than showing a block page for a site that is not blocked.
	if !blocked {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_ = notBlockedTemplate.Execute(w, pageData{Host: host, PanelURL: s.cfg.PanelURL})

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Nothing here should be cached: a name unblocked a minute ago must not
	// keep showing this page.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)

	_ = pageTemplate.Execute(w, pageData{
		Host:          reason.Host,
		Source:        reason.Source,
		MatchedDomain: reason.MatchedDomain,
		AllowRelease:  s.cfg.AllowRelease && s.release != nil,
		PanelURL:      s.cfg.PanelURL,
	})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}
	if !s.cfg.AllowRelease || s.release == nil {
		http.Error(w, "releasing from this page is switched off", http.StatusForbidden)

		return
	}

	// The name comes from the Host header, never from the form.
	//
	// Taking it from a field made this forgeable: any page on the internet
	// could put a form on it that posts host=anything to this node and
	// unblocks whatever it liked, using the visitor's browser to do it. The
	// header cannot be set that way — a browser posting to this address sends
	// the name it actually navigated to, which in the intended flow is the
	// blocked site itself.
	host := hostOf(r)

	// A cross-site form would arrive with somebody else's origin on it. The
	// real one is same-origin with the blocked name.
	if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r.Host) {
		s.logger.WarnContext(r.Context(), "refused a release from another site",
			"origin", origin, "host", host)
		http.Error(w, "this request did not come from the block page", http.StatusForbidden)

		return
	}

	// Releasing a name that is not blocked writes a rule for nothing, and is
	// the shape of a request that is trying something.
	if s.lookup != nil {
		if _, blocked := s.lookup(host); !blocked {
			http.Error(w, "that name is not blocked", http.StatusBadRequest)

			return
		}
	}

	if err := s.release(r.Context(), host); err != nil {
		s.logger.ErrorContext(r.Context(), "releasing a blocked name", "host", host, "err", err)
		http.Error(w, "could not allow it: "+err.Error(), http.StatusInternalServerError)

		return
	}

	s.logger.InfoContext(r.Context(), "released from the block page", "host", host, "by", r.RemoteAddr)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = releasedTemplate.Execute(w, pageData{Host: host, PanelURL: s.cfg.PanelURL})
}

// sameOrigin reports whether an Origin header belongs to the host that was
// asked for.
func sameOrigin(origin, host string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}

	originHost := parsed.Host
	if h, _, splitErr := net.SplitHostPort(originHost); splitErr == nil {
		originHost = h
	}
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = h
	}

	return strings.EqualFold(originHost, host)
}

// hostOf returns the name that was asked for, without its port.
func hostOf(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	return strings.ToLower(strings.TrimSuffix(host, "."))
}

type pageData struct {
	Host          string
	Source        string
	MatchedDomain string
	PanelURL      string
	AllowRelease  bool
}

// The pages are one file each with their own styles: they are served to a
// browser that has just failed to load something, from a node whose panel it
// may never have seen, so nothing can be assumed to be cached or reachable.
const shared = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Host}} — blocked by SedDNS</title>
<style>
  :root { color-scheme: dark light; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    background: #06080c; color: #c9d3e0;
    font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    padding: 1.5rem;
  }
  main { max-width: 34rem; width: 100%; }
  .mark { display: flex; align-items: center; gap: .55rem; margin-bottom: 1.75rem; }
  .mark span { font-weight: 600; letter-spacing: -.01em; }
  .accent { color: #22d3ee; }
  h1 { font-size: 1.35rem; line-height: 1.3; margin: 0 0 .6rem; color: #e6edf6; font-weight: 600; }
  .host { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  p { margin: 0 0 1rem; color: #8b98a9; }
  .card {
    border: 1px solid #1e2733; border-radius: .75rem; padding: 1rem 1.15rem;
    background: rgba(255,255,255,.02); margin-bottom: 1.25rem;
  }
  .label { font-size: .7rem; text-transform: uppercase; letter-spacing: .08em; color: #5b6675; }
  .value { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #c9d3e0; word-break: break-all; }
  button {
    font: inherit; font-size: .9rem; font-weight: 500; cursor: pointer;
    background: #22d3ee; color: #06080c; border: 0; border-radius: .5rem; padding: .6rem 1.1rem;
  }
  button:hover { background: #0891b2; color: #e6edf6; }
  a { color: #22d3ee; }
  .quiet { font-size: .8rem; color: #5b6675; }
</style></head><body><main>
<div class="mark">
  <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
    <path d="M16 5.5 L25 9 v7.2 c0 5.4 -3.7 9.4 -9 11.3 c-5.3 -1.9 -9 -5.9 -9 -11.3 V9 z"
          fill="none" stroke="#22d3ee" stroke-width="2.1" stroke-linejoin="round"/>
    <circle cx="16" cy="15.5" r="2.6" fill="#22d3ee"/>
  </svg>
  <span>Sed<span class="accent">DNS</span></span>
</div>`

var pageTemplate = template.Must(template.New("blocked").Parse(shared + `
<h1>This site was blocked by SedDNS</h1>
<p class="host">{{.Host}}</p>

<div class="card">
  <div class="label">Why</div>
  <div class="value">{{if .Source}}{{.Source}}{{else}}one of your own rules{{end}}</div>
  {{if .MatchedDomain}}
  <div class="label" style="margin-top:.75rem">Matched on</div>
  <div class="value">{{.MatchedDomain}}</div>
  {{end}}
</div>

{{if .AllowRelease}}
<p>If you think this is wrong and you want to allow it, use the button below.</p>
<form method="post" action="/__seddns/release">
  <input type="hidden" name="host" value="{{.Host}}">
  <button type="submit">Allow {{.Host}}</button>
</form>
<p class="quiet" style="margin-top:1rem">
  Anyone on this network can do this. Reload the page after allowing it.
</p>
{{else}}
<p>
  If you think this is wrong, allow it from the panel{{if .PanelURL}} at
  <a href="{{.PanelURL}}">{{.PanelURL}}</a>{{end}}, under Your rules.
</p>
{{end}}
</main></body></html>`))

var releasedTemplate = template.Must(template.New("released").Parse(shared + `
<h1>{{.Host}} is allowed now</h1>
<p>The rule takes effect immediately. Reload the page you were trying to open — your
browser or device may hold the old answer for a minute.</p>
<p class="quiet">
  Remove the exception later from the panel{{if .PanelURL}} at
  <a href="{{.PanelURL}}">{{.PanelURL}}</a>{{end}}, under Your rules.
</p>
</main></body></html>`))

var notBlockedTemplate = template.Must(template.New("notblocked").Parse(shared + `
<h1>Nothing is blocking {{.Host}}</h1>
<p>This address answers for names SedDNS has blocked, and that one is not among them.
You have most likely reached it by typing the node's own address.</p>
<p class="quiet">
  The panel is{{if .PanelURL}} at <a href="{{.PanelURL}}">{{.PanelURL}}</a>{{else}} on port 8080{{end}}.
</p>
</main></body></html>`))
