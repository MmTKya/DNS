// Package web serves the admin panel, compiled into the binary.
//
// The single-binary rule is not cosmetic: it is what makes the installer a
// download plus a systemd unit, and what makes the phase 6 self-update an
// atomic file swap instead of a package graph.
package web

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// distFS holds the built SPA.  The "all:" prefix keeps dotfiles, so the
// committed dist/.gitkeep makes this embed succeed even in a fresh checkout
// where the frontend has not been built yet; Handler falls back to a
// placeholder page in that case.  `make web` fills the directory in.
//
//go:embed all:dist
var distFS embed.FS

// indexFile is the SPA entry point.  Client-side routes fall back to it.
const indexFile = "index.html"

// Handler serves the panel: real files when they exist, index.html for
// everything else so that deep links into client-side routes work on reload.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return placeholderHandler("the embedded panel could not be opened")
	}

	if _, err = fs.Stat(sub, indexFile); err != nil {
		// A developer build without `make web`.  Say so plainly rather than
		// serving a 404 that looks like a routing bug.
		return placeholderHandler("the panel has not been built into this binary")
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = indexFile
		}

		if _, statErr := fs.Stat(sub, name); statErr != nil {
			if !errors.Is(statErr, fs.ErrNotExist) {
				http.Error(w, "reading panel asset", http.StatusInternalServerError)

				return
			}

			// Unknown path: hand it to the SPA router.  Hashed asset bundles
			// are immutable, so a miss there is a genuine 404 rather than a
			// route, and serving HTML for it would break caching.
			if strings.HasPrefix(name, "assets/") {
				http.NotFound(w, r)

				return
			}

			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}

		fileServer.ServeHTTP(w, r)
	})
}

// HasPanel reports whether a built panel is embedded in this binary.
func HasPanel() bool {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return false
	}

	_, err = fs.Stat(sub, indexFile)

	return err == nil
}

func placeholderHandler(reason string) http.Handler {
	body := []byte(`<!doctype html>
<meta charset="utf-8">
<title>AegisDNS</title>
<style>
  body { background:#0a0e14; color:#e6edf3; font:16px/1.6 ui-sans-serif,system-ui,sans-serif;
         display:grid; place-items:center; min-height:100vh; margin:0; }
  main { max-width:34rem; padding:2rem; }
  h1 { color:#22d3ee; font-size:1.5rem; margin:0 0 .5rem; }
  code { background:#111827; padding:.15rem .4rem; border-radius:.25rem; }
  a { color:#22d3ee; }
</style>
<main>
  <h1>AegisDNS</h1>
  <p>The API is running, but ` + reason + `.</p>
  <p>Build it with <code>make web &amp;&amp; make build</code>, or check
     <a href="/api/health">/api/health</a> directly.</p>
</main>
`)

	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}
