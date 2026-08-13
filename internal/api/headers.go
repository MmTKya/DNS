package api

import "net/http"

// securityHeaders sets what a browser needs to be told about this panel.
//
// None of these were here, and a panel that can redirect every name on the
// network is worth defending in depth: an injected script or a page that
// frames this one both end with somebody else driving it.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// Scripts only from here. This is the line that turns an injected
		// string into inert text rather than code.
		//
		// Styles allow inline because the build inlines some, and a style is
		// not an execution primitive. connect-src covers the live stream;
		// frame-ancestors 'none' is the modern half of X-Frame-Options.
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"font-src 'self' data:; "+
				"object-src 'none'; "+
				"base-uri 'none'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'")

		// The older half, for browsers that predate frame-ancestors.
		h.Set("X-Frame-Options", "DENY")

		// A response the browser decides is a script because it looks like one
		// is a way to smuggle code past the content type.
		h.Set("X-Content-Type-Options", "nosniff")

		// The panel's address is a private one and the paths name what is
		// being administered; neither belongs in a Referer header sent
		// elsewhere.
		h.Set("Referrer-Policy", "no-referrer")

		// Nothing here needs a camera, a microphone or a location.
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")

		next.ServeHTTP(w, r)
	})
}
