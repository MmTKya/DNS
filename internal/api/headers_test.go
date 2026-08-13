package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The panel can redirect every name on the network. A page that frames it and
// a script injected into it are the two ways someone else ends up driving it.
func TestSecurityHeadersArePresent(t *testing.T) {
	t.Parallel()

	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}

	csp := rec.Header().Get("Content-Security-Policy")
	for _, directive := range []string{
		"script-src 'self'",      // an injected string stays a string
		"frame-ancestors 'none'", // nobody frames this
		"object-src 'none'",
		"base-uri 'none'",
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("the policy is missing %q: %s", directive, csp)
		}
	}

	// The panel's own scripts and stylesheet have to survive the policy, or
	// the header protects an empty page.
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Error("inline scripts are allowed, which is most of what the policy is for")
	}
}
