package intel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"time"
)

// TLS failure reasons.
//
// Distinct on purpose: a domain with nothing listening on 443 is not
// evidence of anything — plenty of legitimate names carry no web server at
// all — while a certificate a browser would reject is real evidence. Folding
// both into one "no valid TLS" bit is exactly the mistake that would keep
// this feature from doing what it was built for.
const (
	TLSNoResponse       = "no_response"
	TLSCertInvalid      = "cert_invalid"
	TLSHostnameMismatch = "hostname_mismatch"
)

// tlsDialTimeout is short: this always runs off the query path, but a slow
// or unresponsive host must not tie up the queue for long.
const tlsDialTimeout = 4 * time.Second

// checkTLS dials the domain on 443 and asks for a certificate a browser
// would trust, verified against the system's own root store.
//
// Never InsecureSkipVerify: the entire point is to find out whether a
// browser visiting this name would trust it, and skipping verification would
// make every answer "yes".
func checkTLS(ctx context.Context, domain string) (valid bool, reason string) {
	dialCtx, cancel := context.WithTimeout(ctx, tlsDialTimeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: tlsDialTimeout},
		Config:    &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12},
	}

	conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		var (
			hostErr *x509.HostnameError
			certErr *x509.CertificateInvalidError
			authErr *x509.UnknownAuthorityError
		)

		switch {
		case errors.As(err, &hostErr):
			return false, TLSHostnameMismatch
		case errors.As(err, &certErr), errors.As(err, &authErr):
			return false, TLSCertInvalid
		default:
			// Connection refused, timed out, no route, DNS gone stale since the
			// caller resolved it — none of these say anything about the
			// certificate, only that nothing answered on 443 just now.
			return false, TLSNoResponse
		}
	}
	_ = conn.Close()

	return true, ""
}
