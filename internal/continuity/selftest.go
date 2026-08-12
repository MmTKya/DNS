package continuity

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// SelfTest asks this node to answer a question through its own listener.
//
// Any response counts, including SERVFAIL and REFUSED. The question is not
// "does the internet work" — an upstream outage is survivable and is already
// handled by serve-stale — but "is this process still turning queries into
// answers". A node that has stopped doing that is the one the watchdog and the
// virtual address exist to route around.
func SelfTest(addr string, probeName string) HealthCheck {
	if probeName == "" {
		probeName = "health-check.aegisdns.invalid."
	}

	return func(ctx context.Context) error {
		timeout := 2 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining > 0 && remaining < timeout {
				timeout = remaining
			}
		}

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(probeName), dns.TypeA)

		client := &dns.Client{Timeout: timeout}

		resp, _, err := client.ExchangeContext(ctx, msg, addr)
		if err != nil {
			return fmt.Errorf("resolver did not answer on %s: %w", addr, err)
		}
		if resp == nil {
			return fmt.Errorf("resolver returned an empty response on %s", addr)
		}

		return nil
	}
}
