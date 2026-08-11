# AegisDNS

A self-hosted DNS security node for the home network: it blocks ads, trackers
and malware at the DNS layer, and reports on what the network is actually
doing. One static binary — datapath, control plane and admin panel — targeting
Raspberry Pi 4/5 (arm64) and x86-64 Linux.

> **Status: phase 0 (skeleton).** The resolver resolves, the control plane
> reports on it and the panel is embedded. Filtering, threat intelligence,
> client tracking, HA, VPN and self-update are the phases that follow. See
> [the roadmap](#roadmap).

## Install

```bash
curl -sSL https://raw.githubusercontent.com/MmTKya/DNS/main/deploy/install.sh | sudo bash
```

The installer prints exactly what it will change and waits for confirmation.
It verifies the download against the release checksums — and, if `cosign` is
present, against the release signature — before installing anything. Re-running
it upgrades in place and keeps your configuration.

Prefer to read it first:

```bash
curl -sSL -o install.sh https://raw.githubusercontent.com/MmTKya/DNS/main/deploy/install.sh
less install.sh
sudo bash install.sh --dry-run
```

## Deployment modes

This is the decision everything else follows from, so the panel states it on
every screen:

| | **DNS-only** (default) | **Gateway** (phase 3) |
|---|---|---|
| Setup | Point your router's DHCP at the node | Route all traffic through the node |
| Sees | DNS queries | Every packet |
| Blocking ads and malware | Yes | Yes |
| Per-client visited sites | Yes | Yes |
| Bandwidth per client | No — not measurable from DNS | Yes, real byte counters |
| Time spent on a site | Estimated from query clustering | Real session timing |
| "Cut this device off" | DNS refusal only; a device with a hardcoded IP or its own DoH walks around it | Real, enforced at the forwarding layer |

A DNS server sees names, not bytes. Anything the panel cannot actually measure
in the current mode is labelled as an estimate or disabled with a note — it is
never quietly approximated.

## Configuration

`/etc/aegisdns/aegisdns.yaml`, documented in
[deploy/aegisdns.example.yaml](deploy/aegisdns.example.yaml). Every key is
optional; unknown keys are rejected at startup rather than ignored, so a typo
never silently reverts a security setting.

```bash
aegisdns --config /etc/aegisdns/aegisdns.yaml --check-config   # validate
systemctl reload aegisdns                                      # apply (SIGHUP)
```

A reload rebuilds the datapath from the new file. If the new configuration
cannot bind, the previous one is restored and the node keeps resolving.

## Development

Requires Go 1.23+ and Node 20+.

```bash
make dev-config     # writes dev.yaml: DNS on 127.0.0.1:5353, panel on :8080
make build          # builds the panel, then the binary
make run            # runs against dev.yaml, no privileges needed
make test           # go test ./...
make lint           # go vet, gofmt check, panel typecheck
make snapshot       # cross-compile every release target
```

For panel work, run the binary and `npm run dev` in `web/` side by side; Vite
proxies `/api` to the running backend, so the panel talks to a live resolver.

```
cmd/aegisdns        entrypoint and process lifecycle
internal/config     the single source of truth, including DeploymentMode
internal/resolver   the datapath: dnsproxy, cache, the filter hook
internal/store      SQLite (WAL) and migrations
internal/api        REST API and panel serving
internal/web        the embedded panel
web/                React + TypeScript + Vite source
deploy/             installer, systemd unit, example config
```

The datapath and the control plane are kept apart on purpose. The resolver is
stateless with respect to configuration: it is rebuilt from an immutable
snapshot rather than mutated. That is what makes hot reload, cluster
replication and atomic updates possible later.

## Roadmap

| Phase | | Status |
|---|---|---|
| 0 | Skeleton: resolver, store, API, panel, packaging | **done** |
| 1 | Filtering, feeds, encrypted transports, query log, auth, live panel | next |
| 2 | Threat intelligence, the USOM/SGB connector, "should I block this?" | |
| 3 | Client tracking, gateway mode, real bandwidth, enforcement | |
| 4 | HA: VRRP failover, config replication, watchdog, backup/restore | |
| 5 | WireGuard, Cloudflare Tunnel, egress profiles | |
| 6 | Notifications, signed self-update, RBAC and audit log | |

## Licence

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Built on
permissively licensed components (dnsproxy, miekg/dns, chi, modernc sqlite);
no GPL or EUPL code from comparable products is present.

Blocklist and threat-intelligence feeds carry their own licences. Feeds that
forbid commercial use are never enabled by default.
