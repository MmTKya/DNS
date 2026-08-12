# AegisDNS

A self-hosted DNS security node for the home network: it blocks ads, trackers
and malware at the DNS layer, and reports on what the network is actually
doing. One static binary — datapath, control plane and admin panel — targeting
Raspberry Pi 4/5 (arm64) and x86-64 Linux.

> **Status: all six phases complete.** It filters, investigates, identifies,
> survives, travels, and now tells you when it needs attention and updates
> itself safely. See [the roadmap](#roadmap) and, importantly,
> [what has not been verified](#what-has-not-been-verified).

## What it does today

- **Blocks ads, trackers and malware** using curated blocklists — three are
  enabled out of the box (HaGeZi Pro, HaGeZi Threat Intelligence, CERT-PL),
  and the catalogue shows each list's licence, cadence and false-positive
  reputation before you enable it.
- **Answers every record type consistently.** A blocked name returns 0.0.0.0
  for A, :: for AAAA and NODATA with an SOA for everything else. Filtering
  only A records leaks the connection the block was meant to stop.
- **Explains itself.** Every match carries which list it came from and which
  rule inside it matched, so a wrong block is one click to find and one rule
  to override.
- **Streams live.** The panel shows queries as they happen over SSE, batched
  server-side into a few frames a second — never one message per query.
- **Keeps working when upstreams do not.** Expired cache entries are served
  while a refresh runs behind them (RFC 8767).
- **Uncloaks CNAME trackers.** A resolver sees the whole chain; a browser
  extension does not. A tracker hiding behind a subdomain of the site you are
  visiting is blocked at the link where it stops being that site.
- **Syncs Türkiye's national threat feed natively.** USOM's flat file was
  retired in 2026 and now redirects to an API; products still pointed at it are
  fetching nothing. This talks to the API: a full pass, hourly deltas keyed on
  the feed's own ids, and a daily reconcile so a cleaned-up site stops being
  blocked.
- **Investigates what it does not know.** Names your network resolves for the
  first time are checked against threat-intelligence sources and, if they look
  bad, brought to you as a card that says which sources agreed and why — with
  Block, Allow and Ignore. Automatic blocking exists and is off by default.
- **Names the devices on your network.** The hardware address is read from the
  kernel's neighbour table — no traffic has to pass through the node — and
  resolved against the full IEEE registry, so a device list says "Espressif"
  and "TP-Link" rather than four numbers. A phone rotating its address is
  labelled as such rather than being offered as a stable handle.
- **Survives its own failures.** systemd only counts the node as healthy while
  it can still resolve a query through its own listener, so a wedged resolver is
  restarted instead of being trusted. Two nodes share a virtual address and one
  configuration; either can take over. Everything a node is can be exported to
  one file and restored into another.
- **Follows you out of the house.** A WireGuard peer is enrolled by scanning a
  QR code, and its configuration points DNS at the node — so the filtering, the
  threat blocking and the per-device policy keep working on mobile data. Each
  device gets a fixed address inside the tunnel, which is a far better handle
  for policy than a LAN address that changes with every lease. Private keys are
  generated per device, shown once, and never stored on the node.
- **Says when it needs you.** Alerts reach email, a webhook, ntfy, Telegram or
  Discord, with a severity threshold per destination and a cooldown per
  condition — an alert that arrives every minute for an hour gets muted, and
  then the one that mattered arrives into a muted channel.
- **Records who changed what.** None of the comparable products keep an audit
  trail, and it is the difference between "the internet broke last Tuesday" and
  "someone disabled the malware list on Tuesday at nine".
- **Updates without bricking itself.** The archive is verified against a signed
  checksum file before it is unpacked — TLS says nothing about what is inside a
  download — the old binary is kept, and the new one has to start and validate
  its configuration before the old one is discarded.
- **Respects the hardware.** Rules cost about ten bytes each, so a
  600,000-entry ruleset fits in ~6 MB. Query rows are written in batches and
  rolled up into hourly aggregates, and can be kept in RAM only.

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
internal/resolver   the datapath: dnsproxy, cache, transports, the hook
internal/policy     the decision: what happens to a query, and the response
internal/filter     rule parsing and the compact matcher (~10 bytes a rule)
internal/feeds      the blocklist catalogue, downloader and compiler
internal/querylog   the live ring, batched writes and hourly rollups
internal/clients    device identity and per-device policy
internal/sgb        the national threat feed connector
internal/oui        the IEEE hardware registry, embedded
internal/neigh      the kernel neighbour table
internal/enforce    nftables rules for a paused device
internal/traffic    dwell-time inference and per-client byte counters
internal/backup     export and restore, and the replication payload
internal/cluster    heartbeat, promotion and configuration replication
internal/continuity the systemd watchdog and keepalived configuration
internal/vpn        WireGuard keys, peers and the kernel interface
internal/tunnel     panel exposure options and egress profiles
internal/notify     alert destinations, severity and deduplication
internal/audit      who changed what
internal/update     signed self-update with a health gate
internal/metrics    the Prometheus endpoint
internal/intel      threat sources, scoring and the review queue
internal/auth       argon2id, sessions, TOTP
internal/store      SQLite (WAL) and migrations
internal/api        REST API, SSE stream and panel serving
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
| 1 | Filtering, feeds, encrypted transports, query log, auth, live panel | **done** |
| 2 | Threat intelligence, the USOM/SGB connector, "should I block this?" | **done** |
| 3 | Devices and gateway mode: hardware identity, activity, accounting, enforcement | **in progress** |
| 4 | HA: VRRP failover, config replication, watchdog, backup/restore | **done** |
| 5 | WireGuard, Cloudflare Tunnel, egress profiles | **done** |
| 6 | Notifications, signed self-update, RBAC and audit log | **done** |

## What has not been verified

Development happened on a machine without root, without the WireGuard kernel
module, and with port 53 held by systemd-resolved. Everything below is
implemented and unit-tested, but has never run against the real thing:

- Binding port 53, the systemd unit, and the installer's actual install path.
- Programming a real WireGuard interface (keys, peers, addresses and generated
  configurations are tested; `wgctrl` against a live device is not).
- nftables enforcement and byte counters, against a real gateway.
- keepalived failover between two real nodes, and its takeover time.
- Cluster replication between two real nodes (it is tested against fake peers,
  including signature rejection, promotion and the tie-break).
- The systemd watchdog under real systemd (it is tested against a fake notify
  socket).
- The remote threat sources, which need API keys nobody has supplied here.
- Downloading and installing a real release (verification, install, rollback and
  the health gate are tested with generated keys and temporary files).

Treat the first Raspberry Pi deployment as the real integration test.

## Licence

Apache 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Built on
permissively licensed components (dnsproxy, miekg/dns, chi, modernc sqlite);
no GPL or EUPL code from comparable products is present.

Blocklist and threat-intelligence feeds carry their own licences. Feeds that
forbid commercial use are never enabled by default.
