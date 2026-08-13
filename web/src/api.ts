// The typed surface of the SedDNS control plane.
//
// Keep these types in step with internal/api: they are the contract the panel
// is written against, and every phase adds to them rather than reshaping them.

export type ComponentStatus = "ok" | "degraded";

/** Mirrors config.DeploymentMode. Widgets that need real packet visibility
 *  must check this before claiming to measure anything. */
export type DeploymentMode = "dns-only" | "gateway";

export type Verdict = "allowed" | "blocked" | "rewritten" | "paused" | "error";

export interface Health {
  status: ComponentStatus;
  mode: DeploymentMode;
  version: string;
  uptime_seconds: number;
  resolver: { status: ComponentStatus; listen?: string[]; error?: string };
  database: { status: ComponentStatus; schema_version: number; error?: string };
  panel_embedded: boolean;
}

export interface User {
  id: number;
  username: string;
  role: "admin" | "readonly";
  totp_enabled: boolean;
  created_at: string;
  last_login_at?: string;
}

export interface AuthStatus {
  needs_setup: boolean;
  signed_in: boolean;
  user?: User;
}

export interface QueryEntry {
  id: number;
  time: string;
  client: string;
  client_id?: string;
  /** What the device is called: the name someone gave it, or the one it told
   *  the router. An address identifies a device only to whoever assigned it. */
  client_name?: string;
  host: string;
  qtype: string;
  verdict: Verdict;
  rule_source?: string;
  matched_domain?: string;
  upstream?: string;
  error?: string;
  elapsed_ms: number;
  rcode: number;
  answers: number;
  cached: boolean;
}

export interface QueryStats {
  total: number;
  blocked: number;
  allowed: number;
  rewritten: number;
  errors: number;
  cached: number;
  dropped: number;
  blocked_ratio: number;
  cache_ratio: number;
  avg_elapsed_ms: number;
  mode: string;
}

export interface FilterStats {
  rules: number;
  sources: { ID: string; Name: string }[] | null;
  approx_bytes: number;
  compiled_at: string;
}

/** What this deployment can honestly measure. Widgets read this instead of
 *  assuming; a DNS-only node sees names, not bytes. */
export interface Capabilities {
  query_visibility: boolean;
  dns_filtering: boolean;
  per_client_rules: boolean;
  bandwidth: boolean;
  live_connections: boolean;
  real_dwell_time: boolean;
  enforced_blocking: boolean;
}

export interface Stats {
  mode: DeploymentMode;
  queries?: QueryStats;
  filter?: FilterStats;
  capabilities: Capabilities;
}

export interface Client {
  id: number;
  key: string;
  key_type: string;
  name: string;
  tags?: string;
  mac?: string;
  vendor?: string;
  hostname?: string;
  /** A phone rotating its address: the handle is not stable across joins. */
  mac_randomised?: boolean;
  query_count: number;
  filtering_enabled: boolean;
  paused: boolean;
  known: boolean;
  created_at: string;
  last_seen?: string;
}

export interface Enforcement {
  mode: DeploymentMode;
  enforced: boolean;
  available: boolean;
  explanation: string;
}

export interface ClientList {
  clients: Client[] | null;
  mode: DeploymentMode;
  /** False in DNS-only mode: a pause there filters DNS, it does not cut the
   *  device off. The UI must not imply otherwise. */
  pause_is_enforced: boolean;
  enforcement?: Enforcement;
}

export interface SiteTime {
  site: string;
  duration_ns: number;
  sessions: number;
  queries: number;
  last_visit: string;
  estimated: boolean;
}

export interface ActivityReport {
  client: string;
  sites: SiteTime[] | null;
  from: string;
  to: string;
  /** Stated with the numbers, not buried in documentation. */
  caveats: string[];
}

export interface FeedCatalogEntry {
  id: string;
  name: string;
  description: string;
  homepage: string;
  category: string;
  license: string;
  commercial_use: boolean;
  default_on: boolean;
  approx_entries: number;
  high_false_positives: boolean;
}

export interface Feed {
  id: string;
  name: string;
  url: string;
  custom: boolean;
  enabled: boolean;
  rule_count: number;
  bytes: number;
  last_success_at?: string;
  last_error?: string;
  catalog?: FeedCatalogEntry;
}

export interface Upstream {
  id: number;
  address: string;
  /** primary resolvers answer every query; fallbacks only once all primaries
   *  have failed — not a preference order. */
  role: "primary" | "fallback";
  position: number;
  enabled: boolean;
  note?: string;
  created_at: string;
}

export interface UpstreamList {
  upstreams: Upstream[] | null;
  /** What the resolver is actually forwarding to right now. */
  in_use: string[] | null;
  fallbacks_used: string[] | null;
  /** True while nothing has been configured, so the shipped resolvers apply. */
  using_defaults: boolean;
  defaults: string[] | null;
}

export interface NodeEvent {
  id: number;
  at: string;
  kind: string;
  severity: "info" | "warning" | "error";
  subject?: string;
  detail?: string;
}

export interface UpstreamHealth {
  address: string;
  role: "primary" | "fallback";
  latency_ms: number;
  healthy: boolean;
  error?: string;
  checked_at?: string;
}

export interface UpstreamHealthReport {
  available: boolean;
  upstreams?: UpstreamHealth[] | null;
  /** Lookups that only succeeded because a second resolver was asked. A
   *  handful is one broken domain; a lot means the resolver in front is
   *  failing while the answers still arrive. */
  rescues?: number;
}

export interface BenchmarkResult {
  address: string;
  median_ms: number;
  resolved: number;
  probes: number;
  /** True only when every probe resolved. Sorted on before speed: a resolver
   *  that cannot answer for a country is not a faster one, it is a broken one. */
  usable: boolean;
  error?: string;
}

export interface Account {
  id: number;
  username: string;
  role: string;
  totp_enabled: boolean;
  recovery_codes_left: number;
  created_at: string;
  last_login_at?: string;
}

export interface TOTPEnrollment {
  /** Shown as text for anyone typing it into an authenticator by hand. */
  secret: string;
  /** The otpauth:// URI a QR code encodes. */
  url: string;
}

export interface UserRule {
  id: number;
  rule: string;
  comment?: string;
  enabled: boolean;
  created_at: string;

  /** What the engine will actually do, parsed server-side by the same parser
   *  the resolver uses. Never re-derived in the panel: a second reading of
   *  this syntax would drift from the one that enforces it. */
  action: "block" | "allow" | "rewrite";
  domain?: string;
  rewrite?: string;
  qtypes?: string;
  client?: string;
  subdomains: boolean;
  important: boolean;
}

export interface IntelFinding {
  source: string;
  category?: string;
  detail?: string;
  reference?: string;
  score: number;
  malicious: boolean;
}

export interface Suggestion {
  domain: string;
  score: number;
  reason: string;
  status: "pending" | "blocked" | "allowed" | "ignored";
  clients: string[];
  findings: IntelFinding[];
  query_count: number;
  first_seen: string;
  last_seen: string;
}

export interface IntelSource {
  name: string;
  configured: boolean;
}

export interface Peer {
  id: number;
  name: string;
  public_key: string;
  address: string;
  enabled: boolean;
  has_preshared_key: boolean;
  created_at: string;
  last_handshake?: string;
  rx_bytes: number;
  tx_bytes: number;
}

export interface Exposure {
  method: string;
  available: boolean;
  recommended: boolean;
  tradeoff: string;
}

export interface PeerList {
  peers: Peer[] | null;
  enabled: boolean;
  available: boolean;
  endpoint: string;
  public_key: string;
  exposures: Exposure[] | null;
}

export interface NewPeer {
  config: string;
  private_key: string;
  peer: Peer;
  qr_png?: string;
}

export interface ClusterPeer {
  id: string;
  url: string;
  reachable: boolean;
  role?: string;
  revision: number;
  hash?: string;
  version?: string;
  error?: string;
  last_seen?: string;
}

export interface ClusterStatus {
  enabled: boolean;
  self?: {
    node_id: string;
    role: string;
    revision: number;
    hash: string;
    version: string;
    healthy: boolean;
  };
  peers?: ClusterPeer[] | null;
  primary_reachable?: boolean;
  last_sync?: string;
  last_sync_error?: string;
}

export interface NotifyChannel {
  id: number;
  kind: string;
  name: string;
  min_severity: string;
  enabled: boolean;
  config: Record<string, unknown>;
  created_at: string;
  last_sent?: string;
  last_error?: string;
}

export interface AlertHistory {
  key: string;
  severity: string;
  title: string;
  body?: string;
  sent_at: string;
  delivered: number;
}

export interface AuditEntry {
  id: number;
  at: string;
  username: string;
  ip?: string;
  action: string;
  target?: string;
  detail?: string;
  success: boolean;
}

export interface UpdateStatus {
  current: string;
  latest?: string;
  notes?: string;
  error?: string;
  update_available?: boolean;
  managed: boolean;
  checked_at?: string;
}

export interface RestoreResult {
  manifest: {
    created_at: string;
    format_version: number;
    schema_version: number;
    contains_secrets: boolean;
    tables: Record<string, number>;
    hash: string;
  };
  dry_run: boolean;
  note: string;
}

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: init?.body ? { "Content-Type": "application/json", ...init?.headers } : init?.headers,
  });

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  const body = text ? JSON.parse(text) : {};

  if (!response.ok && response.status !== 503 && response.status !== 202) {
    throw new ApiError(body.error ?? `HTTP ${response.status}`, response.status);
  }

  return body as T;
}

export const api = {
  health: () => request<Health>("/api/health"),
  authStatus: () => request<AuthStatus>("/api/auth/status"),

  setup: (username: string, password: string) =>
    request<User>("/api/auth/setup", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  login: (username: string, password: string, code?: string) =>
    request<User & { totp_required?: boolean }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password, code }),
    }),

  logout: () => request<void>("/api/auth/logout", { method: "POST" }),

  stats: () => request<Stats>("/api/stats"),
  queryLog: (limit = 200) => request<{ entries: QueryEntry[] | null }>(`/api/querylog?limit=${limit}`),

  /** Stored history rather than the live ring, so a filter reaches past what
   *  is still in memory. */
  queryHistory: async (opts: { verdict?: string; host?: string; limit?: number }) => {
    const params = new URLSearchParams({ stored: "1", limit: String(opts.limit ?? 200) });
    if (opts.verdict) params.set("verdict", opts.verdict);
    if (opts.host) params.set("host", opts.host);

    const result = await request<{ entries: QueryEntry[] | null }>(`/api/querylog?${params}`);

    return result.entries ?? [];
  },

  events: async (kind = "") => {
    const params = new URLSearchParams({ limit: "200" });
    if (kind) params.set("kind", kind);

    return request<{ events: NodeEvent[] | null; counts: Record<string, number> }>(
      `/api/events?${params}`,
    );
  },

  clients: () => request<ClientList>("/api/clients"),
  updateClient: (key: string, patch: Partial<Pick<Client, "name" | "filtering_enabled" | "paused">>) =>
    request<Client>(`/api/clients/${encodeURIComponent(key)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),

  activity: (key: string, hours = 24) =>
    request<{ report: ActivityReport; measured: boolean }>(
      `/api/clients/${encodeURIComponent(key)}/activity?hours=${hours}`,
    ),

  feeds: () => request<{ feeds: Feed[] | null }>("/api/feeds"),
  setFeedEnabled: (id: string, enabled: boolean) =>
    request<void>(`/api/feeds/${encodeURIComponent(id)}/enabled`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    }),
  refreshFeeds: () => request<{ status: string }>("/api/feeds/refresh", { method: "POST" }),
  addFeed: (id: string, name: string, url: string) =>
    request<void>("/api/feeds", {
      method: "POST",
      body: JSON.stringify({ id, name, url }),
    }),
  deleteFeed: (id: string) =>
    request<void>(`/api/feeds/${encodeURIComponent(id)}`, { method: "DELETE" }),

  applyUpdate: () =>
    request<{ installed: string; previous: string; restarting: boolean }>("/api/update/apply", {
      method: "POST",
    }),

  upstreams: () => request<UpstreamList>("/api/dns/upstreams"),
  upstreamHealth: () => request<UpstreamHealthReport>("/api/dns/upstreams/health"),
  benchmarkUpstreams: (adopt = false) =>
    request<{ results: BenchmarkResult[]; adopted?: string[] }>(
      `/api/dns/upstreams/benchmark${adopt ? "?adopt=true" : ""}`,
      { method: "POST" },
    ),
  addUpstream: (address: string, role: "primary" | "fallback", note?: string) =>
    request<{ id: number }>("/api/dns/upstreams", {
      method: "POST",
      body: JSON.stringify({ address, role, note }),
    }),
  updateUpstream: (id: number, patch: { role?: "primary" | "fallback"; enabled?: boolean }) =>
    request<void>(`/api/dns/upstreams/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  deleteUpstream: (id: number) => request<void>(`/api/dns/upstreams/${id}`, { method: "DELETE" }),

  me: () => request<Account>("/api/auth/me"),
  changePassword: (current: string, next: string) =>
    request<void>("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({ current, new: next }),
    }),
  totpBegin: () => request<TOTPEnrollment>("/api/auth/totp/begin", { method: "POST" }),
  totpConfirm: (code: string) =>
    request<{ recovery_codes: string[] }>("/api/auth/totp/confirm", {
      method: "POST",
      body: JSON.stringify({ code }),
    }),
  totpDisable: (password: string) =>
    request<void>("/api/auth/totp/disable", {
      method: "POST",
      body: JSON.stringify({ password }),
    }),

  rules: () => request<{ rules: UserRule[] | null; stats: FilterStats }>("/api/filters/rules"),
  addRule: (rule: string, comment?: string) =>
    request<{ id: number }>("/api/filters/rules", {
      method: "POST",
      body: JSON.stringify({ rule, comment }),
    }),
  deleteRule: (id: number) => request<void>(`/api/filters/rules/${id}`, { method: "DELETE" }),

  suggestions: () =>
    request<{ suggestions: Suggestion[] | null; pending: number; sources: IntelSource[] | null }>(
      "/api/intel/suggestions",
    ),

  decideSuggestion: (domain: string, decision: "blocked" | "allowed" | "ignored") =>
    request<void>(`/api/intel/suggestions/${encodeURIComponent(domain)}`, {
      method: "POST",
      body: JSON.stringify({ decision }),
    }),

  vpnPeers: () => request<PeerList>("/api/vpn/peers"),
  addPeer: (name: string, fullTunnel: boolean) =>
    request<NewPeer>("/api/vpn/peers", {
      method: "POST",
      body: JSON.stringify({ name, full_tunnel: fullTunnel }),
    }),
  setPeerEnabled: (id: number, enabled: boolean) =>
    request<void>(`/api/vpn/peers/${id}/enabled`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    }),
  deletePeer: (id: number) => request<void>(`/api/vpn/peers/${id}`, { method: "DELETE" }),

  clusterStatus: () => request<ClusterStatus>("/api/cluster/status"),
  demote: () => request<void>("/api/cluster/demote", { method: "POST" }),

  restore: (archive: ArrayBuffer, dryRun: boolean) =>
    request<RestoreResult>(`/api/backup/restore?dry_run=${dryRun}`, {
      method: "POST",
      body: archive,
      headers: { "Content-Type": "application/gzip" },
    }),

  notifyChannels: () =>
    request<{ channels: NotifyChannel[] | null; history: AlertHistory[] | null }>("/api/notify/channels"),
  addChannel: (kind: string, name: string, minSeverity: string, config: Record<string, unknown>) =>
    request<{ id: number }>("/api/notify/channels", {
      method: "POST",
      body: JSON.stringify({ kind, name, min_severity: minSeverity, config }),
    }),
  testChannel: (id: number) => request<void>(`/api/notify/channels/${id}/test`, { method: "POST" }),
  setChannelEnabled: (id: number, enabled: boolean) =>
    request<void>(`/api/notify/channels/${id}/enabled`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    }),
  deleteChannel: (id: number) => request<void>(`/api/notify/channels/${id}`, { method: "DELETE" }),

  audit: (days = 7, limit = 100) =>
    request<{ entries: AuditEntry[] | null }>(`/api/audit?days=${days}&limit=${limit}`),

  updateStatus: () => request<UpdateStatus>("/api/update"),

  lookup: (domain: string) =>
    request<{ domain: string; score: number; verdict: string; findings: IntelFinding[] }>(
      `/api/intel/lookup/${encodeURIComponent(domain)}`,
    ),
};

export function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${secs}s`;

  return `${secs}s`;
}

export function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;

  return String(n);
}

export function formatDuration(nanoseconds: number): string {
  const seconds = Math.round(nanoseconds / 1e9);
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;

  return `${seconds}s`;
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GB`;
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;

  return `${bytes} B`;
}
