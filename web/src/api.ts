// The typed surface of the AegisDNS control plane.
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
  query_count: number;
  filtering_enabled: boolean;
  paused: boolean;
  known: boolean;
  created_at: string;
  last_seen?: string;
}

export interface ClientList {
  clients: Client[] | null;
  mode: DeploymentMode;
  /** False in DNS-only mode: a pause there filters DNS, it does not cut the
   *  device off. The UI must not imply otherwise. */
  pause_is_enforced: boolean;
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

export interface UserRule {
  id: number;
  rule: string;
  comment?: string;
  enabled: boolean;
  created_at: string;
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

  clients: () => request<ClientList>("/api/clients"),
  updateClient: (key: string, patch: Partial<Pick<Client, "name" | "filtering_enabled" | "paused">>) =>
    request<Client>(`/api/clients/${encodeURIComponent(key)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),

  feeds: () => request<{ feeds: Feed[] | null }>("/api/feeds"),
  setFeedEnabled: (id: string, enabled: boolean) =>
    request<void>(`/api/feeds/${encodeURIComponent(id)}/enabled`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    }),
  refreshFeeds: () => request<{ status: string }>("/api/feeds/refresh", { method: "POST" }),

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

export function formatBytes(bytes: number): string {
  if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GB`;
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(1)} KB`;

  return `${bytes} B`;
}
