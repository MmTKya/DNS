import { useCallback, useEffect, useState } from "react";
import { api, formatCount, formatUptime, type AuthStatus, type Stats } from "./api";
import { LoginScreen } from "./components/LoginScreen";
import { ClientsPanel, FeedsPanel, RulesPanel } from "./components/Panels";
import { QueryStream } from "./components/QueryStream";
import { SuggestionsPanel } from "./components/Suggestions";
import { SystemPanel } from "./components/System";
import { TunnelPanel } from "./components/Tunnel";
import { RateChart } from "./components/RateChart";
import { StatusCard } from "./components/StatusCard";
import { useHealth } from "./useHealth";
import { useStream } from "./useStream";

type Tab = "dashboard" | "review" | "clients" | "tunnel" | "feeds" | "rules" | "system";

// Ordered by how often a household actually opens them: what the network is
// doing, what needs a decision, then configuration, then the things you touch
// once a year.
const tabs: { id: Tab; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "review", label: "Review" },
  { id: "clients", label: "Devices" },
  { id: "tunnel", label: "Tunnel" },
  { id: "feeds", label: "Blocklists" },
  { id: "rules", label: "Your rules" },
  { id: "system", label: "System" },
];

export default function App() {
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [tab, setTab] = useState<Tab>("dashboard");

  const loadAuth = useCallback(async () => {
    try {
      setAuth(await api.authStatus());
    } catch {
      setAuth({ needs_setup: false, signed_in: false });
    }
  }, []);

  useEffect(() => {
    void loadAuth();
  }, [loadAuth]);

  if (!auth) {
    return <div className="grid min-h-full place-items-center text-sm text-ink-faint">Loading…</div>;
  }

  if (!auth.signed_in) {
    return <LoginScreen needsSetup={auth.needs_setup} onDone={() => void loadAuth()} />;
  }

  return (
    <div className="min-h-full">
      <Header
        username={auth.user?.username ?? ""}
        tab={tab}
        onTab={setTab}
        onSignOut={async () => {
          await api.logout();
          await loadAuth();
        }}
      />

      <main className="mx-auto max-w-6xl px-6 py-8">
        {tab === "dashboard" && <Dashboard />}
        {tab === "review" && <SuggestionsPanel />}
        {tab === "clients" && <ClientsPanel />}
        {tab === "feeds" && <FeedsPanel />}
        {tab === "tunnel" && <TunnelPanel />}
        {tab === "rules" && <RulesPanel />}
        {tab === "system" && <SystemPanel />}
      </main>
    </div>
  );
}

function Header({
  username,
  tab,
  onTab,
  onSignOut,
}: {
  username: string;
  tab: Tab;
  onTab: (tab: Tab) => void;
  onSignOut: () => void | Promise<void>;
}) {
  const { health, connection } = useHealth(10_000);
  const [pending, setPending] = useState(0);

  // The badge is what makes the review queue something you notice rather than
  // something you remember to check.
  useEffect(() => {
    const poll = () =>
      void api
        .suggestions()
        .then((r) => setPending(r.pending))
        .catch(() => undefined);

    poll();
    const timer = window.setInterval(poll, 60_000);

    return () => window.clearInterval(timer);
  }, []);

  return (
    <header className="border-b border-base-700/60 bg-base-950/40 backdrop-blur-sm">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-6 py-4">
        <div className="flex items-baseline gap-3">
          <h1 className="text-lg font-semibold tracking-tight text-ink">
            Aegis<span className="text-accent">DNS</span>
          </h1>
          <span className="font-mono text-xs text-ink-faint">{health?.version ?? "…"}</span>
          <span className="rounded-full border border-accent-dim/60 bg-accent/10 px-2 py-0.5 font-mono text-[0.65rem] text-accent">
            {health?.mode ?? "…"}
          </span>
        </div>

        <div className="flex items-center gap-4 text-xs">
          <span className="flex items-center gap-2 text-ink-muted">
            <span
              className={`size-2 rounded-full ${
                connection === "live" ? "bg-safe pulse-dot" : connection === "connecting" ? "bg-warn" : "bg-threat"
              }`}
            />
            {connection}
          </span>
          <span className="text-ink-faint">{username}</span>
          <button onClick={() => void onSignOut()} className="text-ink-muted transition-colors hover:text-accent">
            sign out
          </button>
        </div>
      </div>

      <nav className="mx-auto flex max-w-6xl gap-1 px-6">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => onTab(t.id)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm transition-colors ${
              tab === t.id
                ? "border-accent text-ink"
                : "border-transparent text-ink-muted hover:text-ink"
            }`}
          >
            {t.label}
            {t.id === "review" && pending > 0 && (
              <span className="ml-2 rounded-full bg-threat px-1.5 py-0.5 text-[0.6rem] font-medium text-base-950">
                {pending}
              </span>
            )}
          </button>
        ))}
      </nav>
    </header>
  );
}

function Dashboard() {
  const { health } = useHealth();
  const stream = useStream(true);
  const [stats, setStats] = useState<Stats | null>(null);

  // The counters come with every stream frame; this one call is for what the
  // stream does not carry — the compiled ruleset and the mode capabilities.
  useEffect(() => {
    void api.stats().then(setStats).catch(() => undefined);
    const timer = window.setInterval(() => void api.stats().then(setStats).catch(() => undefined), 30_000);

    return () => window.clearInterval(timer);
  }, []);

  const queries = stream.stats ?? stats?.queries ?? null;
  const capabilities = stats?.capabilities;
  const gatewayOnly = capabilities?.bandwidth ? undefined : "Requires gateway mode";

  return (
    <div className="space-y-6">
      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatusCard
          label="Queries"
          value={queries ? formatCount(queries.total) : "—"}
          detail="since start"
        />
        <StatusCard
          label="Blocked"
          value={queries ? `${(queries.blocked_ratio * 100).toFixed(1)}%` : "—"}
          detail={queries ? `${formatCount(queries.blocked)} queries` : undefined}
        />
        <StatusCard
          label="Rules loaded"
          value={stats?.filter ? formatCount(stats.filter.rules) : "—"}
          detail={stats?.filter?.sources ? `${stats.filter.sources.length} lists` : undefined}
        />
        <StatusCard
          label="Bandwidth"
          value="—"
          detail="per-client byte counters"
          unavailable={gatewayOnly}
        />
      </section>

      <RateChart samples={stream.samples} />

      <QueryStream entries={stream.entries} />

      <section className="grid gap-4 sm:grid-cols-3">
        <StatusCard
          label="Resolver"
          value={health?.resolver.status === "ok" ? "serving" : "down"}
          status={health?.resolver.status}
          detail={health?.resolver.listen?.join(", ")}
        />
        <StatusCard
          label="Cache hits"
          value={queries ? `${(queries.cache_ratio * 100).toFixed(0)}%` : "—"}
          detail="answered without an upstream"
        />
        <StatusCard
          label="Uptime"
          value={health ? formatUptime(health.uptime_seconds) : "—"}
          detail={queries ? `${queries.avg_elapsed_ms.toFixed(1)} ms average` : undefined}
        />
      </section>

      {queries && queries.dropped > 0 && (
        <p className="text-xs text-warn">
          {formatCount(queries.dropped)} log entries were dropped because the disk could not keep up. Lower the
          query log retention, or switch it to RAM-only.
        </p>
      )}
    </div>
  );
}
