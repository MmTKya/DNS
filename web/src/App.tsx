import { formatUptime } from "./api";
import { StatusCard } from "./components/StatusCard";
import { useHealth } from "./useHealth";

export default function App() {
  const { health, connection, error } = useHealth();

  const gatewayOnly =
    health?.mode === "gateway" ? undefined : "Requires gateway mode";

  return (
    <div className="min-h-full">
      <header className="border-b border-base-700/60 bg-base-950/40 backdrop-blur-sm">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-6 py-4">
          <div className="flex items-baseline gap-3">
            <h1 className="text-lg font-semibold tracking-tight text-ink">
              Aegis<span className="text-accent">DNS</span>
            </h1>
            <span className="font-mono text-xs text-ink-faint">
              {health?.version ?? "…"}
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span
              className={`size-2 rounded-full ${
                connection === "live"
                  ? "bg-safe pulse-dot"
                  : connection === "connecting"
                    ? "bg-warn"
                    : "bg-threat"
              }`}
            />
            <span className="text-ink-muted">
              {connection === "live"
                ? "live"
                : connection === "connecting"
                  ? "connecting"
                  : "unreachable"}
            </span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-6 py-8">
        {/* The deployment mode is stated up front, because it decides which
            numbers on this page can ever be real measurements. */}
        <div className="mb-6 flex flex-wrap items-center gap-3">
          <span className="rounded-full border border-accent-dim/60 bg-accent/10 px-3 py-1 font-mono text-xs text-accent">
            {health?.mode ?? "…"}
          </span>
          <p className="text-sm text-ink-muted">
            {health?.mode === "gateway"
              ? "All client traffic routes through this node."
              : "DNS-only: this node sees queries, not packets."}
          </p>
        </div>

        {error && connection === "unreachable" && (
          <div className="mb-6 rounded-lg border border-threat/40 bg-threat/10 px-4 py-3 text-sm text-ink">
            Cannot reach the control plane: <span className="font-mono">{error}</span>
          </div>
        )}

        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatusCard
            label="Resolver"
            value={health?.resolver.status === "ok" ? "serving" : "down"}
            status={health?.resolver.status}
            detail={health?.resolver.listen?.join(", ") ?? health?.resolver.error}
          />
          <StatusCard
            label="Database"
            value={health?.database.status === "ok" ? "ready" : "error"}
            status={health?.database.status}
            detail={
              health?.database.error ?? `schema v${health?.database.schema_version ?? "?"}`
            }
          />
          <StatusCard
            label="Uptime"
            value={health ? formatUptime(health.uptime_seconds) : "—"}
            detail="since last restart"
          />
          <StatusCard
            label="Bandwidth"
            value="—"
            detail="per-client byte counters"
            unavailable={gatewayOnly}
          />
        </section>

        <section className="mt-8 rounded-xl border border-base-700/70 bg-base-850/40 p-5">
          <h2 className="text-sm font-medium text-ink">Phase 0 skeleton</h2>
          <p className="mt-1 text-sm text-ink-muted">
            The datapath resolves and the control plane reports on it. Filtering, the live
            query stream, threat intelligence, client tracking, HA and VPN arrive in the
            phases that follow.
          </p>
          <div className="mt-4 flex flex-wrap gap-2 font-mono text-xs">
            {["/api/health", "/api/version"].map((path) => (
              <a
                key={path}
                href={path}
                className="rounded-md border border-base-700 px-2 py-1 text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
              >
                {path}
              </a>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
