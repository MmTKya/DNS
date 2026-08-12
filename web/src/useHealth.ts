import { useEffect, useRef, useState } from "react";
import { api, type Health } from "./api";

export type Connection = "connecting" | "live" | "unreachable";

interface HealthState {
  health: Health | null;
  connection: Connection;
  error: string | null;
}

/**
 * Polls /api/health on an interval.
 *
 * Polling is right for this endpoint and this endpoint only: it is a cheap
 * summary the operator glances at. The high-frequency telemetry added in phase
 * 1 (query stream, live rates) goes over SSE with server-side batching, never
 * over a faster poll.
 */
export function useHealth(intervalMs = 5000): HealthState {
  const [state, setState] = useState<HealthState>({
    health: null,
    connection: "connecting",
    error: null,
  });

  // Held in a ref so the effect below never restarts on a state change.
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();

    const poll = async () => {
      try {
        const health = await api.health();
        if (!mounted.current) return;

        setState({ health, connection: "live", error: null });
      } catch (err) {
        if (!mounted.current || controller.signal.aborted) return;

        // Keep the last known health on screen and mark it stale, rather than
        // blanking the panel every time a restart drops one request.
        setState((prev) => ({
          health: prev.health,
          connection: "unreachable",
          error: err instanceof Error ? err.message : String(err),
        }));
      }
    };

    void poll();
    const timer = window.setInterval(() => void poll(), intervalMs);

    return () => {
      mounted.current = false;
      controller.abort();
      window.clearInterval(timer);
    };
  }, [intervalMs]);

  return state;
}
