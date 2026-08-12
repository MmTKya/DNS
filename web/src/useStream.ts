import { useEffect, useRef, useState } from "react";
import type { QueryEntry, QueryStats } from "./api";

/**
 * How many queries the panel keeps on screen.
 *
 * The server ring holds far more; this is what the DOM and a phone's memory
 * can carry. Anything older is a scroll through the stored log, not a live
 * view.
 */
const MAX_ENTRIES = 500;

/** Samples kept for the rate chart: five minutes at one second each. */
const MAX_SAMPLES = 300;

export interface RateSample {
  t: number;
  total: number;
  blocked: number;
}

export interface StreamState {
  entries: QueryEntry[];
  stats: QueryStats | null;
  samples: RateSample[];
  connected: boolean;
}

/**
 * Consumes the live telemetry stream.
 *
 * The shape of this hook is the whole performance story. The server already
 * batches events into frames a few times a second; on this side, arriving
 * entries are buffered in a ref and flushed to React once per animation frame.
 * Calling setState per event would put a busy network's thousands of queries a
 * second straight into the render loop and freeze the tab.
 */
export function useStream(enabled: boolean): StreamState {
  const [state, setState] = useState<StreamState>({
    entries: [],
    stats: null,
    samples: [],
    connected: false,
  });

  // Buffers written by the event handler and read by the animation frame.
  const pending = useRef<QueryEntry[]>([]);
  const latestStats = useRef<QueryStats | null>(null);
  const frame = useRef<number | null>(null);
  const lastSample = useRef<{ at: number; total: number; blocked: number } | null>(null);

  useEffect(() => {
    if (!enabled) return;

    const source = new EventSource("/api/stream");

    const flush = () => {
      frame.current = null;

      const incoming = pending.current;
      const stats = latestStats.current;
      pending.current = [];

      if (incoming.length === 0 && !stats) return;

      setState((prev) => {
        const entries = incoming.length
          ? [...incoming.reverse(), ...prev.entries].slice(0, MAX_ENTRIES)
          : prev.entries;

        let samples = prev.samples;
        if (stats) {
          const now = Date.now();
          const previous = lastSample.current;

          // The counters are cumulative, so the rate is their difference over
          // the elapsed time.
          if (previous && now > previous.at) {
            const seconds = (now - previous.at) / 1000;
            samples = [
              ...prev.samples,
              {
                t: now / 1000,
                total: Math.max(0, (stats.total - previous.total) / seconds),
                blocked: Math.max(0, (stats.blocked - previous.blocked) / seconds),
              },
            ].slice(-MAX_SAMPLES);
          }

          lastSample.current = { at: now, total: stats.total, blocked: stats.blocked };
        }

        return {
          entries,
          stats: stats ?? prev.stats,
          samples,
          connected: true,
        };
      });
    };

    const schedule = () => {
      if (frame.current === null) {
        frame.current = requestAnimationFrame(flush);
      }
    };

    source.addEventListener("queries", (event) => {
      try {
        const payload = JSON.parse((event as MessageEvent).data) as {
          entries: QueryEntry[] | null;
          stats: QueryStats;
        };

        if (payload.entries?.length) {
          pending.current.push(...payload.entries);

          // A hidden tab gets no animation frames, so this buffer would grow
          // for as long as the laptop lid stayed shut. Only the newest
          // entries can ever be shown, so the rest are dropped here rather
          // than accumulating.
          if (pending.current.length > MAX_ENTRIES) {
            pending.current = pending.current.slice(-MAX_ENTRIES);
          }
        }

        latestStats.current = payload.stats;
        schedule();
      } catch {
        // A malformed frame is not worth tearing the stream down for.
      }
    });

    source.onopen = () => setState((prev) => ({ ...prev, connected: true }));
    source.onerror = () => setState((prev) => ({ ...prev, connected: false }));

    return () => {
      source.close();
      if (frame.current !== null) cancelAnimationFrame(frame.current);
      frame.current = null;
      pending.current = [];
    };
  }, [enabled]);

  return state;
}
