import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import type { RateSample } from "../useStream";
import { useLang } from "../i18n/context";

/**
 * The live query-rate chart.
 *
 * uPlot draws to a canvas, which is why it is here instead of a React chart
 * library: at one point per second over five minutes, redrawn several times a
 * second, an SVG chart would create and discard hundreds of DOM nodes per
 * frame on a machine that is also resolving DNS.
 */
export function RateChart({ samples }: { samples: RateSample[] }) {
  const { t } = useLang();
  const container = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);

  useEffect(() => {
    if (!container.current) return;

    const style = getComputedStyle(document.documentElement);
    const accent = style.getPropertyValue("--color-accent").trim() || "#22d3ee";
    const threat = style.getPropertyValue("--color-threat").trim() || "#f43f5e";
    const grid = "rgba(139, 152, 169, 0.12)";

    const chart = new uPlot(
      {
        width: container.current.clientWidth,
        height: 180,
        padding: [8, 8, 0, 0],
        cursor: { show: true, y: false },
        legend: { show: false },
        scales: { x: { time: true } },
        axes: [
          {
            stroke: "#5b6675",
            grid: { stroke: grid, width: 1 },
            ticks: { stroke: grid },
          },
          {
            stroke: "#5b6675",
            grid: { stroke: grid, width: 1 },
            ticks: { stroke: grid },
            size: 40,
          },
        ],
        series: [
          {},
          { label: "queries/s", stroke: accent, width: 2, fill: `${accent}1a` },
          { label: "blocked/s", stroke: threat, width: 2, fill: `${threat}1a` },
        ],
      },
      [[], [], []],
      container.current,
    );

    plot.current = chart;

    const resize = () => {
      if (container.current) {
        chart.setSize({ width: container.current.clientWidth, height: 180 });
      }
    };
    window.addEventListener("resize", resize);

    return () => {
      window.removeEventListener("resize", resize);
      chart.destroy();
      plot.current = null;
    };
  }, []);

  useEffect(() => {
    if (!plot.current) return;

    plot.current.setData([
      samples.map((s) => s.t),
      samples.map((s) => s.total),
      samples.map((s) => s.blocked),
    ]);
  }, [samples]);

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4 backdrop-blur-sm">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("rateChart.title")}
        </span>
        <div className="flex items-center gap-4 text-xs">
          <span className="flex items-center gap-1.5 text-ink-muted">
            <span className="size-2 rounded-full bg-accent" />{" "}
            {t("rateChart.total")}
          </span>
          <span className="flex items-center gap-1.5 text-ink-muted">
            <span className="size-2 rounded-full bg-threat" />{" "}
            {t("rateChart.blocked")}
          </span>
        </div>
      </div>
      <div ref={container} />
      {samples.length === 0 && (
        <p className="mt-2 text-xs text-ink-faint">
          {/* A rate is the difference between two counts, so this needs a
              moment of running to have anything to draw — unlike the list
              below it, which is already full. */}
          {t("rateChart.measuring")}
        </p>
      )}
    </div>
  );
}
