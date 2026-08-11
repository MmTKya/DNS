// The typed surface of the AegisDNS control plane.
//
// Keep these types in step with internal/api: they are the contract the panel
// is written against, and every phase adds to them rather than reshaping them.

export type ComponentStatus = "ok" | "degraded";

/** Mirrors config.DeploymentMode. Widgets that need real packet visibility
 *  must check this before claiming to measure anything. */
export type DeploymentMode = "dns-only" | "gateway";

export interface Health {
  status: ComponentStatus;
  mode: DeploymentMode;
  version: string;
  uptime_seconds: number;
  resolver: {
    status: ComponentStatus;
    listen?: string[];
    error?: string;
  };
  database: {
    status: ComponentStatus;
    schema_version: number;
    error?: string;
  };
  panel_embedded: boolean;
}

export interface Version {
  version: string;
  commit: string;
  date: string;
  go_version: string;
}

/** A degraded node answers /api/health with 503 and a full body, so the status
 *  code alone must not be treated as a transport failure. */
export async function getHealth(signal?: AbortSignal): Promise<Health> {
  const response = await fetch("/api/health", { signal });

  if (!response.ok && response.status !== 503) {
    throw new Error(`health check failed: HTTP ${response.status}`);
  }

  return (await response.json()) as Health;
}

export async function getVersion(signal?: AbortSignal): Promise<Version> {
  const response = await fetch("/api/version", { signal });

  if (!response.ok) {
    throw new Error(`version request failed: HTTP ${response.status}`);
  }

  return (await response.json()) as Version;
}

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
