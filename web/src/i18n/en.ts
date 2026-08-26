/**
 * The English dictionary is the reference shape: every other locale is
 * typed against its keys, so a missing translation is a compile error, not a
 * silent fallback discovered in production.
 */
export const en = {
  common: {
    loading: "Loading…",
    signOut: "sign out",
  },

  nav: {
    dashboard: "Dashboard",
    review: "Review",
    devices: "Devices",
    tunnel: "Tunnel",
    blocklists: "Blocklists",
    rules: "Your rules",
    system: "System",
  },

  dashboard: {
    queries: "Queries",
    sinceStart: "since start",
    blocked: "Blocked",
    queriesUnit: "{count} queries",
    rulesLoaded: "Rules loaded",
    listsUnit: "{count} lists",
    bandwidth: "Bandwidth",
    perClientCounters: "per-client byte counters",
    gatewayOnly: "Requires gateway mode",
    resolver: "Resolver",
    serving: "serving",
    down: "down",
    cacheHits: "Cache hits",
    answeredWithoutUpstream: "answered without an upstream",
    uptime: "Uptime",
    avgLatency: "{ms} ms average",
    droppedLog:
      "{count} log entries were dropped because the disk could not keep up. Lower the query log retention, or switch it to RAM-only.",
  },

  footer: {
    license: "Apache License 2.0",
    source: "Source",
  },

  language: {
    label: "Language",
    en: "English",
    tr: "Türkçe",
  },

  suggestions: {
    mode: {
      title: "Mode",
      transparentTitle: "Transparent",
      transparentDescription:
        "Only watches and logs. Nothing is ever blocked without a person choosing to.",
      defenseTitle: "Defense",
      defenseDescription:
        "Investigates and reports; never automatically blocks a domain with a valid SSL certificate.",
    },
    sourcesPartialPrefix: "Only {active} of {total} threat sources are active.",
    sourcesPartialSuffix:
      "need a free API key before they can be consulted.",
    loading: "Loading…",
    emptyTitle: "Nothing to review.",
    emptyDetail:
      "Names your network resolves are checked against the threat sources in the background. Anything worth a second opinion will appear here.",
    queries: "{count} queries",
    askedBy: "asked by {clients}",
    firstSeen: "first seen {when}",
    check: "check",
    block: "Block",
    allow: "Allow",
    ignore: "Ignore",
    officialSource: "official source",
    reputable: "reported · your call",
    malicious: "malicious",
    suspect: "suspect",
    tls: {
      unchecked: "SSL not checked",
      valid: "valid SSL",
      certInvalid: "invalid certificate",
      hostnameMismatch: "certificate mismatch",
      noResponse: "no web server responded",
    },
    age: {
      unknown: "age unknown",
      years: "{years}-year-old domain",
      days: "registered {days} days ago",
      highRisk: "new and unverified · ",
    },
  },

  ownedDomains: {
    title: "My Sites",
    description:
      "Domains you host yourself. A name added here never reaches this list — it's never shown and never auto-blocked.",
    loading: "Loading…",
    empty: "No domains added yet.",
    remove: "remove",
    domainLabel: "Domain",
    domainPlaceholder: "mysite.com",
    labelLabel: "Label (optional)",
    labelPlaceholder: "home server",
    add: "Add",
  },
};

export type Dictionary = typeof en;
