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
    sourcesPartialSuffix: "need a free API key before they can be consulted.",
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

  clients: {
    pauseWarning:
      "In DNS-only mode, pausing a device stops it resolving names through this node. It keeps its network access.",
    gatewayEnforceable: "Gateway mode makes this enforceable.",
    device: "Device",
    queries: "Queries",
    lastSeen: "Last seen",
    filtering: "Filtering",
    paused: "Paused",
    none: "No devices have asked yet.",
    randomisedMac: "randomised — not a stable handle",
    activity: {
      last24h: "Last 24 hours",
      measured: "measured",
      estimated: "estimated from DNS",
      none: "Nothing recorded for this device yet.",
      visit: "visit",
      visits: "visits",
    },
  },

  feeds: {
    refreshing: "Refreshing…",
    refreshNow: "Refresh now",
    aggressive: "blocks aggressively",
    nonCommercial: "non-commercial licence",
    notInCatalog:
      "No longer in the catalogue. It keeps running from the URL stored here, but nothing maintains that entry any more — check it still updates, or remove it.",
    rulesCount: "{count} rules",
    updated: "updated {when}",
    fillingNow: "Filling now.",
    remove: "remove",
    addSource: "+ Add a source",
    name: "Name",
    namePlaceholder: "My list",
    url: "URL",
    add: "Add",
    cancel: "cancel",
    addHelp:
      "Hosts files and Adblock-syntax lists both work; the format is detected from the content. The source is downloaded and compiled as soon as you add it",
    addHelpFiledPrefix: "and filed as",
  },

  rules: {
    none: "No rules of your own yet.",
    remove: "remove",
    addRule: "Add rule",
    useForm: "use the form",
    writeSyntax: "write the syntax myself",
    ruleLabel: "Rule",
    domainLabel: "Domain",
    answerWith: "Answer with",
    note: "Note (optional)",
    notePlaceholder: "why you added this",
    important:
      "beat allow rules as well — use when something keeps getting through",
    actions: {
      block: "block",
      allow: "allow",
      rewrite: "rewrite",
      nxdomain: "Say it does not exist",
    },
    help: {
      block: "The name stops resolving, along with everything under it.",
      allow:
        "The name resolves even if a blocklist carries it. Allow beats block, so this is how you get a site back.",
      rewrite:
        "The name answers with an address you choose — pointing a device at a local server, for instance.",
      nxdomain:
        'The name answers "does not exist" rather than an address. Some apps handle that better than 0.0.0.0.',
    },
    describe: {
      scopeAll: "and everything under it",
      scopeExact: "exactly",
      allow: "always resolves {scope}, beating every blocklist",
      rewriteNx: 'answers "does not exist" {scope}',
      rewriteTo: "answers {address} {scope}",
      blockImportant: "blocked {scope}, overriding allow rules",
      block: "blocked {scope}",
      onlyQtype: "only {qtypes} queries",
      onlyClient: "only for {client}",
    },
  },

  system: {
    nav: {
      machine: "Machine",
      logs: "Logs",
      upstreams: "Resolvers",
      intel: "Threat sources",
      gateway: "Gateway mode",
      cluster: "Cluster",
      backup: "Backup",
      alerts: "Alerts",
      audit: "Audit",
      updates: "Updates",
    },
    cluster: {
      standaloneTitle: "This node is running on its own.",
      standaloneDetail:
        "A second node keeps the house resolving when this one is rebooting, updating or simply unplugged — it follows this one's configuration and takes over if it goes quiet. Until then everything here is idle and costs nothing.",
      setupSecondNode: "Set up a second node",
      noPrimary:
        "No primary is reachable. This node will promote itself if that does not change shortly.",
      syncFailed: "Last replication attempt failed: {error}",
      thisNode: "this node",
      stepDown: "Step down to replica",
      revision: "revision {rev}",
      seen: "seen {when}",
      lastReplicated: "Last replicated {when}.",
      showPairing: "show the pairing configuration",
    },
    backup: {
      download: "Download",
      downloadDetail:
        "Settings, blocklist choices, your own rules and your devices. The query log is not included: it is large and it is a record of what this network did, not of how it is configured.",
      downloadBackup: "Download backup",
      includeSecrets: "Include logins and API keys",
      secretsWarning:
        "The second file contains password hashes, two-factor secrets and your threat-source keys. Treat it like the node itself.",
      restore: "Restore",
      restoreDetail:
        "The archive is inspected first and applied only when you confirm. Your configuration file is never overwritten from here — an archive from another node carries its listeners, and restoring those could leave this one unreachable.",
      contains: "This archive contains:",
      restored: "Restored:",
      taken: "taken {when}",
      includesSecrets: "includes logins and keys",
      replaceSettings: "Replace this node's settings",
    },
    alerts: {
      andAbove: "{severity} and above",
      sendTest: "Send a test",
      sent: "Sent",
      remove: "remove",
      addDestination: "Add a destination",
      name: "Name",
      namePlaceholder: "My phone",
      severityLabel: "Send when severity is",
      severityInfo: "info and above — everything",
      severityWarning: "warning and above",
      severityCritical: "critical only",
      add: "Add",
      recent: "Recent alerts",
      none: "Nothing has needed your attention.",
      lastDelivered: "last delivered {when}",
      delivered: "{count} sent",
      kinds: {
        smtp: "Email",
        ntfy: "ntfy",
        webhook: "Webhook",
        telegram: "Telegram",
        discord: "Discord",
      },
    },
    audit: {
      today: "Today",
      thisYear: "This year",
      daysCount: "{days} days",
      none: "Nothing was changed in this period.",
      onlyChanges:
        "Only changes are recorded. A trail that logged every dashboard refresh would bury the entries that matter.",
    },
    updates: {
      running: "Running",
      checking: "Checking…",
      checkAgain: "Check again",
      currentRelease: "This is the current release.",
      notManaged:
        "This binary was not installed by the updater, so it will not replace itself. Update it the way you installed it.",
      howApplied: "How an update is applied",
      verifyTitle: "Verify.",
      verifyDetail:
        "The archive is checked against a signed checksum file before it is unpacked. A valid TLS connection says nothing about what is inside a download.",
      snapshotTitle: "Snapshot.",
      snapshotDetail:
        "Your settings are exported first, so a bad release can be undone rather than mourned.",
      swapTitle: "Swap and prove.",
      swapDetail:
        "The old binary is kept while the new one has to start and validate its configuration. If it cannot, the old one comes back.",
      versionAvailable: "Version {version} is available.",
      whatChanged: "What changed",
      noNotes: "This release was published without notes.",
      installConfirm: "Install {version} and restart the resolver?",
      verifyingInstalling: "Verifying and installing…",
      yesInstall: "Yes, install it",
      cancel: "cancel",
      install: "Install {version}",
      runningVersion: "Running {version}.",
      verifiedBackUp:
        "Verified, installed and back up. The previous binary is kept as",
      waitingBack:
        "{version} is installed and verified. Waiting for the node to come back…",
      dnsUnavailable:
        "DNS is unavailable for a second or two while it restarts; devices retry, so this is usually invisible.",
      stillAnswering: " Still answering as {live}.",
      tookSeconds:
        "It has been {seconds} seconds. The previous binary is still on disk as",
      checkJournal: "— check",
      onTheNode: "on the node.",
    },
  },
};

export type Dictionary = typeof en;
