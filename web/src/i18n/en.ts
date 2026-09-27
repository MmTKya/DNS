/**
 * The English dictionary is the reference shape: every other locale is
 * typed against its keys, so a missing translation is a compile error, not a
 * silent fallback discovered in production.
 */
export const en = {
  common: {
    loading: "Loading…",
    signOut: "sign out",
    and: "and",
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

  login: {
    setupIntro:
      "This node has no administrator yet. Whoever creates one holds the keys — do it now, before anything else can reach the panel.",
    signInIntro: "Sign in to manage this node.",
    username: "Username",
    password: "Password",
    passwordHint: "At least 12 characters. A passphrase is fine.",
    twoFactorCode: "Two-factor code",
    recoveryHint: "A recovery code works here too.",
    createAdmin: "Create administrator",
    signIn: "Sign in",
  },

  panelPort: {
    where: "Where this panel listens",
    port: "port {port}",
    detail:
      "Worth changing when something else on this machine wants the same port. Port 53, which is what devices actually ask for names on, is not affected.",
    isOpen: "Port {port} is open. Nothing has been saved yet.",
    confirmDetail:
      "Open the address below and confirm from there. It has to be confirmed on the new port — that is what proves the port works from where you are sitting, which is the one thing this node cannot check for you.",
    open: "Open {url}",
    closesAt: "Do nothing and the port closes on its own at {when}",
    closesShortly: "Do nothing and the port closes on its own shortly",
    closesSuffix: ", leaving the panel exactly where it is now.",
    cancelNow: "cancel now",
    moveTo: "Move to port",
    openThatPort: "Open that port",
    portRule:
      "1024 or above. Lower ports need a privilege this node deliberately does not hold — it is the part exposed to the network, and the one exception it already has is for port 53.",
    saved: "Saved. The panel will be here after a restart too.",
    reached: "You reached the panel on port {port}",
    proof:
      "That is the proof. Confirm and this becomes the port the panel uses from now on, including after a restart. Do nothing and it goes back to where it was.",
    keepPort: "Keep this port",
  },

  pairing: {
    title: "Pair a second node",
    detail:
      "Two nodes, not a quorum. One holds the configuration and the other follows it; if the first stops answering for fifteen seconds the second promotes itself. Three machines would let you vote, but two cannot — so this is failover, deliberately.",
    close: "close",
    peerAddress: "The other node's panel address",
    thisNodeIs: "This node is",
    thePrimary: "the primary",
    theReplica: "the replica",
    sharedSecret: "Shared secret",
    couldNotGenerate: "could not be generated here",
    newOneBelow: "new one below",
    newToken: "new token",
    noRandomBytes:
      "This browser will not produce random bytes on a plain HTTP page. Make one on either machine instead —",
    noRandomBytesSuffix:
      "— and paste the same value into both files. Nothing weaker will do: it is the only thing guarding the replication port.",
    sameValue:
      "The same value goes on both nodes. It is the only thing between the replication port and a configuration that turns filtering off, so it is generated here rather than invited — a secret someone thinks up is the one part of this that would otherwise be weak.",
    editOnPrimary:
      "Edit configuration on the primary. A replica's own changes are overwritten the next time it syncs, which is a confusing way to lose an afternoon's work.",
    onThisNode: "On this node ({host})",
    pasteRestart:
      "Paste into /etc/seddns/seddns.yaml, then run: systemctl restart seddns",
    fillOtherAddress:
      "Fill in the other node's address above to complete this block.",
    onOtherNodeWithHost: "On the other node ({host})",
    onOtherNode: "On the other node",
    sameFileNote:
      "Same file, same restart. Both nodes need the same token or neither will accept the other's snapshots.",
    then: "Then",
    step1:
      "Restart both. This screen starts showing the other node within a few seconds.",
    step2:
      "Hand both addresses out over DHCP, primary first. Failover only helps if devices know where to go.",
    step3:
      "Never give the router itself as a secondary. Devices drift onto it the moment the first is slow, and filtering stops without anything saying so.",
  },

  account: {
    lastSignedIn: "last signed in {when}",
    firstSession: "first session",
    passwordTitle: "Password",
    passwordDetail:
      "Changing it signs out every browser and device, including this one — so a stolen session cannot outlive the password it came from. You will be asked to sign in again.",
    currentPassword: "Current password",
    newPassword: "New password",
    newPasswordHint: "at least 12 characters",
    repeatPassword: "Repeat new password",
    tooShort: "A password needs at least 12 characters.",
    mismatch: "The two new passwords do not match.",
    changeAndSignOut: "Change password and sign out",
    twoFactorOnSaveNow: "Two-factor is on. Save these now.",
    recoveryCodesWarning:
      "Each code signs you in once if you lose the authenticator. They are shown here and nowhere else — the node stores only their hashes, so no one, including this panel, can show them to you again.",
    copyCodes: "Copy codes",
    savedThem: "I have saved them",
    twoFactor: "Two-factor",
    onWithCodes: "on · {count} recovery codes left",
    off: "off",
    turnOffNeedsPassword:
      "Turning it off needs your password, so someone holding an open session cannot quietly remove it.",
    password: "Password",
    turnOff: "Turn off",
    addToAuthenticator:
      "Add this to your authenticator, then type the six digits it shows. Two-factor only turns on once a code proves the secret arrived intact.",
    orEnterManually: "Or enter this into your app by hand",
    codeFromApp: "Code from the app",
    confirm: "Confirm",
    cancel: "cancel",
    whyItMatters:
      "A second factor matters most here: this panel can redirect every name your household resolves, so a guessed password should not be the only thing in the way.",
    setUp: "Set up two-factor",
  },

  copy: {
    copy: "Copy",
    copied: "Copied",
    selectByHand: "Select it by hand",
  },

  rateChart: {
    title: "Query rate",
    total: "total",
    blocked: "blocked",
    measuring:
      "Measuring — a rate needs a few seconds of traffic before it can be drawn.",
  },

  upstreamHealth: {
    title: "Resolvers behind this node",
    rescues: "{count} lookup needed a second resolver",
    rescuesPlural: "{count} lookups needed a second resolver",
    answering: "answering",
    notAnswering: "not answering",
    fallback: "fallback",
    noAnswer: "no answer",
    allDown:
      "None of them are answering. That is the internet connection or the network, not this node.",
    oneDown:
      "One is not answering. Queries still work through the others; replace it under System → Resolvers.",
    manyRescues:
      "A lot of lookups are only succeeding on the second resolver, which means the first one is failing quietly. Measure them under System → Resolvers.",
  },

  queryStream: {
    title: "Live queries",
    filterPlaceholder: "filter by name or client",
    blockedOnly: "blocked only",
    waiting: "Waiting for queries…",
    noMatch: "Nothing matches that filter.",
  },

  limits: {
    enforcedHint: "Saved now, enforced in gateway mode",
    setLimit: "set a speed limit",
    download: "Download",
    upload: "Upload",
    save: "Save",
    remove: "remove",
    cancel: "cancel",
    leaveEmpty: "Leave a box empty to leave that direction alone.",
  },

  host: {
    boardProblem: "The board is reporting a problem",
    boardDetail:
      "An underpowered board does not stop — it runs at a fraction of its speed, and the household experiences that as a slow connection with nothing in any log to explain it. The usual cause is a phone charger being used as a power supply.",
    thisMachine: "This machine",
    up: "up {time}",
    processor: "Processor",
    processorDetail: "{cores} core · load {load}",
    processorDetailPlural: "{cores} cores · load {load}",
    memory: "Memory",
    memoryDetail: "{used} of {total} in use",
    diskDetail: "{free} free of {total} · {path}",
    swap: "Swap",
    temperature: "Temperature",
    temperatureDetail: "a board slows itself down rather than overheat",
    eachCore: "Each core",
    oneCoreStuck:
      "One core at a hundred while the rest are idle is one job stuck, not a machine that is too small.",
    memoryExplainer:
      "Memory in use is the total minus what is available, not minus what is free. Linux fills the spare with cache and hands it back when something asks — reading free would put a healthy machine at 97% and send you looking for a problem that is not there.",
    notKnown: "not known",
  },

  remoteAccess: {
    threeWays: "Three ways in, and what each one costs",
    recommended: "recommended",
    notSetUp: "not set up",
    portForwarding: "Port forwarding",
    portForwardingDetail:
      "Nothing here can set this up: it is a rule on your router, and this node has no way to reach into it. If you do it anyway, forward to",
    portForwardingDefault: "this node, port 8080",
    portForwardingSuffix:
      "and switch on two-factor first — you are putting a box that can redirect every name in your house on the public internet, behind one password.",
    cloudflareTitle: "Cloudflare Tunnel",
    cloudflareInstalled: "cloudflared installed",
    cloudflareNotInstalled: "cloudflared is not installed here",
    cloudflareDetail:
      "No inbound port and your address stays hidden, but Cloudflare terminates TLS and can see the panel traffic. Pair it with Cloudflare Access so a password is not the only thing in front of your network.",
    installFirst: "Install it first, then create a tunnel:",
    installFirstDetail:
      "The last command prints the tunnel id and the path of the credentials file. Those are the two values below.",
    tunnelId: "Tunnel id",
    publicHostname: "Public hostname",
    credentialsFile: "Credentials file",
    writeConfig: "Write the configuration",
    writeError:
      "Saved, but the file could not be written: {error}. Copy it from below instead.",
    writtenTo: "Written to {path}",
    configuration: "Configuration",
    thenOnThisMachine: "Then, on this machine:",
    installNote:
      "The node writes the file and stops there: it runs unprivileged and installing system services is not something a resolver should be able to do.",
  },

  tunnel: {
    disabled: "The tunnel is switched off. Set",
    disabledSuffix:
      "and an endpoint your devices can dial in the configuration file, then reload the node.",
    notAvailable:
      "The tunnel is enabled but its network interface does not exist yet. Bring it up with wg-quick or systemd-networkd and restart — until then peers can be enrolled but nothing will connect.",
    addDevice: "Add a device",
    addDevicePlaceholder: "Kids phone",
    routeAll: "route all traffic",
    create: "Create",
    routeAllHint:
      'Leaving "route all traffic" off sends only DNS and your home network through the tunnel: the device keeps its own path to the internet and still resolves here. Turning it on routes everything through the house.',
    noneEnrolled: "No devices enrolled.",
    noneEnrolledDetail:
      "A device added here resolves through this node wherever it is, so the filtering does not stop at the front door.",
    connected: "connected",
    idle: "idle",
    lastHandshake: "last handshake {when}",
    neverConnected: "never connected",
    presharedKey: "preshared key",
    remove: "remove",
    readyTitle: "{name} is ready",
    scanNow:
      "Scan this now. The private key was generated for this device and is not kept on the node — close this and the only way to enrol it is to create the device again.",
    done: "done",
    copyConfiguration: "Copy configuration",
  },

  gateway: {
    whatChanges: "What gateway mode changes",
    now: "now: {mode}",
    todayDetail:
      "Today this node answers questions about names. Your devices ask it where a site is, and then talk to that site directly — down a path this node never sees. That is why there are no byte counters here and why pausing a device filters its lookups rather than cutting it off.",
    gatewayDetail:
      "In gateway mode every packet passes through this machine on its way out of the house. It can count what each device actually used, see which one is uploading, and stop a device by dropping its traffic rather than by declining to look up an address.",
    tradeoffDetail:
      "It also becomes the way out. If this machine stops — a failed card, a pulled cable, an update that goes wrong — the house loses the internet, not just its DNS. With one node and no second to take over, that is the whole trade in one sentence.",
    whatMissing: "What this machine is missing",
    allInPlace: "everything is in place",
    notReady: "not ready",
    oneRequirement: "One requirement is",
    manyRequirements: "{count} requirements are",
    requirementsSuffix:
      "not something a setting can fix. Until that changes, the rest of this screen is preparation.",
    networkPorts: "Network ports",
    wayOutToday: "The way out today is",
    via: "via",
    noAddress: "no address",
    down: "down",
    settings: "Settings",
    saved: "Saved",
    storedNotApplied:
      "Stored, not applied. Nothing on this screen changes the network — the mode has never run on real hardware, and a save button that reconfigured your house on that basis would be the most expensive mistake in this project.",
    wanPort: "Port facing the modem",
    lanPort: "Port facing the house",
    notChosen: "not chosen",
    pppoeLabel: "This machine dials the connection itself (PPPoE)",
    pppoeDetail:
      "Only if your modem is put into bridge mode. Then the internet connection terminates here and this machine needs the username and password your provider gave you — the same ones in the modem now.",
    pppoeOffDetail:
      "Leave it off to keep the modem dialling. This machine then sits behind it and does its own address translation: no provider credentials, one more layer of translation, and one less thing to get wrong.",
    providerUsername: "Provider username",
    providerPassword: "Provider password",
    keepStored: "leave empty to keep the stored one",
    handOutFrom: "Hand out addresses from",
    to: "to",
    dhcpRangeNote:
      "Whatever is the gateway has to hand out addresses, and your Deco stops doing it once it is put into access point mode. This range must not overlap the one it uses now.",
    saveForLater: "Save for later",
  },

  upstreams: {
    resolvingThrough: "Resolving through",
    applied: "Applied",
    ifThoseFail: "if those fail",
    usingDefaultsDetail:
      "These are the resolvers that shipped. Add your own below and they take over; remove them all and these come back.",
    usingCustomDetail:
      "Your own resolvers are in use. Remove them all and the ones that shipped come back automatically.",
    effectImmediately:
      "Changes take effect the moment you make them — there is nothing to save.",
    findBest: "Find the best one",
    findBestDetail:
      "Times the well-known public resolvers from this node, and checks each one can actually resolve — including a domain in your own country, which is where a fast resolver most often turns out to be useless.",
    measuring: "Measuring…",
    measure: "Measure",
    resolvedEverything: "resolved everything",
    useBestTwo: "Use the best two",
    useBestTwoDetail:
      "Two, not one: the runner-up costs nothing until the first is slow. This replaces whatever is configured now.",
    primary: "Primary",
    primaryBlurb:
      "Asked for every query. Several are load-balanced by response time, so the fastest one gets most of the traffic.",
    primaryEmpty: "Nothing configured — the shipped resolvers are in use.",
    fallback: "Fallback",
    fallbackBlurb:
      "Only asked once every primary has failed. A plain, always-reachable resolver here means an outage at an encrypted provider does not take the house offline.",
    fallbackEmpty: "None. If every primary fails, queries fail with them.",
    makeFallback: "make fallback",
    makePrimary: "make primary",
    remove: "remove",
    resolver: "Resolver",
    role: "Role",
    note: "Note (optional)",
    notePlaceholder: "why this one",
    add: "Add",
    try: "try",
    addressHint: "A plain address, or an encrypted one —",
    addressHintSuffix:
      "all work. A bare hostname does not: resolving it would need the DNS it is meant to provide.",
    suggestionCloudflare: "fast, no filtering of its own",
    suggestionGoogle: "fast and everywhere; Google sees the queries",
    suggestionQuad9: "blocks known-malicious names itself",
    suggestionQuad9TLS: "encrypted, so your ISP cannot read the names",
  },

  intelKeys: {
    sourcesInUse: "Sources in use",
    noKey: "no key",
    withoutKeysDetail:
      "Without these the review queue still works, but on much less: it can tell that a name is newly registered and looks like a typo of something real, not that somebody has already reported it serving malware.",
    addOrReplace: "Add or replace a key",
    saved: "Saved",
    keepCurrent: "leave empty to keep the current key",
    saveKeys: "Save keys",
    keysNote:
      "Keys are stored and never shown again — nothing here can read them back, so a borrowed session cannot take them. That is also why these fields are empty when a key is already set.",
    abusechFree:
      "Free. Malware and command-and-control domains, reported by researchers.",
    safeBrowsingFree:
      "Free tier. What Chrome checks against — phishing and compromised sites.",
    otxFree:
      "Free. Community-reported indicators, broad and noisier than the other two.",
    askAboutName: "Ask about a name",
    askDetail:
      "Puts a name to every source at once. Also the quickest way to see whether the keys above work: a source that refuses its key looks the same as one that found nothing.",
    asking: "Asking…",
    lookUp: "Look up",
    flaggedIt: "flagged it",
    nothingOnFile: "nothing on file",
    couldNotAnswer: "could not answer",
    noKeyShort: "no key",
    sourceFailedNote:
      "A source could not answer, so this verdict is based on less than it looks. Hover it for the reason — a rejected key is the usual one.",
    flagged: "flagged",
    nothingAtAnySource: "Nothing on file at any source that answered.",
  },

  logs: {
    queries: "Queries",
    events: "What the node noticed",
    filters: {
      everything: "Everything",
      everythingHint: "every query this node answered",
      blocked: "Blocked",
      blockedHint: "stopped by a blocklist or one of your rules",
      allowed: "Allowed",
      allowedHint: "resolved normally",
      rewritten: "Rewritten",
      rewrittenHint: "answered with an address you chose",
      failed: "Failed",
      failedHint: "the node could not answer at all",
      paused: "Paused device",
      pausedHint: "refused because the device is paused",
    },
    filterPlaceholder: "filter by name, e.g. gib.gov.tr",
    refresh: "Refresh",
    nothingMatches: "Nothing matches.",
    noFailedGood: "No failed lookups is the good outcome here.",
    from: "from {who}",
    fromCache: "from cache",
    viaUpstream: "via {upstream}",
    blockedBy: "Blocked by {source}",
    matchedOn: "matched on",
    answeredWithFrom: "Answered with an address from {source}",
    aRule: "a rule",
    oneOfYourRules: "one of your rules",
    verdictFailed: "failed",
    eventKinds: {
      rescued: {
        label: "Needed a second resolver",
        meaning:
          "The first resolver could not answer this name and another one could. Occasional is normal; a lot of these means the resolver in front is failing while the answers still arrive.",
      },
      rebindBlocked: {
        label: "Answer dropped",
        meaning:
          "A public name was answered with an address inside your own network, which is how a page on the internet gets a browser to talk to your router. If something legitimate stopped working, look here first.",
      },
      feedFailed: {
        label: "Blocklist not updated",
        meaning:
          "A list could not be downloaded. Blocking still works from the last copy, but it stops improving, and nothing else would tell you.",
      },
      intelKeyRejected: {
        label: "Threat source refused its key",
        meaning:
          "One of the keys under Threat sources was rejected. Until it is replaced that source contributes nothing, and the review queue quietly runs on less than you think it does.",
      },
      linkDropped: {
        label: "This node lost its own connection",
        meaning:
          "The cable or radio on this machine went down and came back. Nothing could be resolved while it was down, so the whole house loses the internet for that long — and it looks exactly like this node crashing, which it is not. A few seconds now and then is ordinary. Repeated drops on the same port are a cable, a socket, or the switch it is plugged into.",
      },
      upstreamDown: {
        label: "Resolver stopped answering",
        meaning: "One of the resolvers behind this node went quiet.",
      },
      upstreamRecovered: {
        label: "Resolver back",
        meaning: "It is answering again.",
      },
    },
    nothingToReport: "Nothing to report.",
    nothingToReportDetail:
      "Lookups that needed a second resolver, answers dropped for pointing into your network, and blocklists that failed to update all appear here. An empty list is the node working.",
  },
};

export type Dictionary = typeof en;
