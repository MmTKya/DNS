# Changelog

What changed in each release, written for the person deciding whether to
install it. The panel shows the section for the version it is offering, so
these are the words someone reads before replacing the resolver their whole
house depends on — not a list of commits.

Newest first. Each version has its own `## x.y.z` heading; the release
pipeline extracts the matching section.

## 0.7.0

**Blocked sites can now explain themselves.** Instead of a browser error that
says nothing, the name resolves to this node and you get a page: the site, why
it was blocked, and which list stopped it.

Off by default because it changes what a blocked name resolves to. Turn it on
in the configuration file:

```yaml
filtering:
  block_page:
    enabled: true
    allow_release: false
```

**`allow_release` puts an "allow this site" button on that page.** Left off,
because the page is reachable by anything on your network and the button needs
no password — the right trade for one household, the wrong one where the
blocking is a rule for somebody rather than a preference. With it off the page
still explains the block and points at the panel.

**Worth knowing before you turn it on:** almost every site is HTTPS, and a
browser asking for `https://ads.example.com` will be handed a certificate for
something else — so it shows a certificate warning rather than this page. The
page is what you get on plain HTTP. Every product that does this has the same
limit; none can fix it without installing a certificate authority on every
device in the house.

**The live query list is readable.** The name was being squeezed into whatever
space the timestamp and the address left over, which is backwards: the name is
the only thing anyone is reading. It now comes first and takes the room, with
the list that blocked it beside it.

## 0.6.2

**Blocklists were failing because the node was downloading them twice at
once.** Refreshing from the panel and the node's own scheduled refresh could
overlap, so the same lists were fetched from the same servers simultaneously —
and list maintainers rate-limit for exactly that. Being turned away by a mirror
because the node asked itself four times is a failure with nobody to blame but
the node. Only one refresh runs at a time now.

**Resolvers: there is no save button because there is nothing to save.** Each
change is sent as you make it and the resolver is rebuilt around it. The screen
now says so, and confirms when a change has landed — a change with no visible
effect is indistinguishable from one that did not happen.

If a blocklist shows *no longer in the catalogue*, it was withdrawn by whoever
published it and its address no longer works. Remove it with the button beside
it; it cannot recover on its own.

## 0.6.1

**Fixes the 0.6.0 migration.** Moving the configuration directory kept the
ownership it already had, and the account that owned it was then deleted — so
the service could not read its own configuration file and would not start. The
data was never at risk, but the node was down until the permissions were
corrected by hand.

If 0.6.0 left your node not starting, running the installer again fixes it.

## 0.6.0

**The rename is complete.** The service, the program and its directories are
now called seddns rather than aegisdns, and the panel says SedDNS everywhere.

**Upgrading from 0.5.0 or earlier means running the installer again** — the
in-panel update will not carry you across, because the older version is looking
for a file that no longer has that name. One command:

```
curl -sSL https://raw.githubusercontent.com/MmTKya/DNS/main/deploy/install.sh | sudo bash
```

It migrates in place: your configuration, your rules, your devices, your
administrator account and your history all move to the new locations and the
old service is removed. Nothing is lost and nothing needs setting up again.
After this, in-panel updates work as before.

**The log lines are readable.** They were laid out as a table, which meant the
name — the one thing anyone is looking for — was squeezed into whatever space
was left. Each entry now leads with the name at full size, and a blocked one
says which list blocked it and which pattern it matched.

## 0.5.0

**The application is now called SedDNS.** The name in the panel, the browser
tab and the installer. The service, the binary and the configuration paths are
unchanged, so nothing breaks and no existing install needs touching.

**There is a log screen, so nothing here needs a terminal.** System → Logs.

*Queries* — everything the node answered, filtered by what happened to it:
blocked, allowed, rewritten, failed, or refused because a device is paused.
Searchable by name, so "why did that site not open" is one field away.

*What the node noticed* — the handful of moments that explain a failure, which
until now only existed in the system journal:

- **Needed a second resolver.** The first one could not answer and another
  could. Occasional is normal; a lot of them means the resolver in front is
  failing while the answers still arrive, which nothing else would show you.
- **Answer dropped.** A public name was answered with an address inside your
  own network. If something legitimate stopped working after 0.4.0, this is
  the first place to look.
- **Blocklist not updated.** A list could not be downloaded. Blocking still
  works from the last copy, but it stops improving.

## 0.4.1

**The dashboard now shows how the resolvers behind this node are doing.** Each
one with its current latency and whether it is answering at all, measured from
the node every thirty seconds.

It is there because of the question people actually arrive with when a page
will not load: is it this box, the resolvers behind it, or the internet. All
of them red means the connection or the network. One red means queries are
still fine through the others.

Next to it, the number of lookups that only succeeded because a second
resolver was asked. That one is worth watching: answers still arrive, so
nothing looks wrong, while the resolver in front is quietly failing.

## 0.4.0

**Pages that would not open, now open.** When a resolver answers "I could not
find out" — which is different from "that does not exist" — this node now asks
a second one before giving up. That single failure mode was behind the whole
problem: gib.gov.tr resolved perfectly through Google and Cloudflare and not at
all through the resolver shipped as the default, and a household pointed at
this node would have seen a page that simply never loaded, with nothing
anywhere explaining why.

Thirty real domains were checked afterwards — Turkish banks, government,
e-commerce, the mobile operators, and the usual global services — and all
thirty resolve.

**Quad9 is no longer the default.** It was the slowest of the candidates
measured from a real line, at 139 ms against 45 for Google, and it could not
resolve gib.gov.tr at all. New installs use Cloudflare and Google. Existing
ones keep what is in their configuration file; use System → Resolvers →
Measure to change it.

**Answers that point into your own network are dropped.** A page on the
internet can ask for a name its author controls and be handed 192.168.1.1,
after which the browser starts making requests to your router believing it is
still on the same site. Names that are local by definition — anything under
.local, .lan, .home.arpa, a plain hostname, reverse lookups — are exempt, so a
NAS or a printer with a name keeps working.

**Signing in is rate-limited.** Checking a password deliberately costs 19 MiB
and real CPU, which is what makes a stolen password file expensive to attack.
Left unbounded that same cost was a way to take the resolver down from the
local network without logging in at all: enough simultaneous attempts and
there is no memory left for answering DNS. Ten attempts a minute per address,
and no more than four password checks running at once.

## 0.3.2

**The panel can now measure resolvers and pick the best two for you.** System →
Resolvers → Measure. It times the well-known public resolvers from this node —
not from your laptop, which is a different path — and checks each one can
actually resolve, including a domain in your own country.

That second check is the reason this exists rather than being a stopwatch. The
resolver shipped as the default answers a reachability test perfectly and
**cannot resolve gib.gov.tr at all**: on the machine this was written on it
returned SERVFAIL while Google and Cloudflare answered normally. A benchmark
that only measured speed would have gone on recommending it.

If you were running the defaults, run the measurement. Some Turkish government
sites may not have been loading.

## 0.3.1

**Setting up a second node now has a screen.** System → Cluster → "Set up a
second node". Enter the other machine's address, say which of the two is the
primary, and it produces the exact configuration for each — including a shared
secret generated for you, since a token someone thinks up is the weakest part
of this.

The panel does not write those files itself, on purpose: the configuration
carries each node's listen addresses, and a machine that rewrote them because
of a form on another machine could put itself off the network with no way back
except a keyboard.

## 0.3.0

**You can choose which resolvers this node forwards to.** Under System →
Resolvers. Add your own and they take over from the ones that shipped; remove
them all and the shipped ones come back on their own, so trying something out
cannot leave the house without DNS.

Each resolver is either **primary** — asked for every query, with several
load-balanced by speed — or **fallback**, asked only once every primary has
failed. Plain addresses work, and so do encrypted ones (`tls://`, `https://`,
`quic://`).

Worth doing: the shipped default is Quad9, and on a line in Turkey it measured
139 ms against 45 ms for Google and 64 ms for Cloudflare. The fastest resolver
depends on where you are, which is exactly why this is now a setting rather
than a guess baked into the file.

**A second node can be configured.** The clustering was written but never
connected to anything: there was no way to switch it on. There is now a
`cluster` section in the configuration file with a role, a shared token and
the address of the other node, and a replica genuinely follows its primary.
The panel screen for pairing two nodes is still to come.

## 0.2.6

**If you skipped a few releases, you now see all of them.** The update screen
only showed what the newest version changed, so anything in between went
unread. It now lists every release between the one you are running and the one
on offer.

## 0.2.5

**Installing an update from the panel now works.** It failed with a
"read-only file system" error, because the resolver deliberately cannot write
to the directory its own program lives in.

That protection is worth keeping: the resolver is the part of the system
exposed to the network, and one that could rewrite the program it runs next
would turn a break-in into a permanent one. So the work is now split. The
resolver downloads the update and checks its signature, but the swap is done
by a separate step running with the privileges it needs — and that step checks
the signature again before touching anything, rather than trusting what it was
handed.

Nothing about this is visible in the panel. You press install, and it
installs.

## 0.2.4

**A fix to these notes.** The 0.2.3 release published an empty description
because of a mistake in how it was built. The text you are reading now comes
from the right place.

## 0.2.3

**Rules now let you choose what happens.** The "Your rules" screen only
accepted an address, which meant blocking was the only thing you could do
unless you already knew the filter syntax. You can now pick block, allow,
answer with an address of your own, or answer "does not exist" — and each rule
in the list says in plain words what it does, including whether it covers
subdomains and which devices it applies to.

**Release notes are written for you.** This screen used to show a list of
commit messages. It now shows what actually changed.

## 0.2.2

**The panel waits for the node to come back after an update** instead of
asking you to reload and find out. If it takes too long it says so, and tells
you where the previous version is kept and which log to read.

## 0.2.1

**Updates can be installed from the panel.** Until now it could only tell you
a new version existed. It now downloads it, checks the signature before
unpacking anything, keeps the old version, and makes the new one prove it
starts before letting the old one go. If it cannot, the previous version is
put back.

An update is refused outright if it is not signed by this project's release
key. A working HTTPS connection to the wrong server is not proof of anything.

## 0.2.0

**Your password and two-factor are now in the panel**, under your name in the
top corner. Changing your password signs out every device, including the one
you are on — that is deliberate, so a stolen session cannot outlive it.

**You can add your own blocklist sources.** Give a name and a URL; hosts files
and Adblock-syntax lists both work.

**Two blocklists were replaced.** The HaGeZi lists were removed because the
project that published them disappeared: the addresses stopped working and
only a cache was keeping them alive. OISD Big and the AdGuard DNS filter take
their place and are on by default. If you were running the old lists you will
see them marked as withdrawn, with a button to remove them.

## 0.1.1

Fixes found while installing on real hardware for the first time:

- The one-line installer could not ask for confirmation when piped into a
  shell, so it gave up instead of installing.
- Freeing port 53 on Ubuntu left the machine unable to resolve anything,
  which quietly stopped blocklists from downloading.
- The service's restart limit was in the wrong place and did nothing.

## 0.1.0

First release. Filtering with blocklists, the Turkish national threat feed,
domain research with an approve-or-reject queue, device identity, backup and
replication, WireGuard, notifications, an audit trail and signed updates.
