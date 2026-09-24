# Certificate expiry monitoring, done properly

A small, dependency-light system for watching a set of HTTPS endpoints and being told
*reliably* when a certificate is near expiry, has expired, or is not the one you expected.

Extracted from a real setup that issues, renews and verifies Let's Encrypt certificates on a
shared-hosting account. The monitoring half is host-agnostic and worth taking; the issuance
half is specific to cPanel and is included as a worked example of the parts to replace.

## The one idea worth taking

Most certificate monitoring reports what your renewal tooling *believes*. This reports what a
**visitor actually gets**: every check opens a real TLS connection to the public endpoint and
reads the certificate that comes back.

That distinction found everything interesting in the original build:

| What the tooling said | What was actually true |
|---|---|
| `mail Success` from the notification hook | Gmail had rejected the message outright — the hook only knows `sendmail` exited 0 |
| "Successfully deployed certificate to 1 of 1 sites" | True, but the web server kept serving the old certificate for another minute |
| `acme.sh --list` showed a renewal profile | The certificate had never been installed on that subdomain, so HTTPS served something else entirely |
| "Watching 30 endpoints" | The count was hardcoded; four domains had quietly been added behind it |
| A domain was in the hosting control panel | Nothing was monitoring it, and its certificate had 35 days left |

## Quick start

```bash
git clone <this repo> && cd <this repo>
$EDITOR monitor/check-certs.sh      # edit the two domain lists at the top
./monitor/check-certs.sh            # human-readable report
./monitor/check-certs.sh --rows     # tab-separated, for other tooling
```

Two lists drive everything:

```bash
MANAGED="example.com example.net"                       # served from your host
THIRD_PARTY="example.org|vercel example.io|squarespace" # served elsewhere, "domain|who renews it"
```

- **`MANAGED`** — you control the certificate, so the monitor insists it is issued by the CA you
  expect and treats anything else as a possible stale certificate.
- **`THIRD_PARTY`** — a platform or colleague renews it. Watched for expiry and outages only, and
  any issuer is accepted, because a third-party site may legitimately serve a commercial
  certificate. Without this distinction you get a permanent false alarm.
- append **`|apex`** when a name has no `www` record — the normal case for a subdomain. Without
  it the monitor tries `www.<domain>`, fails to connect, and raises a false failure.

Alerts fire at **30, 14 and 7 days** remaining, and immediately on a TLS failure, an HTTP
failure, or an unexpected issuer. De-duplication is per host *and* threshold, in a state file, so
a month-long expiry run does not nag daily.

Requirements: `bash`, `curl`, `openssl`, and either GNU or BSD `date`. Nothing else.

## Alerting

The monitor pushes to an [ntfy](https://ntfy.sh) topic, so an alert does not end up in a spam
folder:

```bash
export NTFY_TOPIC=your-topic-here      # or put it in a file and point the script at it
./monitor/check-certs.sh
```

The topic is the only secret in the system. Anyone who knows it can read the alerts, so treat it
as one, and rotate it if it leaks. Anything that can receive an HTTP POST can be substituted —
the script's `push()` function is a single `curl` call.

If you prefer email, remember the lesson above: a mail hook that reports success is telling you
nothing about delivery. Verify end to end, check the spam folder, and expect to need SPF and
DKIM before Gmail will accept automated mail from a shared host.

## The two-monitor idea

`cloud/` holds the same check as a GitHub Actions workflow, for the reason that a monitor
running on the host it watches shares that host's fate: when the server, its DNS or the whole
account goes down, so does the monitor.

- copy `cloud/cert-expiry.yml` into `.github/workflows/` and `cloud/check-certs.sh` into
  `.github/scripts/` of your own repository
- set the topic as an encrypted repository secret named `NTFY_TOPIC`
- it runs daily and each run appends a line to `.state/history.log`, committing it back

That commit is deliberate: it is an audit trail *and* a heartbeat. GitHub disables scheduled
workflows after 60 days of repository inactivity, and a daily commit prevents that.

Two monitors over the same endpoints is not redundancy theatre — either one failing still leaves
you alerted, and they disagree loudly when a change has not propagated.

## The dashboard

`dashboard/` is a PHP + vanilla-JS page: no build step, no dependencies. It shows an expiry table
sorted by urgency, the renewal profiles, alert configuration, schedules and recent monitor runs,
and offers an "add a site" panel that previews before it acts.

`api.php` shells out over `ssh` to collect one JSON blob and caches it for five minutes. Point
`config.php` at your host. Because the page can run `ssh`, serve it to localhost only
(`Require local` in the Apache vhost) and never render a secret — the topic appears only as a
"configured" flag.

The JSON contract is deliberately boring, so the collector can be anything: in the original, a
Python script on the server calls the monitor's `--rows` mode and adds renewal and schedule
details.

## The host-specific half

`host-specific-examples/cpanel/` shows the *other* half: the helper that adds a site (resolve,
probe the ACME challenge path, issue, deploy, verify, then register it with the monitor) and the
collector that feeds the dashboard. It is written against cPanel's UAPI and will not run on
another host — replace it with your provider's equivalent and keep everything else.

Worth copying from it regardless:

- **Probe before you spend a rate limit.** It writes one throwaway file into the live
  `/.well-known/acme-challenge/` path and fetches it over public HTTP. If that fails it refuses
  to issue, rather than burning a certificate attempt on a doomed request.
- **Follow redirects when probing.** If the site force-redirects HTTP to HTTPS, a probe that does
  not follow them fails on every domain — and would block every legitimate issuance.
- **Wait for propagation before judging a deploy.** Control panels rebuild vhosts asynchronously;
  a check that runs immediately after "deployed successfully" can see the old certificate and
  wrongly conclude the deploy failed. Poll the served serial for a minute or two.
- **Leave the key files alone.** Removal tears down the profile but keeps the key material on
  disk, because deleting it is the only irreversible step — and a re-issue then needs `--force`.

## Other things this learned the hard way

- **Match a CA by organisation, not by common name.** Let's Encrypt renames its intermediates
  periodically (R10/R11, E5/E6, and in one case YE1/YE2/YR1/YR2). Matching the CN broke the
  checks on every domain at once.
- **Audit the monitored set against the host's own domain list.** An unlisted domain is an
  unwatched domain, and nothing will tell you.
- **Record what is deliberately excluded, and why.** Otherwise every audit re-raises the same
  questions.
- **Keep a runbook.** The design is only half of it; the other half is what to do at 8am when an
  alert arrives. Write it while the details are fresh, and record the expiry dates and paths.

## Why nothing here runs on a laptop

An earlier version ran the checks as a shell script on a Mac. Running it triggered a macOS
"Malicious Script Blocked" alert twice and killed the session both times: looping TLS handshakes
across many hosts followed by a POST of the results to an external URL is, understandably, a
pattern security software dislikes. The work moved to a cron job on the server and a GitHub
workflow; the laptop kept only the dashboard, which reads rather than scans.

## Licence

MIT — see `LICENSE`. Take it, change it, no attribution needed.
