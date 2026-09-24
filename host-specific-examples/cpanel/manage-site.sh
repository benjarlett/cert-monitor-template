#!/bin/bash
# manage-site.sh - add or remove a site from the certificate setup and monitors.
#
# ADD:      checks DNS and the ACME challenge path, records the certificate
#           currently being served, issues and deploys a Let's Encrypt
#           certificate, verifies what visitors actually receive, then adds the
#           domain to the on-account monitor list.
# REMOVE:   removes the domain from both monitor lists and optionally stops
#           automatic renewal. It never deletes ACME files, and it does not
#           uninstall the certificate from cPanel - that step is printed for you
#           to perform deliberately, because uapi exposes no parameter signature
#           for it and a wrong call would take the site offline.
#
# Usage:
#   manage-site.sh                          # asks what you want to do
#   manage-site.sh add example.co.uk
#   manage-site.sh remove example.co.uk
#   manage-site.sh add example.co.uk --dry-run
#
# With --dry-run, nothing that consumes Let's Encrypt rate limits, edits a
# monitor list, touches the alert state, or changes any certificate is done.
# The DNS checks and the challenge probe (which writes and removes one test file
# in the site's own acme-challenge directory) still run, because they are the
# point of checking first.

set -o pipefail

# Overridable, so the script can be exercised against copies without touching the
# live monitor list, alert state, backups or ACME profiles.
ACME="${ACME:-$HOME/.acme.sh/acme.sh}"
ACME_HOME="${ACME_HOME:-$HOME/.acme.sh}"
MONITOR="${MONITOR:-$HOME/.cert-monitor/check-certs.sh}"
SSL_BACKUPS="${SSL_BACKUPS:-$HOME/.ssl-backups}"
STATE="${STATE:-$HOME/.cert-monitor/alerted}"
CLOUD_REPO_DIR="${CLOUD_REPO_DIR:-$HOME/.cert-monitor/cloud-repo}"
EXPECTED_IP=203.0.113.10
CLOUD_REPO='~/DS Workpace/cert-monitor/cloud'

ACTION=""; DOMAIN=""; DRY=0; ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    add|remove) ACTION="$1" ;;
    --dry-run) DRY=1 ;;
    --yes) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) DOMAIN="$1" ;;
  esac
  shift
done

say() { printf '%s\n' "$*"; }
head1() { printf '\n=== %s ===\n' "$*"; }
note() { printf '  %s\n' "$*"; }

confirm() {
  [ "$ASSUME_YES" = "1" ] && return 0
  if [ "$DRY" = "1" ]; then note "[dry-run] would ask: $1"; return 1; fi
  printf '%s [y/N] ' "$1" >&2   # stderr: callers may capture stdout
  read -r a
  case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

ask() { # prompt goes to stderr so command substitution captures only the answer
  printf '%s ' "$1" >&2
  read -r a
  if [ -z "$a" ] && [ -n "$2" ]; then a="$2"; fi
  printf '%s' "$a"
}

normalize() {
  d="$1"
  d="${d#http://}"; d="${d#https://}"; d="${d%%/*}"; d="${d%%\?*}"
  d="${d%:*}"; d="${d%.}"; d="${d#www.}"
  printf '%s' "$d"
}

valid_domain() {
  case "$1" in
    ""|*[!a-zA-Z0-9.-]*) return 1 ;;
    *..*|.*|*.) return 1 ;;
    *.*) return 0 ;;
    *) return 1 ;;
  esac
}

# Document root for a domain, straight from cPanel rather than guessed.
docroot_of() {
  uapi --output=json DomainInfo domains_data 2>/dev/null | python3 -c '
import sys, json
want = sys.argv[1]
try:
    data = json.load(sys.stdin)["result"]["data"]
except Exception:
    sys.exit(1)
rows = []
main = data.get("main_domain")
if isinstance(main, dict):
    rows.append(main)
for key in ("addon_domains", "sub_domains", "parked_domains"):
    for item in (data.get(key) or []):
        if isinstance(item, dict):
            rows.append(item)
for row in rows:
    if (row.get("domain") or "").lower() == want:
        print(row.get("documentroot") or "")
        sys.exit(0)
sys.exit(1)
' "$1"
}

hosted_here() { [ -n "$(docroot_of "$1")" ]; }

ip_of() { dig +short A "$1" 2>/dev/null | grep -E '^[0-9]+\.' | head -1; }

live_cert() { # host -> "issuer=... / notAfter=..."
  echo | openssl s_client -connect "$1:443" -servername "$1" 2>/dev/null \
    | openssl x509 -noout -issuer -enddate 2>/dev/null
}

served_serial() { # host -> serial of the certificate actually served
  echo | openssl s_client -connect "$1:443" -servername "$1" 2>/dev/null \
    | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2
}

is_letsencrypt() { printf '%s' "$1" | grep -q "Let's Encrypt"; }

# Writes one throwaway file into the live acme-challenge directory and fetches it
# over public HTTP, FOLLOWING REDIRECTS. Following matters: every domain managed
# here force-redirects http to https with a 301, and Let's Encrypt follows those
# redirects, so without -L this check fails on all of them and blocks a perfectly
# valid issuance. curl also verifies the TLS certificate on any https target,
# which is what Let's Encrypt requires. It cleans up after itself.
probe_challenge() { # domain docroot
  d="$1"; root="$2"
  token="probe-$(date -u +%s)-$RANDOM"
  dir="$root/.well-known/acme-challenge"
  if ! mkdir -p "$dir" 2>/dev/null; then note "cannot create $dir"; return 1; fi
  if ! printf '%s' "$token" > "$dir/$token" 2>/dev/null; then note "cannot write in $dir"; return 1; fi
  got=$(curl -sL --max-time 25 "http://$d/.well-known/acme-challenge/$token" 2>/dev/null)
  rm -f "$dir/$token"
  if [ "$got" = "$token" ]; then
    note "challenge path OK (served from $root, redirects followed)"
    return 0
  fi
  note "challenge path FAILED for $d"
  note "  got: ${got:0:70}"
  note "  check the webroot, .htaccess rewrites, proxies and any CDN"
  note "  a redirect to a DIFFERENT domain also breaks validation"
  return 1
}

monitor_edit_file() { # file mode(remove|add) domain [entry] [var]
  python3 - "$@" <<'PY'
import re, sys
path, mode, domain = sys.argv[1], sys.argv[2], sys.argv[3]
entry = sys.argv[4] if len(sys.argv) > 4 else ""
var = sys.argv[5] if len(sys.argv) > 5 else ""
src = open(path).read()
orig = src
notes = []
targets = ("MANAGED", "THIRD_PARTY") if mode == "remove" else (var,)
for name in targets:
    m = re.search(r'^%s="([^"]*)"' % name, src, re.M)
    if not m:
        notes.append(f"{name}: line not found")
        continue
    items = m.group(1).split()
    present = [i for i in items if i.split("|")[0] == domain]
    if mode == "add":
        if present:
            notes.append(f"{name}: already present")
            continue
        items.append(entry)
        notes.append(f"{name}: added {entry}")
    else:
        if not present:
            notes.append(f"{name}: not present")
            continue
        items = [i for i in items if i.split("|")[0] != domain]
        notes.append(f"{name}: removed")
    src = src[:m.start()] + f'{name}="{" ".join(items)}"' + src[m.end():]
if src != orig:
    open(path, "w").write(src)
    print("  monitor list updated - " + "; ".join(notes))
else:
    print("  monitor list unchanged - " + "; ".join(notes))
PY
}

monitor_edit() { monitor_edit_file "$MONITOR" "$@"; }

state_clean() { # domain - drop alert keys so a re-added domain alerts afresh
  [ -f "$STATE" ] || return 0
  python3 - "$STATE" "$1" <<'PY'
import sys
path, domain = sys.argv[1], sys.argv[2]
targets = {domain, "www." + domain}
lines = [l for l in open(path).read().splitlines() if l]
kept = [l for l in lines if l.rsplit(":", 1)[-1] not in targets]
open(path, "w").write(("\n".join(kept) + "\n") if kept else "")
print(f"  alert state: {len(lines) - len(kept)} stale key(s) cleared")
PY
}

cloud_note() { # "add <domain>" or "remove <domain>"
  action="${1%% *}"; domain="${1##* }"
  cloud_file="$CLOUD_REPO_DIR/.github/scripts/check-certs.sh"

  if [ ! -d "$CLOUD_REPO_DIR/.git" ]; then
    note "no local clone of the cloud repo on this account"
    cloud_manual "$1"
    return 1
  fi
  if ! git -C "$CLOUD_REPO_DIR" pull -q --rebase origin main 2>/dev/null; then
    note "the cloud clone could not be updated (offline?)"
    cloud_manual "$1"
    return 1
  fi

  # Mirror whatever the server list now says about this domain, so the two lists
  # cannot drift: copy the entry across if the server list has one, otherwise
  # clear the domain from the cloud list as well.
  entry=$(sed -n 's/^MANAGED="\([^"]*\)"/\1/p; s/^THIRD_PARTY="\([^"]*\)"/\1/p' "$MONITOR" \
          | tr ' ' '\n' | grep -F "$domain" | head -1)
  if [ -n "$entry" ]; then
    if grep -q "^THIRD_PARTY=\".*$entry" "$MONITOR"; then var=THIRD_PARTY; else var=MANAGED; fi
    monitor_edit_file "$cloud_file" add "$domain" "$entry" "$var"
  else
    monitor_edit_file "$cloud_file" remove "$domain"
  fi

  if ! bash -n "$cloud_file"; then
    note "the cloud list failed its syntax check - reverting, nothing pushed"
    git -C "$CLOUD_REPO_DIR" checkout -- .github/scripts/check-certs.sh
    cloud_manual "$1"
    return 1
  fi
  if [ -z "$(git -C "$CLOUD_REPO_DIR" status --porcelain)" ]; then
    note "the cloud monitor list already matches - nothing to push"
    return 0
  fi

  git -C "$CLOUD_REPO_DIR" add -A
  if git -C "$CLOUD_REPO_DIR" commit -q -m "monitor list: $action $domain" \
     && git -C "$CLOUD_REPO_DIR" push -q origin main; then
    note "cloud monitor list updated and pushed - no manual step needed"
    return 0
  fi
  note "the cloud push failed; the change is committed locally but not published"
  cloud_manual "$1"
  return 1
}

cloud_manual() { # fallback instructions, only if the sync above cannot run
  head1 "Sync the cloud monitor's list by hand"
  say "The off-account monitor keeps its own copy of the domain list. From your Mac:"
  say ""
  say "  cd \"\$HOME/DS Workpace/cert-monitor/cloud\""
  say "  git pull --quiet"
  say "  # apply the same list edit to .github/scripts/check-certs.sh"
  say "  git commit -am \"monitor list: $1\" && git push"
  say ""
  say "Note \$HOME, not ~ : a tilde inside quotes is not expanded by the shell, so"
  say "cd \"~/...\" fails with 'no such file or directory'."
}

# ---------------------------------------------------------------------------
# gather input
# ---------------------------------------------------------------------------

if [ -z "$ACTION" ]; then
  say "What would you like to do?"
  say "  1) add a site"
  say "  2) remove a site"
  ACT=$(ask "Choice [1]:" "1")
  case "$ACT" in 2|remove|r) ACTION="remove" ;; *) ACTION="add" ;; esac
fi

if [ -z "$DOMAIN" ]; then
  DOMAIN=$(ask "Domain or URL:" "")
fi

DOMAIN=$(normalize "$DOMAIN")
if ! valid_domain "$DOMAIN"; then
  say "That does not look like a domain: '$DOMAIN'"
  exit 2
fi
[ "$DRY" = "1" ] && say "(dry run: nothing will be changed)"

# ---------------------------------------------------------------------------
# ADD
# ---------------------------------------------------------------------------
if [ "$ACTION" = "add" ]; then
  head1 "Checking $DOMAIN"

  apex_ip=$(ip_of "$DOMAIN")
  www_ip=$(ip_of "www.$DOMAIN")
  note "apex A record : ${apex_ip:-none}"
  note "www  A record : ${www_ip:-none}"
  note "this account  : $EXPECTED_IP"

  if [ -z "$apex_ip" ]; then
    say "The apex does not resolve. Point its DNS here before adding it."
    exit 1
  fi

  root=$(docroot_of "$DOMAIN")

  if [ "$apex_ip" = "$EXPECTED_IP" ] && [ -z "$root" ]; then
    say "DNS for $DOMAIN points at this account but cPanel has no entry for it."
    say "Create the domain in cPanel first, then run this again."
    exit 1
  fi

  # Served from this account only if BOTH hold: DNS points here and cPanel has a
  # document root. A domain can sit in cPanel while its DNS points at Vercel or
  # Squarespace - example.org is exactly that - and issuing here would then
  # fail validation or fight the other platform for the name.
  if [ "$apex_ip" = "$EXPECTED_IP" ] && [ -n "$root" ]; then
    note "hosted here   : yes, document root $root"
    served_here=1
  else
    served_here=0
    if [ -n "$root" ]; then
      note "hosted here   : cPanel entry exists ($root) but DNS points to $apex_ip"
    else
      note "hosted here   : no cPanel entry for $DOMAIN"
    fi
  fi

  # www joins the certificate only when it resolves to this same account.
  mode="apex"
  if [ "$served_here" = "1" ] && [ -n "$www_ip" ] && [ "$www_ip" = "$EXPECTED_IP" ]; then
    mode="both"
  fi
  if [ "$served_here" = "1" ]; then
    if [ "$mode" = "both" ]; then
      note "www name      : resolves here, so the certificate will cover it too"
    else
      note "www name      : does not resolve here - certificate and monitor entry are apex-only"
    fi
  else
    if [ -n "$www_ip" ]; then
      note "www name      : resolves to $www_ip (covered by that platform's certificate)"
    else
      note "www name      : does not resolve - monitor entry will be apex-only"
    fi
  fi

  if [ "$served_here" = "0" ]; then
    head1 "Not served from this account"
    owner=$(ask "Who serves HTTPS for it? [vercel/squarespace/other]:" "other")
    # For a third-party site the monitor entry depends only on whether the www
    # name resolves at all; where DNS points is that platform's business.
    entry="$DOMAIN|$owner"
    [ -z "$www_ip" ] && entry="$entry|apex"
    if [ "$DRY" = "1" ]; then
      note "[dry-run] would add to THIRD_PARTY: $entry"
    else
      monitor_edit add "$DOMAIN" "$entry" THIRD_PARTY || exit 1
      bash -n "$MONITOR" || { say "monitor syntax broken - restore from the .bak file"; exit 1; }
    fi
    say ""
    say "Nothing is issued for it here; $owner renews its certificate."
    cloud_note "add $DOMAIN"
    exit 0
  fi

  # Hosted here: show the certificate currently served, and abort early if the
  # challenge path cannot work, so no rate limit is spent on a doomed attempt.
  head1 "Certificate currently served"
  before_cert=$(live_cert "$DOMAIN")
  if [ -n "$before_cert" ]; then
    printf '%s\n' "$before_cert" | sed 's/^/  /'
    if is_letsencrypt "$before_cert"; then
      note "already Let's Encrypt - re-issuing would spend a rate limit for nothing"
      if ! confirm "Re-issue anyway?"; then
        say "Stopping. If you only wanted it monitored, add it to the list without issuing."
        exit 0
      fi
    fi
  else
    note "nothing served yet (or port 443 unreachable)"
  fi

  head1 "Probing the ACME challenge path"
  if ! probe_challenge "$DOMAIN" "$root"; then
    say ""
    say "Not issuing anything: HTTP-01 would fail. Fix the path above first."
    exit 1
  fi

  head1 "Planned actions"
  [ -n "$before_cert" ] && note "record the current certificate in $SSL_BACKUPS"
  note "issue:  $ACME --issue --ecc -d $DOMAIN$([ "$mode" = both ] && printf ' -d www.%s' "$DOMAIN") -w $root"
  note "deploy: DEPLOY_CPANEL_USER=youruser $ACME --deploy --ecc -d $DOMAIN --deploy-hook cpanel_uapi"
  note "verify: served certificate on apex$([ "$mode" = both ] && printf ' and www')"
  entry="$DOMAIN"; [ "$mode" = "apex" ] && entry="$DOMAIN|apex"
  note "monitor: add '$entry' to MANAGED"

  if ! confirm "Proceed?"; then say "Nothing done."; exit 0; fi

  if [ -n "$before_cert" ]; then
    bdir="$SSL_BACKUPS/$DOMAIN-$(date -u +%Y%m%d)-pre-letsencrypt"
    mkdir -p "$bdir" && chmod 700 "$bdir"
    echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null \
      | openssl x509 -outform PEM > "$bdir/certificate.pem" 2>/dev/null
    {
      echo "{"
      echo "  \"domain\": \"$DOMAIN\","
      echo "  \"captured_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
      echo "  \"captured_from\": \"public https endpoint\","
      echo "  \"note\": \"public certificate only; the private key cannot be captured from outside cPanel\""
      echo "}"
    } > "$bdir/source.json"
    note "saved $bdir (public certificate only)"
  fi

  head1 "Issuing"
  # acme.sh --remove (which the remove action uses) clears the profile but leaves
  # the domain key on disk. A later re-issue then refuses with "Domain key exists,
  # do you want to overwrite it? If so, add '--force'". Detect that here so that
  # remove-then-re-add works without any manual cleanup.
  force=""
  if [ -f "$ACME_HOME/${DOMAIN}_ecc/${DOMAIN}.key" ]; then
    note "leftover domain key from a previous profile - issuing with --force"
    force="--force"
  fi
  if [ "$mode" = "both" ]; then
    "$ACME" --issue $force --ecc -d "$DOMAIN" -d "www.$DOMAIN" -w "$root" || { say "issuance failed"; exit 1; }
  else
    "$ACME" --issue $force --ecc -d "$DOMAIN" -w "$root" || { say "issuance failed"; exit 1; }
  fi

  head1 "Deploying through cPanel"
  serial_before=$(served_serial "$DOMAIN")
  DEPLOY_CPANEL_USER=youruser "$ACME" --deploy --ecc -d "$DOMAIN" --deploy-hook cpanel_uapi
  say "(Perl warnings from NcCustomHooks/SSL.pm are normal; the live certificate decides.)"

  head1 "Verifying what visitors actually get"
  # cPanel rebuilds the vhost asynchronously, so the certificate it serves can lag
  # a minute or two behind the hook reporting success. Checking too early makes a
  # working deploy look broken, so wait for the served serial to actually change.
  waited=0
  serial_after=$(served_serial "$DOMAIN")
  while [ -n "$serial_before" ] && [ "$serial_after" = "$serial_before" ] && [ "$waited" -lt 120 ]; do
    sleep 10; waited=$((waited + 10))
    serial_after=$(served_serial "$DOMAIN")
  done

  served=$(live_cert "$DOMAIN")
  printf '%s\n' "$served" | sed 's/^/  /'
  if is_letsencrypt "$served"; then
    note "apex is serving Let's Encrypt"
  else
    note "apex is NOT serving a Let's Encrypt certificate yet - check the deploy hook"
  fi
  if [ -n "$serial_before" ] && [ "$serial_after" != "$serial_before" ]; then
    note "served certificate changed (propagated after about ${waited}s)"
  elif [ -n "$serial_before" ]; then
    note "WARNING: the served certificate has not changed after ${waited}s."
    note "  cPanel vhost rebuilds can lag. Re-check in a few minutes before"
    note "  concluding the deploy failed; if it still has not changed, re-run the"
    note "  deploy hook, or uninstall and reinstall the certificate in cPanel."
  fi
  if [ "$mode" = "both" ]; then
    served_www=$(live_cert "www.$DOMAIN")
    printf '%s\n' "$served_www" | sed 's/^/  www: /'
  fi
  curl -sI --max-time 20 "https://$DOMAIN/" | head -1 | sed 's/^/  /'

  head1 "Adding to the monitor"
  monitor_edit add "$DOMAIN" "$entry" MANAGED || exit 1
  if bash -n "$MONITOR"; then
    note "syntax OK"
  else
    say "monitor syntax broken - restore $MONITOR.bak-*"
    exit 1
  fi
  note "running the monitor to confirm the new site is picked up..."
  bash "$MONITOR" 2>&1 | grep -iE "$DOMAIN|endpoints" | sed 's/^/  /'

  cloud_note "add $DOMAIN"
  head1 "Remember"
  say "  - add a row for $DOMAIN to the runbook's 'Certificates managed here' table"
  say "  - renewal is automatic from now on (four-times-daily acme.sh cron)"
  exit 0
fi

# ---------------------------------------------------------------------------
# REMOVE
# ---------------------------------------------------------------------------
if [ "$ACTION" = "remove" ]; then
  head1 "Current state of $DOMAIN"

  profile=$("$ACME" --list 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | awk -v d="$DOMAIN" '$1==d || $1=="www."d {print}')
  if [ -n "$profile" ]; then note "ACME renewal profile: present"; else note "ACME renewal profile: none"; fi

  in_managed=$(grep -c "\b$DOMAIN\b" "$MONITOR" 2>/dev/null || echo 0)
  note "monitor list entries mentioning it: $in_managed"

  served=$(live_cert "$DOMAIN")
  if [ -n "$served" ]; then
    printf '%s\n' "$served" | sed 's/^/  served: /'
  else
    note "served: nothing retrieved on 443"
  fi

  backups=$(ls -d "$SSL_BACKUPS/$DOMAIN"-* 2>/dev/null | tr '\n' ' ')
  note "backups on file: ${backups:-none}"

  say ""
  say "How far should the removal go?"
  say "  1) stop monitoring it only (keeps renewing and serving)"
  say "  2) also stop automatic renewal (keeps serving the current certificate)"
  say "  3) also uninstall the certificate in cPanel (breaks HTTPS until replaced)"
  scope=$(ask "Choice [1]:" "1")

  if [ "$DRY" = "1" ]; then
    note "[dry-run] would remove the monitor entry"
    [ "$scope" != "1" ] && note "[dry-run] would run: $ACME --remove -d $DOMAIN --ecc"
    [ "$scope" = "3" ] && note "[dry-run] would then instruct you to uninstall in cPanel"
    note "[dry-run] would clear alert-state keys for $DOMAIN"
    exit 0
  fi

  if [ "$scope" = "3" ] && ! [ "$ASSUME_YES" = "1" ]; then
    say ""
    say "Type the domain to confirm uninstalling its certificate:"
    typed=$(ask "Domain:")
    [ "$typed" = "$DOMAIN" ] || { say "Does not match - nothing done."; exit 1; }
  fi

  head1 "Removing from the monitor"
  cp -p "$MONITOR" "$MONITOR.bak-remove-$(date -u +%Y%m%d-%H%M%S)"
  monitor_edit remove "$DOMAIN" || exit 1
  if bash -n "$MONITOR"; then note "syntax OK"; else say "syntax broken - restore the .bak file"; exit 1; fi
  state_clean "$DOMAIN"

  if [ "$scope" != "1" ]; then
    head1 "Stopping automatic renewal"
    "$ACME" --remove -d "$DOMAIN" --ecc && note "removed from the renewal list"
    note "ACME files are left in place on purpose - do not delete them until the"
    note "incident or change is fully closed (see the runbook)"
  fi

  if [ "$scope" = "3" ]; then
    head1 "Uninstall the certificate in cPanel"
    say "Do this in the browser, deliberately:"
    say "  cPanel > SSL/TLS Status > select $DOMAIN > Uninstall"
    say "It is not automated here: uapi exposes no parameter signature for"
    say "SSL::delete_ssl, and a wrong call would take the site offline."
    say ""
    say "If HTTPS matters for this name, install another certificate first."
  fi

  cloud_note "remove $DOMAIN"
  head1 "Remember"
  say "  - remove the row for $DOMAIN from the runbook's tables"
  say "  - verify from outside: openssl s_client -connect $DOMAIN:443 -servername $DOMAIN"
  exit 0
fi

say "Nothing to do."
