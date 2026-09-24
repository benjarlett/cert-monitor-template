#!/bin/bash
# Off-account public HTTPS certificate monitor (runs on GitHub Actions).
#
# Checks the certificate each domain actually SERVES to visitors, plus its HTTP
# response, and pushes problems to the same ntfy topic acme.sh uses. Alerts at
# 30/14/7 days remaining and immediately on a TLS/HTTP failure or a served
# certificate that is not from Let's Encrypt.
#
# This is the off-account half of the monitoring: the on-account
# $HOME/.cert-monitor/check-certs.sh cannot report that the account
# itself is unreachable.
#
# Alert de-duplication uses .state/alerted, which the workflow commits back to
# the repository so it persists between runs.
set -o pipefail

BASE=".state"
STATE_FILE="${STATE_FILE:-$BASE/alerted}"
HISTORY_FILE="$BASE/history.log"
NTFY_URL="${NTFY_URL:-https://ntfy.sh}"

# 11 domains renewed by acme.sh on the Namecheap account, plus 4 whose
# certificates belong to Vercel / Squarespace. Apex and www are checked for each entry unless it carries the |apex marker.
MANAGED="example.com example.net"
THIRD_PARTY="example.org|vercel example.io|squarespace"

read -r -a THRESHOLDS <<< "${THRESHOLDS_OVERRIDE:-30 14 7}"
WARN_DAYS="${WARN_DAYS_OVERRIDE:-45}"

QUIET=0
for arg in "$@"; do
  case "$arg" in
    --quiet) QUIET=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

mkdir -p "$BASE"
touch "$STATE_FILE" "$HISTORY_FILE"

push() {
  [ -z "${NTFY_TOPIC:-}" ] && { echo "NTFY_TOPIC not set — no push sent" >&2; return 0; }
  curl -sS --max-time 20 -H "Title: $1" -H "Priority: high" -H "Tags: warning" \
    -d "$2" "$NTFY_URL/$NTFY_TOPIC" >/dev/null 2>&1
}
already_alerted() { grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }
mark_alerted() { echo "$1" >> "$STATE_FILE"; }

now=$(date -u +%s)
alerts=(); report=(); problems=0
min_days=""

check_host() {
  host="$1"; owner="$2"
  handshake=$(echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null)
  enddate=$(printf '%s\n' "$handshake" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

  if [ -z "$enddate" ]; then
    problems=$((problems+1)); report+=("FAIL  $host [$owner] — no certificate retrieved over TLS")
    if ! already_alerted "fail:$host"; then mark_alerted "fail:$host"; alerts+=("$host [$owner]: TLS handshake or certificate retrieval FAILED"); fi
    return
  fi

  end_epoch=$(date -u -d "$enddate" +%s 2>/dev/null)
  if [ -z "$end_epoch" ]; then
    problems=$((problems+1)); report+=("FAIL  $host [$owner] — cannot parse expiry '$enddate'")
    if ! already_alerted "parse:$host"; then mark_alerted "parse:$host"; alerts+=("$host [$owner]: cannot parse expiry '$enddate'"); fi
    return
  fi

  days=$(( (end_epoch - now) / 86400 ))
  if [ -z "$min_days" ] || [ "$days" -lt "$min_days" ]; then min_days="$days"; fi

  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://$host/" 2>/dev/null)
  http_note=""
  case "$code" in
    2*|3*) ;;
    "") http_note=" — HTTP check failed (no response)" ;;
    *) http_note=" — HTTP $code" ;;
  esac
  if [ -n "$http_note" ]; then
    problems=$((problems+1))
    if ! already_alerted "http:$host"; then mark_alerted "http:$host"; alerts+=("$host [$owner]: HTTP problem$http_note"); fi
  fi

  # Let's Encrypt renames its intermediate CAs periodically (R10/R11, E5/E6, and
  # in September 2026 YE1/YE2/YR1/YR2). Match the organisation, never the CN,
  # or every legitimate certificate is reported as a problem.
  issuer_full=$(printf '%s\n' "$handshake" | openssl x509 -noout -issuer 2>/dev/null)
  issuer_note=""
  case "$issuer_full" in
    *"Let's Encrypt"*) ;;
    "") ;;
    *)
      # The must-be-Let's-Encrypt rule applies only where acme.sh is the
      # source of the certificate. A third-party platform may legitimately
      # serve a commercial certificate of its own (a Sectigo PositiveSSL,
      # say); alerting on that would be a permanent false alarm. The issuer
      # is still reported, and expiry is still checked.
      if [ "$owner" = "namecheap-acme" ]; then
        issuer_cn=$(printf '%s\n' "$issuer_full" | sed -n 's/.*CN *= *//p')
        problems=$((problems+1))
        issuer_note=" [NOT Let's Encrypt: ${issuer_cn:-unknown}]"
        if ! already_alerted "issuer:$host"; then
          mark_alerted "issuer:$host"
          alerts+=("$host [$owner]: served certificate is NOT Let's Encrypt (${issuer_cn:-unknown}); a stale certificate may be installed")
        fi
      fi
      ;;
  esac

  line=$(printf '%-38s %4d days  (expires %s) [%s]%s%s' "$host" "$days" "$enddate" "$owner" "$issuer_note" "$http_note")

  if [ "$days" -le 0 ]; then
    problems=$((problems+1)); report+=("EXPIRED  $line")
    if ! already_alerted "expired:$host"; then mark_alerted "expired:$host"; alerts+=("$host [$owner]: certificate EXPIRED"); fi
  elif [ "$days" -le "$WARN_DAYS" ]; then
    report+=("WATCH  $line")
    tightest=""
    for t in "${THRESHOLDS[@]}"; do [ "$days" -le "$t" ] && tightest="$t"; done
    if [ -n "$tightest" ]; then
      # Decide before recording: marking first makes the check always true.
      if ! already_alerted "d$tightest:$host"; then
        alerts+=("$host [$owner]: $days days left (threshold $tightest)")
      fi
      for t in "${THRESHOLDS[@]}"; do
        if [ "$days" -le "$t" ] && ! already_alerted "d$t:$host"; then mark_alerted "d$t:$host"; fi
      done
    fi
  else
    report+=("ok     $line")
  fi
}

# Entry forms: "domain" or "domain|apex" for MANAGED; "domain|owner" or
# "domain|owner|apex" for THIRD_PARTY. The "apex" marker means the site has no
# www name, so only the apex host is checked - which is the normal case for a
# subdomain. Without the marker a missing www produces a false failure alert.
check_entry() {
  e="$1"; base_owner="$2"
  d="${e%%|*}"; rest="${e#*|}"
  if [ "$rest" = "$e" ]; then o="$base_owner"; mode="both"
  elif [ "$rest" = "apex" ]; then o="$base_owner"; mode="apex"
  else
    o="${rest%%|*}"; mode="${rest#*|}"
    [ "$mode" = "$o" ] && mode="both"
  fi
  case "$mode" in
    both) check_host "$d" "$o"; check_host "www.$d" "$o" ;;
    apex) check_host "$d" "$o" ;;
    *) echo "unknown entry mode '$mode' for $d" >&2; problems=$((problems+1)) ;;
  esac
}
for e in $MANAGED; do check_entry "$e" "namecheap-acme"; done
for e in $THIRD_PARTY; do check_entry "$e" "vercel-or-squarespace"; done

if [ "$QUIET" = "0" ]; then
  printf '%s\n' "${report[@]}"
  echo
  echo "checked ${#report[@]} endpoints at $(date -u '+%Y-%m-%d %H:%M UTC')"
fi

# One line per run, doubling as the repository heartbeat.
echo "$(date -u '+%Y-%m-%d %H:%M UTC') checked=${#report[@]} problems=$problems alerts=${#alerts[@]} min_days=${min_days:-n/a}" >> "$HISTORY_FILE"

if [ "${#alerts[@]}" -gt 0 ]; then
  body=$(printf '%s\n' "${alerts[@]}")
  push "Certificate monitor (cloud): ${#alerts[@]} problem(s)" "$body"
  echo
  echo "ALERTS:"
  echo "$body"
  exit 1
fi

[ "$QUIET" = "0" ] && echo "no certificate problems detected"
[ "$problems" -gt 0 ] && exit 1
exit 0
