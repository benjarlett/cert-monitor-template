#!/bin/bash
# Public HTTPS certificate expiry monitor for the Namecheap hosting account.
#
# Checks the certificate each domain actually SERVES to visitors (not local
# files), plus its HTTP response, and pushes problems to the same ntfy topic
# that acme.sh uses. Alerts at 30/14/7 days remaining and immediately on a TLS
# or HTTP failure.
#
# LIMITATION: this runs on the account it watches, so it cannot report that the
# account, its DNS or the server is unreachable. An off-box monitor is still
# required for that case.
#
# Usage: check-certs.sh [--quiet] [--list-urls]
set -o pipefail

ACCOUNT_CONF="$HOME/.acme.sh/account.conf"
BASE="$HOME/.cert-monitor"
STATE_FILE="${STATE_FILE:-$BASE/alerted}"
NTFY_URL=https://ntfy.sh

# 11 domains renewed by acme.sh here, plus 4 whose certificates belong to
# Vercel / Squarespace. Apex and www are checked for each entry unless it carries the |apex marker.
MANAGED="example.com example.net"
THIRD_PARTY="example.org|vercel example.io|squarespace"

read -r -a THRESHOLDS <<< "${THRESHOLDS_OVERRIDE:-30 14 7}"
WARN_DAYS="${WARN_DAYS_OVERRIDE:-45}"

QUIET=0
LIST_URLS=0
ROWS=0
for arg in "$@"; do
  case "$arg" in
    --quiet) QUIET=1 ;;
    --rows) ROWS=1 ;;
    --list-urls) LIST_URLS=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ "$LIST_URLS" = "1" ]; then
  for e in $MANAGED $THIRD_PARTY; do
    d="${e%%|*}"
    case "$e" in
      *"|apex") printf 'https://%s/\n' "$d" ;;
      *) printf 'https://%s/\nhttps://www.%s/\n' "$d" "$d" ;;
    esac
  done
  exit 0
fi

mkdir -p "$BASE"
touch "$STATE_FILE"
TOPIC=$(sed -n "s/^SAVED_NTFY_TOPIC='\(.*\)'$/\1/p" "$ACCOUNT_CONF")

push() {
  [ -z "$TOPIC" ] && return 0
  curl -fsS --max-time 20 -H "Title: $1" -H "Priority: high" -H "Tags: warning" \
    -d "$2" "$NTFY_URL/$TOPIC" >/dev/null 2>&1
}
already_alerted() { grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }
mark_alerted() { echo "$1" >> "$STATE_FILE"; }

now=$(date -u +%s)
alerts=(); report=(); problems=0

# --rows emits one tab-separated record per endpoint and nothing else on
# stdout, so the local dashboard can convert it to JSON. Columns:
# state, host, owner, days, expires, issuer, http_code
emit_row() {
  [ "$ROWS" = "1" ] || return 0
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7"
}

check_host() {
  host="$1"; owner="$2"
  if command -v timeout >/dev/null 2>&1; then
    handshake=$(timeout 15 openssl s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null)
  else
    handshake=$(openssl s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null)
  fi
  enddate=$(printf '%s\n' "$handshake" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

  if [ -z "$enddate" ]; then
    problems=$((problems+1)); report+=("FAIL  $host [$owner] — no certificate retrieved over TLS")
    if ! already_alerted "fail:$host"; then mark_alerted "fail:$host"; alerts+=("$host [$owner]: TLS handshake or certificate retrieval FAILED"); fi
    emit_row fail "$host" "$owner" "" "" "" ""
    return
  fi
  end_epoch=$(date -u -d "$enddate" +%s 2>/dev/null || date -u -j -f "%b %d %T %Y %Z" "$enddate" +%s 2>/dev/null)
  if [ -z "$end_epoch" ]; then
    problems=$((problems+1)); report+=("FAIL  $host [$owner] — cannot parse expiry '$enddate'")
    if ! already_alerted "parse:$host"; then mark_alerted "parse:$host"; alerts+=("$host [$owner]: cannot parse expiry '$enddate'"); fi
    emit_row parsefail "$host" "$owner" "" "$enddate" "" ""
    return
  fi
  days=$(( (end_epoch - now) / 86400 ))

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

  # Let's Encrypt renames its intermediate CAs periodically (R10/R11, E5/E6 and
  # now YE1/YE2/YR1/YR2), so match the organisation, not the CN. A certificate
  # that is not from Let's Encrypt means cPanel is serving something stale.
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
      if [ "$owner" = "managed-acme" ]; then
        issuer_cn=$(printf '%s\n' "$issuer_full" | sed -n 's/.*CN *= *//p')
        problems=$((problems+1))
        issuer_note=" [NOT Let's Encrypt: ${issuer_cn:-unknown}]"
        if ! already_alerted "issuer:$host"; then
          mark_alerted "issuer:$host"
          alerts+=("$host [$owner]: served certificate is NOT Let's Encrypt (${issuer_cn:-unknown}); cPanel may still be serving a stale certificate")
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
      if ! already_alerted "d$tightest:$host"; then alerts+=("$host [$owner]: $days days left (threshold $tightest)"); fi
      for t in "${THRESHOLDS[@]}"; do
        if [ "$days" -le "$t" ] && ! already_alerted "d$t:$host"; then mark_alerted "d$t:$host"; fi
      done
    fi
  else
    report+=("ok     $line")
  fi

  if [ "$days" -le 0 ]; then rstate="EXPIRED"
  elif [ "$days" -le "$WARN_DAYS" ]; then rstate="WATCH"
  else rstate="ok"; fi
  emit_row "$rstate" "$host" "$owner" "$days" "$enddate" "${issuer_full:-}" "$code"
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
for e in $MANAGED; do check_entry "$e" "managed-acme"; done
for e in $THIRD_PARTY; do check_entry "$e" "vercel-or-squarespace"; done

if [ "$QUIET" = "0" ] && [ "$ROWS" = "0" ]; then
  printf '%s\n' "${report[@]}"
  echo
  echo "checked ${#report[@]} endpoints at $(date -u '+%Y-%m-%d %H:%M UTC')"
fi

if [ "${#alerts[@]}" -gt 0 ]; then
  body=$(printf '%s\n' "${alerts[@]}")
  push "Certificate monitor: ${#alerts[@]} problem(s)" "$body"
  [ "$ROWS" = "0" ] && echo "$body"
  exit 1
fi
[ "$QUIET" = "0" ] && [ "$ROWS" = "0" ] && echo "no certificate problems detected"
[ "$problems" -gt 0 ] && exit 1
exit 0
