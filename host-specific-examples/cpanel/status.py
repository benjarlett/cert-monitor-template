#!/usr/bin/env python3
"""Assemble the JSON that the local dashboard consumes.

Read-only with respect to the certificates: it may run the monitor to refresh the
endpoint data, but it never issues, deploys or removes anything. No secrets are
emitted - the ntfy topic is reported only as a boolean, never by value.
"""
import datetime
import glob
import json
import os
import re
import subprocess
import sys
import time

BASE = "$HOME/.cert-monitor"
ACME_HOME = "$HOME/.acme.sh"
ACCOUNT_CONF = os.path.join(ACME_HOME, "account.conf")
TSV = os.path.join(BASE, "status.tsv")
MONITOR = os.path.join(BASE, "check-certs.sh")
STATE = os.path.join(BASE, "alerted")
HOSTNAME = "your-host.example.com"
CACHE_MAX_AGE = 26 * 3600  # a day plus slack, so the dashboard is never very stale


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def refresh_rows():
    """Run the monitor in --rows mode and replace the cache atomically."""
    tmp = TSV + ".web"
    try:
        with open(tmp, "w", encoding="utf-8") as out:
            subprocess.call([MONITOR, "--rows"], stdout=out,
                            stderr=subprocess.DEVNULL)
        if os.path.getsize(tmp) > 0:
            os.rename(tmp, TSV)
            return True
        os.remove(tmp)
    except Exception:
        pass
    return False


def to_iso(gmt_string):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %e %H:%M:%S %Y %Z"):
        try:
            dt = datetime.datetime.strptime(gmt_string.strip(), fmt)
            return dt.replace(tzinfo=datetime.timezone.utc).isoformat()
        except ValueError:
            continue
    return None


def parse_endpoint_rows():
    rows, checked_at = [], None
    try:
        checked_at = os.path.getmtime(TSV)
    except OSError:
        return rows, None

    for line in read(TSV).splitlines():
        parts = line.split("\t")
        if len(parts) != 7:
            continue
        state, host, owner, days, expires, issuer, http = parts
        issuer_cn = ""
        match = re.search(r"CN *= *([^,]+)", issuer)
        if match:
            issuer_cn = match.group(1).strip()
        rows.append({
            "state": state,
            "host": host,
            "owner": owner,
            "days": int(days) if days.lstrip("-").isdigit() else None,
            "expires": expires,
            "expires_utc": to_iso(expires) if expires else None,
            "issuer": issuer,
            "issuer_cn": issuer_cn,
            "letsencrypt": "Let's Encrypt" in issuer,
            "http": http or None,
        })
    return rows, checked_at


def parse_conf(path):
    values = {}
    for line in read(path).splitlines():
        match = re.match(r"^([A-Za-z0-9_]+)='(.*)'$", line.strip())
        if match:
            values[match.group(1)] = match.group(2)
    return values


def run_acme_list():
    """acme.sh --list is authoritative for the renewal list.

    A directory under .acme.sh is NOT proof that a profile is active - removed
    profiles leave their files behind, so globbing directories over-reports.
    """
    try:
        out = subprocess.run([os.path.join(ACME_HOME, "acme.sh"), "--list"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             universal_newlines=True).stdout
    except Exception:
        return []
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    rows = []
    for line in out.splitlines():
        if not line.strip() or line.startswith("Main_Domain"):
            continue
        parts = [p for p in re.split(r"\s{2,}", line.strip()) if p]
        if len(parts) < 5:
            continue
        # columns: Main_Domain, KeyLength, [SAN_Domains], [Profile], CA, Created, Renew
        rows.append({
            "domain": parts[0],
            "keylength": parts[1].strip('"'),
            "middle": parts[2:-3],
            "ca": parts[-3],
            "created": parts[-2],
            "renew": parts[-1],
        })
    return rows


def parse_profiles():
    profiles = []
    for row in run_acme_list():
        middle = row["middle"]
        san = next((x for x in middle if "." in x), "")
        profile = next((x for x in middle if "." not in x), "")
        conf = os.path.join(ACME_HOME, row["domain"] + "_ecc", row["domain"] + ".conf")
        vals = parse_conf(conf) if os.path.exists(conf) else {}
        ca = row["ca"]
        if "letsencrypt" in ca.lower():
            ca = "Let's Encrypt"
        profiles.append({
            "domain": row["domain"],
            "alt": [a.strip() for a in san.split() if a.strip()],
            "keylength": row["keylength"],
            "ca": ca,
            "created": row["created"],
            "renew": row["renew"],
            "profile": profile,
            # the saved deploy hook is what makes renewal reinstall into cPanel
            "deploy_hook": vals.get("Le_DeployHook", "").strip(","),
        })
    return profiles


def parse_notifications():
    vals = parse_conf(ACCOUNT_CONF)
    return {
        "hooks": vals.get("NOTIFY_HOOK", ""),
        "level": vals.get("NOTIFY_LEVEL", ""),
        "mode": vals.get("NOTIFY_MODE", ""),
        "source": vals.get("NOTIFY_SOURCE", ""),
        "mail_to": vals.get("SAVED_MAIL_TO", ""),
        "mail_from": vals.get("SAVED_MAIL_FROM", ""),
        "mail_bin": vals.get("SAVED_MAIL_BIN", ""),
        "ntfy_url": vals.get("SAVED_NTFY_URL", ""),
        # never emit the topic itself; only whether one is configured
        "ntfy_topic_configured": bool(vals.get("SAVED_NTFY_TOPIC", "")),
        "ntfy_topic_length": len(vals.get("SAVED_NTFY_TOPIC", "")),
    }


def parse_schedules():
    out = []
    for line in read_crontab().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" in line.split(" ")[0]:
            continue
        if "check-certs.sh" in line:
            out.append({"kind": "expiry monitor", "spec": " ".join(line.split()[:5]),
                        "detail": "daily public-endpoint check, pushes to ntfy"})
        elif "acme.sh" in line and "--cron" in line:
            out.append({"kind": "renewal", "spec": " ".join(line.split()[:5]),
                        "detail": "acme.sh renewal sweep (issues and deploys when due)"})
    return out


def read_crontab():
    try:
        return subprocess.run(["crontab", "-l"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL,
                              universal_newlines=True).stdout
    except Exception:
        return ""


def parse_lists():
    src = read(MONITOR)
    managed = re.search(r'^MANAGED="([^"]*)"', src, re.M)
    third = re.search(r'^THIRD_PARTY="([^"]*)"', src, re.M)

    def entries(match):
        if not match:
            return []
        out = []
        for token in match.group(1).split():
            parts = token.split("|")
            out.append({"domain": parts[0],
                        "owner": parts[1] if len(parts) > 1 and parts[1] != "apex" else "namecheap-acme",
                        "apex_only": "apex" in parts[1:]})
        return out

    return entries(managed), entries(third)


def parse_alert_state():
    keys = [l.strip() for l in read(STATE).splitlines() if l.strip()]
    return {"count": len(keys), "keys": keys[-25:]}


def main():
    force = "--refresh" in sys.argv
    try:
        age = time.time() - os.path.getmtime(TSV)
    except OSError:
        age = None
    if force or age is None or age > CACHE_MAX_AGE:
        refresh_rows()
        try:
            age = time.time() - os.path.getmtime(TSV)
        except OSError:
            age = None

    endpoints, checked_at = parse_endpoint_rows()
    managed, third = parse_lists()

    days = [e["days"] for e in endpoints if e["days"] is not None]
    states = {}
    for e in endpoints:
        states[e["state"]] = states.get(e["state"], 0) + 1

    payload = {
        "generated_at_utc": datetime.datetime.now(
            datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "checked_at_utc": (datetime.datetime.utcfromtimestamp(checked_at)
                           .replace(microsecond=0).isoformat() + "Z") if checked_at else None,
        "checked_age_seconds": int(age) if age is not None else None,
        "host": HOSTNAME,
        "summary": {
            "endpoints": len(endpoints),
            "problems": sum(v for k, v in states.items() if k not in ("ok", "WATCH")),
            "min_days": min(days) if days else None,
            "states": states,
            "managed_domains": len(managed),
            "third_party_domains": len(third),
            "profiles": None,  # filled below
        },
        "endpoints": endpoints,
        "lists": {"managed": managed, "third_party": third},
        "notifications": parse_notifications(),
        "schedules": parse_schedules(),
        "alerts": parse_alert_state(),
    }
    payload["profiles"] = parse_profiles()
    payload["summary"]["profiles"] = len(payload["profiles"])
    payload["summary"]["profiles_with_deploy_hook"] = sum(
        1 for p in payload["profiles"] if p["deploy_hook"])
    payload["summary"]["domains_without_profile"] = sorted(
        d["domain"] for d in managed
        if d["domain"] not in {p["domain"] for p in payload["profiles"]})

    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
