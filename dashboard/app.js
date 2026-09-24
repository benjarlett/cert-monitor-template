/* Certificate monitor dashboard - vanilla JS, no dependencies.
   Everything rendered here comes from api.php, which in turn reads the hosting
   account. The page holds no secrets: the ntfy topic exists only as a flag. */

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function clsForDays(days) {
  if (days === null || days === undefined) return "bad";
  if (days <= 7) return "bad";
  if (days <= 30) return "alert";
  if (days <= 45) return "watch";
  return "ok";
}

function rowClassForDays(days) {
  const cls = clsForDays(days);
  if (cls === "alert" || cls === "bad") return "state-alert";
  if (cls === "watch") return "state-watch";
  return "";
}

/* 90-day scale keeps the bars comparable across the estate. */
function daysBar(days) {
  const pct = Math.max(2, Math.min(100, ((days ?? 0) / 90) * 100));
  return `<div class="bar bar-${clsForDays(days)}"><span style="width:${pct.toFixed(1)}%"></span></div>`;
}

function fmtRelative(seconds) {
  if (seconds === null || seconds === undefined) return "unknown";
  if (seconds < 90) return `${seconds}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} d ago`;
}

function fmtStamp(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return esc(iso);
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });
}

function shortIssuer(ep) {
  if (!ep.issuer_cn) return esc(ep.issuer || "—");
  const name = ep.letsencrypt ? "Let's Encrypt" : "not LE";
  return `${esc(name)} <span class="muted">${esc(ep.issuer_cn)}</span>`;
}

function statePill(state, days) {
  const clean = String(state || "").toUpperCase();
  if (clean === "OK") return `<span class="chip chip-ok">ok</span>`;
  if (clean === "WATCH") return `<span class="chip chip-warn">watch</span>`;
  if (clean === "EXPIRED") return `<span class="chip chip-warn">expired</span>`;
  if (clean === "FAIL" || clean === "PARSEFAIL") {
    return `<span class="chip chip-warn">${esc(clean.toLowerCase())}</span>`;
  }
  return `<span class="chip">${esc(clean.toLowerCase())}</span>`;
}

function renderHealth(summary, stale) {
  const pill = $("health");
  const problems = summary.problems || 0;
  const minDays = summary.min_days;
  pill.classList.remove("pill-ok", "pill-watch", "pill-alert", "pill-muted");
  if (problems > 0) {
    pill.classList.add("pill-alert");
    pill.textContent = `${problems} problem${problems === 1 ? "" : "s"}`;
  } else if (minDays !== null && minDays <= 30) {
    pill.classList.add("pill-watch");
    pill.textContent = `closest expiry ${minDays} days`;
  } else {
    pill.classList.add("pill-ok");
    pill.textContent = `all clear · closest ${minDays} days`;
  }
  if (stale) pill.textContent += " · cached";
}

function renderCards(summary, notifications) {
  const cards = [
    {
      label: "Endpoints checked",
      value: summary.endpoints,
      detail: `${summary.managed_domains} managed · ${summary.third_party_domains} third-party`,
    },
    {
      label: "Problems",
      value: summary.problems,
      detail: summary.problems ? "see the table" : "no failures or expired certs",
      acc: summary.problems ? "accent-alert" : "accent-ok",
    },
    {
      label: "Closest expiry",
      value: summary.min_days === null ? "—" : `${summary.min_days}d`,
      detail: summary.min_days === null ? "" : "alerts at 30, 14 and 7 days",
      acc: summary.min_days !== null && summary.min_days <= 30 ? "accent-watch" : "",
    },
    {
      label: "Renewal profiles",
      value: summary.profiles,
      detail: `${summary.profiles_with_deploy_hook} with a cPanel deploy hook`,
    },
    {
      label: "Alert channels",
      value: (notifications.hooks || "").split(",").filter(Boolean).length,
      detail: (notifications.hooks || "none") + (notifications.ntfy_topic_configured ? " · topic set" : ""),
    },
  ];
  $("cards").innerHTML = cards.map((c) => `
    <div class="card ${c.acc || ""}">
      <div class="label">${esc(c.label)}</div>
      <div class="value">${esc(c.value)}</div>
      <div class="detail">${esc(c.detail)}</div>
    </div>`).join("");
}

function renderEndpoints(endpoints, checkedAt) {
  const rows = [...endpoints].sort((a, b) => {
    const av = a.days === null ? 1e9 : a.days;
    const bv = b.days === null ? 1e9 : b.days;
    return av - bv;
  });
  $("endpoints").querySelector("tbody").innerHTML = rows.map((ep) => `
    <tr class="${rowClassForDays(ep.days)}" data-key="${esc((ep.host + " " + ep.owner).toLowerCase())}">
      <td class="mono">${esc(ep.host)}</td>
      <td><span class="chip">${esc(ep.owner)}</span></td>
      <td class="num">
        <div class="days-cell">
          <span class="days-num">${ep.days === null ? "—" : esc(ep.days)}</span>
          ${daysBar(ep.days)}
        </div>
      </td>
      <td class="muted">${esc(ep.expires || "—")}</td>
      <td>${shortIssuer(ep)}</td>
      <td class="num">${esc(ep.http || "—")}</td>
      <td>${statePill(ep.state, ep.days)}</td>
    </tr>`).join("");
  $("endpoints-note").textContent =
    `${rows.length} endpoints · certificates last read ${fmtStamp(checkedAt)}`;
}

function renderProfiles(profiles, summary) {
  $("profiles-count").textContent = `${profiles.length}`;
  const missing = summary.domains_without_profile || [];
  const rows = profiles.map((p) => `
    <tr>
      <td class="mono">${esc(p.domain)}</td>
      <td class="muted">${esc(p.alt.join(", ") || "—")}</td>
      <td>${fmtStamp(p.renew)}</td>
      <td>${p.deploy_hook
        ? `<span class="chip chip-ok">cpanel_uapi</span>`
        : `<span class="chip chip-warn">none</span>`}</td>
    </tr>`).join("");
  // a dedicated element, so refreshing does not pile up duplicate warnings
  const note = $("profiles-note");
  if (missing.length) {
    note.hidden = false;
    note.innerHTML = `Managed domains with no renewal profile: <strong>${esc(missing.join(", "))}</strong>`;
  } else {
    note.hidden = true;
    note.textContent = "";
  }
  $("profiles").querySelector("tbody").innerHTML = rows;
}

function renderNotifications(n) {
  $("notifications").innerHTML = `
    <dl class="kv">
      <dt>Hooks</dt><dd>${esc(n.hooks || "—")}</dd>
      <dt>Errors only</dt><dd>${n.level === "1" ? "yes (level 1)" : esc(n.level || "—")}</dd>
      <dt>Mode</dt><dd>${n.mode === "0" ? "one combined message per run" : esc(n.mode || "—")}</dd>
      <dt>Email</dt><dd>${esc(n.mail_from || "—")} → ${esc(n.mail_to || "—")}</dd>
      <dt>Push</dt><dd>${n.ntfy_topic_configured
        ? `ntfy topic configured (${esc(n.ntfy_topic_length)} chars, value not shown)`
        : "no topic configured"}</dd>
      <dt>Source label</dt><dd>${esc(n.source || "—")}</dd>
    </dl>`;
}

function renderSchedules(schedules) {
  if (!schedules.length) {
    document.getElementById("schedules").innerHTML = `<p class="hint">No cron entries found.</p>`;
    return;
  }
  $("schedules").innerHTML = `<ul class="tight">${schedules.map((s) => `
    <li><strong>${esc(s.kind)}</strong> <span class="mono">${esc(s.spec)}</span><br>
      <span class="hint">${esc(s.detail)}</span></li>`).join("")}</ul>`;
}

function renderAlerts(a) {
  $("alerts").innerHTML = a.count
    ? `<p class="hint">${a.count} alert key(s) already sent, so these will not repeat:</p>
       <ul class="tight">${a.keys.map((k) => `<li class="mono">${esc(k)}</li>`).join("")}</ul>`
    : `<p class="hint">No alert state stored — every threshold is armed and will fire once.</p>`;
}

function renderCloud(cloud) {
  const history = (cloud.history || []).map((l) => `<li class="mono">${esc(l)}</li>`).join("");
  const commits = (cloud.commits || []).map((c) =>
    `<li><span class="mono">${esc(c.hash)}</span> <span class="muted">${esc(c.date)}</span><br>
       <span class="hint">${esc(c.subject)}</span></li>`).join("");
  $("cloud").innerHTML = `
    <dl class="kv">
      <dt>Repository</dt><dd><a href="https://github.com/${esc(cloud.repo)}" target="_blank"
        rel="noreferrer">${esc(cloud.repo)}</a> (private)</dd>
      <dt>Schedule</dt><dd>daily 07:00 UTC</dd>
      <dt>Local clone</dt><dd>${cloud.git_ok ? "readable" : "not reachable"}</dd>
    </dl>
    <h3 class="sub-head">Recent daily runs</h3>
    ${history ? `<ul class="tight">${history}</ul>` : `<p class="hint">No history yet.</p>`}
    <h3 class="sub-head">Recent commits</h3>
    ${commits ? `<ul class="tight">${commits}</ul>` : `<p class="hint">No commits yet.</p>`}`;
}

function showError(data) {
  const box = $("error");
  box.hidden = false;
  box.textContent = [
    data.error || "Something went wrong.",
    data.exit_code !== undefined ? `exit code: ${data.exit_code}` : "",
    data.stderr ? `stderr: ${data.stderr}` : "",
    data.stdout_head ? `output: ${data.stdout_head}` : "",
  ].filter(Boolean).join("\n");
}

async function loadStatus(force) {
  $("error").hidden = true;
  const data = await (await fetch(`api.php?action=${force ? "refresh" : "status"}`)).json();
  if (data.error) {
    showError(data);
    $("health").className = "pill pill-alert";
    $("health").textContent = "unreachable";
    return null;
  }
  const stale = data.checked_age_seconds > 3600;
  renderHealth(data.summary, stale);
  renderCards(data.summary, data.notifications);
  renderEndpoints(data.endpoints, data.checked_at_utc);
  renderProfiles(data.profiles, data.summary);
  renderNotifications(data.notifications);
  renderSchedules(data.schedules);
  renderAlerts(data.alerts);
  $("checked").textContent =
    `endpoints checked ${fmtRelative(data.checked_age_seconds)}` +
    (data.served_from_cache ? " (cached)" : "");
  $("generated").textContent = `page data generated ${fmtStamp(data.generated_at_utc)}`;
  return data;
}

async function loadCloud() {
  const data = await (await fetch("api.php?action=cloud")).json();
  renderCloud(data);
}

$("refresh").addEventListener("click", async () => {
  const btn = $("refresh");
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span>checking…`;
  try {
    await loadStatus(true);
    await loadCloud();
  } finally {
    btn.disabled = false;
    btn.textContent = "Check now";
  }
});

$("filter").addEventListener("input", (event) => {
  const needle = event.target.value.trim().toLowerCase();
  document.querySelectorAll("#endpoints tbody tr").forEach((tr) => {
    tr.hidden = needle !== "" && !tr.dataset.key.includes(needle);
  });
});

/* ---- add a site ----------------------------------------------------------
   Two steps on purpose: preview runs the helper with --dry-run, which performs
   every check and issues nothing, and only then is a confirm button offered.
   Previewing twice is harmless - the helper reports an existing entry. */

let pendingAdd = null;

async function siteAction(action, domain, owner) {
  const body = new URLSearchParams({ domain, owner });
  const response = await fetch(`api.php?action=${action}`, { method: "POST", body });
  return response.json();
}

function showAddResult(result) {
  const box = $("add-result");
  const out = $("add-output");
  box.hidden = false;
  if (result.error) {
    out.textContent = result.error;
    return false;
  }
  const text = [result.output, result.stderr].filter(Boolean).join("\n");
  out.textContent = text || "(the helper produced no output)";
  return result.exit_code === 0;
}

async function previewSite(domain, owner) {
  const box = $("add-result");
  box.hidden = false;
  $("add-confirm").hidden = true;
  $("add-cancel").hidden = true;
  $("add-output").textContent = "checking \u2014 this runs the same checks as the command line\u2026";
  const result = await siteAction("preview", domain, owner);
  const ok = showAddResult(result);
  if (ok) {
    pendingAdd = { domain: result.domain || domain, owner };
    $("add-confirm").hidden = false;
    $("add-cancel").hidden = false;
  } else {
    pendingAdd = null;
  }
}

async function confirmAdd() {
  if (!pendingAdd) return;
  const button = $("add-confirm");
  button.disabled = true;
  button.innerHTML = `<span class="spinner"></span>adding\u2026`;
  try {
    const result = await siteAction("add", pendingAdd.domain, pendingAdd.owner);
    showAddResult(result);
    $("add-confirm").hidden = true;
    $("add-cancel").hidden = true;
    pendingAdd = null;
    // the list changed: read the estate again so the new row appears
    await loadStatus(true);
    await loadCloud();
  } finally {
    button.disabled = false;
    button.textContent = "Confirm and add";
  }
}

$("add-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const domain = $("add-domain").value.trim();
  const owner = $("add-owner").value.trim() || "other";
  if (domain) previewSite(domain, owner);
});

$("add-confirm").addEventListener("click", confirmAdd);
$("add-cancel").addEventListener("click", () => {
  $("add-result").hidden = true;
  pendingAdd = null;
});

(async () => {
  await loadStatus(false);
  await loadCloud();
})();
