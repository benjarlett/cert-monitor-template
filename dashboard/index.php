<?php
declare(strict_types=1);
require __DIR__ . '/config.php';
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Certificate monitor</title>
<link rel="stylesheet" href="styles.css">
</head>
<body>

<header class="top">
  <div class="top-left">
    <h1>Certificate monitor</h1>
    <p class="sub">
      Public endpoint expiry for <strong><?= htmlspecialchars(SSH_HOST) ?></strong>
      &middot; read-only view
    </p>
  </div>
  <div class="top-right">
    <div id="health" class="pill pill-muted">loading…</div>
    <div class="refresh-box">
      <button id="refresh" type="button">Check now</button>
      <span id="checked" class="hint">&nbsp;</span>
    </div>
  </div>
</header>

<div id="error" class="error" hidden></div>

<main>
  <section id="cards" class="cards" aria-label="Summary"></section>

  <section class="panel">
    <div class="panel-head">
      <h2>Public endpoints</h2>
      <div class="panel-tools">
        <input id="filter" type="search" placeholder="filter host or owner…" aria-label="Filter endpoints">
      </div>
    </div>
    <p class="hint" id="endpoints-note">
      Sorted by urgency. A row turns amber below 45 days and red at 30, 14 and 7 days,
      which are the thresholds that push an alert.
    </p>
    <div class="table-wrap">
      <table id="endpoints">
        <thead>
          <tr>
            <th>Host</th><th>Owner</th><th class="num">Days left</th>
            <th>Expires</th><th>Issuer</th><th class="num">HTTP</th><th>State</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </section>

  <section class="panel" id="add-panel">
    <h2>Add a site</h2>
    <p class="hint">
      Runs the same helper the command line uses: it checks DNS, works out whether the site is
      served from this account, and tests the ACME challenge path &mdash; before anything is
      issued. <strong>Preview changes nothing.</strong> Pressing it again on a site already in
      the list reports that and stops.
    </p>
    <form id="add-form" autocomplete="off">
      <input id="add-domain" type="text" placeholder="example.co.uk or a full URL"
             aria-label="Domain" required>
      <input id="add-owner" type="text" value="other" aria-label="Owner label">
      <button type="submit" id="add-preview">Preview</button>
    </form>
    <p class="hint">
      The owner label names whoever renews the certificate and is only used for sites served
      elsewhere: <code>vercel</code>, <code>managed-other</code>, <code>other</code>. Sites
      served from this account are labelled automatically. Adding is what the monitor uses to
      decide whether a certificate must be Let's Encrypt.
    </p>
    <div id="add-result" hidden>
      <pre id="add-output" class="console"></pre>
      <div class="add-actions">
        <button id="add-confirm" hidden>Confirm and add</button>
        <button id="add-cancel" class="secondary" hidden>Cancel</button>
      </div>
    </div>
  </section>

  <div class="grid">
    <section class="panel">
      <h2>Renewals <span class="hint" id="profiles-count"></span></h2>
      <p class="hint">Every profile here is in the renewal list, so acme.sh renews it
        automatically and reinstalls it into cPanel through the deploy hook.</p>
      <div class="table-wrap">
        <table id="profiles">
          <thead><tr><th>Domain</th><th>Also covers</th><th>Next attempt</th><th>Hook</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <p class="hint" id="profiles-note" hidden></p>
    </section>

    <section class="panel">
      <h2>Alerts</h2>
      <div id="notifications"></div>
      <h3 class="sub-head">Schedules</h3>
      <div id="schedules"></div>
      <h3 class="sub-head">Pending alert state</h3>
      <div id="alerts"></div>
    </section>

    <section class="panel">
      <h2>Off-account monitor</h2>
      <p class="hint">
        Runs on GitHub's infrastructure, so it still reports when the hosting account
        itself is unreachable.
      </p>
      <div id="cloud"></div>
    </section>
  </div>
</main>

<footer>
  <span id="generated" class="hint"></span>
  <span class="hint">
    &middot; <a href="https://github.com/your-user/cert-expiry-monitor" target="_blank" rel="noreferrer">monitor repository</a>
    &middot; <a href="https://ntfy.sh" target="_blank" rel="noreferrer">ntfy</a>
    &middot; no secrets are rendered on this page
  </span>
</footer>

<script src="app.js"></script>
</body>
</html>
