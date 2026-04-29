"""
Embedded HTML for the SOC dashboard.

Kept inline (not in templates/) so the SOC view is fully self-contained
and shippable as a single Python module. Replace `__VIEW_TOKEN__` at
render time with the active view token (or empty string).
"""

SOC_DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetGuard SOC</title>
  <style>
    :root {
      --bg-0: #0a0e14;
      --bg-1: #11161f;
      --bg-2: #1a212d;
      --border: #243042;
      --text: #d8e0ed;
      --text-dim: #8898a8;
      --accent: #00d4ff;
      --crit: #ff1a4b;
      --high: #ff8800;
      --med:  #ffdd00;
      --low:  #00ffaa;
      --ok:   #1de9b6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 13px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif;
      background: var(--bg-0);
      color: var(--text);
    }
    header {
      padding: 14px 22px;
      background: linear-gradient(90deg, #0d1320 0%, #16213a 100%);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 14px;
    }
    header h1 {
      margin: 0;
      font-size: 18px;
      font-weight: 600;
      letter-spacing: 0.5px;
    }
    header h1 span { color: var(--accent); }
    header .pill {
      margin-left: auto;
      padding: 4px 10px;
      border: 1px solid var(--border);
      border-radius: 999px;
      color: var(--text-dim);
      font-size: 11px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      padding: 18px 22px;
    }
    .card {
      background: var(--bg-1);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
    }
    .stat { font-size: 26px; font-weight: 600; }
    .stat-label { color: var(--text-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.7px; }
    .stat.crit { color: var(--crit); }
    .stat.high { color: var(--high); }
    .stat.ok   { color: var(--ok); }
    .panel {
      margin: 0 22px 22px;
      background: var(--bg-1);
      border: 1px solid var(--border);
      border-radius: 8px;
    }
    .panel h2 {
      margin: 0;
      padding: 12px 16px;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.7px;
      text-transform: uppercase;
      color: var(--text-dim);
      border-bottom: 1px solid var(--border);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12.5px;
    }
    th, td {
      padding: 9px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    th { color: var(--text-dim); font-weight: 500; text-transform: uppercase; font-size: 10.5px; letter-spacing: 0.6px; }
    tr:hover td { background: rgba(0, 212, 255, 0.05); }
    .sev {
      display: inline-block;
      padding: 1px 8px;
      border-radius: 999px;
      font-size: 10.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .sev.critical { background: rgba(255, 26, 75, 0.15); color: var(--crit); border: 1px solid var(--crit); }
    .sev.high     { background: rgba(255, 136, 0, 0.15); color: var(--high); border: 1px solid var(--high); }
    .sev.medium   { background: rgba(255, 221, 0, 0.15); color: var(--med);  border: 1px solid var(--med); }
    .sev.low      { background: rgba(0, 255, 170, 0.15); color: var(--low);  border: 1px solid var(--low); }
    .risk-bar {
      width: 110px; height: 8px; background: var(--bg-2); border-radius: 4px;
      overflow: hidden; display: inline-block; vertical-align: middle;
      margin-right: 8px;
    }
    .risk-bar > div { height: 100%; }
    .risk-bar.LOW > div      { background: var(--low); }
    .risk-bar.MEDIUM > div   { background: var(--med); }
    .risk-bar.HIGH > div     { background: var(--high); }
    .risk-bar.CRITICAL > div { background: var(--crit); }
    .timeline {
      display: flex; align-items: flex-end; height: 110px;
      gap: 3px; padding: 14px 16px;
    }
    .timeline > div {
      flex: 1;
      background: linear-gradient(180deg, var(--accent), #006e84);
      min-height: 1px; border-radius: 2px 2px 0 0;
      position: relative;
    }
    .timeline > div:hover::after {
      content: attr(data-tip);
      position: absolute; bottom: 100%; left: 50%;
      transform: translateX(-50%);
      background: var(--bg-2); color: var(--text);
      padding: 3px 8px; border-radius: 4px; font-size: 11px;
      white-space: nowrap;
    }
    .mitre-grid { padding: 14px 16px; display: flex; flex-wrap: wrap; gap: 8px; }
    .mitre-tag {
      background: var(--bg-2); padding: 4px 10px; border-radius: 4px;
      border: 1px solid var(--border); color: var(--text);
      font-size: 12px;
    }
    .mitre-tag b { color: var(--accent); }
    .coverage-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      padding: 14px 16px;
    }
    .coverage-card {
      background: var(--bg-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      min-height: 92px;
    }
    .coverage-card strong {
      display: block;
      font-size: 22px;
      color: var(--text);
    }
    .coverage-card span {
      color: var(--text-dim);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.6px;
    }
    .coverage-list {
      padding: 0 16px 16px;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .coverage-pill {
      background: rgba(0, 212, 255, 0.08);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 11px;
    }
    .coverage-pill.warn {
      color: var(--high);
      border-color: rgba(255, 136, 0, 0.65);
      background: rgba(255, 136, 0, 0.08);
    }
    code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; color: var(--text-dim); }
    .empty { padding: 22px; text-align: center; color: var(--text-dim); font-style: italic; }
    .footer {
      text-align: center; padding: 18px; color: var(--text-dim); font-size: 11px;
    }
    @media (max-width: 860px) {
      .grid, .coverage-grid { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 560px) {
      header { align-items: flex-start; flex-direction: column; }
      header .pill { margin-left: 0; }
      .grid, .coverage-grid { grid-template-columns: 1fr; padding: 14px; }
      .panel { margin: 0 14px 16px; }
      th, td { padding: 8px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Net<span>Guard</span> SOC</h1>
    <span class="pill" id="last-refresh">loading…</span>
  </header>

  <section class="grid" id="kpis">
    <div class="card"><div class="stat-label">Hosts</div><div class="stat" id="kpi-hosts">—</div></div>
    <div class="card"><div class="stat-label">Alerts (24h)</div><div class="stat" id="kpi-alerts">—</div></div>
    <div class="card"><div class="stat-label">Critical</div><div class="stat crit" id="kpi-crit">—</div></div>
    <div class="card"><div class="stat-label">Avg risk</div><div class="stat" id="kpi-risk">—</div></div>
  </section>

  <section class="panel">
    <h2>Alerts (last 24h)</h2>
    <div class="timeline" id="timeline"></div>
  </section>

  <section class="panel">
    <h2>Hosts by risk</h2>
    <table id="hosts-table">
      <thead>
        <tr>
          <th>Host</th><th>Platform</th><th>Agent</th><th>Risk</th>
          <th>Last seen</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </section>

  <section class="panel">
    <h2>Top MITRE techniques</h2>
    <div class="mitre-grid" id="mitre"></div>
  </section>

  <section class="panel">
    <h2>Detection coverage</h2>
    <div class="coverage-grid" id="coverage-cards"></div>
    <div class="coverage-list" id="coverage-list"></div>
  </section>

  <div class="footer">
    NetGuard EDR · refreshes every 30s ·
    <a href="https://attack.mitre.org" target="_blank" rel="noopener" style="color:var(--accent)">MITRE ATT&CK</a>
  </div>

  <script>
  const TOKEN = "__VIEW_TOKEN__";
  const tokenQS = TOKEN ? ("?token=" + encodeURIComponent(TOKEN)) : "";

  function escapeHtml(s) {
    if (s === undefined || s === null) return "";
    return String(s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function fmtDate(s) {
    if (!s) return "—";
    return s.replace("T", " ").replace("Z", " UTC").substring(0, 19);
  }

  async function refresh() {
    try {
      const [overviewResp, rulesResp] = await Promise.all([
        fetch("api/overview" + tokenQS),
        fetch("api/rules" + tokenQS)
      ]);
      if (!overviewResp.ok) throw new Error("overview HTTP " + overviewResp.status);
      if (!rulesResp.ok) throw new Error("rules HTTP " + rulesResp.status);
      const data = await overviewResp.json();
      const ruleCatalog = await rulesResp.json();
      render(data, ruleCatalog);
      document.getElementById("last-refresh").textContent =
        "updated " + fmtDate(data.as_of);
    } catch (err) {
      document.getElementById("last-refresh").textContent = "load failed";
      console.error(err);
    }
  }

  function render(d, ruleCatalog) {
    document.getElementById("kpi-hosts").textContent  = d.summary.host_count;
    document.getElementById("kpi-alerts").textContent = d.summary.alert_count_24h;
    document.getElementById("kpi-crit").textContent   = d.summary.critical_24h;
    document.getElementById("kpi-risk").textContent   = d.summary.avg_risk;

    const tl = document.getElementById("timeline");
    tl.innerHTML = "";
    const max = Math.max(1, ...d.timeline_24h.map(b => b.count));
    d.timeline_24h.forEach(b => {
      const el = document.createElement("div");
      el.style.height = (8 + 90 * (b.count / max)) + "px";
      el.dataset.tip = b.hour + " · " + b.count + " alerts";
      tl.appendChild(el);
    });

    const tbody = document.querySelector("#hosts-table tbody");
    if (!d.hosts.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">No hosts enrolled yet.</td></tr>';
    } else {
      tbody.innerHTML = d.hosts.map(h => `
        <tr>
          <td><b>${escapeHtml(h.hostname || h.host_id)}</b><br><code>${escapeHtml(h.host_id.substring(0,8))}…</code></td>
          <td>${escapeHtml(h.platform || '—')}</td>
          <td><code>${escapeHtml(h.agent_version || '—')}</code></td>
          <td>
            <span class="risk-bar ${escapeHtml(h.risk_level)}">
              <div style="width:${Math.max(2, h.risk_score)}%"></div>
            </span>
            <b>${h.risk_score}</b>
            <span class="sev ${h.risk_level.toLowerCase()}">${h.risk_level}</span>
          </td>
          <td>${fmtDate(h.last_seen)}</td>
        </tr>
      `).join("");
    }

    const mitre = document.getElementById("mitre");
    if (!d.top_techniques.length) {
      mitre.innerHTML = '<div class="empty">No alerts mapped yet.</div>';
    } else {
      mitre.innerHTML = d.top_techniques.map(t =>
        `<a class="mitre-tag" target="_blank" rel="noopener"
            href="https://attack.mitre.org/techniques/${t.technique.replace('.', '/')}/">
            <b>${escapeHtml(t.technique)}</b> · ${t.count}
        </a>`
      ).join("");
    }

    renderCoverage(ruleCatalog);
  }

  function renderCoverage(catalog) {
    const summary = (catalog && catalog.summary) || {};
    const health = summary.yaml_health || {};
    const coverage = summary.event_type_coverage || {};
    const bySource = summary.by_source || {};
    const cards = [
      ["Total rules", summary.total_rules || 0],
      ["Built-in", bySource.builtin || 0],
      ["YAML/Sigma", bySource.yaml || 0],
      ["YAML skipped", health.skipped_files || 0]
    ];
    document.getElementById("coverage-cards").innerHTML = cards.map(([label, value]) => `
      <div class="coverage-card">
        <span>${escapeHtml(label)}</span>
        <strong>${escapeHtml(value)}</strong>
      </div>
    `).join("");

    const covered = (coverage.covered || []).map(item =>
      `<span class="coverage-pill">${escapeHtml(item)}</span>`
    );
    const missing = (coverage.missing || []).map(item =>
      `<span class="coverage-pill warn">missing ${escapeHtml(item)}</span>`
    );
    const yamlErrors = (health.errors || []).slice(0, 3).map(item =>
      `<span class="coverage-pill warn">${escapeHtml(item.source_path || 'yaml')} skipped</span>`
    );
    document.getElementById("coverage-list").innerHTML =
      [...covered, ...missing, ...yamlErrors].join("") ||
      '<span class="coverage-pill warn">No detection catalog loaded</span>';
  }

  refresh();
  setInterval(refresh, 30000);
  </script>
</body>
</html>
"""
