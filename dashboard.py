"""
dashboard.py
------------
Inline HTML/CSS/JS dashboard served by Flask at GET /.
Self-contained single-file frontend — no build step required.
"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>PhishGuard — URL Threat Detector</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0a0c10;
    --surface: #0f1117;
    --surface2: #161b27;
    --border: #1e2535;
    --accent: #00e5ff;
    --accent2: #ff4d6d;
    --warn: #ffb300;
    --safe: #00e676;
    --text: #e2e8f0;
    --muted: #64748b;
    --radius: 12px;
    --glow: 0 0 24px rgba(0,229,255,0.15);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
    background-image:
      radial-gradient(ellipse 60% 40% at 20% 10%, rgba(0,229,255,0.04) 0%, transparent 70%),
      radial-gradient(ellipse 50% 30% at 80% 80%, rgba(255,77,109,0.04) 0%, transparent 70%);
  }

  /* ── HEADER ── */
  header {
    padding: 28px 40px;
    display: flex;
    align-items: center;
    gap: 16px;
    border-bottom: 1px solid var(--border);
    background: rgba(15,17,23,0.8);
    backdrop-filter: blur(12px);
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .logo-icon {
    width: 40px; height: 40px;
    background: linear-gradient(135deg, var(--accent), #7b61ff);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
    box-shadow: var(--glow);
  }
  header h1 { font-size: 1.4rem; font-weight: 800; letter-spacing: -0.02em; }
  header h1 span { color: var(--accent); }
  .header-badge {
    margin-left: auto;
    font-family: 'Space Mono', monospace;
    font-size: 0.7rem;
    background: rgba(0,229,255,0.08);
    color: var(--accent);
    border: 1px solid rgba(0,229,255,0.2);
    padding: 4px 10px;
    border-radius: 20px;
  }

  /* ── LAYOUT ── */
  main { max-width: 1200px; margin: 0 auto; padding: 40px 32px; }

  /* ── SCAN PANEL ── */
  .scan-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 32px;
    margin-bottom: 40px;
    position: relative;
    overflow: hidden;
  }
  .scan-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent), #7b61ff, var(--accent2));
  }
  .scan-card h2 { font-size: 1rem; font-weight: 700; color: var(--muted); letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 20px; }

  .input-row { display: flex; gap: 12px; }
  .url-input {
    flex: 1;
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: 'Space Mono', monospace;
    font-size: 0.85rem;
    padding: 14px 18px;
    border-radius: 8px;
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
  }
  .url-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(0,229,255,0.1);
  }
  .scan-btn {
    background: var(--accent);
    color: #000;
    font-family: 'Syne', sans-serif;
    font-weight: 700;
    font-size: 0.85rem;
    letter-spacing: 0.05em;
    padding: 14px 28px;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    transition: transform 0.15s, box-shadow 0.15s;
    white-space: nowrap;
  }
  .scan-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 20px rgba(0,229,255,0.3); }
  .scan-btn:active { transform: translateY(0); }
  .scan-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

  /* ── SAMPLE URLS ── */
  .sample-urls { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
  .sample-chip {
    font-family: 'Space Mono', monospace;
    font-size: 0.7rem;
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 4px 10px;
    border-radius: 20px;
    cursor: pointer;
    transition: color 0.2s, border-color 0.2s;
  }
  .sample-chip:hover { color: var(--accent); border-color: var(--accent); }

  /* ── LOADER ── */
  .loader { display: none; align-items: center; gap: 12px; margin-top: 20px; color: var(--muted); font-size: 0.85rem; }
  .loader.active { display: flex; }
  .spinner {
    width: 20px; height: 20px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── RESULT PANEL ── */
  #result { display: none; margin-top: 28px; animation: fadeUp 0.4s ease; }
  @keyframes fadeUp { from { opacity:0; transform: translateY(12px); } to { opacity:1; transform: translateY(0); } }

  .result-header { display: flex; align-items: center; gap: 20px; margin-bottom: 24px; }
  .verdict-badge {
    font-size: 1rem; font-weight: 800; letter-spacing: 0.05em;
    padding: 10px 20px; border-radius: 8px;
  }
  .verdict-Safe    { background: rgba(0,230,118,0.12); color: var(--safe); border: 1px solid rgba(0,230,118,0.3); }
  .verdict-Suspicious { background: rgba(255,179,0,0.12); color: var(--warn); border: 1px solid rgba(255,179,0,0.3); }
  .verdict-Phishing { background: rgba(255,77,109,0.12); color: var(--accent2); border: 1px solid rgba(255,77,109,0.3); }

  .score-ring { position: relative; width: 72px; height: 72px; flex-shrink: 0; }
  .score-ring svg { width: 72px; height: 72px; transform: rotate(-90deg); }
  .score-ring .track { fill: none; stroke: var(--border); stroke-width: 5; }
  .score-ring .fill  { fill: none; stroke-width: 5; stroke-linecap: round; transition: stroke-dashoffset 0.8s cubic-bezier(.4,0,.2,1); }
  .score-label {
    position: absolute; inset: 0; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    font-family: 'Space Mono', monospace;
  }
  .score-label .num { font-size: 1.1rem; font-weight: 700; line-height: 1; }
  .score-label .lbl { font-size: 0.55rem; color: var(--muted); }

  .result-url { font-family: 'Space Mono', monospace; font-size: 0.75rem; color: var(--muted); word-break: break-all; }

  /* ── SCORE BARS ── */
  .score-bars { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .score-bar-item { background: var(--surface2); border-radius: 8px; padding: 14px 16px; border: 1px solid var(--border); }
  .bar-label { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 0.8rem; color: var(--muted); }
  .bar-label span:last-child { font-family: 'Space Mono', monospace; }
  .bar-track { background: var(--border); border-radius: 4px; height: 6px; }
  .bar-fill { height: 6px; border-radius: 4px; transition: width 0.6s cubic-bezier(.4,0,.2,1); }

  /* ── DETAILS GRID ── */
  .details-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; }
  .detail-chip {
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 8px; padding: 10px 12px;
    display: flex; align-items: center; gap: 8px;
    font-size: 0.75rem;
  }
  .chip-icon { font-size: 1rem; flex-shrink: 0; }
  .chip-text { color: var(--muted); }
  .chip-val { font-weight: 700; color: var(--text); }
  .chip-bad .chip-val { color: var(--accent2); }
  .chip-warn .chip-val { color: var(--warn); }
  .chip-good .chip-val { color: var(--safe); }

  /* ── STATS GRID ── */
  .stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 40px; }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 20px 24px;
  }
  .stat-card .stat-val { font-family: 'Space Mono', monospace; font-size: 2rem; font-weight: 700; line-height: 1; }
  .stat-card .stat-lbl { color: var(--muted); font-size: 0.75rem; margin-top: 6px; letter-spacing: 0.05em; text-transform: uppercase; }
  .stat-total .stat-val { color: var(--accent); }
  .stat-phish .stat-val { color: var(--accent2); }
  .stat-sus   .stat-val { color: var(--warn); }
  .stat-safe  .stat-val { color: var(--safe); }

  /* ── CHARTS ── */
  .charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 40px; }
  .chart-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 24px;
  }
  .chart-card h3 { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 20px; }
  .chart-wrap { height: 220px; }

  /* ── HISTORY TABLE ── */
  .history-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 24px;
  }
  .history-card h3 { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 20px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 0.7rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; padding: 0 12px 12px; }
  td { padding: 10px 12px; font-size: 0.78rem; border-top: 1px solid var(--border); }
  td.mono { font-family: 'Space Mono', monospace; font-size: 0.72rem; color: var(--muted); max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badge { padding: 3px 8px; border-radius: 4px; font-size: 0.68rem; font-weight: 700; }
  .badge-Safe       { background: rgba(0,230,118,0.1); color: var(--safe); }
  .badge-Suspicious { background: rgba(255,179,0,0.1); color: var(--warn); }
  .badge-Phishing   { background: rgba(255,77,109,0.1); color: var(--accent2); }

  @media (max-width: 768px) {
    main { padding: 20px 16px; }
    .stats-row { grid-template-columns: 1fr 1fr; }
    .charts-row { grid-template-columns: 1fr; }
    .input-row { flex-direction: column; }
  }
</style>
</head>
<body>

<header>
  <div class="logo-icon">🛡</div>
  <h1>Phish<span>Guard</span></h1>
  <div class="header-badge">v1.0 · Real-time Detection</div>
</header>

<main>

  <!-- ── SCAN CARD ── -->
  <div class="scan-card">
    <h2>🔍 URL Scanner</h2>
    <div class="input-row">
      <input class="url-input" id="urlInput" type="text" placeholder="https://example.com — paste any URL to analyze..." />
      <button class="scan-btn" id="scanBtn" onclick="scanUrl()">Analyze URL</button>
    </div>
    <div class="sample-urls">
      <span style="font-size:0.72rem;color:var(--muted)">Try:</span>
      <span class="sample-chip" onclick="setUrl('https://google.com')">google.com</span>
      <span class="sample-chip" onclick="setUrl('http://paypal-secure-verify-login.tk/update')">paypal phishing</span>
      <span class="sample-chip" onclick="setUrl('http://192.168.1.1/login?secure=true')">IP login</span>
      <span class="sample-chip" onclick="setUrl('https://github.com')">github.com</span>
      <span class="sample-chip" onclick="setUrl('http://bit.ly/3xyzABC')">bit.ly</span>
    </div>
    <div class="loader" id="loader">
      <div class="spinner"></div>
      <span id="loaderMsg">Running analysis pipeline…</span>
    </div>

    <!-- Result -->
    <div id="result">
      <div class="result-header">
        <div class="score-ring">
          <svg viewBox="0 0 72 72">
            <circle class="track" cx="36" cy="36" r="30"/>
            <circle class="fill" id="scoreArc" cx="36" cy="36" r="30" stroke-dasharray="188.5" stroke-dashoffset="188.5"/>
          </svg>
          <div class="score-label">
            <span class="num" id="scoreNum">0</span>
            <span class="lbl">/100</span>
          </div>
        </div>
        <div>
          <div id="verdictBadge" class="verdict-badge">—</div>
          <div class="result-url" id="resultUrl" style="margin-top:8px"></div>
        </div>
      </div>

      <!-- Category score bars -->
      <div class="score-bars" id="scoreBars"></div>

      <!-- Feature chips -->
      <div class="details-grid" id="detailChips"></div>
    </div>
  </div>

  <!-- ── STATS ── -->
  <div class="stats-row" id="statsRow">
    <div class="stat-card stat-total"><div class="stat-val" id="s-total">—</div><div class="stat-lbl">Total Scanned</div></div>
    <div class="stat-card stat-phish"><div class="stat-val" id="s-phish">—</div><div class="stat-lbl">Phishing</div></div>
    <div class="stat-card stat-sus"  ><div class="stat-val" id="s-sus">—</div><div class="stat-lbl">Suspicious</div></div>
    <div class="stat-card stat-safe" ><div class="stat-val" id="s-safe">—</div><div class="stat-lbl">Safe</div></div>
  </div>

  <!-- ── CHARTS ── -->
  <div class="charts-row">
    <div class="chart-card">
      <h3>📊 Classification Distribution</h3>
      <div class="chart-wrap"><canvas id="pieChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>📈 Daily Detections (14 days)</h3>
      <div class="chart-wrap"><canvas id="lineChart"></canvas></div>
    </div>
  </div>

  <!-- ── HISTORY TABLE ── -->
  <div class="history-card">
    <h3>🕐 Recent Scans</h3>
    <table>
      <thead>
        <tr>
          <th>URL</th>
          <th>Score</th>
          <th>Result</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody id="historyBody">
        <tr><td colspan="4" style="color:var(--muted);text-align:center;padding:24px">No scans yet</td></tr>
      </tbody>
    </table>
  </div>

</main>

<script>
const API = '';  // Same origin

// ── SCAN ──
async function scanUrl() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) return;

  const btn = document.getElementById('scanBtn');
  const loader = document.getElementById('loader');
  const result = document.getElementById('result');
  const msgs = [
    'Extracting URL features…',
    'Checking domain trust & WHOIS…',
    'Querying threat intelligence…',
    'Analyzing page content…',
    'Calculating risk score…'
  ];

  btn.disabled = true;
  result.style.display = 'none';
  loader.classList.add('active');

  let i = 0;
  const msgInterval = setInterval(() => {
    document.getElementById('loaderMsg').textContent = msgs[Math.min(i++, msgs.length-1)];
  }, 900);

  try {
    const res = await fetch(`${API}/api/scan`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url})
    });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    renderResult(data);
    loadStats();
    loadHistory();
  } catch(e) {
    alert('Scan failed: ' + e.message);
  } finally {
    clearInterval(msgInterval);
    loader.classList.remove('active');
    btn.disabled = false;
  }
}

document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') scanUrl();
});

function setUrl(u) {
  document.getElementById('urlInput').value = u;
  document.getElementById('urlInput').focus();
}

// ── RENDER RESULT ──
function renderResult(data) {
  const r = document.getElementById('result');
  r.style.display = 'block';

  const score = data.risk_score || 0;
  const cls   = data.classification || 'Unknown';

  // Score ring
  const arc = document.getElementById('scoreArc');
  const circ = 188.5;
  const color = cls === 'Safe' ? '#00e676' : cls === 'Suspicious' ? '#ffb300' : '#ff4d6d';
  arc.style.stroke = color;
  setTimeout(() => {
    arc.style.strokeDashoffset = circ - (circ * score / 100);
  }, 50);

  document.getElementById('scoreNum').textContent = score;
  document.getElementById('scoreNum').style.color = color;

  // Verdict
  const badge = document.getElementById('verdictBadge');
  badge.textContent = cls === 'Safe' ? '✓ Safe' : cls === 'Suspicious' ? '⚠ Suspicious' : '✗ Phishing';
  badge.className = 'verdict-badge verdict-' + cls;

  document.getElementById('resultUrl').textContent = data.url;

  // Score bars
  const bd = data.score_breakdown || {};
  const bars = [
    {label: 'URL Features',     key: 'url_features',    max: 25},
    {label: 'Domain Trust',     key: 'domain_trust',    max: 25},
    {label: 'Threat Intel',     key: 'threat_intel',    max: 30},
    {label: 'Content Analysis', key: 'content_analysis', max: 20},
  ];
  document.getElementById('scoreBars').innerHTML = bars.map(b => {
    const s = bd[b.key]?.score || 0;
    const pct = (s / b.max) * 100;
    const c = pct > 66 ? '#ff4d6d' : pct > 33 ? '#ffb300' : '#00e676';
    return `<div class="score-bar-item">
      <div class="bar-label"><span>${b.label}</span><span>${s} / ${b.max}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${c}"></div></div>
    </div>`;
  }).join('');

  // Feature chips
  const f = data.features || {};
  const uf = f.url || {};
  const df = f.domain || {};
  const sf = f.ssl || {};
  const cf = f.content || {};

  const chips = [
    {icon:'🔐', label:'HTTPS',       val: uf.is_https ? 'Yes' : 'No',          type: uf.is_https ? 'good' : 'bad'},
    {icon:'📛', label:'IP in URL',   val: uf.has_ip_address ? 'Yes' : 'No',    type: uf.has_ip_address ? 'bad' : 'good'},
    {icon:'📜', label:'SSL Valid',   val: sf.ssl_valid ? 'Yes' : 'No',          type: sf.ssl_valid ? 'good' : 'bad'},
    {icon:'🗓', label:'Domain Age',  val: df.domain_age_days >= 0 ? df.domain_age_days + 'd' : 'Unknown', type: df.domain_age_days < 30 ? 'bad' : 'good'},
    {icon:'🏷', label:'Login Form',  val: cf.has_login_form ? 'Yes' : 'No',    type: cf.has_login_form ? 'warn' : 'good'},
    {icon:'🔑', label:'Password',    val: cf.has_password_field ? 'Yes' : 'No', type: cf.has_password_field ? 'bad' : 'good'},
    {icon:'🎭', label:'Brand Imp.',  val: cf.brand_impersonation ? 'Yes' : 'No', type: cf.brand_impersonation ? 'bad' : 'good'},
    {icon:'🔗', label:'URL Length',  val: uf.url_length,                        type: uf.url_length > 100 ? 'warn' : 'good'},
    {icon:'⚠', label:'Keywords',    val: uf.has_suspicious_keyword ? 'Yes' : 'No', type: uf.has_suspicious_keyword ? 'warn' : 'good'},
    {icon:'🌐', label:'WHOIS',       val: df.whois_available ? 'Yes' : 'No',    type: df.whois_available ? 'good' : 'warn'},
  ];

  document.getElementById('detailChips').innerHTML = chips.map(c =>
    `<div class="detail-chip chip-${c.type}">
      <span class="chip-icon">${c.icon}</span>
      <div><div class="chip-text">${c.label}</div><div class="chip-val">${c.val}</div></div>
    </div>`
  ).join('');
}

// ── STATS ──
let pieChart, lineChart;

async function loadStats() {
  try {
    const [stats, daily] = await Promise.all([
      fetch(`${API}/api/stats`).then(r=>r.json()),
      fetch(`${API}/api/daily`).then(r=>r.json()),
    ]);

    document.getElementById('s-total').textContent = stats.total;
    document.getElementById('s-phish').textContent = stats.phishing;
    document.getElementById('s-sus').textContent   = stats.suspicious;
    document.getElementById('s-safe').textContent  = stats.safe;

    renderPie(stats);
    renderLine(daily);
  } catch(e) { console.warn('Stats load failed', e); }
}

function renderPie(stats) {
  const ctx = document.getElementById('pieChart').getContext('2d');
  if (pieChart) pieChart.destroy();
  pieChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Suspicious', 'Phishing'],
      datasets: [{
        data: [stats.safe, stats.suspicious, stats.phishing],
        backgroundColor: ['rgba(0,230,118,0.7)', 'rgba(255,179,0,0.7)', 'rgba(255,77,109,0.7)'],
        borderColor: ['#00e676','#ffb300','#ff4d6d'],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#64748b', font: {family:'Syne'} } } },
      cutout: '65%'
    }
  });
}

function renderLine(daily) {
  const ctx = document.getElementById('lineChart').getContext('2d');
  if (lineChart) lineChart.destroy();

  // Pivot data
  const dates = [...new Set(daily.map(d=>d.date))].sort();
  const toSeries = cls => dates.map(date => {
    const row = daily.find(d => d.date === date && d.classification === cls);
    return row ? row.count : 0;
  });

  lineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: dates.map(d => d.slice(5)),
      datasets: [
        { label:'Safe',       data: toSeries('Safe'),       borderColor:'#00e676', backgroundColor:'rgba(0,230,118,0.07)', tension:0.4, pointRadius:3, fill:true },
        { label:'Suspicious', data: toSeries('Suspicious'), borderColor:'#ffb300', backgroundColor:'rgba(255,179,0,0.07)', tension:0.4, pointRadius:3, fill:true },
        { label:'Phishing',   data: toSeries('Phishing'),   borderColor:'#ff4d6d', backgroundColor:'rgba(255,77,109,0.07)',tension:0.4, pointRadius:3, fill:true },
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { labels: { color:'#64748b', font:{family:'Syne'} } } },
      scales: {
        x: { ticks: { color:'#64748b' }, grid: { color:'#1e2535' } },
        y: { ticks: { color:'#64748b' }, grid: { color:'#1e2535' }, beginAtZero: true }
      }
    }
  });
}

// ── HISTORY ──
async function loadHistory() {
  try {
    const rows = await fetch(`${API}/api/history`).then(r=>r.json());
    const tbody = document.getElementById('historyBody');
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:24px">No scans yet</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td class="mono" title="${r.url}">${r.url}</td>
        <td style="font-family:'Space Mono',monospace">${r.risk_score}</td>
        <td><span class="badge badge-${r.classification}">${r.classification}</span></td>
        <td style="color:var(--muted);font-size:0.7rem">${r.scanned_at?.slice(0,16).replace('T',' ')}</td>
      </tr>
    `).join('');
  } catch(e) { console.warn('History load failed', e); }
}

// ── INIT ──
loadStats();
loadHistory();
setInterval(() => { loadStats(); loadHistory(); }, 30000);
</script>
</body>
</html>"""
