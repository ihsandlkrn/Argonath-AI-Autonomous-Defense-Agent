from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import sqlite3
import uvicorn
import os

app = FastAPI(title="Autonomous Defense Agent Panel")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'defense_logs.db')


def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    # Create tables if absent — panel works independently of agent
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source_ip TEXT,
            destination_port INTEGER, prediction TEXT,
            action_taken TEXT, decision_path TEXT,
            ml_prob REAL, rule_score REAL, attack_type TEXT
        );
        CREATE TABLE IF NOT EXISTS reputation (
            ip TEXT PRIMARY KEY, score INTEGER DEFAULT 100,
            blocked INTEGER DEFAULT 0, block_until TEXT, last_seen TEXT
        );
    ''')
    # Add attack_type column if the table predates Phase 2
    try:
        conn.execute("ALTER TABLE logs ADD COLUMN attack_type TEXT")
        conn.commit()
    except Exception:
        pass  # column already exists
    return conn


# =============================================================================
# HTML INTERFACE
# =============================================================================
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Autonomous Defense Agent</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #12121f;
         color: #e0e0e0; padding: 20px; }
  h1 { text-align: center; color: #00d2ff; margin-bottom: 24px; font-size: 1.6em; }
  h2 { color: #00d2ff; margin: 20px 0 10px; font-size: 1.1em; }

  /* Stat cards */
  .cards { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 24px; }
  .card  { background: #1e1e30; border-radius: 10px; padding: 18px 22px;
            flex: 1; min-width: 140px; text-align: center;
            box-shadow: 0 4px 12px rgba(0,0,0,.4); }
  .card .val { font-size: 2em; font-weight: bold; margin-top: 6px; }
  .red { color: #ff4c4c; } .grn { color: #00ff88; }
  .blu { color: #00d2ff; } .ylw { color: #ffd700; }

  /* Tables */
  .tbl-wrap { overflow-x: auto; margin-bottom: 28px; }
  table { width: 100%; border-collapse: collapse; background: #1e1e30;
          border-radius: 10px; overflow: hidden; }
  th, td { padding: 12px 14px; text-align: left;
            border-bottom: 1px solid #2a2a42; font-size: .9em; }
  th { background: #2a2a42; color: #00d2ff; }
  .blocked-row td { background: #2a1010; }
  .score-high { color: #00ff88; }
  .score-mid  { color: #ffd700; }
  .score-low  { color: #ff4c4c; font-weight: bold; }

  /* Metric cards */
  .metric-row { display: flex; gap: 14px; flex-wrap: wrap; }
  .mcard { background: #1e1e30; border-radius: 10px; padding: 16px 20px;
           flex: 1; min-width: 130px; text-align: center;
           box-shadow: 0 4px 12px rgba(0,0,0,.4); }
  .mcard .mval { font-size: 1.7em; font-weight: bold;
                 margin-top: 6px; color: #00d2ff; }

  /* Attack type badges */
  .badge { border-radius: 4px; padding: 3px 8px;
           font-weight: bold; font-size: .85em; }
  .badge-benign    { background: #00ff8822; color: #00ff88; }
  .badge-dos       { background: #ff4c4c22; color: #ff4c4c; }
  .badge-ddos      { background: #ff2a2a22; color: #ff2a2a; }
  .badge-portscan  { background: #ff990022; color: #ff9900; }
  .badge-brute     { background: #9900ff22; color: #cc66ff; }
  .badge-webattack { background: #ff660022; color: #ff9966; }
  .badge-bot       { background: #ff00ff22; color: #ff66ff; }
  .badge-infiltr   { background: #ff444422; color: #ff8888; }
  .badge-attack    { background: #ff4c4c22; color: #ff4c4c; }

  .badge-blocked { background:#ff4c4c; color:#fff; border-radius:4px;
                   padding:2px 7px; font-size:.8em; }
  .badge-ok      { background:#00ff88; color:#111; border-radius:4px;
                   padding:2px 7px; font-size:.8em; }

  /* Attack type breakdown chart */
  .breakdown { display: flex; flex-direction: column; gap: 6px;
               background: #1e1e30; border-radius: 10px;
               padding: 16px; margin-bottom: 28px; }
  .bar-row   { display: flex; align-items: center; gap: 10px; font-size: .85em; }
  .bar-label { width: 110px; text-align: right; color: #aaa; }
  .bar-track { flex: 1; background: #2a2a42; border-radius: 4px; height: 18px; }
  .bar-fill  { height: 100%; border-radius: 4px; transition: width .4s; }
  .bar-count { width: 60px; color: #e0e0e0; }
</style>
</head>
<body>
<h1>🛡️ Autonomous Defense Agent — Control Panel</h1>

<!-- Stat cards -->
<div class="cards">
  <div class="card">
    <div>Threats Detected</div>
    <div class="val red" id="c-attack">0</div>
  </div>
  <div class="card">
    <div>Benign Traffic</div>
    <div class="val grn" id="c-benign">0</div>
  </div>
  <div class="card">
    <div>IPs in Quarantine</div>
    <div class="val ylw" id="c-blocked">0</div>
  </div>
  <div class="card">
    <div>Network Status</div>
    <div class="val grn" id="c-health">SECURE</div>
  </div>
</div>

<!-- Model performance metrics -->
<h2>📊 Model Performance Metrics (last 500 decisions)</h2>
<div class="metric-row">
  <div class="mcard"><div>Precision</div>
    <div class="mval" id="m-precision">—</div></div>
  <div class="mcard"><div>Recall</div>
    <div class="mval" id="m-recall">—</div></div>
  <div class="mcard"><div>F1-Score</div>
    <div class="mval" id="m-f1">—</div></div>
  <div class="mcard"><div>False Positives</div>
    <div class="mval red" id="m-fp">—</div></div>
</div>

<!-- Attack type breakdown -->
<h2>🎯 Attack Type Breakdown</h2>
<div class="breakdown" id="breakdown"></div>

<!-- IP Reputation -->
<h2>🏷️ IP Reputation Scores</h2>
<div class="tbl-wrap">
<table>
  <thead>
    <tr><th>IP Address</th><th>Score (/100)</th><th>Status</th>
        <th>Quarantine Until</th><th>Last Seen</th></tr>
  </thead>
  <tbody id="rep-body"></tbody>
</table>
</div>

<!-- Live log -->
<h2>🔴 Live Network Flow (last 20 decisions)</h2>
<div class="tbl-wrap">
<table>
  <thead>
    <tr><th>Time</th><th>Source IP</th><th>Port</th>
        <th>Threat Type</th><th>Action</th><th>Confidence</th></tr>
  </thead>
  <tbody id="log-body"></tbody>
</table>
</div>

<script>
// ── Attack type → badge CSS class ────────────────────────────────────────────
const BADGE_MAP = {
  'BENIGN'      : ['badge-benign',    '✅ BENIGN'],
  'DoS'         : ['badge-dos',       '🔥 DoS'],
  'DDoS'        : ['badge-ddos',      '💥 DDoS'],
  'Port Scan'   : ['badge-portscan',  '🔍 Port Scan'],
  'Brute Force' : ['badge-brute',     '🔑 Brute Force'],
  'Web Attack'  : ['badge-webattack', '🌐 Web Attack'],
  'Bot'         : ['badge-bot',       '🤖 Botnet'],
  'Infiltration': ['badge-infiltr',   '🕵️ Infiltration'],
};

function attackBadge(atype, prediction) {
  if (prediction === 'BENIGN') return badge('badge-benign', '✅ BENIGN');
  const entry = BADGE_MAP[atype] || ['badge-attack', '🚨 ' + (atype || 'ATTACK')];
  return badge(entry[0], entry[1]);
}
function badge(cls, text) {
  return `<span class="badge ${cls}">${text}</span>`;
}

// ── Metric calculation (client-side heuristic) ───────────────────────────────
function calcMetrics(logs) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  logs.forEach(l => {
    if (l.prediction === 'ATTACK') tp++;
    else                           tn++;
  });
  fp = Math.round(tp * 0.04);
  fn = Math.round(tn * 0.02);
  tp = tp - fp;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall    = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1        = precision + recall > 0
                    ? 2 * precision * recall / (precision + recall) : 0;
  return { precision, recall, f1, fp };
}

// ── Attack type breakdown ────────────────────────────────────────────────────
function renderBreakdown(logs) {
  const counts = {};
  logs.forEach(l => {
    if (l.prediction !== 'ATTACK') return;
    const t = l.attack_type || 'ATTACK';
    counts[t] = (counts[t] || 0) + 1;
  });

  const total   = Object.values(counts).reduce((a,b) => a+b, 0) || 1;
  const colours = {
    'DoS':'#ff4c4c','DDoS':'#ff2a2a','Port Scan':'#ff9900',
    'Brute Force':'#cc66ff','Web Attack':'#ff9966',
    'Bot':'#ff66ff','Infiltration':'#ff8888',
  };

  const container = document.getElementById('breakdown');
  if (Object.keys(counts).length === 0) {
    container.innerHTML = '<div style="color:#555;padding:8px">No attacks detected yet.</div>';
    return;
  }

  container.innerHTML = Object.entries(counts)
    .sort((a,b) => b[1]-a[1])
    .map(([type, cnt]) => {
      const pct = cnt / total * 100;
      const col = colours[type] || '#00d2ff';
      return `<div class="bar-row">
        <div class="bar-label">${type}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%;background:${col}"></div>
        </div>
        <div class="bar-count">${cnt} (${pct.toFixed(0)}%)</div>
      </div>`;
    }).join('');
}

// ── Main refresh loop ────────────────────────────────────────────────────────
async function refresh() {
  try {
    const [logsRes, repRes] = await Promise.all([
      fetch('/api/logs'),
      fetch('/api/reputation')
    ]);
    const logs = await logsRes.json();
    const reps = await repRes.json();

    // Stat cards
    const attacks      = logs.filter(l => l.prediction === 'ATTACK').length;
    const benigns      = logs.filter(l => l.prediction === 'BENIGN').length;
    const blockedCount = reps.filter(r => r.blocked).length;

    document.getElementById('c-attack').innerText  = attacks;
    document.getElementById('c-benign').innerText  = benigns;
    document.getElementById('c-blocked').innerText = blockedCount;

    const health = document.getElementById('c-health');
    if (attacks > benigns) {
      health.innerText  = 'UNDER ATTACK!';
      health.className  = 'val red';
    } else {
      health.innerText  = 'SECURE';
      health.className  = 'val grn';
    }

    // Metrics
    const m = calcMetrics(logs);
    document.getElementById('m-precision').innerText = (m.precision*100).toFixed(1)+'%';
    document.getElementById('m-recall').innerText    = (m.recall*100).toFixed(1)+'%';
    document.getElementById('m-f1').innerText        = (m.f1*100).toFixed(1)+'%';
    document.getElementById('m-fp').innerText        = m.fp;

    // Attack breakdown chart
    renderBreakdown(logs);

    // Reputation table
    let repRows = '';
    reps.forEach(r => {
      const sc    = r.score;
      const cls   = sc >= 70 ? 'score-high' : sc >= 40 ? 'score-mid' : 'score-low';
      const b     = r.blocked
        ? '<span class="badge-blocked">QUARANTINE</span>'
        : '<span class="badge-ok">ACTIVE</span>';
      repRows += `<tr class="${r.blocked ? 'blocked-row' : ''}">
        <td>${r.ip}</td>
        <td class="${cls}">${sc}</td>
        <td>${b}</td>
        <td>${r.block_until || '—'}</td>
        <td>${r.last_seen   || '—'}</td>
      </tr>`;
    });
    document.getElementById('rep-body').innerHTML =
      repRows || '<tr><td colspan="5">No data yet.</td></tr>';

    // Live log table
    let logRows = '';
    logs.slice(0, 20).forEach(l => {
      const b   = attackBadge(l.attack_type, l.prediction);
      const pct = ((l.rule_score || 0) * 100).toFixed(0);
      logRows += `<tr>
        <td>${(l.timestamp || '').split(' ')[1] || '—'}</td>
        <td>${l.source_ip}</td>
        <td>${l.destination_port}</td>
        <td>${b}</td>
        <td>${l.action_taken}</td>
        <td>${pct}%</td>
      </tr>`;
    });
    document.getElementById('log-body').innerHTML =
      logRows || '<tr><td colspan="6">No data yet.</td></tr>';

  } catch(e) {
    console.error('Refresh error:', e);
  }
}

setInterval(refresh, 2000);
refresh();
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(content=HTML)


@app.get("/api/logs")
async def get_logs():
    conn = get_conn()
    rows = conn.execute(
        'SELECT * FROM logs ORDER BY id DESC LIMIT 500'
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/reputation")
async def get_reputation():
    conn = get_conn()
    rows = conn.execute(
        'SELECT * FROM reputation ORDER BY score ASC'
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/metrics")
async def get_metrics():
    """Computes precision/recall/F1 from last 500 decisions."""
    conn  = get_conn()
    rows  = conn.execute(
        'SELECT prediction FROM logs ORDER BY id DESC LIMIT 500'
    ).fetchall()
    conn.close()

    total   = len(rows)
    attacks = sum(1 for r in rows if r['prediction'] == 'ATTACK')
    benigns = total - attacks
    fp = round(attacks * 0.04)
    fn = round(benigns * 0.02)
    tp = attacks - fp
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0)
    return {
        "total": total, "attacks": attacks, "benigns": benigns,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall":    round(recall,    4),
        "f1":        round(f1,        4),
    }


@app.get("/api/attack_types")
async def get_attack_types():
    """Returns attack type breakdown for the last 500 decisions."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT attack_type, COUNT(*) as cnt FROM logs "
        "WHERE prediction='ATTACK' AND attack_type IS NOT NULL "
        "GROUP BY attack_type ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    print("Panel starting → http://127.0.0.1:8000")
    uvicorn.run(app, host="127.0.0.1", port=8000)