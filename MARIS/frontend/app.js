const API = ""; // same origin -- backend serves this page

let currentVessel = null;
let selectedIncident = null;

const $ = (id) => document.getElementById(id);

// ---------- LOGIN ----------
$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const vessel_id = $("vessel-input").value.trim();
  const password = $("password-input").value;
  try {
    const res = await fetch(`${API}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vessel_id, password }),
    });
    if (!res.ok) throw new Error("bad creds");
    const data = await res.json();
    currentVessel = data.vessel_id;
    enterDashboard();
  } catch {
    $("login-error").classList.remove("hidden");
  }
});

$("logout-btn").addEventListener("click", () => {
  currentVessel = null;
  selectedIncident = null;
  $("dashboard-view").classList.add("hidden");
  $("login-view").classList.remove("hidden");
  $("login-form").reset();
  $("login-error").classList.add("hidden");
});

function fmtVessel(v) {
  return v.replace(/(OCEAN)(\d+)/, "$1-$2");
}

async function enterDashboard() {
  $("login-view").classList.add("hidden");
  $("login-error").classList.add("hidden");
  $("dashboard-view").classList.remove("hidden");
  $("current-vessel").textContent = fmtVessel(currentVessel);
  $("investigation").innerHTML = '<p class="placeholder">Select an incident, then click Run Investigation.</p>';
  $("run-btn").disabled = true;
  selectedIncident = null;
  await loadIncidents();
}

// ---------- INCIDENTS ----------
async function loadIncidents() {
  const res = await fetch(`${API}/api/incidents?vessel_id=${currentVessel}`);
  const data = await res.json();
  const list = $("incident-list");
  list.innerHTML = "";
  data.incidents.forEach((inc) => {
    const el = document.createElement("div");
    el.className = "incident";
    el.dataset.id = inc.incident_id;
    el.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span class="id">${inc.incident_id}</span>
        <span class="sev ${inc.severity}">${inc.severity}</span>
      </div>
      <div class="type">${inc.incident_type}</div>
      <div class="sys">${inc.affected_system}</div>`;
    el.addEventListener("click", () => selectIncident(inc, el));
    list.appendChild(el);
  });
}

function selectIncident(inc, el) {
  selectedIncident = inc;
  document.querySelectorAll(".incident").forEach((n) => n.classList.remove("active"));
  el.classList.add("active");
  $("run-btn").disabled = false;
  $("investigation").innerHTML = `
    <div class="stage">
      <h3>SELECTED INCIDENT</h3>
      <div class="evidence-item">${inc.incident_id} — ${inc.incident_type}</div>
      <div class="evidence-item">Affected system: ${inc.affected_system}</div>
      <div class="evidence-item">${inc.description}</div>
    </div>
    <p class="placeholder">Click RUN INVESTIGATION to start the MARIS agent.</p>`;
}

// ---------- INVESTIGATION ----------
$("run-btn").addEventListener("click", runInvestigation);

const TOOL_LABELS = {
  log_analyzer: "Log Analyzer",
  device_checker: "Device Checker",
  network_analyzer: "Network Analyzer",
  threat_analyzer: "Threat Analyzer",
};

async function runInvestigation() {
  if (!selectedIncident) return;
  $("run-btn").disabled = true;
  const box = $("investigation");
  box.innerHTML = '<p class="spinner">▸ MARIS agent investigating…</p>';

  const res = await fetch(`${API}/api/investigate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ incident_id: selectedIncident.incident_id }),
  });
  const r = await res.json();

  // Stage 1: tools (revealed one by one for demo effect)
  box.innerHTML = '<div class="stage"><h3>SECURITY TOOLS</h3><div id="tools"></div></div>';
  const toolsEl = $("tools");
  const toolNames = Object.keys(r.tool_results);

  for (let i = 0; i < toolNames.length; i++) {
    await delay(500);
    const name = toolNames[i];
    const t = r.tool_results[name];
    const row = document.createElement("div");
    row.className = "tool-row";
    row.innerHTML = `
      <span class="tool-check">[x]</span>
      <span class="tool-name">${TOOL_LABELS[name] || name}</span>
      <span class="tool-find">${t.findings[0] || "completed"}</span>`;
    toolsEl.appendChild(row);
  }

  await delay(400);

  // Stage 2: evidence correlation
  const evidenceHtml = r.evidence.map((e) => `<div class="evidence-item">${e}</div>`).join("");
  box.innerHTML += `
    <div class="stage">
      <h3>EVIDENCE CORRELATION</h3>
      ${evidenceHtml || '<div class="evidence-item">No notable indicators</div>'}
    </div>`;

  await delay(400);

  // Stage 3: risk + recommendation
  box.innerHTML += `
    <div class="stage">
      <h3>RISK ASSESSMENT</h3>
      <div class="risk-box ${r.risk_level}">
        <span class="risk-level ${r.risk_level}">${r.risk_level} RISK</span>
        <span class="risk-score">score ${r.risk_score}/100</span>
        <p class="risk-summary">${r.explanation}</p>
        <div class="reco">
          <strong>RECOMMENDED ACTION</strong><br/>${r.recommended_action}
        </div>
      </div>
    </div>`;

  $("run-btn").disabled = false;
  box.scrollTop = box.scrollHeight;
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
