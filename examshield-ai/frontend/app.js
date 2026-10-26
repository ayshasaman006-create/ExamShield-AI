/* ExamShield AI - frontend logic (no build step, no dependencies) */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(url, opts = {}) {
  const res = await fetch(url, opts.body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(opts.body) } : opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

let toastTimer;
function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "show" + (err ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = ""), 3200);
}

/* ---------- navigation ---------- */
function show(view) {
  $$("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === "view-" + view));
  ({ dashboard: loadDashboard, trapdoor: loadTrap, cases: loadCases }[view] || (() => {}))();
}
$("#nav").addEventListener("click", (e) => e.target.dataset.view && show(e.target.dataset.view));

/* ---------- shared renderers ---------- */
const sev = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;

function caseHTML(c) {
  const ai = c.ai || {};
  const finds = c.findings.length
    ? [...c.findings].sort((a, b) => b.points - a.points).map((f) => `<div class="find">${sev(f.severity)}<b>${esc(f.title)}</b> <span class="muted">+${f.points}</span><p>${esc(f.detail)}</p></div>`).join("")
    : `<p class="empty">No suspicious indicators found.</p>`;
  const users = (c.extra.top_users || []).length
    ? `<div class="panel"><h2>Highest-risk accounts</h2>${c.extra.top_users.map((u) => `<div class="row"><div class="t"><b>${esc(u.user)}</b><small>${u.signals} signal(s)</small></div><span class="score">${u.points}</span></div>`).join("")}</div>` : "";
  return `
  <div class="panel">
    <div class="big"><span class="n">${c.score}</span><div><span class="lvl ${esc(c.level)}">${esc(c.level)} risk</span><div class="muted">Case #${c.id}, ${esc(c.created_at)}</div></div></div>
    <h2>Detected indicators</h2>${finds}
  </div>
  <div class="panel ai"><h2>AI threat analysis</h2>
    <p>${esc(ai.summary)}</p>
    <p><b>Likely threat:</b> ${esc(ai.attack_type)} &nbsp; <b>Confidence:</b> ${esc(ai.confidence)}</p>
    ${(ai.recommendations || []).length ? `<b>Recommended actions</b><ul>${ai.recommendations.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>` : ""}
    <p class="src">Engine: ${esc(ai.source)}${ai.note ? " - " + esc(ai.note) : ""}</p>
    <a class="btn" href="/api/report/case/${c.id}">Download PDF report</a>
  </div>${users}`;
}

/* ---------- dashboard ---------- */
async function loadDashboard() {
  const d = await api("/api/dashboard");
  $("#pScore").textContent = d.posture.score;
  const l = $("#pLevel"); l.textContent = d.posture.level; l.className = "lvl " + d.posture.level;
  $("#needle").style.left = `calc(${d.posture.score}% - 1px)`;
  $("#aiBadge").textContent = d.ai_enabled ? "AI: Claude connected" : "AI: offline analyst";
  $("#aiBadge").classList.toggle("on", d.ai_enabled);
  $("#dist").innerHTML = ["Low", "Medium", "High", "Critical"].map((k) => `<div class="${k}"><b>${d.distribution[k]}</b><span>${k}</span></div>`).join("");
  $("#totals").textContent = `${d.totals.cases} analysed case(s), ${d.totals.trap_hits} trapdoor hit(s).`;
  $("#topFind").innerHTML = d.top_findings.length ? d.top_findings.map((f) => `<li>${sev(f.severity)}${esc(f.title)}</li>`).join("") : `<li class="muted">Nothing yet. Analyse an email or log, or load demo data.</li>`;
  $("#recentCases").innerHTML = d.recent_cases.length ? d.recent_cases.map((c) => `<div class="row click" data-case="${c.id}"><div class="t"><b>${esc(c.title)}</b><small>${esc(c.created_at)}</small></div><span class="lvl ${esc(c.level)}">${c.score}</span></div>`).join("") : `<p class="empty">No cases yet.</p>`;
  $("#recentHits").innerHTML = hitsHTML(d.recent_hits);
}

function hitsHTML(hits) {
  return hits.length ? hits.map((h) => `<div class="row"><div class="t"><b>${sev(h.severity)}${esc(h.trap)}</b><small>${esc(h.created_at)} from ${esc(h.ip)}</small></div><span class="score">+${h.points}</span></div>`).join("") : `<p class="empty">No trapdoor hits yet.</p>`;
}

document.addEventListener("click", (e) => {
  const row = e.target.closest("[data-case]");
  if (row) { show("cases"); openCase(row.dataset.case); }
});

/* ---------- email ---------- */
let samples = null;
async function loadSamples() {
  samples = await api("/api/samples");
  $("#emailSample").innerHTML = `<option value="">Load a sample…</option>` + samples.emails.map((s, i) => `<option value="${i}">${esc(s.label)}</option>`).join("");
}
$("#emailSample").addEventListener("change", (e) => {
  if (e.target.value === "") return;
  const s = samples.emails[+e.target.value], f = $("#emailForm");
  ["sender", "reply_to", "subject", "body", "attachments"].forEach((k) => (f.elements[k].value = s[k] || ""));
});
$("#emailForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.submitter; btn.disabled = true; btn.textContent = "Analysing…";
  try {
    const body = Object.fromEntries(new FormData(e.target));
    const { case: c } = await api("/api/analyze/email", { body });
    $("#emailResult").innerHTML = caseHTML(c);
    toast(`Saved as case #${c.id}`);
  } catch (err) { toast(err.message, true); }
  btn.disabled = false; btn.textContent = "Analyse email";
});

/* ---------- activity ---------- */
$("#logSample").addEventListener("click", () => { $("#logText").value = samples.activity_log; });
$("#logFile").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (f) $("#logText").value = await f.text();
});
$("#actForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.submitter; btn.disabled = true; btn.textContent = "Analysing…";
  try {
    const { case: c } = await api("/api/analyze/activity", { body: { log: $("#logText").value } });
    $("#actResult").innerHTML = caseHTML(c);
    toast(`Saved as case #${c.id}`);
  } catch (err) { toast(err.message, true); }
  btn.disabled = false; btn.textContent = "Analyse log";
});

/* ---------- trapdoors ---------- */
async function loadTrap() {
  const cfg = await api("/api/trapdoor/config");
  $("#decoyList").innerHTML = cfg.decoys.map((d) => `<div class="decoy"><div><b>${esc(d.name)}</b><code>${esc(d.path)}</code></div><button class="btn small ghost" data-decoy="${esc(d.path)}">Trigger</button></div>`).join("");
  $("#botBtn").dataset.field = cfg.honeypot_field;
  refreshHits();
}
async function refreshHits() { $("#hitList").innerHTML = hitsHTML((await api("/api/trapdoor/hits")).hits); }
$("#decoyList").addEventListener("click", async (e) => {
  const p = e.target.dataset.decoy; if (!p) return;
  await fetch(p); toast("Decoy accessed and logged"); refreshHits();
});
$("#botBtn").addEventListener("click", async (e) => {
  await api("/api/trapdoor/form", { body: { name: "Bot", message: "buy now", [e.target.dataset.field]: "http://spam.example" } });
  toast("Hidden field filled - bot flagged"); refreshHits();
});
$("#refreshHits").addEventListener("click", refreshHits);

/* ---------- cases ---------- */
async function loadCases() {
  const { cases } = await api("/api/cases");
  $("#caseList").innerHTML = cases.length ? cases.map((c) => `<div class="row click" data-open="${c.id}"><div class="t"><b>#${c.id} ${esc(c.title)}</b><small>${esc(c.created_at)}</small></div><span class="lvl ${esc(c.level)}">${c.score}</span></div>`).join("") : `<p class="empty">No cases yet. Analyse an email or an activity log to create one.</p>`;
}
$("#caseList").addEventListener("click", (e) => { const r = e.target.closest("[data-open]"); if (r) openCase(r.dataset.open); });
async function openCase(id) {
  const { case: c } = await api("/api/cases/" + id);
  $("#caseDetail").innerHTML = caseHTML(c);
}

/* ---------- demo / reset ---------- */
$("#demoBtn").addEventListener("click", async () => {
  try {
    for (const s of samples.emails) await api("/api/analyze/email", { body: s });
    await api("/api/analyze/activity", { body: { log: samples.activity_log } });
    for (const d of (await api("/api/trapdoor/config")).decoys.slice(0, 3)) await fetch(d.path);
    toast("Demo data loaded"); loadDashboard();
  } catch (err) { toast(err.message, true); }
});
$("#resetBtn").addEventListener("click", async () => {
  if (!confirm("Delete all cases and trapdoor hits?")) return;
  await api("/api/demo/reset", { body: {} });
  toast("All data cleared"); show("dashboard");
});

loadSamples().then(loadDashboard).catch((e) => toast(e.message, true));
