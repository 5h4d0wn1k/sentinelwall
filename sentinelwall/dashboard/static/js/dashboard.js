"use strict";

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

function esc(s) {
  const div = document.createElement("div");
  div.textContent = String(s == null ? "" : s);
  return div.innerHTML;
}

async function loadOverview() {
  try {
    const data = await fetchJSON("/api/overview");
    document.getElementById("stat-events").textContent = data.events_processed;
    document.getElementById("stat-clusters").textContent = data.clusters;
    document.getElementById("stat-alerts").textContent = data.alerts;
    document.getElementById("stat-techniques").textContent = data.techniques;
    document.getElementById("stat-throughput").textContent =
      Math.round(data.events_per_second).toLocaleString();

    const sev = data.severity_distribution || {};
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];
    let html = "";
    for (const name of order) {
      const count = sev[name] || 0;
      html +=
        `<div class="sev-line"><span class="sev-name">${name}</span>` +
        `<div class="sev-bar"><div class="sev-fill sev-${name.toLowerCase()}" style="width:${Math.min(100, count * 8)}%"></div></div>` +
        `<span class="sev-count">${count}</span></div>`;
    }
    document.getElementById("severity-chart").innerHTML = html || '<div class="muted">No alerts</div>';

    const proto = data.protocol_counts || {};
    let protoHtml = "";
    for (const [name, count] of Object.entries(proto)) {
      protoHtml += `<div class="proto-bar"><span class="proto-name">${esc(name)}</span><span class="proto-count">${count}</span></div>`;
    }
    document.getElementById("protocols").innerHTML = protoHtml || '<div class="muted">No data</div>';
  } catch (e) {
    console.error(e);
  }
}

async function loadNarrative() {
  try {
    const data = await fetchJSON("/api/narrative");
    const md = document.createElement("div");
    md.innerHTML = renderMarkdown(data.text || "");
    document.getElementById("narrative").innerHTML = md.innerHTML;
  } catch (e) {
    console.error(e);
  }
}

async function loadTechniques() {
  try {
    const data = await fetchJSON("/api/techniques");
    const max = Math.max(...data.map((t) => t.count), 1);
    let html = "";
    for (const t of data) {
      html +=
        `<div class="tech-row"><span class="tech-id">${t.technique_id}</span>` +
        `<div class="tech-bar"><div class="tech-fill" style="width:${(t.count / max) * 100}%"></div></div>` +
        `<span class="tech-name">${t.count} detection(s)</span></div>`;
    }
    document.getElementById("techniques").innerHTML = html || '<div class="muted">No techniques</div>';
  } catch (e) {
    console.error(e);
  }
}

async function loadClusters() {
  try {
    const clusters = await fetchJSON("/api/clusters");
    const tbody = document.querySelector("#clusters-table tbody");
    if (!clusters.length) {
      tbody.innerHTML = '<tr><td class="muted" colspan="5">No clusters</td></tr>';
      return;
    }
    tbody.innerHTML = clusters.map((c) => {
      const labels = (c.labels || []).slice(0, 4).map((l) => `<span class="chip chip-tech">${esc(l)}</span>`).join("");
      const techs = (c.techniques || []).slice(0, 5).map((t) => `<span class="chip chip-tech">${esc(t)}</span>`).join("");
      return (
        `<tr><td><span class="chip chip-sev-${esc(c.severity)}">${esc(c.severity)}</span></td>` +
        `<td>${labels}</td><td>${techs}</td><td>${c.event_count}</td>` +
        `<td>${esc(c.chain_description || "").slice(0, 160)}</td></tr>`
      );
    }).join("");
  } catch (e) {
    console.error(e);
  }
}

async function loadTimeline() {
  try {
    const timelines = await fetchJSON("/api/timelines");
    const el = document.getElementById("timeline");
    if (!timelines.length) {
      el.innerHTML = '<div class="muted">No timeline</div>';
      return;
    }
    const tl = timelines[0];
    const phases = tl.kill_chain_phases || [];
    let html = '<div class="timeline">';
    phases.forEach((phase, i) => {
      html +=
        `<div class="phase"><span class="num">${i + 1}</span>` +
        `<div><span class="name">${esc(phase.replace(/-/g, " "))}</span>` +
        `<div class="detail">attacker ${esc(tl.attacker_ip)} → target ${esc(tl.target_ip)}</div></div></div>`;
    });
    html += `</div><div class="panel body" style="margin-top: 4px;">Duration: ${esc(fmtDuration(tl.total_duration_seconds))} · ${tl.event_count} events across ${phases.length} phases</div>`;
    el.innerHTML = html;
  } catch (e) {
    console.error(e);
  }
}

async function loadEvents() {
  try {
    const events = await fetchJSON("/api/events");
    const tbody = document.querySelector("#events-table tbody");
    tbody.innerHTML = events.slice(0, 100).map((e) => {
      return (
        `<tr><td>${esc((e.timestamp || "").slice(11, 19))}</td>` +
        `<td>${esc(e.source_ip)}:${e.source_port}</td>` +
        `<td>${esc(e.destination_ip)}:${e.destination_port}</td>` +
        `<td>${esc(e.protocol)}</td><td>${esc(e.event_type)}</td>` +
        `<td><span class="chip chip-sev-${esc(e.severity)}">${esc(e.severity)}</span></td>` +
        `<td>${esc(e.payload_size)}</td></tr>`
      );
    }).join("");
  } catch (e) {
    console.error(e);
  }
}

function fmtDuration(seconds) {
  seconds = Number(seconds || 0);
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`;
  return `${(seconds / 3600).toFixed(2)}h`;
}

function renderMarkdown(text) {
  if (!text) return "";
  let html = text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    .replace(/^## (.+)$/gm, "<h2>$1</h2>")
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/^- (.+)$/gm, "<li>$1</li>")
    .replace(/\n/g, "<br>");
  return html;
}

document.addEventListener("DOMContentLoaded", () => {
  loadOverview();
  loadNarrative();
  loadTechniques();
  loadClusters();
  loadTimeline();
  loadEvents();
  setInterval(loadOverview, 10000);
});