"""HTML report exporter — generates a self-contained SOC-quality dashboard."""

from __future__ import annotations

import html as _html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelwall.core.correlator import CorrelatedCluster
from sentinelwall.core.events import NetworkEvent
from sentinelwall.core.timeline import AttackTimeline
from sentinelwall.mitre.techniques import MITRE_TECHNIQUES


class HtmlReportExporter:
    """Generates a self-contained HTML security report with embedded data."""

    def export(
        self,
        events: list[NetworkEvent],
        clusters: list[CorrelatedCluster],
        timelines: list[AttackTimeline],
        stats: Any | None = None,
        output_path: str | Path | None = None,
    ) -> str:
        """Generate and optionally write an HTML report. Returns the HTML string."""
        payload = {
            "events": [e.to_dict() for e in events],
            "clusters": [c.to_dict() for c in clusters],
            "timelines": [t.to_dict() for t in timelines],
            "stats": stats.to_dict() if stats else {},
            "mitre_techniques": {t: i.to_dict() for t, i in MITRE_TECHNIQUES.items()},
        }
        html_str = self._build_html(payload)
        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html_str)
        return html_str

    def _build_html(self, payload: dict[str, Any]) -> str:
        events = payload["events"]
        clusters = payload["clusters"]
        timelines = payload["timelines"]
        stats = payload["stats"]

        total_events = len(events)
        total_clusters = len(clusters)
        severity_counts = stats.get("severity_distribution", {})
        tech_counts = stats.get("technique_counts", {})
        proto_counts = stats.get("protocol_counts", {})

        cluster_rows = "".join(
            self._cluster_row(c) for c in clusters
        )
        event_rows = "".join(
            self._event_row(e) for e in events[-100:]
        )
        timeline_rows = "".join(
            self._timeline_row(t) for t in timelines
        )
        technique_chips = "".join(
            f'<span class="chip chip-tech">{_html.escape(t)} <small>{_html.escape(MITRE_TECHNIQUES[t].name if t in MITRE_TECHNIQUES else "")}</small></span>'
            for t in sorted(tech_counts.keys())
        ) or '<span class="muted">No techniques detected</span>'

        proto_bars = "".join(
            f'<div class="proto-bar"><span class="proto-name">{_html.escape(p)}</span>'
            f'<span class="proto-count">{c}</span></div>'
            for p, c in sorted(proto_counts.items(), key=lambda x: -x[1])
        ) or '<span class="muted">No protocol data</span>'

        sev_dist = "".join(
            f'<div class="sev-line"><span class="sev-name">{_html.escape(s)}</span>'
            f'<div class="sev-bar"><div class="sev-fill sev-{s.lower()}" '
            f'style="width:{min(100, c * 8)}%"></div></div>'
            f'<span class="sev-count">{c}</span></div>'
            for s, c in sorted(severity_counts.items())
        ) or '<span class="muted">No alerts</span>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelWall Security Report</title>
<style>
:root {{
  --bg: #0b0e14; --panel: #12161f; --panel2: #171c28; --border: #232b3d;
  --text: #d7dce5; --muted: #6b7690; --accent: #4f8cff; --green: #3ddc84;
  --yellow: #f5c518; --orange: #ff8c00; --red: #ff4444; --purple: #a855f7;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; }}
.wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
.header {{ display: flex; justify-content: space-between; align-items: center; padding: 20px 0; border-bottom: 1px solid var(--border); }}
.logo {{ font-size: 26px; font-weight: 800; letter-spacing: 1px; }}
.logo span {{ color: var(--accent); }}
.report-meta {{ color: var(--muted); font-size: 13px; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 24px 0; }}
.card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }}
.card .value {{ font-size: 32px; font-weight: 700; }}
.card .label {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
.panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; margin: 16px 0; overflow: hidden; }}
.panel h2 {{ font-size: 16px; padding: 14px 18px; background: var(--panel2); border-bottom: 1px solid var(--border); }}
.panel .body {{ padding: 18px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; color: var(--muted); font-weight: 600; padding: 10px 12px; border-bottom: 1px solid var(--border); }}
td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); }}
tr:hover td {{ background: rgba(79,140,255,0.05); }}
.chip {{ display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; margin: 2px; }}
.chip-tech {{ background: rgba(168,85,247,0.15); color: var(--purple); }}
.chip-sev-CRITICAL {{ background: rgba(255,68,68,0.15); color: var(--red); }}
.chip-sev-HIGH {{ background: rgba(255,140,0,0.15); color: var(--orange); }}
.chip-sev-MEDIUM {{ background: rgba(245,197,24,0.15); color: var(--yellow); }}
.chip-sev-LOW {{ background: rgba(61,220,132,0.15); color: var(--green); }}
.chip-sev-INFORMATIONAL {{ background: rgba(107,118,144,0.2); color: var(--muted); }}
.muted {{ color: var(--muted); }}
.proto-bar {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 13px; }}
.proto-name {{ color: var(--text); }}
.proto-count {{ color: var(--accent); font-weight: 600; }}
.sev-line {{ display: flex; align-items: center; gap: 10px; padding: 5px 0; }}
.sev-bar {{ flex: 1; background: var(--panel2); height: 8px; border-radius: 4px; overflow: hidden; }}
.sev-fill {{ height: 100%; border-radius: 4px; }}
.sev-critical {{ background: var(--red); }} .sev-high {{ background: var(--orange); }}
.sev-medium {{ background: var(--yellow); }} .sev-low {{ background: var(--green); }}
.sev-informational {{ background: var(--muted); }}
.sev-name {{ width: 110px; font-size: 13px; }}
.sev-count {{ width: 30px; text-align: right; color: var(--muted); font-size: 13px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">SENTINEL<span>WALL</span></div>
    <div class="report-meta">
      Security Incident Report<br>
      Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC
    </div>
  </div>

  <div class="cards">
    <div class="card"><div class="value">{total_events}</div><div class="label">Events Analyzed</div></div>
    <div class="card"><div class="value">{total_clusters}</div><div class="label">Threat Clusters</div></div>
    <div class="card"><div class="value">{len(tech_counts)}</div><div class="label">ATT&amp;CK Techniques</div></div>
    <div class="card"><div class="value">{stats.get('events_per_second', 0):.0f}</div><div class="label">Events/sec</div></div>
  </div>

  <div class="panel">
    <h2>MITRE ATT&amp;CK Coverage</h2>
    <div class="body">{technique_chips}</div>
  </div>

  <div class="panel">
    <h2>Severity Distribution</h2>
    <div class="body">{sev_dist}</div>
  </div>

  <div class="panel">
    <h2>Protocol Distribution</h2>
    <div class="body">{proto_bars}</div>
  </div>

  <div class="panel">
    <h2>Correlated Threat Clusters</h2>
    <div class="body"><table>
      <tr><th>Severity</th><th>Labels</th><th>Techniques</th><th>Events</th><th>Description</th></tr>
      {cluster_rows}
    </table></div>
  </div>

  <div class="panel">
    <h2>Attack Timelines</h2>
    <div class="body"><table>
      <tr><th>ID</th><th>Attacker</th><th>Target</th><th>Phases</th><th>Duration</th><th>Events</th></tr>
      {timeline_rows}
    </table></div>
  </div>

  <div class="panel">
    <h2>Event Log (last 100)</h2>
    <div class="body"><table>
      <tr><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Type</th><th>Severity</th><th>Bytes</th></tr>
      {event_rows}
    </table></div>
  </div>
</div>
</body>
</html>"""

    def _cluster_row(self, cluster: dict[str, Any]) -> str:
        severity = cluster.get("severity", "UNKNOWN")
        labels = "".join(
            f'<span class="chip chip-tech">{_html.escape(l)}</span>'
            for l in cluster.get("labels", [])[:4]
        )
        techniques = "".join(
            f'<span class="chip chip-tech">{_html.escape(t)}</span>'
            for t in cluster.get("techniques", [])[:5]
        )
        return (
            f"<tr><td><span class=\"chip chip-sev-{_html.escape(severity)}\">{_html.escape(severity)}</span></td>"
            f"<td>{labels}</td><td>{techniques}</td>"
            f"<td>{cluster.get('event_count', 0)}</td>"
            f"<td>{_html.escape(cluster.get('chain_description', ''))[:140]}</td></tr>"
        )

    def _event_row(self, event: dict[str, Any]) -> str:
        severity = event.get("severity", "INFORMATIONAL")
        ts = event.get("timestamp", "")[11:19]
        return (
            f"<tr><td>{_html.escape(ts)}</td>"
            f"<td>{_html.escape(event.get('source_ip', ''))}:{event.get('source_port', 0)}</td>"
            f"<td>{_html.escape(event.get('destination_ip', ''))}:{event.get('destination_port', 0)}</td>"
            f"<td>{_html.escape(event.get('protocol', ''))}</td>"
            f"<td>{_html.escape(event.get('event_type', ''))}</td>"
            f"<td><span class=\"chip chip-sev-{_html.escape(severity)}\">{_html.escape(severity)}</span></td>"
            f"<td>{event.get('payload_size', 0)}</td></tr>"
        )

    def _timeline_row(self, timeline: dict[str, Any]) -> str:
        phases = " → ".join(_html.escape(p) for p in timeline.get("kill_chain_phases", []))
        duration = float(timeline.get("total_duration_seconds", 0))
        dur_str = f"{duration:.0f}s"
        if duration > 60:
            dur_str = f"{duration / 60:.1f}m"
        return (
            f"<tr><td>{_html.escape(timeline.get('timeline_id', ''))}</td>"
            f"<td>{_html.escape(timeline.get('attacker_ip', ''))}</td>"
            f"<td>{_html.escape(timeline.get('target_ip', ''))}</td>"
            f"<td>{phases}</td><td>{dur_str}</td>"
            f"<td>{timeline.get('event_count', 0)}</td></tr>"
        )