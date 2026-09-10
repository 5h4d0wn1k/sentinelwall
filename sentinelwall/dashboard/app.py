"""Flask web dashboard for SentinelWall."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinelwall.api.client import SentinelWall
from sentinelwall.ml.synthetic import generate_attack_scenario, generate_benign_traffic

DEMO_RESULTS: dict[str, Any] | None = None


def _load_demo_data() -> dict[str, Any]:
    """Generate the demo dataset once and reuse it for live rendering."""
    global DEMO_RESULTS
    if DEMO_RESULTS is not None:
        return DEMO_RESULTS

    benign = generate_benign_traffic(duration_minutes=120, samples_per_minute=6, seed=42)
    attack, _ = generate_attack_scenario("multi-stage")

    sw = SentinelWall()
    sw.ingest_events(benign + attack)
    result = sw.scan()
    story = sw.engine.generate_narrative()
    stix = sw.export_stix()
    navigator = sw.export_mitre_navigator()

    DEMO_RESULTS = {
        "events": [e.to_dict() for e in sw.get_events()],
        "clusters": [c.to_dict() for c in sw.get_clusters()],
        "timelines": [t.to_dict() for t in sw.get_timelines()],
        "stats": result["stats"],
        "narrative": story,
        "stix": stix,
        "navigator": navigator,
    }
    return DEMO_RESULTS


def create_app() -> Any:
    """Create and return the Flask application."""
    try:
        from flask import Flask, jsonify, render_template
    except ImportError as exc:
        raise ImportError(
            "Dashboard requires Flask: pip install 'sentinelwall[web]'"
        ) from exc

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/overview")
    def api_overview():
        data = _load_demo_data()
        return jsonify({
            "events_processed": data["stats"]["events_processed"],
            "clusters": data["stats"]["clusters_detected"],
            "alerts": data["stats"]["alerts_generated"],
            "techniques": len(data["stats"]["technique_counts"]),
            "events_per_second": data["stats"]["events_per_second"],
            "severity_distribution": data["stats"]["severity_distribution"],
            "protocol_counts": data["stats"]["protocol_counts"],
        })

    @app.route("/api/events")
    def api_events():
        data = _load_demo_data()
        limit = 200
        return jsonify(data["events"][:limit])

    @app.route("/api/clusters")
    def api_clusters():
        data = _load_demo_data()
        return jsonify(data["clusters"])

    @app.route("/api/timelines")
    def api_timelines():
        data = _load_demo_data()
        return jsonify(data["timelines"])

    @app.route("/api/narrative")
    def api_narrative():
        data = _load_demo_data()
        return jsonify({"text": data["narrative"]})

    @app.route("/api/mitre")
    def api_mitre():
        data = _load_demo_data()
        return jsonify(data["navigator"])

    @app.route("/api/stix")
    def api_stix():
        data = _load_demo_data()
        return jsonify(data["stix"])

    @app.route("/api/techniques")
    def api_techniques():
        data = _load_demo_data()
        counts = data["stats"]["technique_counts"]
        return jsonify([
            {"technique_id": tid, "count": count}
            for tid, count in sorted(counts.items(), key=lambda x: -x[1])
        ])

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=True)