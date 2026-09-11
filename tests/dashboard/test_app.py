"""Tests for the Flask dashboard."""

import pytest

from sentinelwall.dashboard.app import create_app


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture(scope="module")
def overview(client):
    resp = client.get("/api/overview")
    assert resp.status_code == 200
    return resp.get_json()


class TestIndex:
    def test_index_renders(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.content_type.startswith("text/html")

    def test_index_has_markup(self, client):
        resp = client.get("/")
        assert b"sentinelwall" in resp.data.lower()


class TestOverview:
    def test_events_processed(self, overview):
        assert overview["events_processed"] > 0

    def test_detects_clusters(self, overview):
        assert overview["clusters"] >= 3

    def test_alerts_generated(self, overview):
        assert overview["alerts"] >= 0

    def test_techniques_count(self, overview):
        assert 1 <= overview["techniques"] <= 100

    def test_severity_distribution(self, overview):
        assert isinstance(overview["severity_distribution"], dict)
        assert any(k in overview["severity_distribution"] for k in
                   ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])

    def test_protocol_counts(self, overview):
        assert isinstance(overview["protocol_counts"], dict)
        assert overview["protocol_counts"]


class TestLiveData:
    def test_events_endpoint(self, client):
        resp = client.get("/api/events")
        assert resp.status_code == 200
        events = resp.get_json()
        assert isinstance(events, list)
        assert 0 < len(events) <= 200
        assert events[0]["source_ip"]

    def test_clusters_endpoint(self, client):
        resp = client.get("/api/clusters")
        assert resp.status_code == 200
        clusters = resp.get_json()
        assert isinstance(clusters, list)
        assert clusters
        assert clusters[0]["techniques"]

    def test_timelines_endpoint(self, client):
        resp = client.get("/api/timelines")
        assert resp.status_code == 200
        timelines = resp.get_json()
        assert isinstance(timelines, list)
        assert timelines

    def test_narrative_endpoint(self, client):
        resp = client.get("/api/narrative")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "text" in data
        assert data["text"]

    def test_mitre_endpoint(self, client):
        resp = client.get("/api/mitre")
        assert resp.status_code == 200
        layer = resp.get_json()
        assert layer["domain"] == "enterprise-attack"

    def test_stix_endpoint(self, client):
        resp = client.get("/api/stix")
        assert resp.status_code == 200
        bundle = resp.get_json()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"

    def test_techniques_endpoint(self, client):
        resp = client.get("/api/techniques")
        assert resp.status_code == 200
        items = resp.get_json()
        assert items
        assert items[0]["technique_id"].startswith("T")
        assert items[0]["count"] >= 1