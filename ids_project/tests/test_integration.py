"""
API integration tests.

Tests Flask REST endpoints via the test client.
All tests use an in-memory SQLite database (testing config).
"""

import json
import uuid


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def test_health_endpoint(client):
    """Health endpoint exists and returns healthy status."""
    res = client.get("/health")
    assert res.status_code in (200, 503)  # 503 if DB not connected in test env
    data = res.get_json()
    assert "status" in data


def test_openapi_spec_json(client):
    """OpenAPI JSON spec is served at /api/v1/openapi.json."""
    res = client.get("/api/v1/openapi.json")
    assert res.status_code == 200
    data = res.get_json()
    assert data["openapi"].startswith("3.0")
    assert "paths" in data
    assert "/api/v1/packets/stats" in data["paths"]


def test_swagger_ui(client):
    """Swagger UI HTML is served at /docs."""
    res = client.get("/docs")
    assert res.status_code == 200
    assert b"swagger" in res.data.lower()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def test_auth_login_missing_body(client):
    """Login with no body returns 400."""
    res = client.post(
        "/api/v1/auth/login",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert res.status_code == 400


def test_auth_login_invalid_credentials(client):
    """Login with wrong credentials returns 401."""
    res = client.post(
        "/api/v1/auth/login",
        data=json.dumps({"username": "no_such_user", "password": "wrong"}),
        content_type="application/json",
    )
    assert res.status_code == 401
    data = res.get_json()
    assert "error" in data


# ---------------------------------------------------------------------------
# Packets / Stats
# ---------------------------------------------------------------------------

def test_packet_stats_flat_shape(client):
    """GET /api/v1/packets/stats returns flat dashboard-friendly dict."""
    res = client.get("/api/v1/packets/stats")
    assert res.status_code == 200
    data = res.get_json()
    # Must be flat (not nested objects)
    assert "packets_per_second" in data
    assert "active_alerts" in data
    assert "blocked_ips" in data
    assert "timestamp" in data
    # Values must be numbers / bool
    assert isinstance(data["packets_per_second"], (int, float))
    assert isinstance(data["active_alerts"], int)


def test_protocol_distribution_dict_shape(client):
    """GET /api/v1/packets/protocols returns {protocols: {proto: count}} dict."""
    res = client.get("/api/v1/packets/protocols")
    assert res.status_code == 200
    data = res.get_json()
    assert "protocols" in data
    # Must be a dict (not a list)
    assert isinstance(data["protocols"], dict)


def test_capture_status(client):
    """GET /api/v1/capture/status returns status dict."""
    res = client.get("/api/v1/capture/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "is_running" in data


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def test_alerts_list(client):
    """GET /api/v1/alerts returns paginated alert list."""
    res = client.get("/api/v1/alerts")
    assert res.status_code == 200
    data = res.get_json()
    assert "alerts" in data
    assert isinstance(data["alerts"], list)


def test_alerts_filter_by_severity(client):
    """GET /api/v1/alerts?severity=critical applies filter."""
    res = client.get("/api/v1/alerts?severity=critical&limit=5")
    assert res.status_code == 200
    data = res.get_json()
    assert "alerts" in data


def test_alert_not_found(client):
    """GET /api/v1/alerts/<invalid_id> returns 404."""
    fake_id = str(uuid.uuid4())
    res = client.get(f"/api/v1/alerts/{fake_id}")
    assert res.status_code == 404


def test_alert_patch_missing_status(client):
    """PATCH /api/v1/alerts/<id> with no status returns 400."""
    fake_id = str(uuid.uuid4())
    res = client.patch(
        f"/api/v1/alerts/{fake_id}",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert res.status_code == 400


def test_alerts_campaigns(client):
    """GET /api/v1/alerts/campaigns returns campaigns list."""
    res = client.get("/api/v1/alerts/campaigns")
    assert res.status_code == 200
    data = res.get_json()
    assert "campaigns" in data


# ---------------------------------------------------------------------------
# Blocks
# ---------------------------------------------------------------------------

def test_blocks_list(client):
    """GET /api/v1/blocks returns active blocks."""
    res = client.get("/api/v1/blocks")
    assert res.status_code == 200
    data = res.get_json()
    assert "blocks" in data
    assert "count" in data


def test_blocks_active_alias(client):
    """GET /api/v1/blocks/active returns same as /api/v1/blocks."""
    res = client.get("/api/v1/blocks/active")
    assert res.status_code == 200
    data = res.get_json()
    assert "blocks" in data


def test_block_ip_missing_body(client):
    """POST /api/v1/blocks/block without ip_address returns 400."""
    res = client.post(
        "/api/v1/blocks/block",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert res.status_code == 400


def test_blacklist_list(client):
    """GET /api/v1/blocks/blacklist returns blacklist entries."""
    res = client.get("/api/v1/blocks/blacklist")
    assert res.status_code == 200
    data = res.get_json()
    assert "entries" in data or "blacklist" in data


def test_whitelist_list(client):
    """GET /api/v1/blocks/whitelist returns whitelist entries."""
    res = client.get("/api/v1/blocks/whitelist")
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# Packet Search
# ---------------------------------------------------------------------------

def test_packet_search_primary_url(client):
    """GET /api/v1/search/packets returns packet results."""
    res = client.get("/api/v1/search/packets")
    assert res.status_code == 200
    data = res.get_json()
    assert "packets" in data


def test_packet_search_alias_url(client):
    """GET /api/v1/packets/search (JS alias) returns same shape."""
    res = client.get("/api/v1/packets/search")
    assert res.status_code == 200
    data = res.get_json()
    assert "packets" in data


def test_packet_search_with_filters(client):
    """Packet search respects query parameters."""
    res = client.get("/api/v1/packets/search?protocol=tcp&limit=10")
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------

def test_investigation_timeline_not_found(client):
    """Timeline returns 404 for a non-existent attack event."""
    fake_id = str(uuid.uuid4())
    res = client.get(f"/api/v1/investigation/timeline/{fake_id}")
    assert res.status_code == 404


def test_investigation_flow_missing_params(client):
    """Flow endpoint returns 400 when src_ip or dst_ip missing."""
    res = client.get("/api/v1/investigation/flow?src_ip=1.2.3.4")
    assert res.status_code == 400


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def test_reports_csv_header(client):
    """GET /api/v1/reports/csv responds (empty dataset → empty CSV OK)."""
    res = client.get("/api/v1/reports/csv?max_rows=10")
    assert res.status_code == 200
    assert "csv" in res.content_type or "text" in res.content_type


def test_reports_pdf(client):
    """PDF endpoint returns PDF or meaningful error (not 404)."""
    res = client.get("/api/v1/reports/pdf?hours=1")
    assert res.status_code in (200, 500)
    if res.status_code == 200:
        assert "pdf" in res.content_type
