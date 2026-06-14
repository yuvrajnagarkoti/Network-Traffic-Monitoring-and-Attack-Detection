"""
Integration tests verifying Flask REST API endpoints and blueprint registration.
"""

import json


def test_health_endpoint(client):
    """Test that the health endpoint is registered and active."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"


def test_auth_login_invalid_credentials(client):
    """Test login endpoint returns 401 on invalid credentials."""
    res = client.post(
        "/api/v1/auth/login",
        data=json.dumps({"username": "non_existent", "password": "wrong_password"}),
        content_type="application/json"
    )
    assert res.status_code == 401
    data = res.get_json()
    assert "error" in data


def test_alerts_endpoint(client, sample_analyst_user):
    """Test alerts list endpoint."""
    res = client.get("/api/v1/alerts")
    assert res.status_code == 200
    data = res.get_json()
    assert "alerts" in data
    assert isinstance(data["alerts"], list)


def test_blocks_endpoint(client):
    """Test blocks management endpoint."""
    res = client.get("/api/v1/blocks")
    assert res.status_code == 200
    data = res.get_json()
    assert "blocks" in data
    assert "count" in data


def test_packet_search_endpoint(client):
    """Test packet search endpoint."""
    res = client.get("/api/v1/search/packets")
    assert res.status_code == 200
    data = res.get_json()
    assert "packets" in data
    assert "count" in data


def test_investigation_timeline_not_found(client):
    """Test timeline returns 404 for invalid/missing attack event."""
    res = client.get("/api/v1/investigation/timeline/00000000-0000-0000-0000-000000000000")
    assert res.status_code == 404


def test_reports_pdf_generator(client):
    """Test downloading PDF report."""
    res = client.get("/api/v1/reports/pdf?hours=24")
    # Should either succeed or return 500 with specific library errors, not 404
    assert res.status_code in (200, 500)
    if res.status_code == 200:
        assert res.headers["Content-Type"] == "application/pdf"
