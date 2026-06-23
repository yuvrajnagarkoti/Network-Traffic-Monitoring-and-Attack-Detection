"""
OpenAPI 3.0 documentation endpoint.

Routes:
  GET /docs                  — Swagger UI HTML page
  GET /api/v1/openapi.json   — Raw OpenAPI 3.0 JSON spec
"""

import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, Response, jsonify, render_template_string

logger = logging.getLogger(__name__)

docs_bp = Blueprint("docs", __name__)

# ---------------------------------------------------------------------------
# OpenAPI spec (static — kept in sync with actual routes manually)
# ---------------------------------------------------------------------------

_OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "NetIDS — Network Intrusion Detection System API",
        "version": "1.0.0",
        "description": (
            "REST API for the Network Traffic Monitoring & Attack Detection System. "
            "Provides endpoints for live packet stats, alert management, IP blocking, "
            "threat intelligence, packet search, investigation, and reporting."
        ),
        "contact": {"name": "NetIDS Team"},
    },
    "servers": [{"url": "/", "description": "Current server"}],
    "tags": [
        {"name": "health",        "description": "System health"},
        {"name": "packets",       "description": "Live traffic monitoring"},
        {"name": "alerts",        "description": "Alert lifecycle management"},
        {"name": "blocks",        "description": "IP blocking & lists"},
        {"name": "search",        "description": "Packet log search"},
        {"name": "investigation", "description": "Attack investigation tools"},
        {"name": "reports",       "description": "PDF & CSV report generation"},
        {"name": "reputation",    "description": "IP reputation & intelligence"},
    ],
    "paths": {
        "/health": {
            "get": {
                "tags": ["health"],
                "summary": "System health check",
                "responses": {
                    "200": {"description": "System is healthy"},
                    "503": {"description": "System is unhealthy"},
                },
            }
        },
        "/api/v1/packets/stats": {
            "get": {
                "tags": ["packets"],
                "summary": "Live dashboard metrics",
                "description": "Returns packets/s, bytes/s, active alerts, blocked IPs.",
                "responses": {
                    "200": {
                        "description": "Dashboard metrics",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "packets_per_second": {"type": "number"},
                                        "bytes_per_second":   {"type": "number"},
                                        "active_alerts":      {"type": "integer"},
                                        "critical_count":     {"type": "integer"},
                                        "blocked_ips":        {"type": "integer"},
                                        "is_capturing":       {"type": "boolean"},
                                        "timestamp":          {"type": "string"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/api/v1/packets/protocols": {
            "get": {
                "tags": ["packets"],
                "summary": "Protocol distribution",
                "responses": {
                    "200": {
                        "description": "Protocol packet counts",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "protocols": {
                                            "type": "object",
                                            "additionalProperties": {"type": "integer"},
                                            "example": {"TCP": 8421, "UDP": 3102, "ICMP": 47},
                                        },
                                        "timestamp": {"type": "string"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/api/v1/alerts": {
            "get": {
                "tags": ["alerts"],
                "summary": "List alerts (paginated)",
                "parameters": [
                    {"name": "severity",     "in": "query", "schema": {"type": "string", "enum": ["critical","high","medium","low"]}},
                    {"name": "status",       "in": "query", "schema": {"type": "string"}},
                    {"name": "hours",        "in": "query", "schema": {"type": "integer", "default": 24}},
                    {"name": "limit",        "in": "query", "schema": {"type": "integer", "default": 50}},
                    {"name": "offset",       "in": "query", "schema": {"type": "integer", "default": 0}},
                ],
                "responses": {"200": {"description": "Alert list"}},
            }
        },
        "/api/v1/alerts/{alert_id}": {
            "get": {
                "tags": ["alerts"],
                "summary": "Get single alert",
                "parameters": [{"name": "alert_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Alert detail"}, "404": {"description": "Not found"}},
            },
            "patch": {
                "tags": ["alerts"],
                "summary": "Update alert status",
                "parameters": [{"name": "alert_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "status": {"type": "string", "enum": ["new","acknowledged","investigating","resolved","false_positive"]},
                                    "user_id": {"type": "string"},
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "Updated"}},
            },
        },
        "/api/v1/alerts/bulk-acknowledge": {
            "post": {
                "tags": ["alerts"],
                "summary": "Bulk acknowledge alerts",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "severity": {"type": "string"},
                                    "user_id":  {"type": "string"},
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "Acknowledged"}},
            }
        },
        "/api/v1/blocks/active": {
            "get": {
                "tags": ["blocks"],
                "summary": "List active IP blocks",
                "responses": {"200": {"description": "Active blocks list"}},
            }
        },
        "/api/v1/blocks/block": {
            "post": {
                "tags": ["blocks"],
                "summary": "Block an IP address",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["ip_address"],
                                "properties": {
                                    "ip_address":     {"type": "string"},
                                    "reason":         {"type": "string"},
                                    "duration_hours": {"type": "integer"},
                                },
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "Blocked"}},
            }
        },
        "/api/v1/blocks/unblock": {
            "post": {
                "tags": ["blocks"],
                "summary": "Unblock an IP address",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["ip_address"],
                                "properties": {"ip_address": {"type": "string"}},
                            }
                        }
                    }
                },
                "responses": {"200": {"description": "Unblocked"}, "404": {"description": "Not found"}},
            }
        },
        "/api/v1/blocks/blacklist": {
            "get": {
                "tags": ["blocks"],
                "summary": "List blacklist entries",
                "responses": {"200": {"description": "Blacklist"}},
            }
        },
        "/api/v1/blocks/whitelist": {
            "get": {
                "tags": ["blocks"],
                "summary": "List whitelist entries",
                "responses": {"200": {"description": "Whitelist"}},
            }
        },
        "/api/v1/search/packets": {
            "get": {
                "tags": ["search"],
                "summary": "Search packet logs (cursor-paginated)",
                "parameters": [
                    {"name": "src_ip",    "in": "query", "schema": {"type": "string"}},
                    {"name": "dst_ip",    "in": "query", "schema": {"type": "string"}},
                    {"name": "protocol",  "in": "query", "schema": {"type": "string"}},
                    {"name": "dst_port",  "in": "query", "schema": {"type": "integer"}},
                    {"name": "min_size",  "in": "query", "schema": {"type": "integer"}},
                    {"name": "max_size",  "in": "query", "schema": {"type": "integer"}},
                    {"name": "start",     "in": "query", "schema": {"type": "string", "format": "date-time"}},
                    {"name": "end",       "in": "query", "schema": {"type": "string", "format": "date-time"}},
                    {"name": "cursor",    "in": "query", "schema": {"type": "string"}},
                    {"name": "limit",     "in": "query", "schema": {"type": "integer", "default": 50}},
                ],
                "responses": {"200": {"description": "Packet results with next_cursor"}},
            }
        },
        "/api/v1/packets/search": {
            "get": {
                "tags": ["search"],
                "summary": "Search packets (dashboard alias)",
                "description": "Alias for /api/v1/search/packets.",
                "responses": {"200": {"description": "Packet results"}},
            }
        },
        "/api/v1/investigation/timeline/{attack_event_id}": {
            "get": {
                "tags": ["investigation"],
                "summary": "Attack event timeline",
                "parameters": [
                    {"name": "attack_event_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "context_minutes",  "in": "query", "schema": {"type": "integer", "default": 5}},
                ],
                "responses": {"200": {"description": "Timeline events"}, "404": {"description": "Not found"}},
            }
        },
        "/api/v1/investigation/ip/{ip}": {
            "get": {
                "tags": ["investigation"],
                "summary": "IP address profile",
                "parameters": [
                    {"name": "ip",   "in": "path",  "required": True, "schema": {"type": "string"}},
                    {"name": "days", "in": "query", "schema": {"type": "integer", "default": 30}},
                ],
                "responses": {"200": {"description": "IP profile"}},
            }
        },
        "/api/v1/investigation/flow": {
            "get": {
                "tags": ["investigation"],
                "summary": "TCP flow reconstruction",
                "parameters": [
                    {"name": "src_ip",   "in": "query", "required": True, "schema": {"type": "string"}},
                    {"name": "dst_ip",   "in": "query", "required": True, "schema": {"type": "string"}},
                    {"name": "dst_port", "in": "query", "schema": {"type": "integer"}},
                    {"name": "start",    "in": "query", "schema": {"type": "string", "format": "date-time"}},
                    {"name": "end",      "in": "query", "schema": {"type": "string", "format": "date-time"}},
                ],
                "responses": {"200": {"description": "Flow packets"}},
            }
        },
        "/api/v1/reports/pdf": {
            "get": {
                "tags": ["reports"],
                "summary": "Download security report PDF",
                "parameters": [{"name": "hours", "in": "query", "schema": {"type": "integer", "default": 24}}],
                "responses": {"200": {"description": "PDF file", "content": {"application/pdf": {}}}},
            }
        },
        "/api/v1/reports/csv": {
            "get": {
                "tags": ["reports"],
                "summary": "Stream packet log as CSV",
                "parameters": [
                    {"name": "src_ip",    "in": "query", "schema": {"type": "string"}},
                    {"name": "protocol",  "in": "query", "schema": {"type": "string"}},
                    {"name": "max_rows",  "in": "query", "schema": {"type": "integer", "default": 1000000}},
                ],
                "responses": {"200": {"description": "CSV download", "content": {"text/csv": {}}}},
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }
    },
    "security": [{"bearerAuth": []}],
}


# ---------------------------------------------------------------------------
# Swagger UI HTML (served inline — no CDN dependency issues)
# ---------------------------------------------------------------------------

_SWAGGER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NetIDS API Docs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body { margin: 0; background: #0a0f1e; }
    .swagger-ui .topbar { background: #0a0f1e; border-bottom: 1px solid #1e2d4a; }
    .swagger-ui .topbar .download-url-wrapper { display: none; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: '/api/v1/openapi.json',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
      deepLinking: true,
    });
  </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@docs_bp.route("/docs", methods=["GET"])
def swagger_ui():
    """GET /docs — Swagger UI for the OpenAPI spec."""
    return Response(_SWAGGER_HTML, mimetype="text/html")


@docs_bp.route("/api/v1/openapi.json", methods=["GET"])
def openapi_spec():
    """GET /api/v1/openapi.json — raw OpenAPI 3.0 spec."""
    spec = dict(_OPENAPI_SPEC)
    spec["info"]["x_generated_at"] = datetime.now(timezone.utc).isoformat()
    return Response(
        json.dumps(spec, indent=2),
        mimetype="application/json",
    )
