# Week 1 Progress Report

## Network Traffic Monitoring & Attack Detection System

**Week:** 1 of 8  
**Period:** Planning & Architecture Phase  
**Status:** ✅ Completed

---

## Summary

> Completed the planning and design phase of the Network Traffic Monitoring and Attack Detection project. Defined system requirements, designed the overall architecture, developed threat models, and created database schemas. Established the Flask backend structure, PostgreSQL database design, Docker environment, and logging framework for future development.

---

## Phase 1 — Project Planning & System Architecture ✅

### Milestone 1.1: Requirements Analysis ✅

**Functional Requirements Defined:**
- All 15 detection modules documented with input/output specifications
- Attack detection thresholds established:
  - Port Scan: >15 unique ports from same IP within 10 seconds
  - Brute Force SSH: >5 failed auth attempts within 60 seconds
  - Brute Force HTTP: >10 failed POST /login within 30 seconds
  - DDoS: >1,000 packets/second from distributed IPs
  - Traffic Spike: >300% increase from rolling 5-minute baseline
- Report formats defined (PDF layout, CSV columns)
- Alert content structure specified

**Non-Functional Requirements Established:**
- Performance: ≥10,000 packets/second without packet loss
- Latency: Alert generation within 2 seconds of detection
- Availability: 99.5% uptime for monitoring daemon
- Storage: Packet logs retained 30 days; attack records 1 year
- Scalability: Designed for horizontal scaling of detection modules

**User Roles & Permission Matrix:**
| Role | Access Level | Key Permissions |
|------|-------------|-----------------|
| Administrator | Full | Configure thresholds, manage users, block IPs, all data |
| Security Analyst | Read/Write | View alerts, run investigations, generate reports |
| Viewer | Read-Only | View dashboard, alerts, and reports |

📄 **Deliverables:**
- [functional_requirements.md](ids_project/docs/requirements/functional_requirements.md)
- [non_functional_requirements.md](ids_project/docs/requirements/non_functional_requirements.md)
- [permission_matrix.md](ids_project/docs/requirements/permission_matrix.md)

---

### Milestone 1.2: System Architecture Design ✅

**5-Layer Architecture Designed:**

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 5 — PRESENTATION                                      │
│  Nginx → Flask/Gunicorn → Dashboard + REST API              │
│  WebSocket (Flask-SocketIO) for live alert streaming         │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4 — DETECTION                                         │
│  Port Scan │ Brute Force │ DDoS │ Traffic Pattern Analysis   │
│  Detection Orchestrator (parallel thread pool)               │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3 — INTELLIGENCE                                      │
│  ML Anomaly Engine │ IP Reputation │ Threat Scoring          │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2 — RESPONSE                                          │
│  Alert Center │ Email Notifier │ IP Blocker (iptables)       │
├─────────────────────────────────────────────────────────────┤
│  LAYER 1 — CAPTURE                                           │
│  Scapy Sniffer │ PyShark │ Protocol Parser                   │
│  Flow Tracker │ Batch Writer │ Stats Aggregator              │
├─────────────────────────────────────────────────────────────┤
│  DATA LAYER                                                  │
│  PostgreSQL 15+ (partitioned) │ Redis │ File Storage         │
└─────────────────────────────────────────────────────────────┘
```

**All 15 Modules Mapped to Architecture Layers**

**Architecture Decisions Made:**
- Modular monolith with clear package boundaries (Docker-ready)
- Internal REST communication between components
- WebSocket (Flask-SocketIO) for real-time dashboard updates
- API versioning strategy: `/api/v1/`

📄 **Deliverables:**
- [system_architecture.md](ids_project/docs/architecture/system_architecture.md)

---

### Milestone 1.3: Data Flow Design ✅

**Complete Packet-to-Alert Pipeline Designed:**

```
Network Interface
      ↓
Scapy/PyShark Capture (dedicated thread)
      ↓
Packet Parser → packet_logs (PostgreSQL)
      ↓
Detection Engine (parallel thread pool: 4–8 workers)
      ↓ (attack detected)
attack_events table
      ↓
Threat Scoring Engine
      ↓
scored_threats table
      ↓
Alert Engine
      ↓
alerts table + Email (SMTP) + WebSocket Push
      ↓ (high severity)
IP Blocking Module → iptables firewall rules
```

**Event Schemas Defined:**

| Schema | Key Fields |
|--------|-----------|
| PacketEvent | src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp, payload_hash |
| AttackEvent | attack_type, source_ip, target_ip, severity, confidence_score, evidence (JSONB) |
| AlertEvent | alert_id, attack_event_id, threat_score, severity_level, status, created_at |

**Concurrency Model:**
- Packet capture: Dedicated thread (never blocked by processing)
- Detection modules: Thread pool (4–8 workers)
- Database writes: Async batch inserts (flush every 500ms or 100 packets)
- Alert dispatch: Separate thread with retry queue

📄 **Deliverables:**
- [data_flow.md](ids_project/docs/architecture/data_flow.md)

---

### Milestone 1.4: Threat Modeling ✅

**STRIDE Analysis Applied to All Critical Components:**

| Component | Threats Identified | Controls Designed |
|-----------|-------------------|------------------|
| Dashboard Login | Spoofing (brute force), Info Disclosure (session fixation) | Rate limiting, secure session management |
| Packet Capture | Tampering (packet injection), DoS (IDS flood) | Input validation, resource limits |
| Alert Email | Spoofing (email header injection) | Output encoding, SMTP auth |
| IP Blocking Module | Elevation of Privilege (trigger false blocks via spoofed IPs) | Source validation, whitelist protection |
| Database | Info Disclosure (SQL injection), Tampering (log deletion) | Parameterized queries, append-only audit logs |

**Attacker Profiles Defined:**
1. **External Attacker** — Port scans, brute force, DDoS
2. **Insider Threat** — Log deletion, privilege escalation
3. **Evasion Attacker** — Slow scans below threshold, ML model evasion

📄 **Deliverables:**
- [stride_analysis.md](ids_project/docs/threat_model/stride_analysis.md)

---

## Phase 2 — Development Environment & Database Design ✅

### Milestone 2.1: Project Structure & Flask Application Factory ✅

**Flask Application Factory Pattern Implemented:**
- `create_app(config_name)` function with Blueprint registration
- Configuration classes: `BaseConfig`, `DevelopmentConfig`, `TestingConfig`, `ProductionConfig`
- All Flask extensions initialized inside factory (SQLAlchemy, Migrate, SocketIO, Login)
- Circular import prevention via extension instances in `extensions.py`

**Blueprint Architecture:**
- `/auth` — Authentication routes
- `/dashboard` — Web dashboard routes
- `/api/v1/` — REST API endpoints (versioned)
- `/alerts` — Alert management
- `/api/v1/packets` — Packet data APIs

📄 **File:** [app/\_\_init\_\_.py](ids_project/app/__init__.py)

---

### Milestone 2.2: PostgreSQL Schema Design ✅

**15+ Tables Designed Across 8 Categories:**

#### Authentication Tables
| Table | Purpose |
|-------|---------|
| `users` | User accounts with UUID PK, roles, login tracking, account lockout |
| `sessions` | Token-based sessions with revocation support |

#### Packet Monitoring Tables
| Table | Purpose |
|-------|---------|
| `packet_logs` | High-volume packet storage (BIGSERIAL, partitioned by date) |
| `protocol_stats` | Aggregated protocol statistics (updated every 60s) |

#### Attack Detection Tables
| Table | Purpose |
|-------|---------|
| `attack_events` | Core attack records with JSONB evidence storage |
| `port_scan_details` | Port scan specifics (ports array, scan pattern, technique) |
| `brute_force_details` | Brute force specifics (service, attempts, usernames tried) |
| `ddos_details` | DDoS specifics (vector, pps, bps, contributing IPs array) |

#### Intelligence & Scoring Tables
| Table | Purpose |
|-------|---------|
| `threat_scores` | Calculated scores (0–100) with modifiers |
| `ip_reputation` | IP reputation cache with manual override support |
| `ml_predictions` | ML model predictions with feature vectors |

#### Alert & Response Tables
| Table | Purpose |
|-------|---------|
| `alerts` | Alert lifecycle management with assignment |
| `alert_comments` | Analyst commentary per alert |
| `email_notifications` | Email delivery tracking with retry |
| `ip_blocks` | Active IP blocks (auto/manual, expiry support) |
| `blacklist` | Persistent IP blacklist |
| `whitelist` | Protected IP whitelist |

#### Audit & History Tables
| Table | Purpose |
|-------|---------|
| `audit_logs` | Immutable admin action log with old/new JSONB values |
| `system_stats` | Time-series system metrics (1-minute buckets, partitioned) |

**Performance Design:**
- `packet_logs` partitioned by `captured_at` (monthly partitions)
- Indexes on: `(src_ip, captured_at)`, `(dst_ip, captured_at)`, `(protocol, captured_at)`
- `system_stats` partitioned by `recorded_at`
- Connection pool: size=10, max_overflow=20

📄 **Files:** [app/models/](ids_project/app/models/)

---

### Milestone 2.3: Docker Environment ✅

**Docker Compose Configuration:**
- `web` service: Flask/Gunicorn application
- `db` service: PostgreSQL 15 with persistent named volume
- `redis` service: For detection state and caching
- `nginx` service: Reverse proxy with SSL termination

**PostgreSQL Optimization:**
- `max_connections=200`
- `shared_buffers=256MB`
- `work_mem=16MB`
- Dedicated database role (no SUPERUSER)
- Separate test database

📄 **Files:**
- [docker/docker-compose.yml](ids_project/docker/docker-compose.yml)
- [docker/Dockerfile](ids_project/docker/Dockerfile)

---

### Milestone 2.4: Logging Architecture ✅

**Multi-Channel Structured JSON Logging:**

| Channel | Level | Destination | Notes |
|---------|-------|-------------|-------|
| Application | INFO+ | `logs/app.log` | Rotating 10MB, 5 backups |
| Security | WARNING+ | `logs/security.log` | Never truncated |
| Error | ERROR+ | `logs/error.log` | Full stack traces |
| Audit | ALL | `audit_logs` DB table + `logs/audit.log` | Append-only |

**Every log entry contains:**
- `timestamp`, `level`, `logger_name`, `message`
- `request_id` (UUID per HTTP request)
- `user_id` (if authenticated)
- `source_ip`

📄 **File:** [app/core/](ids_project/app/core/)

---

## Week 1 Deliverables Summary

| # | Deliverable | File | Status |
|---|-------------|------|--------|
| 1 | Functional Requirements | [functional_requirements.md](ids_project/docs/requirements/functional_requirements.md) | ✅ |
| 2 | Non-Functional Requirements | [non_functional_requirements.md](ids_project/docs/requirements/non_functional_requirements.md) | ✅ |
| 3 | RBAC Permission Matrix | [permission_matrix.md](ids_project/docs/requirements/permission_matrix.md) | ✅ |
| 4 | System Architecture Doc | [system_architecture.md](ids_project/docs/architecture/system_architecture.md) | ✅ |
| 5 | Data Flow Design | [data_flow.md](ids_project/docs/architecture/data_flow.md) | ✅ |
| 6 | STRIDE Threat Model | [stride_analysis.md](ids_project/docs/threat_model/stride_analysis.md) | ✅ |
| 7 | Flask App Factory | [app/\_\_init\_\_.py](ids_project/app/__init__.py) | ✅ |
| 8 | Configuration Classes | [app/config.py](ids_project/app/config.py) | ✅ |
| 9 | Database Models (15+ tables) | [app/models/](ids_project/app/models/) | ✅ |
| 10 | Alembic Migrations | [migrations/](ids_project/migrations/) | ✅ |
| 11 | Flask Extensions Setup | [app/extensions.py](ids_project/app/extensions.py) | ✅ |
| 12 | Logging Framework | [app/core/](ids_project/app/core/) | ✅ |
| 13 | Docker Compose Environment | [docker/docker-compose.yml](ids_project/docker/docker-compose.yml) | ✅ |
| 14 | Dockerfile | [docker/Dockerfile](ids_project/docker/Dockerfile) | ✅ |
| 15 | `.env.example` Template | [.env.example](ids_project/.env.example) | ✅ |
| 16 | `.gitignore` | [.gitignore](ids_project/.gitignore) | ✅ |
| 17 | `requirements.txt` | [requirements.txt](ids_project/requirements.txt) | ✅ |
| 18 | Application Entry Point | [run.py](ids_project/run.py) | ✅ |

---

## Week 1 Success Criteria — All Met ✅

- [x] All 15 modules accounted for in architecture
- [x] Data flow covers complete packet-to-alert pipeline
- [x] 10+ STRIDE threats identified with mitigations
- [x] Architecture reviewed and self-review checklist completed
- [x] `flask db upgrade` runs without errors
- [x] All models can be instantiated and saved
- [x] Logging produces structured JSON output
- [x] Docker Compose brings up application and database

---

## Next: Week 2 — Packet Monitoring Engine

The next phase builds the core packet capture engine:
- Scapy sniffer with dedicated capture thread and ring buffer queue
- PyShark application-layer capture (HTTP, DNS, FTP)
- Protocol parser (TCP/UDP/ICMP/HTTP/DNS/SSH/FTP)
- Batch insert manager (500ms flush, 10k pps capacity)
- Live traffic metrics API endpoints

---

*Week 1 completed — 8-week Network IDS project.*
