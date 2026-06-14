# System Architecture Design

> **Network Traffic Monitoring & Attack Detection System**
> Version 1.0 | Phase 1 — Milestone 1.2

---

## 1. Architectural Decision: Modular Monolith

**Decision:** Modular monolith with clear package boundaries, Docker-ready for future service extraction.

**Rationale:**
- Microservices add network latency between detection modules — unacceptable for a system requiring <2 second detection latency
- A monolith allows direct function calls between modules (nanoseconds vs milliseconds)
- Clear package boundaries (Flask Blueprints + Python packages) enable future extraction to microservices if horizontal scaling is needed
- Single deployment unit simplifies operations for security-critical infrastructure
- Docker Compose provides container isolation benefits without service mesh complexity

---

## 2. Five-Layer Architecture

The system is organized into 5 architectural layers, each with clearly defined responsibilities and interfaces.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PRESENTATION LAYER                              │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │          NGINX (SSL Termination, Static Files, Rate Limiting)   │   │
│   └──────────────────────────┬──────────────────────────────────────┘   │
│                              │                                          │
│   ┌──────────────────────────▼──────────────────────────────────────┐   │
│   │              FLASK APPLICATION (Gunicorn WSGI)                  │   │
│   │                                                                 │   │
│   │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐ │   │
│   │  │ Dashboard  │  │  REST API  │  │ Auth/RBAC  │  │WebSocket │ │   │
│   │  │  (Jinja2)  │  │  (/api/v1) │  │ (Login/JWT)│  │(SocketIO)│ │   │
│   │  └────────────┘  └────────────┘  └────────────┘  └──────────┘ │   │
│   └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                    Internal Python function calls
                                │
┌─────────────────────────────────────────────────────────────────────────┐
│                          DETECTION LAYER                                │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                   DETECTION ORCHESTRATOR                        │   │
│   │          Dispatches packets to all detectors in parallel         │   │
│   │                                                                 │   │
│   │  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌───────────┐  │   │
│   │  │ Port Scan  │  │Brute Force │  │   DDoS   │  │  Traffic  │  │   │
│   │  │ Detector   │  │ Detector   │  │ Detector │  │  Pattern  │  │   │
│   │  │            │  │            │  │          │  │  Analyzer │  │   │
│   │  │ Module 4   │  │ Module 5   │  │ Module 6 │  │ Module 7  │  │   │
│   │  └────────────┘  └────────────┘  └──────────┘  └───────────┘  │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                   ATTACK STATE MANAGER                          │   │
│   │     In-memory tracking of active attacks with DB persistence    │   │
│   └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                    AttackEvent objects passed down
                                │
┌─────────────────────────────────────────────────────────────────────────┐
│                        INTELLIGENCE LAYER                               │
│                                                                         │
│   ┌────────────────────────┐       ┌────────────────────────────────┐   │
│   │   ML ANOMALY ENGINE    │       │    IP REPUTATION ENGINE        │   │
│   │                        │       │                                │   │
│   │  Feature Extractor     │       │  AbuseIPDB Adapter             │   │
│   │  Isolation Forest      │       │  Local Blacklist Checker       │   │
│   │  Model Manager         │       │  External Feed Importer        │   │
│   │  Drift Detector        │       │  Reputation Cache (24h TTL)    │   │
│   │                        │       │                                │   │
│   │  Module 8              │       │  Module 9                      │   │
│   └────────────────────────┘       └────────────────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                   THREAT SCORING ENGINE                         │   │
│   │                                                                 │   │
│   │  Base Score (attack type) + Rate Modifier + Duration Modifier   │   │
│   │  + Recurrence + IP Reputation Modifier + ML Confidence          │   │
│   │  + Blacklist/Whitelist Override                                  │   │
│   │  → Final Score (0–100) → Severity (LOW/MEDIUM/HIGH/CRITICAL)   │   │
│   │                                                                 │   │
│   │  Module 10                                                      │   │
│   └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                    Scored ThreatEvents dispatched
                                │
┌─────────────────────────────────────────────────────────────────────────┐
│                         RESPONSE LAYER                                  │
│                                                                         │
│   ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐   │
│   │   ALERT MANAGER  │  │  EMAIL NOTIFIER  │  │   IP BLOCKER       │   │
│   │                  │  │                  │  │                    │   │
│   │  Alert CRUD      │  │  SMTP Queue      │  │  iptables Manager  │   │
│   │  WebSocket Push  │  │  HTML Templates   │  │  Temporary Blocks  │   │
│   │  Lifecycle Mgmt  │  │  Retry + Backoff  │  │  Auto-Expiry       │   │
│   │  Aggregation     │  │  Throttling       │  │  Whitelist Guard   │   │
│   │                  │  │                  │  │                    │   │
│   │  Module 11       │  │  Module 12       │  │  Module 13         │   │
│   └──────────────────┘  └──────────────────┘  └────────────────────┘   │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │              BLACKLIST / WHITELIST MANAGER                       │   │
│   │   Bulk import/export, external feed sync, iptables integration  │   │
│   └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                    Protection rules applied to
                                │
┌─────────────────────────────────────────────────────────────────────────┐
│                          CAPTURE LAYER                                  │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                  PACKET CAPTURE ENGINE                          │   │
│   │                                                                 │   │
│   │  ┌──────────────────┐          ┌────────────────────────────┐  │   │
│   │  │  Scapy Sniffer   │          │  PyShark App-Layer Capture │  │   │
│   │  │  (Layer 2–4)     │          │  (HTTP, DNS, FTP headers)  │  │   │
│   │  │  Dedicated thread │          │  Async coroutine           │  │   │
│   │  └────────┬─────────┘          └──────────────┬─────────────┘  │   │
│   │           │                                    │                │   │
│   │           └─────────────┬──────────────────────┘                │   │
│   │                         ▼                                       │   │
│   │          ┌──────────────────────────────┐                      │   │
│   │          │  Thread-Safe Queue (10,000)  │                      │   │
│   │          └──────────────┬───────────────┘                      │   │
│   │                         ▼                                       │   │
│   │  ┌──────────────────────────────────────────────────────────┐  │   │
│   │  │           PACKET PROCESSING WORKER POOL (4 threads)      │  │   │
│   │  │                                                          │  │   │
│   │  │  Protocol Identifier → TCP Flag Parser → Feature Extract │  │   │
│   │  │  → IP Geolocation Enrichment → Flow Tracker Update       │  │   │
│   │  └──────────────────────────────────────────────────────────┘  │   │
│   │                         │                                       │   │
│   │                         ▼                                       │   │
│   │  ┌──────────────────────────────────────────────────────────┐  │   │
│   │  │           BATCH INSERT MANAGER                           │  │   │
│   │  │  Flush every 500ms OR 500 packets → PostgreSQL           │  │   │
│   │  │  Write-ahead buffer (50k packets if DB unavailable)      │  │   │
│   │  └──────────────────────────────────────────────────────────┘  │   │
│   │                                                                 │   │
│   │  Module 1 (Capture) + Module 2 (Protocol) + Module 3 (Flow)   │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│                      Network Interface (eth0)                           │
└─────────────────────────────────────────────────────────────────────────┘
                                │
                    All data persisted to
                                │
┌─────────────────────────────────────────────────────────────────────────┐
│                           DATA LAYER                                    │
│                                                                         │
│   ┌──────────────────┐  ┌──────────────┐  ┌─────────────────────────┐  │
│   │   PostgreSQL 15  │  │    Redis     │  │     File Storage        │  │
│   │                  │  │              │  │                         │  │
│   │  15+ tables      │  │  Cache       │  │  ML model files (.pkl)  │  │
│   │  Partitioned     │  │  Session     │  │  Generated reports      │  │
│   │  Indexed         │  │  Rate limits │  │  Archived packet logs   │  │
│   │  Connection pool │  │  Pub/sub     │  │  Backup files           │  │
│   └──────────────────┘  └──────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module-to-Layer Mapping

| Layer | Module # | Module Name | Package |
|-------|---------|-------------|---------|
| Capture | 1 | Packet Capture Engine | `app/capture/` |
| Capture | 2 | Protocol Analyzer | `app/capture/` |
| Capture | 3 | Flow Tracker | `app/capture/` |
| Detection | 4 | Port Scan Detector | `app/detection/port_scan/` |
| Detection | 5 | Brute Force Detector | `app/detection/brute_force/` |
| Detection | 6 | DDoS Detector | `app/detection/ddos/` |
| Detection | 7 | Traffic Pattern Analyzer | `app/detection/traffic_analysis/` |
| Intelligence | 8 | ML Anomaly Detector | `app/ml/` |
| Intelligence | 9 | IP Reputation Engine | `app/intelligence/` |
| Scoring/Response | 10 | Threat Scoring Engine | `app/scoring/` |
| Response | 11 | Alert Manager | `app/alerts/` |
| Response | 12 | Email Notification System | `app/notifications/` |
| Response | 13 | IP Blocking Engine | `app/protection/` |
| Presentation | 14 | REST API | `app/api/v1/` |
| Presentation | 15 | Web Dashboard | `app/dashboard/`, `app/auth/` |

---

## 4. Inter-Layer Communication

| From → To | Communication Method | Rationale |
|-----------|---------------------|-----------|
| Capture → Detection | Thread-safe `queue.Queue` | Decouples capture speed from detection processing |
| Detection → Intelligence | Direct Python function calls | Same process; minimal latency required |
| Intelligence → Scoring | Direct Python function calls | Scoring must be synchronous with detection |
| Scoring → Response | `queue.PriorityQueue` | Prioritizes CRITICAL alerts for immediate processing |
| Response → Presentation | Flask-SocketIO emit (WebSocket) | Real-time dashboard updates |
| Presentation → All | Flask REST API (HTTP) | Dashboard queries all layers via API endpoints |
| All → Data Layer | SQLAlchemy ORM | Unified database access with connection pooling |
| All → Data Layer (cache) | Redis client | Fast reads for dashboard stats, reputation cache |

---

## 5. Packet Processing Pipeline

```
                    ┌──────────────────────┐
                    │   NETWORK INTERFACE   │
                    │       (eth0)          │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
              ┌─────│     1. CAPTURE       │
              │     │   Scapy sniff()      │
              │     │   Dedicated thread    │
              │     │   BPF filter applied  │
              │     └──────────┬───────────┘
              │                │ Raw packets
              │     ┌──────────▼───────────┐
              │     │      2. PARSE        │
              │     │   Protocol identify  │
              │     │   Header extraction  │
              │     │   Flag parsing       │
              │     └──────────┬───────────┘
              │                │ Parsed PacketEvent
     PyShark  │     ┌──────────▼───────────┐
     merges ──┘     │     3. ENRICH        │
      here          │   Geolocation lookup │
                    │   Flow assignment    │
                    │   Feature extraction │
                    └──────────┬───────────┘
                               │ Enriched PacketEvent
                    ┌──────────▼───────────┐
                    │     4. DETECT        │
                    │   All detectors run  │
                    │   in parallel        │
                    │   (thread pool)      │
                    └──────────┬───────────┘
                               │ AttackEvent (if detected)
                    ┌──────────▼───────────┐
                    │     5. SCORE         │
                    │   Threat scoring     │
                    │   Severity classify  │
                    │   Response decision  │
                    └──────────┬───────────┘
                               │ Scored ThreatEvent
                    ┌──────────▼───────────┐
                    │     6. RESPOND       │
                    │   Create alert       │
                    │   Send email         │
                    │   Block IP           │
                    │   WebSocket push     │
                    └──────────────────────┘
```

**Pipeline Performance Targets:**
- Stage 1→2: <100 µs per packet
- Stage 2→3: <200 µs per packet
- Stage 3→4: <500 µs per packet
- Stage 4→5: <1 second (aggregate)
- Stage 5→6: <200 ms per event
- **End-to-end:** <2 seconds from capture to alert

---

## 6. Data Architecture

### 6.1 Hot / Warm / Cold Storage Strategy

| Tier | Data Age | Storage | Access Pattern |
|------|----------|---------|---------------|
| **Hot** | Last 24 hours | PostgreSQL (unlogged tables for stats) + Redis cache | Real-time dashboard queries, detection state |
| **Warm** | 1–30 days | PostgreSQL (standard tables, indexed, partitioned) | Search, investigation, report generation |
| **Cold** | 30+ days | Compressed CSV archives on disk | Forensic analysis, compliance, rare access |

### 6.2 Partitioning Strategy

**packet_logs table** (highest volume):
- Partitioned by RANGE on `captured_at` (monthly partitions)
- Partition naming: `packet_logs_2024_01`, `packet_logs_2024_02`, etc.
- Next month's partition created proactively on the 25th
- Old partitions archived and dropped after 30 days

**system_stats table** (time-series):
- Partitioned by RANGE on `recorded_at` (monthly)
- 90-day retention

### 6.3 Indexing Strategy

| Table | Index | Type | Purpose |
|-------|-------|------|---------|
| packet_logs | (src_ip, captured_at) | B-tree | Source IP search with time range |
| packet_logs | (dst_ip, captured_at) | B-tree | Destination IP search with time range |
| packet_logs | (protocol, captured_at) | B-tree | Protocol filter with time range |
| packet_logs | (src_port, dst_port) | B-tree | Port-based search |
| attack_events | (source_ip, first_seen) | B-tree | Attack history per IP |
| attack_events | (attack_type, status) | B-tree | Active attacks by type |
| alerts | (severity, status, created_at) | B-tree | Alert triage queries |
| audit_logs | (user_id, created_at) | B-tree | User activity audit |
| ip_reputation | (ip_address) | Primary key | Reputation lookups |

---

## 7. API Architecture

### 7.1 API Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Versioning** | URL path versioning: `/api/v1/` |
| **Authentication** | JWT Bearer token for API; Flask-Login session for dashboard |
| **Content type** | JSON request/response; `Content-Type: application/json` |
| **Error format** | `{"error": "error_type", "message": "human-readable", "details": {...}}` |
| **Pagination** | Cursor-based for large datasets; offset-based for small |
| **Rate limiting** | Per-user token bucket; different limits per endpoint category |
| **CORS** | Disabled by default; configurable for known dashboard origins |

### 7.2 API Resource Groups

| Group | Prefix | Endpoints | Blueprint |
|-------|--------|-----------|-----------|
| Authentication | `/auth/` | 5 | `auth_bp` |
| Packets | `/api/v1/packets/` | 4 | `packets_bp` |
| Capture | `/api/v1/capture/` | 3 | `capture_bp` |
| Attacks | `/api/v1/attacks/` | 5 | `attacks_bp` |
| Reputation | `/api/v1/reputation/` | 3 | `reputation_bp` |
| ML | `/api/v1/ml/` | 2 | `ml_bp` |
| Threats | `/api/v1/threats/` | 3 | `threats_bp` |
| Alerts | `/api/v1/alerts/` | 6 | `alerts_bp` |
| Blocks | `/api/v1/blocks/` | 3 | `blocks_bp` |
| Blacklist | `/api/v1/blacklist/` | 4 | `blacklist_bp` |
| Whitelist | `/api/v1/whitelist/` | 3 | `whitelist_bp` |
| Search | `/api/v1/search/` | 4 | `search_bp` |
| Investigation | `/api/v1/investigation/` | 3 | `investigation_bp` |
| Reports | `/api/v1/reports/` | 3 | `reports_bp` |
| Users | `/api/v1/users/` | 4 | `users_bp` |
| Config | `/api/v1/config/` | 2 | `config_bp` |
| Audit | `/api/v1/audit/` | 1 | `audit_bp` |
| System | `/api/v1/system/` | 2 | `system_bp` |
| Notifications | `/api/v1/notifications/` | 1 | `notifications_bp` |

### 7.3 Real-Time Channel (WebSocket)

| Namespace | Events | Direction | Purpose |
|-----------|--------|-----------|---------|
| `/alerts` | `new_alert`, `alert_updated`, `ip_blocked` | Server→Client | Live alert feed |
| `/packets` | `packet_event`, `traffic_stats` | Server→Client | Live traffic monitor |

**WebSocket authentication:** JWT token verified during `connect` event; unauthorized connections rejected.

---

## 8. Deployment Architecture

```
┌─────────────────────────────────────────────────────┐
│                   HOST MACHINE                       │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │              Docker Compose                    │  │
│  │                                               │  │
│  │  ┌──────────┐   ┌───────────────────────────┐ │  │
│  │  │  NGINX   │──▶│  FLASK APP (Gunicorn)     │ │  │
│  │  │ :80/:443 │   │  Worker 1 │ Worker 2      │ │  │
│  │  └──────────┘   └───────────┬───────────────┘ │  │
│  │                              │                 │  │
│  │  ┌──────────────────────────┐│ ┌─────────────┐│  │
│  │  │   PACKET CAPTURE         ││ │    REDIS    ││  │
│  │  │   (privileged container) ││ │   :6379     ││  │
│  │  │   CAP_NET_RAW            │▼ └─────────────┘│  │
│  │  └──────────────────────────┘                  │  │
│  │                              │                 │  │
│  │  ┌──────────────────────────┐                  │  │
│  │  │     POSTGRESQL 15        │                  │  │
│  │  │     :5432                │                  │  │
│  │  │     Named volume         │                  │  │
│  │  └──────────────────────────┘                  │  │
│  │                                               │  │
│  │  ┌──────────────────────────┐ (dev only)      │  │
│  │  │     MAILHOG              │                  │  │
│  │  │     :1025 (SMTP)         │                  │  │
│  │  │     :8025 (Web UI)       │                  │  │
│  │  └──────────────────────────┘                  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**Container Security:**
- Flask app and Nginx run as non-root user
- Packet capture container has `CAP_NET_RAW` capability only — no other elevated privileges
- PostgreSQL data on named volume — persists across container restarts
- Only Nginx port exposed to host network; all other containers on internal Docker network

---

## 9. Technology Justifications

| Technology | Alternative Considered | Reason for Selection |
|-----------|----------------------|---------------------|
| **Flask** | Django, FastAPI | Lightweight; better suited for modular monolith with Blueprints; extensive SocketIO support |
| **PostgreSQL** | MySQL, MongoDB | INET type for IP addresses; JSONB for flexible evidence storage; table partitioning; array types for port lists |
| **Scapy** | Raw sockets, tcpdump | Python-native packet manipulation; rich protocol dissection; programmatic filter building |
| **PyShark** | Pure Scapy | Superior application-layer (Layer 7) parsing via tshark; better HTTP/DNS header extraction |
| **Isolation Forest** | Autoencoder, OneClassSVM | Best performance on tabular network flow data; fast training; interpretable anomaly scores |
| **Redis** | Memcached | Pub/sub for WebSocket scaling; sorted sets for sliding windows; richer data structures |
| **SQLAlchemy** | Raw SQL, Peewee | Enterprise ORM; migration support via Alembic; relationship management; query builder |
| **Docker Compose** | Kubernetes, bare metal | Right-sized for single-host deployment; simple configuration; reproducible environments |
| **Chart.js** | D3.js, Plotly | Lightweight; built-in time-series support; simple API for real-time updates |
