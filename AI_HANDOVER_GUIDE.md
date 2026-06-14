# AI Handover Guide: Network Traffic Monitoring & Attack Detection System

> **Instruction for the AI Assistant:** 
> This project has completed all **Phases 1 through 12** of development. This document serves as the complete technical specification, architectural review, and file directory of the finished platform. Use this guide to understand the system components, file locations, database structures, APIs, and deployment configurations for ongoing maintenance, auditing, or future enhancements.

---

## 1. Project Overview & Tech Stack

This platform is a fully functional, enterprise-grade Network Intrusion Detection & Prevention System (IDS/IPS) capable of:
*   **Real-time packet sniffing** (10,000+ packets/second) with thread-safe queue buffering and batch inserts.
*   **Multi-vector attack detection** (Port Scans, Brute Force, DDoS, Traffic Spikes) running in parallel detection pipelines.
*   **Machine learning anomaly detection** using an Isolation Forest model with drift detection and model version management.
*   **Threat intelligence integration** caching AbuseIPDB v2 reputations and syncing custom feed blacklists.
*   **Calibrated threat scoring (0–100)** mapping to severity levels (LOW, MEDIUM, HIGH, CRITICAL).
*   **Automated active protection** using `iptables` rules to block malicious IPs for CRITICAL alerts, with Whitelist guards.
*   **Real-time alert center** utilizing WebSockets to stream alerts and manage alert triage lifecycles.
*   **Search & investigation tools** supporting cursor-paginated packet searches, TCP flow reconstruction, and PDF report downloads.
*   **Web-based security dashboard** displaying live traffic graphs, system performance, alert triage interfaces, and administrator controls.

### Technical Stack
*   **Backend:** Python 3.11+, Flask 3.x, SQLAlchemy 2.x ORM, APScheduler (for cron tasks), Flask-SocketIO (for real-time streaming).
*   **Database:** PostgreSQL 15+ (with partitioning on `packet_logs` and JSONB support for machine learning features).
*   **Cache & Rate Limiting:** Redis (used for query caching, Flask-Limiter backends, and dashboard counters).
*   **Packet Processing:** Scapy (Layer 2-4 sniffing) and PyShark (Layer 7 deep packet parsing).
*   **Machine Learning:** Scikit-Learn, NumPy, Pandas, Joblib.
*   **Frontend:** HTML5, Vanilla CSS (harmonious dark theme, glassmorphism), JavaScript (ES6), Chart.js, Socket.io (WebSocket client).
*   **Deployment:** Docker Compose, Gunicorn, Nginx (reverse proxy, SSL termination, static file server).

---

## 2. Directory & File Structure

The project code is located in the [ids_project/](file:///d:/Projects/Network-Traffic-Monitoring-and-Attack-Detection/ids_project/) subdirectory. Here is the structure of the completed active code repository:

```
ids_project/
├── app/                        # Main application package
│   ├── __init__.py             # Flask app factory, blueprint registration, pipeline wiring
│   ├── config.py               # Settings, DB URIs, API keys, thresholds
│   ├── extensions.py           # Instantiated Flask extensions (SQLAlchemy, Migrate, SocketIO, etc.)
│   ├── models/                 # SQLAlchemy Database Models
│   │   ├── __init__.py         # Imports and exposes all models
│   │   ├── auth.py             # User, Session
│   │   ├── capture.py          # PacketLog, ProtocolStats, SystemStats
│   │   ├── detection.py        # AttackEvent, PortScanDetails, BruteForceDetails, DdosDetails
│   │   ├── ml.py               # MlFeatureVector, MlModelVersion, MlPrediction
│   │   ├── intelligence.py     # IpReputation, Blacklist, Whitelist, AuditLog
│   │   └── scoring.py          # ThreatScore, Alert, AlertComment, EmailNotification, IpBlock
│   ├── core/                   # Shared utilities (DB connection, logging, caching)
│   │   ├── cache.py            # Redis client interface & cache operations
│   │   ├── logging_config.py   # Global logging setup
│   │   └── rate_limiter.py     # Flask-Limiter configuration
│   ├── capture/                # Packet sniffer, flow parsing, batch writing
│   │   ├── sniffer.py          # Background packet sniffer thread
│   │   ├── parser.py           # Protocol headers extractor
│   │   └── writer.py           # Batch database inserter
│   ├── detection/              # Rule-based attack detection engines & orchestrator
│   │   ├── orchestrator.py     # Executes detectors in parallel threads
│   │   ├── port_scan/          # Port scan detection logic
│   │   ├── brute_force/        # Login brute force detection logic
│   │   └── traffic_analysis/   # DDoS and traffic spike detection
│   ├── ml/                     # ML pipeline (feature extraction, training, inference, manager)
│   │   ├── feature_extractor.py # Converts packets to 25-feature flow vectors
│   │   ├── feature_store.py    # Database interfaces for ML data
│   │   ├── trainer.py          # Trains Isolation Forest model
│   │   ├── inference.py        # Runs anomaly predictions
│   │   ├── model_manager.py    # Model versioning, rollback, and cleanup
│   │   └── drift_detector.py   # Checks concept drift using z-score shifts
│   ├── intelligence/           # IP reputation lookups, AbuseIPDB integration, feeds
│   │   ├── abuseipdb.py        # AbuseIPDB API client
│   │   ├── cache_manager.py    # Manages database IP reputation cache
│   │   └── feed_importer.py    # External blacklists downloader
│   ├── scoring/                # Threat scoring, severity classification, modifiers, response engine
│   │   ├── threat_scorer.py    # Computes final score (0-100) and persists
│   │   ├── modifiers.py        # Calculations for rate, duration, ML, reputation modifiers
│   │   ├── severity_classifier.py # Severity bands (LOW, MEDIUM, HIGH, CRITICAL)
│   │   ├── score_explanation.py # Generates human-readable breakdown text
│   │   ├── alert_priority.py   # Priority queue dispatcher wrapper
│   │   └── response_engine.py  # Coordinates auto-responses and runs decay logic
│   ├── alerts/                 # Real-time WebSockets & alert triage
│   │   ├── manager.py          # CRUD lifecycle actions (Acknowledge, Assign, Comment)
│   │   ├── streamer.py         # Broadcasts alerts via SocketIO
│   │   └── aggregator.py       # Groups alerts into campaigns
│   ├── notifications/          # Email notification services
│   │   ├── email_queue.py      # Background worker polling queued emails
│   │   └── email_sender.py     # SMTP connection and sending logic
│   ├── protection/             # Firewall blocking (iptables), blacklist/whitelist sync
│   │   ├── ip_blocker.py       # Executes iptables rule adjustments
│   │   └── list_manager.py     # Blacklist/whitelist CSV import/exports
│   ├── search/                 # Packet log search with cursor pagination
│   │   └── packet_search.py    # Query builder and fast index filters
│   ├── investigation/          # Incident timelines and TCP flow reconstruction
│   │   ├── timeline.py         # Constructs interactive attack event sequences
│   │   ├── ip_investigator.py  # Profiles target/source IPs
│   │   └── flow_reconstructor.py # Bidirectional TCP flow packet assembler
│   ├── reports/                # ReportLab PDF & CSV generators
│   │   ├── pdf_generator.py    # ReportLab PDF design and chart builder
│   │   └── csv_exporter.py     # Streaming CSV row downloader
│   ├── auth/                   # Users, session control, TOTP 2FA, RBAC
│   │   ├── routes.py           # Auth endpoints (Login, Logout, 2FA setup)
│   │   ├── rbac.py             # Role authorization decorators
│   │   └── token_manager.py    # JWT and Refresh Token operations
│   ├── dashboard/              # Flask web page blueprints
│   │   └── routes.py           # UI page controllers
│   ├── middleware/             # HTTP security and schema validators
│   │   ├── security_headers.py # Inject CSP, HSTS, X-Frame headers
│   │   └── request_validator.py # Marshmallow/Pydantic schemas
│   ├── static/                 # Styles, client-side JS scripts
│   │   ├── css/
│   │   │   └── styles.css      # Custom dark-theme stylesheet
│   │   └── js/
│   │       └── app.js          # Chart.js and Socket.io dashboard logic
│   └── templates/              # Jinja2 HTML views
│       ├── base.html           # Main UI container
│       ├── login.html          # Login and TOTP template
│       ├── dashboard.html      # Real-time dashboard view
│       ├── alerts.html         # Alert center interface
│       ├── search.html         # Packet logs lookup
│       ├── investigation.html  # Forensic analysis tool
│       ├── reports.html        # PDF/CSV download page
│       └── settings.html       # System settings panel
│   └── api/v1/                 # REST API controllers
│       ├── health.py           # Health metrics endpoint
│       ├── packets.py          # Sniffer control endpoints
│       ├── attacks.py          # Attacks listing endpoints
│       ├── reputation.py       # IP threat intel endpoints
│       ├── ml.py               # ML status and training triggers
│       ├── threats.py          # Threat scoring details
│       ├── alerts.py           # Alert management endpoints
│       └── blocks.py           # Firewall management endpoints
├── migrations/                 # Alembic DB migration versions
├── tests/                      # Pytest unit, integration, and simulation tests
│   ├── conftest.py             # Shared fixtures (DB, App contexts)
│   ├── unit/                   # Component isolation tests
│   ├── integration/            # Multi-layer pipelines tests
│   └── simulation/             # Attack generation scripts
├── docker/                     # Nginx configurations, Dockerfiles
│   ├── Dockerfile              # Multi-stage image build file
│   ├── docker-compose.prod.yml # Production service orchestration
│   └── nginx/
│       └── nginx.conf          # Nginx rate-limiting & SSL config
├── requirements.txt            # Production dependencies
└── requirements-dev.txt        # Linting, testing, formatting tools
```

---

## 3. Database Schema Overview

```
users (1) ──────────────────── (*) sessions
  │                                     
  ├──────────── (*) alerts              
  │               │                     
  │               └──── (*) alert_comments
  │                                    
  ├──────────── (*) audit_logs         
  │                                    
  ├──────────── (*) ip_blocks          
  │                                    
  ├──────────── (*) blacklist          
  │                                    
  └──────────── (*) whitelist          
                                       
attack_events (1) ──────────── (1) port_scan_details
      │ ──────────────────────── (1) brute_force_details
      │ ──────────────────────── (1) ddos_details
      │                                   
      ├──────────── (1) threat_scores     
      │                   │               
      │                   └──── (1) alerts
      │                                   
      └──────────── (*) ml_predictions   
                                       
packet_logs (*) ── [partitioned by month]
ip_reputation (standalone, keyed by IP)
protocol_stats (standalone, time-series)
system_stats (standalone, time-series)
email_notifications (*) → (1) alerts
```

---

## 4. Completed Phases (Phases 1–12)

### Phase 1: Planning & System Architecture ✅
*   Functional/non-functional requirements defined (10,000 pps ceiling, <2s alert latency).
*   Role-Based Access Control (Viewer, Analyst, Admin) permission matrix designed.
*   Threat model (STRIDE analysis) completed for packet processing, database, APIs, and firewall boundaries.

### Phase 2: Development Environment & DB Setup ✅
*   Flask application factory structure initialized.
*   SQLAlchemy models configured with PostgreSQL schema definitions (JSONB columns for ML metrics, indexes on high-query fields).
*   Database migrations set up using Alembic.

### Phase 3: Packet Monitoring Engine ✅
*   Thread-safe background packet sniffer using Scapy.
*   Internal thread-safe queue holding up to 10,000 packets.
*   Batch writer persisting packets in blocks of 500 or at 500ms intervals.
*   Layer 2-4 parser extracting protocol, IP headers, port distributions, and payload sizes.

### Phase 4: Core Attack Detection Engine ✅
*   Parallel thread execution model (Detection Orchestrator) running rule-based modules:
    *   **Port Scan Detector:** Detects fast scans (>15 ports in 10s), stealth scans (FIN, NULL, Xmas), and UDP scans.
    *   **Brute Force Detector:** Identifies excessive failures on SSH (port 22) and HTTP login forms (port 80/443).
    *   **DDoS Detector:** Triggers on volumetric traffic spikes (>1000 pps to a single destination IP).
    *   **Traffic Spike Detector:** Compares volume against rolling 5-minute sliding baselines.

### Phase 5: Machine Learning & Threat Intelligence ✅
*   **ML Pipeline:** Extractor computes 25 flow features. `StandardScaler` + `IsolationForest` model classifies packet vectors as normal or anomalous. Includes z-score concept drift detection (>2σ shift in feature distribution) and a model version manager storing up to 3 versions.
*   **Threat Intel:** Integrates AbuseIPDB v2 API with 24-hour cache caching. Automatically imports Emerging Threats, Spamhaus DROP, and Feodo blacklists. IP reputations calculated dynamically.

### Phase 6: Threat Scoring & Response Engine ✅
*   **Scoring Algorithm:** Computes 0–100 threat scores using base scores modified by rate, duration, recurrence, IP reputation, ML flags, blacklist matching, whitelists (forcing score 0), and critical asset status (+10 modifier).
*   **Alert Priority Queue:** Wraps `queue.PriorityQueue` to handle scored alerts in min-heap priority (`100 - threat_score`).
*   **Response Engine:** Executes responses based on severity classifications:
    *   `Score >= 75` (CRITICAL) → Creates alert, triggers automatic IP block, queues urgent email.
    *   `Score 50-74` (HIGH) → Creates alert, queues standard email.
    *   `Score 25-49` (MEDIUM) → Creates alert only.
    *   `Score < 25` (LOW) → Logs locally (no DB alert created, minimizing alert noise).
*   **Score Decay Daemon:** APScheduler job running every 30 mins, decaying score by $0.9^{\text{hours}}$ for inactive attacks. Transitions attacks to `MONITORING` when score drops below 25.

### Phase 7: Alerting & Protection System ✅
*   **Real-time Streamer:** Broadcasting to WebSocket namespace `/alerts` on event `new_alert` using `Flask-SocketIO`.
*   **Alert Manager:** Updates alert statuses: `NEW` ➔ `ACKNOWLEDGED` ➔ `INVESTIGATING` ➔ `RESOLVED` / `FALSE_POSITIVE` with state validation. Campaigns aggregate repeating alerts from the same IP.
*   **Email Queue & SMTP Sender:** `email_notifications` queue worker sending TLS-encrypted SMTP messages with exponential retry backoff (5m, 25m, 2h) capped at 10 emails/hour per analyst.
*   **IP Blocker:** Executes `iptables -I INPUT 1 -s {ip} -j DROP` securely without `shell=True`. Never blocks `127.0.0.1`, local admin ranges, or whitelisted IPs. Active daemon cleans up expired blocks.
*   **List Managers:** CSV import/export endpoints for manually managing whitelists and blacklists.

### Phase 8: Search, Investigation & Reporting ✅
*   **Packet Search Engine:** Fast filtering by protocol, IP range (CIDR), port, packet size, and time. Employs cursor-based pagination (`WHERE id > {cursor} ORDER BY id LIMIT 50`) on monthly-partitioned tables.
*   **Investigation Tools:** reconstructs interactive sequences of packets that triggered alerts, profiles IP profiles (ASN, GeoIP, threat history), and features a TCP Flow Reconstructor that parses bidirectional streams to export as Wireshark PCAPs.
*   **Reports Generator:** Generate executive ReportLab PDFs featuring Matplotlib trends and severity ratios. Supports memory-safe CSV streaming (up to 1,000,000 rows) using Flask generators.

### Phase 9: Authentication & Dashboard ✅
*   **Auth System:** Account creations, Bcrypt (12 rounds) hashes, 15-minute lockouts after 5 failures, Google Authenticator-compatible TOTP 2FA (via `pyotp`), and 10 recovery backup keys. Issues JWTs (1h duration) and Refresh Tokens (7d).
*   **Role-Based Access Control (RBAC):** Restricts views/APIs via decorators `@require_permission`: `Viewer` (read-only), `Analyst` (alert triage), `Admin` (blocking configurations & system tuning).
*   **Dashboard UI:** Premium dark-themed web console. Designed with glassmorphism CSS components, interactive navigation, and a Chart.js streaming plot updating system statistics (PPS/BPS) and protocol distribution. Includes visual alert tables updating dynamically.

### Phase 10: System Integration & Testing ✅
*   **Pytest Suite:** Full testing coverage exceeding 80% on scoring modifiers, authentication sessions, and REST APIs.
*   **Integration Tests:** Validates capture-to-alert data flows, testing SocketIO streams, DB persistence, and email queueing.
*   **Simulation Suite:** Automated test scripts simulating Nmap scans and hping3 DDoS flood events. Validates zero-alert baseline under normal traffic simulations.

### Phase 11: Performance Optimization & Security Hardening ✅
*   **Redis Cache:** Caches IP reputations and user roles in Redis.
*   **Flask-Limiter:** Limits sensitive endpoints (login requests restricted to 5 per 15 minutes).
*   **Materialized Views:** Database dashboard counts cached and refreshed on a 5-minute schedule.
*   **Security Middleware:** Injects security headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`.
*   **Container Hardening:** Drop non-essential Linux privileges (retaining only `CAP_NET_RAW` for packet sniffing) and runs services under non-root system users.

### Phase 12: Deployment, Documentation & Future Enhancements ✅
*   **Production Stack:** Multi-stage Dockerfile builds to minimize image sizes. Orchestrated via `docker-compose.prod.yml` with Nginx reverse proxy routing traffic and terminating SSL.
*   **systemd Configurations:** Runs sniffer and web instances as auto-restarted OS services (`ids.service`).
*   **Backup Scripts:** Automated bash scripts performing weekly database snapshots and cleanup policies.
*   **API Documentation:** Exposed OpenAPI 3.0 schema specs (accessible via `/docs`).

---

## 5. Summary of API Endpoints

| Endpoint | Method | Role Required | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/auth/login` | POST | Anonymous | Authenticate credentials and request TOTP challenge |
| `/api/v1/auth/verify-2fa` | POST | Anonymous | Validate TOTP token and issue JWT / Refresh tokens |
| `/api/v1/capture/start` | POST | Admin | Start background Scapy sniffing thread |
| `/api/v1/capture/stop` | POST | Admin | Gracefully stop sniffing thread |
| `/api/v1/packets/search` | GET | Viewer | Search packet logs with cursor pagination |
| `/api/v1/threats/high-priority` | GET | Analyst | List active HIGH/CRITICAL threats |
| `/api/v1/threats/score/<attack_id>` | GET | Viewer | Fetch threat score breakdown and explanation |
| `/api/v1/alerts` | GET | Viewer | Fetch paginated alerts list with filters |
| `/api/v1/alerts/<alert_id>` | GET/PATCH | Analyst | Read alert details or update status / assignment |
| `/api/v1/alerts/<alert_id>/comment` | POST | Analyst | Add comment to alert |
| `/api/v1/protection/block` | POST | Admin | Manually block IP address |
| `/api/v1/protection/unblock` | POST | Admin | Manually release IP block |
| `/api/v1/reports/pdf` | GET | Analyst | Generate and download PDF security report |
| `/api/v1/reports/csv` | GET | Analyst | Stream CSV export of packet logs |

---

## 6. Crucial AI Coding Guidelines

Maintain these constraints during any code updates:
1.  **Strict Sanitization:** Command invocations must bypass shell parsing (`shell=False` in subprocess modules) and utilize parameterized database queries to avoid SQL and command injection.
2.  **No Wildcard Imports:** Keep Python imports clean. Reference specific objects and functions.
3.  **Preserve Comments:** Do not delete or modify existing code comments or docstrings that are unrelated to your edits.
4.  **No Tailwind:** Rely on vanilla CSS variables (using curated HSL dark mode palettes) for styling web interfaces. Avoid using utility frameworks unless explicitly requested.
