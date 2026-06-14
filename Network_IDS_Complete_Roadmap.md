# Network Traffic Monitoring & Attack Detection System
## Complete Development Roadmap — Senior-Level Implementation Guide

> **Stack:** Python · Flask · PostgreSQL · Scapy · PyShark · Scikit-Learn · HTML/CSS/JS · Docker
> **Duration:** 16 Weeks | **Difficulty:** Advanced | **Type:** Full-Stack Cybersecurity Platform

---

# TABLE OF CONTENTS

1. [Phase 1 — Project Planning & System Architecture](#phase-1)
2. [Phase 2 — Development Environment & Database Design](#phase-2)
3. [Phase 3 — Packet Monitoring Engine](#phase-3)
4. [Phase 4 — Core Attack Detection Engine](#phase-4)
5. [Phase 5 — Machine Learning & Threat Intelligence](#phase-5)
6. [Phase 6 — Threat Scoring & Response Engine](#phase-6)
7. [Phase 7 — Alerting & Protection System](#phase-7)
8. [Phase 8 — Search, Investigation & Reporting](#phase-8)
9. [Phase 9 — Authentication & Dashboard](#phase-9)
10. [Phase 10 — System Integration & Testing](#phase-10)
11. [Phase 11 — Performance Optimization & Security Hardening](#phase-11)
12. [Phase 12 — Deployment, Documentation & Future Enhancements](#phase-12)
13. [Complete System Architecture](#architecture)
14. [Database ER Diagram](#er-diagram)
15. [API Blueprint](#api-blueprint)
16. [Week-by-Week Timeline](#timeline)
17. [GitHub Repository Structure](#repo-structure)
18. [Resume-Worthy Features](#resume)
19. [Interview Questions & Answers](#interview)
20. [Industry-Level Future Enhancements](#future)

---

<a name="phase-1"></a>
# PHASE 1: Project Planning & System Architecture
**Duration:** Week 1 | **Complexity:** Medium

---

## Objective
Define the complete system blueprint before writing a single line of code. Establish architectural decisions, data flows, threat models, and technology justifications that will govern all subsequent phases.

## Why This Phase Is Necessary
Skipping architecture design is the #1 cause of project failure in security systems. An IDS built without a clear blueprint becomes unmaintainable, has performance bottlenecks at the packet capture layer, and introduces security gaps at module boundaries. This phase prevents costly rewrites later.

---

## Concepts to Learn Before Starting

- **OSI Model (Layers 1–7):** Understand how data travels through network layers. Packet monitoring operates at Layers 2–4; application-layer attacks operate at Layer 7.
- **TCP/IP Protocol Suite:** Deep understanding of TCP handshake, UDP connectionless behavior, ICMP messages, and how ports function.
- **Attack Taxonomy:** Understand the kill chain — reconnaissance (port scanning), credential attacks (brute force), volumetric attacks (DDoS), and behavioral anomalies.
- **IDS vs IPS Architecture:** Difference between passive detection (IDS) and active prevention (IPS). This project begins as IDS with IPS capabilities (auto-blocking).
- **Software Architecture Patterns:** Understand layered architecture, event-driven architecture, and microservice boundaries.
- **Data Flow Diagrams (DFD):** Learn to draw Level 0 and Level 1 DFDs to model how data moves between system components.
- **Threat Modeling (STRIDE):** Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.

---

## Technologies Used
- **Lucidchart / draw.io** — Architecture diagrams
- **Notion / Markdown** — Requirements documentation
- **OWASP Threat Dragon** — Threat modeling
- **Git** — Version control initialization

---

## Milestone 1.1: Requirements Analysis

### Tasks
1. **Define Functional Requirements**
   - List all 15 modules with input/output specifications
   - Define what constitutes a "detected attack" for each module
   - Specify alert thresholds (e.g., >20 port connections in 5 seconds = port scan)
   - Define report formats (PDF layout, CSV columns)
   - Specify email alert content structure

2. **Define Non-Functional Requirements**
   - Performance: System must process ≥10,000 packets/second without packet loss
   - Latency: Alert generation within 2 seconds of attack detection
   - Availability: 99.5% uptime for monitoring daemon
   - Storage: Packet logs retained for 30 days; attack records for 1 year
   - Scalability: Design for horizontal scaling of detection modules

3. **Define User Roles & Permissions Matrix**
   - Administrator: Full access — configure thresholds, manage users, view all data, block IPs
   - Security Analyst: Read/write — view alerts, run investigations, generate reports
   - Viewer: Read-only — view dashboard, alerts, and reports only
   - Document which API endpoints each role can access

4. **Define Attack Detection Thresholds**
   - Port Scan: >15 unique ports accessed from same IP within 10 seconds
   - Brute Force SSH: >5 failed auth attempts within 60 seconds
   - Brute Force HTTP: >10 failed login POST requests within 30 seconds
   - DDoS: >1,000 packets/second from distributed IPs targeting single destination
   - Traffic Spike: >300% increase from rolling 5-minute baseline

---

## Milestone 1.2: System Architecture Design

### Tasks
1. **Design High-Level Component Architecture**
   - Define 5 major system layers: Capture Layer, Processing Layer, Detection Layer, Intelligence Layer, Presentation Layer
   - Map each of the 15 modules to one of these layers
   - Define inter-layer communication protocols (internal REST, message queues, direct function calls)
   - Decide: monolithic vs modular architecture (recommendation: modular monolith with clear package boundaries, Docker-ready)

2. **Design Packet Processing Pipeline**
   - Capture → Parse → Enrich → Detect → Score → Alert
   - Define buffer sizes and queue depths between pipeline stages
   - Design for non-blocking I/O at capture stage
   - Plan packet sampling strategy for high-traffic environments (capture all packets under 5k/sec; sample 1-in-10 above threshold)

3. **Design Data Architecture**
   - Hot data (last 24 hours): In-memory + PostgreSQL with unlogged tables
   - Warm data (1–30 days): PostgreSQL with standard tables + indexing
   - Cold data (30+ days): Compressed CSV archives or TimescaleDB extension
   - Define data partitioning strategy for packet_logs table (partition by date)

4. **Design API Architecture**
   - Internal APIs: Python function calls between modules
   - External APIs: RESTful Flask endpoints for dashboard consumption
   - Real-time channel: WebSocket (Flask-SocketIO) for live alert streaming
   - Define API versioning strategy (/api/v1/)

5. **Create Architecture Diagrams**
   - Component diagram showing all 15 modules and their connections
   - Deployment diagram (single-host Docker Compose setup)
   - Sequence diagram for: packet capture → attack detection → alert generation

---

## Milestone 1.3: Data Flow Design

### Tasks
1. **Map Complete Data Flow**
   - Network Interface → Scapy/PyShark Capture → Packet Parser → PostgreSQL packet_logs
   - packet_logs → Detection Engine (parallel threads) → attack_events table
   - attack_events → Threat Scoring → scored_threats table
   - scored_threats → Alert Engine → alerts table + Email + WebSocket push
   - alerts → IP Blocking Module → system firewall rules

2. **Define Message/Event Schema**
   - PacketEvent schema: {src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp, payload_hash}
   - AttackEvent schema: {attack_type, source_ip, target_ip, target_port, severity, confidence_score, evidence}
   - AlertEvent schema: {alert_id, attack_event_id, threat_score, severity_level, status, created_at}

3. **Design Concurrency Model**
   - Packet capture: Dedicated thread (never blocked)
   - Detection modules: Thread pool (4–8 workers)
   - Database writes: Async batch inserts (flush every 500ms or 100 packets)
   - Alert dispatch: Separate thread with retry queue

---

## Milestone 1.4: Threat Modeling

### Tasks
1. **Apply STRIDE to Each System Component**
   - Dashboard Login: Spoofing (brute force on own login), Information Disclosure (session fixation)
   - Packet Capture: Tampering (packet injection by attacker to confuse IDS), Denial of Service (flood IDS itself)
   - Alert Email: Spoofing (email header injection if inputs unsanitized)
   - IP Blocking Module: Elevation of Privilege (attacker triggers blocking of legitimate IPs — IP spoofing to cause false blocks)
   - Database: Information Disclosure (SQL injection via search filters), Tampering (log deletion by insider)

2. **Define Attacker Profiles**
   - External attacker: Scans ports, attempts brute force, launches DDoS
   - Insider threat: Attempts to delete logs, access admin features as viewer
   - Evasion attacker: Deliberately slow port scan below threshold, tries to evade ML model

3. **Define Security Controls for Each Threat**
   - Input validation on all search/filter fields
   - Prepared statements for all DB queries
   - Rate limiting on dashboard login
   - Audit logging for all admin actions
   - IP whitelist cannot be empty (prevent locking out admin)

---

## Folder Structure After Phase 1
```
ids_project/
├── docs/
│   ├── architecture/
│   │   ├── component_diagram.png
│   │   ├── data_flow_diagram.png
│   │   └── deployment_diagram.png
│   ├── requirements/
│   │   ├── functional_requirements.md
│   │   ├── non_functional_requirements.md
│   │   └── permission_matrix.md
│   └── threat_model/
│       └── stride_analysis.md
├── .gitignore
└── README.md
```

## APIs Required
None — this is a planning phase.

## Testing Strategy
- Peer review of architecture diagrams with mentor/senior engineer
- Validate data flow covers all 15 modules with no orphaned components
- Confirm threat model addresses all STRIDE categories for top 5 critical components

## Security Considerations
- All architectural decisions must consider principle of least privilege
- No module should have direct network access except the Packet Capture module
- All external communications (email, threat intel API) must go through dedicated adapters

## Expected Deliverables
- Functional and non-functional requirements document
- System architecture diagrams (component, deployment, sequence)
- Data flow design document
- STRIDE threat model document
- Permission matrix for RBAC

## Estimated Timeline
- Days 1–2: Requirements gathering and documentation
- Days 3–4: Architecture design and diagramming
- Day 5: Data flow mapping
- Day 6–7: Threat modeling and review

## Success Criteria
- All 15 modules are accounted for in architecture
- Data flow covers complete packet-to-alert pipeline
- At least 10 STRIDE threats identified with mitigations
- Architecture reviewed and signed off (self-review checklist minimum)

---

<a name="phase-2"></a>
# PHASE 2: Development Environment & Database Design
**Duration:** Week 1–2 | **Complexity:** Medium | **Depends On:** Phase 1

---

## Objective
Build the project's technical foundation: directory structure, Flask application factory, PostgreSQL schema with all tables, migrations system, logging infrastructure, and Docker development environment. Every subsequent phase adds to this foundation.

## Why This Phase Is Necessary
A well-designed database schema that changes frequently forces expensive ALTER TABLE migrations that can corrupt data. Designing the complete schema now — informed by Phase 1's data flow design — prevents this. The Flask application factory pattern enables testing and prevents circular imports that plague large Flask projects.

---

## Concepts to Learn Before Starting

- **Flask Application Factory Pattern:** Using `create_app()` function instead of global app instance — enables multiple app instances for testing
- **Flask Blueprints:** Organizing routes into logical groups (auth, dashboard, api, alerts) with their own URL prefixes
- **SQLAlchemy ORM:** Define Python models that map to PostgreSQL tables; understand relationships (ForeignKey, relationship()), lazy vs eager loading
- **Alembic Database Migrations:** Version-control your schema; `alembic upgrade head` applies changes without data loss
- **PostgreSQL Advanced Features:** Indexes (B-tree, GIN), table partitioning by date range, JSONB columns for flexible schema, connection pooling with PgBouncer
- **Python Logging Module:** Hierarchical loggers, handlers (file, console, rotating), formatters, log levels
- **Docker Compose:** Define multi-container applications; understand volumes for data persistence, networks for container isolation
- **Environment Variables & .env:** Never hardcode secrets; use python-dotenv to load configuration

---

## Technologies Used
- Flask + Flask-SQLAlchemy + Flask-Migrate (Alembic)
- PostgreSQL 15+
- Python-dotenv
- Docker + Docker Compose
- Psycopg2-binary (PostgreSQL adapter)
- Flask-SocketIO (install now, use in Phase 9)

---

## Milestone 2.1: Project Structure Setup

### Tasks
1. **Initialize Python Virtual Environment**
   - Create virtual environment: `python -m venv venv`
   - Install core dependencies and pin versions in requirements.txt
   - Separate requirements files: requirements.txt (production), requirements-dev.txt (testing/dev tools)
   - Create .gitignore with Python, venv, .env, __pycache__ exclusions

2. **Create Application Directory Structure**
   - Design package structure around Flask Blueprint architecture
   - Each major system area (capture, detection, alerts, auth, api) gets its own package
   - Shared utilities (database models, helpers, config) in a core package
   - Tests mirror application structure in /tests directory

3. **Implement Flask Application Factory**
   - Create `app/__init__.py` with `create_app(config_name)` function
   - Load configuration from environment (development, testing, production)
   - Register all blueprints inside factory function
   - Initialize all Flask extensions (SQLAlchemy, Migrate, SocketIO, Login) inside factory

4. **Create Configuration Classes**
   - BaseConfig: Common settings (SECRET_KEY, SQLALCHEMY_TRACK_MODIFICATIONS=False)
   - DevelopmentConfig: DEBUG=True, verbose SQL logging
   - TestingConfig: In-memory SQLite or test PostgreSQL DB, TESTING=True
   - ProductionConfig: No debug, security headers, PostgreSQL URL from environment

---

## Milestone 2.2: PostgreSQL Schema Design

### Tasks
1. **Design Core Tables**

   **users** table:
   - id (UUID primary key), username (unique), email (unique), password_hash, role (enum: admin/analyst/viewer), is_active, created_at, last_login, failed_login_count, locked_until

   **sessions** table:
   - id (UUID), user_id (FK), token_hash, ip_address, user_agent, created_at, expires_at, is_active, revoked_at

2. **Design Packet Monitoring Tables**

   **packet_logs** table (HIGH VOLUME — design for performance):
   - id (BIGSERIAL), src_ip (INET), dst_ip (INET), src_port (INTEGER), dst_port (INTEGER), protocol (VARCHAR 10), packet_size (INTEGER), flags (VARCHAR 20), payload_hash (CHAR 64), captured_at (TIMESTAMPTZ)
   - Partition by RANGE on captured_at (monthly partitions)
   - Indexes: (src_ip, captured_at), (dst_ip, captured_at), (protocol, captured_at), (src_port, dst_port)

   **protocol_stats** table (aggregated, updated every minute):
   - id, protocol, packet_count, byte_count, unique_src_ips, unique_dst_ips, window_start, window_end

3. **Design Attack Detection Tables**

   **attack_events** table:
   - id (UUID), attack_type (enum: port_scan/brute_force/ddos/traffic_anomaly/ml_anomaly), source_ip (INET), target_ip (INET), target_port (INTEGER), evidence (JSONB — stores raw evidence details), confidence_score (FLOAT 0–1), packet_count (INTEGER), duration_seconds (INTEGER), first_seen (TIMESTAMPTZ), last_seen (TIMESTAMPTZ), status (enum: active/resolved/false_positive)

   **port_scan_details** table:
   - id, attack_event_id (FK), scanned_ports (INTEGER[]), scan_rate (FLOAT), scan_pattern (VARCHAR), technique (enum: syn/connect/udp/fin/xmas/null)

   **brute_force_details** table:
   - id, attack_event_id (FK), targeted_service (VARCHAR), failed_attempts (INTEGER), attempt_rate (FLOAT), usernames_tried (TEXT[])

   **ddos_details** table:
   - id, attack_event_id (FK), attack_vector (VARCHAR), packets_per_second (FLOAT), bytes_per_second (FLOAT), contributing_ips (INET[]), amplification_factor (FLOAT)

4. **Design Intelligence & Scoring Tables**

   **threat_scores** table:
   - id, attack_event_id (FK unique), base_score (INTEGER 0–100), ip_reputation_modifier (INTEGER -20 to +30), ml_confidence_modifier (INTEGER -10 to +20), final_score (INTEGER 0–100), severity (enum: low/medium/high/critical), calculated_at

   **ip_reputation** table:
   - ip_address (INET primary key), reputation_score (INTEGER 0–100), is_malicious (BOOLEAN), categories (TEXT[]), sources (JSONB), last_checked (TIMESTAMPTZ), manual_override (BOOLEAN)

   **ml_predictions** table:
   - id, packet_feature_vector (FLOAT[]), prediction (VARCHAR), confidence (FLOAT), model_version (VARCHAR), predicted_at (TIMESTAMPTZ), attack_event_id (FK nullable)

5. **Design Alert & Response Tables**

   **alerts** table:
   - id (UUID), attack_event_id (FK), threat_score_id (FK), title (VARCHAR), message (TEXT), severity (enum), status (enum: new/acknowledged/investigating/resolved/false_positive), assigned_to (FK users nullable), created_at, acknowledged_at, resolved_at

   **alert_comments** table:
   - id, alert_id (FK), user_id (FK), comment (TEXT), created_at

   **email_notifications** table:
   - id, alert_id (FK), recipient_email, subject, body_template, sent_at, delivery_status (enum: pending/sent/failed), retry_count, last_retry_at

   **ip_blocks** table:
   - id, ip_address (INET unique), block_type (enum: auto/manual), reason (TEXT), blocked_by (FK users nullable), attack_event_id (FK nullable), blocked_at, expires_at (nullable — NULL means permanent), is_active (BOOLEAN), firewall_rule_id (VARCHAR)

   **blacklist** table:
   - ip_address (INET primary key), added_by (FK users nullable), reason (TEXT), source (VARCHAR), added_at, is_permanent (BOOLEAN), expires_at

   **whitelist** table:
   - ip_address (INET primary key), description (TEXT), added_by (FK users), added_at

6. **Design Audit & History Tables**

   **audit_logs** table:
   - id (BIGSERIAL), user_id (FK nullable), action (VARCHAR), resource_type (VARCHAR), resource_id (VARCHAR), old_value (JSONB), new_value (JSONB), ip_address (INET), user_agent (TEXT), created_at
   - Index: (user_id, created_at), (action, created_at)

   **system_stats** table (time-series, 1-minute buckets):
   - id, packets_per_second (FLOAT), bytes_per_second (FLOAT), active_connections (INTEGER), alerts_count (INTEGER), blocked_ips_count (INTEGER), recorded_at (TIMESTAMPTZ)
   - Partition by RANGE on recorded_at

---

## Milestone 2.3: Database Setup & Migration

### Tasks
1. **Set Up PostgreSQL in Docker**
   - Define postgres service in docker-compose.yml with persistent named volume
   - Configure PostgreSQL with: max_connections=200, shared_buffers=256MB, work_mem=16MB
   - Create database and role with principle of least privilege (no SUPERUSER)
   - Create separate test database

2. **Implement SQLAlchemy Models**
   - Create model files mirroring table design in `app/models/` directory
   - Define all relationships: User→Session (one-to-many), AttackEvent→ThreatScore (one-to-one), Alert→Comments (one-to-many)
   - Add `__repr__` methods for debugging
   - Add `to_dict()` methods for JSON serialization
   - Use SQLAlchemy TypeDecorators for custom types (INET, ENUM)

3. **Set Up Alembic Migrations**
   - Initialize Flask-Migrate: creates migrations/ directory
   - Generate initial migration: captures all models as first migration
   - Write down migration in both `upgrade()` and `downgrade()` — always
   - Run migration and verify all tables created correctly
   - Create seed data migration with: default admin user, example whitelist entries, test attack events

4. **Implement Database Connection Pool**
   - Configure SQLAlchemy pool: pool_size=10, max_overflow=20, pool_timeout=30, pool_recycle=3600
   - Implement health check endpoint that verifies DB connectivity
   - Handle database connection errors gracefully with retry logic

---

## Milestone 2.4: Logging Architecture

### Tasks
1. **Design Multi-Channel Logging System**
   - Application log: INFO+ level, rotating file handler (10MB max, 5 backups)
   - Security log: WARNING+ level, separate file, never truncated
   - Packet log: Custom handler that batches writes to PostgreSQL
   - Error log: ERROR+ level, includes full stack traces

2. **Implement Structured Logging**
   - Use JSON format for logs (easier to parse, ship to ELK stack later)
   - Every log entry includes: timestamp, level, logger_name, message, request_id (for HTTP), user_id (if authenticated), source_ip
   - Implement request ID middleware that generates UUID per HTTP request and threads it through all logs

3. **Implement Security Audit Logger**
   - Every admin action written to audit_logs table AND to audit.log file
   - Audit events: login, logout, failed login, user created, user role changed, IP blocked, IP unblocked, whitelist changes, alert status changes
   - Audit logs are append-only (no UPDATE or DELETE operations permitted programmatically)

---

## Folder Structure After Phase 2
```
ids_project/
├── app/
│   ├── __init__.py                 # Application factory
│   ├── config.py                   # Configuration classes
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py                 # User, Session models
│   │   ├── packet.py               # PacketLog, ProtocolStats models
│   │   ├── attack.py               # AttackEvent and detail models
│   │   ├── threat.py               # ThreatScore, IpReputation, MlPrediction
│   │   ├── alert.py                # Alert, AlertComment, EmailNotification
│   │   ├── block.py                # IpBlock, Blacklist, Whitelist
│   │   └── audit.py                # AuditLog, SystemStats
│   ├── core/
│   │   ├── database.py             # SQLAlchemy instance, db helpers
│   │   ├── logging.py              # Logging configuration
│   │   └── exceptions.py           # Custom exception classes
│   └── extensions.py               # All Flask extension instances
├── migrations/
│   ├── versions/
│   │   └── 001_initial_schema.py
│   └── env.py
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── tests/
│   ├── conftest.py
│   └── unit/
├── .env.example
├── requirements.txt
└── run.py                          # Application entry point
```

## Database Changes
- Full schema created in this phase (no further structural changes until Phase 10 optimization)
- All indexes created at this stage

## APIs Required
- `GET /health` — Returns DB connectivity status

## Testing Strategy
- Verify all tables exist with correct columns: `\d table_name` in psql
- Verify indexes created: `\di` in psql
- Verify seed data inserted correctly
- Verify migration rollback works: `flask db downgrade`

## Security Considerations
- Database password must be strong (minimum 20 chars, generated)
- DB user has no DROP TABLE or CREATE permissions in production
- All connection strings loaded from environment variables only
- Logs must not contain passwords, tokens, or PII beyond IP addresses

## Expected Deliverables
- Fully functional Flask application factory
- Complete PostgreSQL schema with all 15+ tables
- Working Alembic migrations with rollback capability
- Structured JSON logging system
- Docker Compose for development environment
- `GET /health` endpoint returning DB status

## Estimated Timeline
- Days 1–2: Project structure and Flask factory setup
- Days 3–5: Database schema design and model implementation
- Day 6: Migrations, seed data, logging
- Day 7: Docker setup and integration verification

## Success Criteria
- `flask db upgrade` runs without errors
- All models can be instantiated and saved
- Logging produces JSON-formatted output to correct files
- Docker Compose brings up application and database together

---

<a name="phase-3"></a>
# PHASE 3: Packet Monitoring Engine
**Duration:** Week 2–3 | **Complexity:** High | **Depends On:** Phase 2

---

## Objective
Build the core packet capture engine that monitors live network traffic in real time. This is the system's most critical component — all other detection modules depend on the data it produces. Must be reliable, performant, and never the system's bottleneck.

## Why This Phase Is Necessary
All 14 remaining modules depend on packet data. A poorly designed capture engine creates cascading failures: missed packets mean missed attacks. This phase establishes the data pipeline that feeds the entire system.

---

## Concepts to Learn Before Starting

- **Scapy Deep Dive:** `sniff()` function with `prn` callback, packet layers (Ether/IP/TCP/UDP/DNS/HTTP), filter expressions (BPF filters), `store=0` for non-blocking capture, `iface` parameter for interface selection
- **PyShark:** AsyncLiveCapture vs LiveCapture, packet parsing, display filters, capture filters; when to use PyShark over Scapy (PyShark is better for application-layer parsing; Scapy better for raw manipulation)
- **Berkeley Packet Filter (BPF):** Kernel-level packet filtering syntax; filtering at capture reduces CPU load significantly vs filtering in userspace
- **Network Interfaces:** `/proc/net/dev` on Linux, promiscuous mode (allows capturing all traffic, not just traffic to this host), `ip link show` to list interfaces
- **Python Threading for I/O:** Using `threading.Thread`, daemon threads, thread-safe queues (`queue.Queue`) to decouple capture from processing
- **Ring Buffer Pattern:** Fixed-size in-memory buffer for packets; when full, oldest packets discarded — prevents memory exhaustion
- **Packet Dissection:** How to parse Ethernet frames, extract IP headers, read TCP flags (SYN, ACK, FIN, RST, PSH, URG), parse DNS queries, HTTP request lines

---

## Technologies Used
- Scapy 2.5+
- PyShark 0.6+
- Python threading + queue
- PostgreSQL (via SQLAlchemy models from Phase 2)
- libpcap (system dependency — `apt install libpcap-dev`)

---

## Milestone 3.1: Packet Capture Core

### Tasks
1. **Implement Interface Manager**
   - Function to list available network interfaces (using netifaces library)
   - Validate interface exists before starting capture
   - Support specifying interface via configuration (default: eth0)
   - Handle virtual interfaces (veth, docker0, lo) with appropriate filtering
   - Implement interface statistics tracking (bytes received, packets dropped by kernel)

2. **Implement Scapy Packet Sniffer**
   - Create PacketCapture class with start(), stop(), pause() methods
   - Run Scapy sniff() in a dedicated daemon thread — this thread does nothing but capture
   - Use `queue.Queue(maxsize=10000)` as ring buffer between capture and processing threads
   - Apply BPF capture filter to exclude broadcast/multicast noise: `"not (ether broadcast or ether multicast)"`
   - Count dropped packets (when queue is full) and expose as metric
   - Implement graceful shutdown: drain queue before stopping

3. **Implement PyShark Application-Layer Capture**
   - Run PyShark AsyncLiveCapture for HTTP, DNS, FTP protocol extraction
   - Extract HTTP: method, URI, status code, Host header, User-Agent, Content-Length
   - Extract DNS: query name, query type, response code, resolved IPs
   - Merge PyShark events with Scapy events using correlation (src_ip + dst_ip + timestamp window)

4. **Implement Packet Processing Worker Pool**
   - Create thread pool of 4 workers consuming from packet queue
   - Each worker: dequeue packet → parse → validate → enrich → push to DB batch queue
   - If queue blocks for >100ms, log warning (potential packet loss condition)
   - Track per-worker statistics: packets processed, processing time percentile

---

## Milestone 3.2: Protocol Analysis & Packet Parsing

### Tasks
1. **Implement Protocol Identifier**
   - Layer 3: IPv4, IPv6, ARP
   - Layer 4: TCP, UDP, ICMP, ICMPv6
   - Layer 7: HTTP (port 80/8080), HTTPS (port 443), DNS (port 53), FTP (port 20/21), SSH (port 22), SMTP (port 25/587), RDP (port 3389), SMB (port 445)
   - Unknown protocols: log protocol number from IP header for later analysis
   - Protocol fingerprinting: identify protocol even on non-standard ports using payload inspection

2. **Implement TCP Flag Parser**
   - Parse SYN, ACK, FIN, RST, PSH, URG, ECE, CWR flags
   - Classify connection state: SYN-only = new connection attempt, SYN+ACK = response, FIN = close, RST = forced close
   - SYN-only packets to many ports = port scan indicator (feed to Phase 4)
   - Track TCP connection state machine: SYN → SYN-ACK → ESTABLISHED → FIN-WAIT → CLOSED

3. **Implement Packet Feature Extractor**
   - Extract all fields needed for ML model (Phase 5): inter-arrival time, packet size distribution, protocol distribution, flag ratios
   - Compute flow-level statistics: packets per flow, bytes per flow, flow duration
   - Define "flow" as: (src_ip, dst_ip, src_port, dst_port, protocol) 5-tuple within 30-second window
   - Cache active flows in memory dictionary for real-time statistics

4. **Implement IP Geolocation Enrichment**
   - Integrate MaxMind GeoLite2 database (free, downloadable)
   - For each unique source IP seen for first time: resolve country, city, ASN (Autonomous System Number)
   - Cache in ip_reputation table to avoid repeated lookups
   - Flag IPs from high-risk countries (configurable list) for prioritized inspection

---

## Milestone 3.3: Packet Storage & Batch Writing

### Tasks
1. **Implement Batch Insert Manager**
   - Collect parsed packets in memory list
   - Flush to PostgreSQL every 500ms OR when batch size reaches 500 packets
   - Use SQLAlchemy bulk_insert_mappings() for high-performance inserts (10x faster than ORM)
   - Implement write-ahead buffer: if DB is temporarily unavailable, buffer up to 50k packets in memory
   - Log insert latency — alert if >1 second

2. **Implement Packet Log Partitioning**
   - Create monthly partition tables automatically: packet_logs_2024_01, packet_logs_2024_02, etc.
   - Implement partition creation check at system startup
   - Create next month's partition proactively on the 25th of each month
   - Implement old partition archiving (compress and move to cold storage after 30 days)

3. **Implement Packet Deduplication**
   - Hash each packet: SHA-256 of (src_ip + dst_ip + src_port + dst_port + timestamp + payload_first_64_bytes)
   - Maintain sliding window dedup cache (last 1000 hashes) — discard exact duplicates
   - Log dedup rate as metric (high dedup rate may indicate capture loop or replay attack)

4. **Implement Statistics Aggregator**
   - Every 60 seconds: aggregate protocol_stats from raw packet_logs
   - Calculate: packets/second, bytes/second, top 10 source IPs, top 10 destination IPs, protocol distribution
   - Write to system_stats table and protocol_stats table
   - These aggregates drive the traffic pattern analysis in Phase 4

---

## Milestone 3.4: Real-Time Traffic Dashboard Data

### Tasks
1. **Implement Live Traffic Metrics API**
   - `GET /api/v1/packets/live` — Returns last 60 seconds of packet statistics
   - `GET /api/v1/packets/protocols` — Returns protocol distribution for last N minutes
   - `GET /api/v1/packets/top-talkers` — Returns top 10 source IPs by packet count
   - `GET /api/v1/packets/stats` — Returns current packets/second, bytes/second

2. **Implement WebSocket Packet Feed**
   - Emit `packet_event` via Flask-SocketIO for every 10th packet (don't emit every packet — browser can't keep up)
   - Emit `traffic_stats_update` every 5 seconds with current statistics
   - Implement namespace `/packets` to separate from `/alerts` namespace

3. **Implement Packet Capture Status API**
   - `GET /api/v1/capture/status` — Returns: is_running, interface, packets_captured, packets_dropped, uptime
   - `POST /api/v1/capture/start` (admin only) — Start capture on specified interface
   - `POST /api/v1/capture/stop` (admin only) — Graceful shutdown of capture

---

## Folder Structure After Phase 3
```
app/
├── capture/
│   ├── __init__.py
│   ├── sniffer.py               # PacketCapture class (Scapy)
│   ├── pyshark_capture.py       # PyShark application-layer capture
│   ├── parser.py                # Packet parsing and feature extraction
│   ├── protocol_identifier.py   # Protocol detection logic
│   ├── batch_writer.py          # Async batch insert manager
│   ├── stats_aggregator.py      # Traffic statistics computation
│   └── flow_tracker.py          # TCP/UDP flow state machine
├── api/
│   └── v1/
│       └── packets.py           # Packet-related API endpoints
```

## Database Changes
- packet_logs table receives all new data
- protocol_stats updated every 60 seconds
- system_stats updated every 60 seconds

## APIs Required
- `GET /api/v1/packets/live`
- `GET /api/v1/packets/protocols`
- `GET /api/v1/packets/top-talkers`
- `GET /api/v1/packets/stats`
- `GET /api/v1/capture/status`
- `POST /api/v1/capture/start`
- `POST /api/v1/capture/stop`
- WebSocket: `ws://host/packets` with events `packet_event`, `traffic_stats_update`

## Testing Strategy
- **Unit Tests:** Test parser with pre-captured .pcap files (use Wireshark sample captures)
- **Volume Test:** Replay 10,000-packet pcap file and verify all packets stored correctly
- **Concurrency Test:** Verify no race conditions between capture and processing threads (use threading.Lock where needed)
- **Memory Test:** Run for 30 minutes and verify memory usage stays below 500MB

## Security Considerations
- Packet capture requires root/sudo privileges — run capture process as minimal-privilege user with CAP_NET_RAW capability only
- Payload data should only store first 64 bytes max + hash — never store full payloads (privacy + storage)
- Rate limit the live packet API to prevent dashboard from overloading the system

## Expected Deliverables
- PacketCapture class that captures from live interface
- Protocol parser covering TCP/UDP/ICMP/HTTP/DNS/FTP/SSH
- Batch insert system that handles 10k+ packets/second
- 6 REST API endpoints
- WebSocket live packet feed

## Estimated Timeline
- Days 1–3: Scapy capture engine and queue system
- Days 4–5: Protocol parser and feature extractor
- Days 6–7: Batch writer and API endpoints

## Success Criteria
- System captures packets on live interface without dropping more than 1% at 10k pps
- All parsed packets written to PostgreSQL within 1 second of capture
- API endpoints return correct data
- Memory usage stable over 30-minute run

---

<a name="phase-4"></a>
# PHASE 4: Core Attack Detection Engine
**Duration:** Week 3–4 | **Complexity:** Very High | **Depends On:** Phase 3

---

## Objective
Build the rule-based attack detection engine covering Port Scan Detection, Brute Force Detection, Traffic Pattern Analysis, and DDoS Detection. These modules analyze the packet data stream from Phase 3 and generate attack events.

## Why This Phase Is Necessary
This is the IDS brain. Without this phase, the system is just a packet logger. The detection algorithms must balance sensitivity (catching real attacks) against specificity (avoiding false positives on legitimate traffic).

---

## Concepts to Learn Before Starting

- **Port Scan Techniques:** SYN scan (half-open), Connect scan (full TCP), FIN/NULL/Xmas scans (stealth), UDP scan; each has different TCP flag patterns
- **Nmap Behavior:** How Nmap performs SYN scans, timing templates (-T1 to -T5), how slow scans evade time-window detectors
- **Brute Force Patterns:** Dictionary attacks vs credential stuffing; SSH brute force (TCP port 22 repeated SYN+ACK sequences); HTTP brute force (repeated POST to /login with 401/403 responses)
- **DDoS Attack Types:** SYN flood (exhaust connection table), UDP flood (bandwidth exhaustion), HTTP flood (Layer 7, harder to detect), Amplification attacks (DNS/NTP reflection)
- **Sliding Window Algorithm:** Detect rate-based attacks without storing all historical data; use deque or Redis sorted sets for efficient window queries
- **Token Bucket / Leaky Bucket:** Rate limiting algorithms useful for threshold detection
- **Statistical Analysis:** Mean, standard deviation, z-score for anomaly thresholds; rolling average for traffic baseline
- **Thread-Safe Data Structures:** `collections.defaultdict` with locks, `threading.RLock` for re-entrant locking, atomic operations

---

## Technologies Used
- Python (collections, threading, time, statistics modules)
- SQLAlchemy (attack_events, detail tables from Phase 2)
- Scapy (packet parsing utilities)
- Redis (optional but recommended for sliding window state — much faster than DB)

---

## Milestone 4.1: Detection Framework Design

### Tasks
1. **Design BaseDetector Abstract Class**
   - `analyze(packet_event)` → returns list of AttackIndicator objects (or empty list)
   - `get_name()` → returns detector name
   - `get_config()` → returns threshold configuration
   - `reset_state()` → clears internal state (for testing)
   - `get_stats()` → returns detection statistics (calls analyzed, alerts generated, false positive rate)

2. **Implement Detection Orchestrator**
   - Receives parsed packets from Phase 3 processing queue
   - Dispatches each packet to all registered detectors in parallel (thread pool)
   - Collects returned AttackIndicators from all detectors
   - Deduplicates: if same attack_type + source_ip already in active_attacks within 60 seconds, update existing rather than creating new
   - Writes confirmed AttackEvents to attack_events table
   - Dispatches AttackEvents to Threat Scoring Engine (Phase 6)

3. **Implement Attack State Manager**
   - In-memory dictionary: `active_attacks = {(attack_type, src_ip): AttackState}`
   - AttackState contains: first_seen, last_seen, evidence list, confidence, packet_count
   - Attack "resolves" when no new evidence for 5 minutes
   - Persist resolved attacks to attack_events table with full timeline

4. **Implement Configurable Thresholds**
   - All thresholds in config file (YAML), not hardcoded
   - Support hot-reload of thresholds without restarting system
   - Admin can modify thresholds via dashboard API
   - Threshold changes logged to audit_logs

---

## Milestone 4.2: Port Scan Detection

### Tasks
1. **Implement SYN Scan Detector**
   - Trigger condition: Same source IP sends SYN packets to >15 different destination ports within 10 seconds
   - Use sliding window: `deque` of (port, timestamp) per source IP, discard entries older than 10 seconds
   - Detect scan velocity: ports per second (fast scan = >20/sec, slow scan = >5/sec)
   - Classify scan: sequential ports (1,2,3,4...) = systematic scan; random ports = evasive scan
   - Evidence: record all scanned ports, timestamps, scan rate

2. **Implement Stealth Scan Detector (FIN/NULL/Xmas)**
   - FIN scan: TCP packets with only FIN flag set (no SYN, no ACK)
   - NULL scan: TCP packets with NO flags set
   - Xmas scan: TCP packets with FIN+PSH+URG flags set
   - Even a single such packet to multiple ports = alert (these are never legitimate)
   - Confidence: 0.95 (these are almost always malicious)

3. **Implement UDP Scan Detector**
   - UDP to many different ports triggers ICMP "port unreachable" responses
   - Track: source IP sends UDP to >10 unique ports within 30 seconds
   - Correlate outbound UDP with inbound ICMP type 3 code 3 responses

4. **Implement Vertical vs Horizontal Scan Classifier**
   - Vertical scan: Single target IP, many ports → targeted host reconnaissance
   - Horizontal scan: Many target IPs, same port → service-specific scanning (e.g., scanning whole subnet for SSH)
   - Network sweep: Many target IPs, few ports → network discovery
   - Classification affects severity score in Phase 6

5. **Implement Scan Evasion Detection**
   - Slow scan detection: accumulate scan evidence over 5-minute window (not just 10 seconds)
   - Fragmented scan: detect port scan hidden in IP fragments
   - Decoy scan: multiple source IPs all scanning same target — look for timing correlation

---

## Milestone 4.3: Brute Force Detection

### Tasks
1. **Implement SSH Brute Force Detector**
   - SSH authentication failure pattern: TCP connection established to port 22, then immediate RST or FIN (failed auth causes disconnect)
   - Track: per source IP, count of short-lived connections to port 22 within 60 seconds
   - Threshold: >5 failed SSH connections in 60 seconds from same IP
   - Evidence: connection timestamps, connection durations

2. **Implement HTTP Brute Force Detector**
   - Requires HTTP-layer data from PyShark (Phase 3)
   - Track: repeated POST requests to same URI (e.g., /login, /admin, /wp-login.php) from same IP
   - Response code analysis: 401 and 403 responses indicate failed auth
   - Threshold: >10 POST requests to auth endpoint with 401/403 responses in 30 seconds
   - Detect credential stuffing: many failed attempts with different User-Agent strings or from many IPs

3. **Implement FTP/SMTP/RDP Brute Force Detector**
   - FTP: Port 21, repeated connections with short duration (<5 seconds) = failed auth
   - SMTP: Port 25/587, AUTH command failures
   - RDP: Port 3389, repeated short-duration TLS sessions
   - Generic handler: configurable per-protocol thresholds

4. **Implement Username Enumeration Detector**
   - Different response times for valid vs invalid usernames (timing oracle)
   - Rapid fire of different usernames to same endpoint
   - Classify as low-severity brute force variant

5. **Implement Distributed Brute Force Detector**
   - Multiple source IPs targeting same service (credential stuffing with IP rotation)
   - Threshold: >50 failed auth attempts to same service from >5 different IPs within 5 minutes
   - Harder to block (need to block by pattern, not single IP)
   - Alert type: DISTRIBUTED_BRUTE_FORCE with list of contributing IPs

---

## Milestone 4.4: Traffic Pattern Analysis

### Tasks
1. **Implement Traffic Baseline Builder**
   - Collect 24 hours of normal traffic statistics (or use first hour as bootstrap baseline)
   - Compute per-hour averages: packets/min, bytes/min, unique IPs, top protocols
   - Compute standard deviation for each metric
   - Store baseline in system_stats table, update rolling average daily

2. **Implement Traffic Spike Detector**
   - Compare current 1-minute packet rate to baseline
   - Alert if current rate > baseline_mean + (3 × baseline_stddev)
   - Z-score calculation: (current - mean) / stddev
   - Classify by spike type: general spike vs protocol-specific spike (only UDP spiked = possible UDP flood)

3. **Implement Protocol Anomaly Detector**
   - Detect unusual protocol distributions: normally 80% TCP, 15% UDP, 5% ICMP
   - Alert if ICMP > 30% of total traffic (possible ICMP flood)
   - Alert if unknown protocol numbers appear
   - Detect protocol tunneling indicators: DNS packets larger than 512 bytes (possible DNS tunneling)

4. **Implement Connection Tracking Anomaly Detector**
   - Track concurrent connections per IP
   - Alert if single IP maintains >200 concurrent connections
   - Track half-open connections (SYN without SYN-ACK): >500 half-open = SYN flood indicator
   - Track connection duration anomalies: connections lasting <100ms at high volume = scan indicator

---

## Milestone 4.5: DDoS Detection

### Tasks
1. **Implement SYN Flood Detector**
   - SYN flood = massive volume of SYN packets without completing handshake
   - Track: SYN packet rate to single destination IP
   - Track: ratio of SYN to SYN-ACK responses (should be ~1:1 normally; 100:1 or higher = SYN flood)
   - Threshold: >500 SYN packets/second to single IP with <10% completion rate
   - Severity: HIGH (can crash servers without protection)

2. **Implement UDP Flood Detector**
   - UDP flood: high-volume UDP to many ports on single destination
   - Track: UDP packet rate per destination IP
   - Threshold: >1000 UDP packets/second to single IP
   - Classify if amplification: check if source ports are from known amplification services (NTP/123, DNS/53, SSDP/1900)

3. **Implement HTTP Flood Detector (Layer 7 DDoS)**
   - Many IPs sending HTTP requests to same endpoint
   - Threshold: >500 HTTP requests/second to single endpoint from >50 unique IPs
   - Distinguish from legitimate traffic spike (legitimate: requests spread across many URLs; flood: concentrated on single URL)
   - Analyze User-Agent distribution: flood often has uniform or random User-Agent strings

4. **Implement Amplification Attack Detector**
   - DNS amplification: small DNS query sent with spoofed source IP → large response goes to victim
   - NTP amplification: monlist command to NTP server → large response flood
   - Detection: single IP receiving massive DNS/NTP response traffic it didn't request
   - Amplification factor calculation: response_bytes / request_bytes (NTP can be 556x)

5. **Implement DDoS Severity Classifier**
   - LOW: 100–500 pps, single attack vector, short duration (<5 minutes)
   - MEDIUM: 500–2000 pps, single attack vector, sustained (>5 minutes)
   - HIGH: >2000 pps, multiple attack vectors, sustained
   - CRITICAL: >10000 pps, service impacting, requires immediate response

---

## Folder Structure After Phase 4
```
app/
├── detection/
│   ├── __init__.py
│   ├── orchestrator.py          # DetectionOrchestrator class
│   ├── base_detector.py         # BaseDetector abstract class
│   ├── state_manager.py         # AttackState management
│   ├── port_scan/
│   │   ├── syn_detector.py
│   │   ├── stealth_detector.py
│   │   ├── udp_scan_detector.py
│   │   └── classifier.py
│   ├── brute_force/
│   │   ├── ssh_detector.py
│   │   ├── http_detector.py
│   │   ├── generic_detector.py
│   │   └── distributed_detector.py
│   ├── traffic_analysis/
│   │   ├── baseline_builder.py
│   │   ├── spike_detector.py
│   │   └── protocol_anomaly.py
│   └── ddos/
│       ├── syn_flood_detector.py
│       ├── udp_flood_detector.py
│       ├── http_flood_detector.py
│       └── severity_classifier.py
```

## Database Changes
- attack_events table populated for first time
- port_scan_details, brute_force_details, ddos_details tables populated

## APIs Required
- `GET /api/v1/attacks/active` — Current active attacks
- `GET /api/v1/attacks/{id}` — Attack event details
- `GET /api/v1/attacks/stats` — Attack counts by type and time window
- `POST /api/v1/attacks/{id}/status` — Update attack status (analyst/admin)

## Testing Strategy
- **Attack Simulation:** Use Nmap (-sS, -sF, -sN, -sX flags) against test VM to trigger scan detectors
- **Brute Force Simulation:** Use Hydra or Medusa against test SSH server
- **DDoS Simulation:** Use hping3 for SYN flood simulation in isolated network
- **False Positive Testing:** Normal web browsing, large file downloads — verify no false alerts
- **Threshold Testing:** Verify alerts trigger exactly at threshold, not before

## Security Considerations
- Detection state (IP tracking dictionaries) must be bounded — cap at 100,000 tracked IPs to prevent memory exhaustion from an attacker sending spoofed IPs
- Ensure attack event creation rate is limited — an attacker flooding with varied patterns shouldn't create millions of DB records
- Detection thresholds must be tunable without code deployment

## Expected Deliverables
- 4 detection modules (Port Scan, Brute Force, Traffic Analysis, DDoS) fully implemented
- Detection orchestrator that runs all detectors in parallel
- Configurable thresholds via YAML file
- 4 REST API endpoints for attack data

## Estimated Timeline
- Days 1–2: Detection framework (BaseDetector, Orchestrator, StateManager)
- Days 3–4: Port scan detection (all techniques)
- Days 5–6: Brute force detection (all services)
- Day 7: DDoS detection

## Success Criteria
- Nmap SYN scan detected within 10 seconds of start
- SSH brute force (Hydra) detected after 6th attempt
- No false positives during 30 minutes of normal browsing
- All attack events persisted to database

---

<a name="phase-5"></a>
# PHASE 5: Machine Learning & Threat Intelligence
**Duration:** Week 5–6 | **Complexity:** Very High | **Depends On:** Phase 3, Phase 4

---

## Objective
Add an ML-based anomaly detection layer that catches novel attacks not covered by Phase 4's rule-based detectors, and integrate IP reputation intelligence to enrich attack events with historical threat data.

## Why This Phase Is Necessary
Rule-based detectors have known evasion techniques. An ML layer that learns what "normal" looks like will flag deviations even from unknown attacks. Combined with IP reputation, this significantly reduces both false negatives (missed attacks) and false positives (erroneous alerts).

---

## Concepts to Learn Before Starting

- **Supervised vs Unsupervised Learning:** For anomaly detection with no labeled data, unsupervised is required (Isolation Forest, Autoencoder). If labeled attack data is available, supervised is possible.
- **Isolation Forest Algorithm:** Anomaly detection by randomly partitioning data; anomalies are isolated faster (fewer partitions needed). Contamination parameter = expected anomaly rate (~0.01 for most networks)
- **Feature Engineering for Network Data:** Converting raw packet fields into numerical feature vectors suitable for ML; importance of normalization; handling categorical features (protocol) with one-hot encoding
- **Scikit-Learn Pipeline:** Chain preprocessing (StandardScaler) and model (IsolationForest) into a Pipeline object — prevents data leakage and simplifies inference
- **Model Serialization:** Save trained model with joblib; load at startup; version models
- **Online vs Batch Learning:** Network traffic is a stream; batch retraining needed periodically; online learning with partial_fit() for incremental updates
- **Precision/Recall Trade-off:** Higher sensitivity catches more attacks but generates more false positives; tune contamination parameter to acceptable false positive rate
- **Threat Intelligence Feeds:** Understanding IP reputation sources (AbuseIPDB, VirusTotal, Shodan, AlienVault OTX); API rate limits; caching strategies

---

## Technologies Used
- Scikit-Learn (IsolationForest, OneClassSVM, StandardScaler, Pipeline)
- NumPy + Pandas (feature engineering)
- Joblib (model persistence)
- Requests (threat intelligence API calls)
- APScheduler (periodic model retraining)

---

## Milestone 5.1: Feature Engineering

### Tasks
1. **Define Flow-Level Feature Set (25+ features)**

   Per-flow features (5-tuple window = 30 seconds):
   - packet_count: total packets in flow
   - byte_count: total bytes in flow
   - avg_packet_size: mean bytes per packet
   - std_packet_size: standard deviation of packet sizes
   - max_packet_size: largest packet in flow
   - min_packet_size: smallest packet in flow
   - flow_duration_seconds: time from first to last packet
   - packets_per_second: packet_count / flow_duration
   - bytes_per_second: byte_count / flow_duration
   - syn_count: number of SYN packets
   - ack_count: number of ACK packets
   - fin_count: number of FIN packets
   - rst_count: number of RST packets
   - syn_ratio: syn_count / packet_count
   - rst_ratio: rst_count / packet_count
   - unique_dest_ports: number of unique destination ports
   - unique_src_ports: number of unique source ports
   - protocol_tcp: 1 if TCP, 0 otherwise
   - protocol_udp: 1 if UDP, 0 otherwise
   - protocol_icmp: 1 if ICMP, 0 otherwise
   - inter_arrival_mean: mean time between packets (microseconds)
   - inter_arrival_std: std dev of inter-arrival times
   - inter_arrival_max: maximum inter-arrival time
   - payload_size_mean: mean non-header bytes
   - small_packet_ratio: packets < 100 bytes / total packets

2. **Implement Feature Extractor**
   - FlowFeatureExtractor class that maintains in-memory flow table
   - For each new packet: update the matching flow's statistics
   - When flow expires (30-second inactivity): emit complete feature vector
   - Feature vector returned as NumPy array in consistent order

3. **Implement Feature Store**
   - Write feature vectors to ml_features table (JSONB column)
   - Label known attack flows (from Phase 4's attack_events) for supervised learning experiments
   - Provide function to retrieve last N feature vectors for batch retraining

---

## Milestone 5.2: Training Dataset Creation

### Tasks
1. **Collect Normal Traffic Baseline Dataset**
   - Run system for 48 hours collecting only feature vectors (no attack events)
   - Label all flows as "normal" (class 0)
   - Store 50,000+ normal flow samples minimum

2. **Generate Attack Traffic Samples (Simulation)**
   - Run Nmap scans with various timing templates and scan types → label as port_scan (class 1)
   - Run Hydra SSH brute force → label as brute_force (class 1)
   - Run hping3 SYN flood → label as ddos (class 1)
   - Use PCAP datasets: NSL-KDD, CICIDS2017, or UNSW-NB15 (publicly available labeled datasets)
   - Extract same 25 features from labeled PCAP files using offline feature extraction

3. **Implement Dataset Preprocessing Pipeline**
   - Handle missing values: fill with median for continuous features
   - Remove duplicate feature vectors
   - Normalize using StandardScaler (fit on training set only, save scaler)
   - Split: 80% training, 20% validation
   - Handle class imbalance: normal >> attack — use SMOTE or adjust contamination parameter

---

## Milestone 5.3: Anomaly Detection Model

### Tasks
1. **Train Isolation Forest Model**
   - Train on normal traffic only (unsupervised approach)
   - IsolationForest(contamination=0.01, n_estimators=200, random_state=42)
   - Wrap in Pipeline with StandardScaler preprocessing
   - Evaluate: AUC-ROC on labeled validation set; target AUC > 0.85
   - Save model with joblib: `model_v1.pkl` and scaler separately

2. **Implement Inference Engine**
   - Load model at system startup
   - AnomalyDetector.predict(feature_vector) → returns: {is_anomaly: bool, anomaly_score: float, confidence: float}
   - anomaly_score from Isolation Forest: negative = more anomalous; normalize to 0–1 scale
   - Batch prediction: predict on accumulated 100 flow features every 10 seconds

3. **Implement Model Versioning**
   - Track model versions in ml_model_versions table: version, trained_at, training_samples, validation_auc, feature_count, model_path
   - Only deploy model if AUC > 0.80 on validation set
   - Keep last 3 model versions; rollback capability if new model underperforms

4. **Implement Periodic Model Retraining**
   - APScheduler job: retrain model weekly using last 7 days of normal traffic
   - Exclude flow features from windows where attack_events were detected (don't train on attack patterns as "normal")
   - Compare new model vs current model on held-out validation set before promoting
   - Log retraining results to audit log

5. **Implement Feature Drift Detection**
   - Monitor distribution of incoming feature vectors vs training distribution
   - Alert if >30% of features show >2 standard deviations of shift (concept drift = network behavior changed significantly)
   - Trigger emergency retraining if concept drift detected

---

## Milestone 5.4: IP Reputation System

### Tasks
1. **Implement AbuseIPDB Integration**
   - Register for free API key (1,000 checks/day on free tier)
   - CheckIP endpoint: `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}`
   - Response includes: abuseConfidenceScore (0–100), totalReports, lastReportedAt, countryCode, usageType
   - Handle API errors: rate limit (429), network failure, invalid response

2. **Implement IP Reputation Cache**
   - Check ip_reputation table before making API call
   - Cache valid for 24 hours (IPs don't change reputation that fast)
   - Background worker checks new IPs encountered in packet stream
   - Prioritize: IPs involved in attack_events get checked immediately; others checked in batch

3. **Implement Local Threat Intelligence**
   - Import common blocklists (Emerging Threats, Spamhaus DROP list, Feodo Tracker)
   - Store in blacklist table with source="external_feed"
   - APScheduler job: refresh external blocklists daily
   - Blocklist check is instant (DB lookup) vs API call (network latency)

4. **Implement Threat Intelligence Aggregator**
   - For any IP: aggregate reputation_score from multiple sources
   - Weighted scoring: AbuseIPDB (40%), local blacklist (40%), Shodan (20%)
   - Final reputation_score: 0 (clean) to 100 (definitively malicious)
   - risk_level classification: 0–25 (clean), 26–50 (suspicious), 51–75 (likely malicious), 76–100 (confirmed malicious)

5. **Implement IP Reputation API**
   - `GET /api/v1/reputation/{ip}` — Returns reputation data for specific IP
   - `POST /api/v1/reputation/check-bulk` — Check list of IPs (for investigation)
   - `POST /api/v1/reputation/{ip}/override` (admin) — Manually set reputation and lock

---

## Folder Structure After Phase 5
```
app/
├── ml/
│   ├── __init__.py
│   ├── feature_extractor.py       # Flow feature extraction
│   ├── feature_store.py           # Feature persistence
│   ├── trainer.py                 # Model training pipeline
│   ├── inference.py               # AnomalyDetector prediction engine
│   ├── model_manager.py           # Version management, deployment
│   ├── drift_detector.py          # Feature distribution monitoring
│   └── models/                    # Saved model files
│       ├── model_v1.pkl
│       └── scaler_v1.pkl
├── intelligence/
│   ├── __init__.py
│   ├── ip_reputation.py           # Reputation aggregator
│   ├── abuseipdb.py               # AbuseIPDB adapter
│   ├── feed_importer.py           # External blocklist importer
│   └── cache_manager.py           # Reputation cache logic
```

## Database Changes
- ml_predictions table receives predictions
- ip_reputation table populated by background worker
- New table: ml_model_versions

## APIs Required
- `GET /api/v1/reputation/{ip}`
- `POST /api/v1/reputation/check-bulk`
- `POST /api/v1/reputation/{ip}/override`
- `GET /api/v1/ml/model/status` — Current model version, last trained, AUC
- `POST /api/v1/ml/model/retrain` (admin) — Trigger manual retraining

## Testing Strategy
- **Feature Extractor Test:** Feed known PCAP file, verify feature vectors match expected values
- **Model Test:** Feed labeled attack flows, verify >85% detected as anomalies
- **False Positive Test:** Feed 1 hour of normal traffic, verify <2% flagged as anomalous
- **Reputation Test:** Check known malicious IPs (use test IPs from AbuseIPDB documentation)
- **Cache Test:** Verify cached results returned for second lookup within 24h

## Security Considerations
- API keys for threat intelligence stored in environment variables only
- IP reputation data must not be used to block IPs automatically (only inform scoring) — auto-block only through Phase 7's explicit logic
- Model files should be checksummed; verify integrity at load time

## Expected Deliverables
- 25-feature flow extractor
- Trained Isolation Forest model with >0.85 AUC
- IP reputation system with AbuseIPDB integration and caching
- External blocklist importer
- 5 API endpoints

## Estimated Timeline
- Days 1–2: Feature engineering and extractor
- Days 3–4: Dataset creation and model training
- Day 5: Inference engine and model versioning
- Day 6–7: IP reputation system

## Success Criteria
- Model detects Nmap scans as anomalous with confidence > 0.7
- IP reputation check returns result in <50ms (from cache) or <2s (fresh API call)
- No model deployment if AUC < 0.80
- Blocklists refreshed successfully on schedule

---

<a name="phase-6"></a>
# PHASE 6: Threat Scoring & Response Engine
**Duration:** Week 6–7 | **Complexity:** High | **Depends On:** Phase 4, Phase 5

---

## Objective
Implement a unified threat scoring system that aggregates detection results from all modules (rule-based + ML + IP reputation) into a single 0–100 threat score with severity classification. This score drives automated response decisions.

## Why This Phase Is Necessary
Without scoring, all detected events are equal — a Nmap SYN scan and a critical DDoS attack both generate "alerts" with no priority differentiation. The scoring engine enables analysts to triage alerts efficiently and enables the auto-blocking system to make calibrated decisions.

---

## Concepts to Learn Before Starting

- **Multi-Criteria Decision Analysis (MCDA):** Combining scores from multiple independent sources with different weights
- **Bayesian Score Aggregation:** Updating probability of attack given multiple evidence sources
- **Risk Matrix:** Likelihood × Impact = Risk; how to map detection confidence and attack severity to a risk score
- **Alert Fatigue:** The danger of too many alerts causing analysts to miss real threats; scoring helps prioritize
- **CVSS Score System:** Common Vulnerability Scoring System — inspiration for network threat scoring methodology

---

## Technologies Used
- Python (statistics module, math)
- SQLAlchemy (threat_scores table)
- APScheduler (re-scoring periodic job)

---

## Milestone 6.1: Threat Scoring Algorithm

### Tasks
1. **Define Base Score Components**
   - Attack Type Score (0–50):
     - Port Scan: 20
     - Brute Force: 35
     - Traffic Anomaly: 25
     - DDoS: 45
     - ML Anomaly (Unknown): 30
   - Attack Rate Modifier (+0 to +20): based on packets/second or attempts/second percentile
   - Duration Modifier (+0 to +10): longer attack = higher modifier
   - Recurrence Modifier (+0 to +10): if same IP attacked before within 7 days

2. **Define Intelligence Modifiers**
   - IP Reputation Modifier: reputation_score > 75 → +15; > 50 → +8; < 25 → -10 (likely safe IP, may be false positive)
   - ML Confidence Modifier: if ML also flagged this IP within same time window → +10
   - Blacklist Modifier: IP on known blacklist → +20 (immediate escalation)
   - Whitelist Check: if IP on whitelist → override all scores → total score = 0 → no alert

3. **Implement Score Calculator**
   - ThreatScorer.calculate(attack_event) → ThreatScore object
   - Clamp final score: 0–100 (cannot exceed 100 or go below 0)
   - Severity mapping: 0–24 = LOW, 25–49 = MEDIUM, 50–74 = HIGH, 75–100 = CRITICAL
   - Include score breakdown in ThreatScore: shows contribution of each component

4. **Implement Score Explanation Generator**
   - For each threat score, generate human-readable explanation
   - Example: "Score: 78 (CRITICAL). Base: 45 (DDoS), Rate modifier: +13 (8,500 pps), IP Reputation: +15 (confirmed malicious), Recurrence: +5 (attacked 2 days ago)"
   - Explanation stored in threat_scores.explanation column (TEXT)

---

## Milestone 6.2: Alert Prioritization Engine

### Tasks
1. **Implement Alert Queue with Priority**
   - Use `queue.PriorityQueue` for alert dispatch
   - Priority = 100 - threat_score (lower number = higher priority in Python's min-heap)
   - CRITICAL alerts always processed first regardless of arrival order

2. **Implement Automatic Response Decision Engine**
   - Score ≥ 75 (CRITICAL) + not whitelisted → automatic IP block + immediate email alert
   - Score 50–74 (HIGH) → email alert + create alert for analyst
   - Score 25–49 (MEDIUM) → create alert, no automatic action
   - Score 0–24 (LOW) → log only, no alert created (reduce noise)
   - All automatic decisions logged to audit_logs with reason

3. **Implement Score Decay**
   - Threat score decreases over time if no new evidence arrives
   - Decay formula: current_score × 0.9^(hours_since_last_evidence)
   - Re-score every 30 minutes for active attacks
   - Attack transitions from ACTIVE to MONITORING when score decays below 25

4. **Implement Threat Context Enrichment**
   - For each scored threat: automatically fetch geolocation, ASN, hostname (reverse DNS)
   - Check if target IP is a critical asset (configurable list: database servers, auth servers)
   - Escalate score by +10 if target is critical asset

---

## Folder Structure After Phase 6
```
app/
├── scoring/
│   ├── __init__.py
│   ├── threat_scorer.py        # Main scoring algorithm
│   ├── modifiers.py            # Score modifier calculations
│   ├── severity_classifier.py  # CRITICAL/HIGH/MEDIUM/LOW logic
│   ├── alert_priority.py       # Priority queue management
│   ├── response_engine.py      # Auto-response decision logic
│   └── score_explanation.py    # Human-readable score explanation
```

## Database Changes
- threat_scores table fully populated
- alerts table begins receiving prioritized alerts

## APIs Required
- `GET /api/v1/threats/score/{attack_event_id}` — Score details for specific attack
- `GET /api/v1/threats/high-priority` — All active HIGH and CRITICAL threats
- `GET /api/v1/threats/statistics` — Score distribution, average score by attack type

## Testing Strategy
- Unit test each score component independently
- Integration test: feed known attack events, verify correct severity classification
- Test score decay: verify HIGH alert transitions to MEDIUM after 4 hours of inactivity
- Test whitelist: IP on whitelist must always score 0 regardless of other signals

## Security Considerations
- Score manipulation resistance: scoring inputs must come only from internal modules, never from API calls
- Whitelist bypass prevention: whitelist check is the last step — even if score is 100, whitelist overrides

## Expected Deliverables
- Threat scoring algorithm with explanation generation
- Alert priority queue
- Automated response decision engine
- Score decay system
- 3 API endpoints

## Estimated Timeline
- Days 1–2: Scoring algorithm and modifiers
- Days 3–4: Alert prioritization and response engine
- Day 5: Score decay and enrichment
- Days 6–7: Integration with Phase 4 and Phase 5 outputs

## Success Criteria
- DDoS attacks score ≥ 70
- Whitelisted IPs always score 0
- CRITICAL alerts auto-trigger IP block within 5 seconds of detection
- Score explanation is human-readable and accurate

---

<a name="phase-7"></a>
# PHASE 7: Alerting & Protection System
**Duration:** Week 7–8 | **Complexity:** High | **Depends On:** Phase 6

---

## Objective
Build the complete alerting and active protection infrastructure: real-time alert center with WebSocket streaming, email notification system, automatic IP blocking via iptables, and blacklist/whitelist management.

---

## Concepts to Learn Before Starting

- **Flask-SocketIO:** Server-side WebSocket events, rooms (group connections), namespaces (logical separation of event types), emit vs broadcast
- **Email Systems:** SMTP protocol, TLS vs STARTTLS, email authentication (SPF, DKIM basics), HTML email templates with Jinja2, email delivery tracking
- **Linux Firewall (iptables):** CHAIN concepts (INPUT, OUTPUT, FORWARD), -A (append), -I (insert), -D (delete), -j DROP vs REJECT, persistent rules with iptables-save
- **Python subprocess Module:** Safely calling system commands from Python, handling returncode, stdout/stderr, preventing shell injection (use list args, not string)
- **Retry Logic:** Exponential backoff for email delivery retries; dead letter queue for permanently failed notifications
- **Alert Lifecycle:** NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED or FALSE_POSITIVE

---

## Technologies Used
- Flask-SocketIO (WebSocket)
- Flask-Mail or smtplib (email)
- Jinja2 (email templates)
- subprocess (iptables commands)
- APScheduler (alert cleanup, email retry)

---

## Milestone 7.1: Real-Time Alert Center

### Tasks
1. **Implement Alert CRUD Operations**
   - Create alert from scored threat (automatically by Phase 6)
   - Update alert status (manually by analysts via API)
   - Add comments to alerts
   - Bulk acknowledge: mark all LOW alerts as acknowledged
   - Alert assignment: assign alert to specific analyst

2. **Implement WebSocket Alert Streaming**
   - On new alert creation: emit `new_alert` event to `/alerts` namespace
   - Event payload: {alert_id, title, severity, source_ip, threat_score, created_at}
   - On alert status change: emit `alert_updated` event
   - Connect authentication: verify JWT token in WebSocket connection handshake
   - Support reconnection: on WebSocket reconnect, client receives last 50 alerts to re-sync state

3. **Implement Alert Filtering & Aggregation**
   - API endpoint to get alerts with filters: severity, status, attack_type, time_range, assigned_to, source_ip
   - Aggregate consecutive alerts from same IP as "attack campaign" — single campaign card in UI
   - Auto-expire LOW alerts after 24 hours without action
   - Daily alert digest: count by severity and attack type

4. **Implement Alert Statistics**
   - Real-time counters: new, active, acknowledged, resolved (today)
   - Mean time to acknowledge (MTTA) per severity level
   - Mean time to resolve (MTTR) per analyst
   - False positive rate tracking per detection module

---

## Milestone 7.2: Email Notification System

### Tasks
1. **Design Email Templates**
   - Critical alert template: red header, attack details, source IP, threat score, map screenshot if geolocation available, one-click acknowledge button (deeplink to dashboard)
   - Daily digest template: table of alerts by severity, top attacking IPs, comparison to previous day
   - Weekly report template: full statistics, attack trend charts as base64-embedded images

2. **Implement Email Queue System**
   - Queue email jobs in email_notifications table (status: pending)
   - Background worker polls queue every 30 seconds
   - Send via SMTP with TLS; update status to sent/failed
   - Retry failed emails: 3 attempts with exponential backoff (5min, 25min, 2hr)
   - Dead letter: after 3 failures, mark as permanently_failed and notify admin in-app

3. **Implement Email Configuration**
   - Admin configures: SMTP host, port, username, password, from address
   - Configure per-severity email recipients (CRITICAL → security team; MEDIUM/HIGH → primary analyst)
   - Email throttling: max 10 emails/hour per recipient (batch alerts to avoid inbox flooding)
   - Unsubscribe tracking: respect unsubscribe requests

4. **Implement Email Test Functionality**
   - Admin can send test email to verify configuration
   - Test includes sample critical alert to verify template rendering

---

## Milestone 7.3: Automatic IP Blocking

### Tasks
1. **Implement iptables Rule Manager**
   - IpBlocker.block(ip_address, duration=None, reason="") → bool
   - Executes: `iptables -I INPUT 1 -s {ip} -j DROP`
   - Executes: `iptables -I FORWARD 1 -s {ip} -j DROP`
   - Verify rule was added: check `iptables -L -n` output
   - Record firewall rule in ip_blocks table

2. **Implement IP Unblock Logic**
   - IpBlocker.unblock(ip_address) → bool
   - Remove specific iptables rules for IP
   - Update ip_blocks record: is_active=False, removed_at=now
   - Log to audit_logs: who triggered unblock, reason

3. **Implement Temporary Block with Auto-Expiry**
   - APScheduler job every 5 minutes: check ip_blocks where expires_at < now AND is_active=True
   - Auto-unblock expired IPs
   - Send notification: "IP {x} auto-unblock after 24-hour block expired"

4. **Implement Block Rule Persistence**
   - On system restart: re-apply all active blocks from ip_blocks table
   - Run at startup: compare current iptables rules with active ip_blocks; add missing rules
   - Save iptables rules to file: `iptables-save > /etc/iptables/rules.v4`

5. **Implement Block Safeguards**
   - NEVER block: 127.0.0.1, ::1, configured whitelist IPs, admin's current IP
   - Whitelist check before every block operation
   - Block audit: all blocks (auto and manual) recorded in audit_logs with evidence
   - Block notification: email admin when >10 IPs blocked in 5 minutes (may indicate false positive cascade)

---

## Milestone 7.4: Blacklist & Whitelist Management

### Tasks
1. **Implement Blacklist Manager**
   - Add IP to blacklist (manual, with reason and optional expiry)
   - Import external blacklist (CSV format: ip, reason, source)
   - Export blacklist to CSV
   - Blacklisted IPs automatically scored +20 in Phase 6 and blocked on first contact

2. **Implement Whitelist Manager**
   - Add IP or CIDR range to whitelist (e.g., 10.0.0.0/8 for internal network)
   - Support hostname resolution: add hostname → resolve to IP → add
   - Whitelisted IPs: never blocked, never alerted, always score 0
   - Validate: whitelist must contain admin IP before allowing changes (prevent lockout)

3. **Implement Bulk Import/Export**
   - CSV import: validate format, check for overlaps with existing entries, preview before import
   - CSV export: full blacklist or whitelist with metadata
   - Support popular format: Emerging Threats blocklist format

4. **Implement List Sync**
   - Sync active whitelist/blacklist with iptables rules on change
   - Rebuild iptables rules from database on system startup

---

## Folder Structure After Phase 7
```
app/
├── alerts/
│   ├── __init__.py
│   ├── manager.py              # Alert CRUD, lifecycle
│   ├── streamer.py             # WebSocket event emission
│   ├── aggregator.py           # Campaign detection, dedup
│   └── statistics.py           # MTTA, MTTR, false positive rate
├── notifications/
│   ├── __init__.py
│   ├── email_queue.py          # Email job queue
│   ├── email_sender.py         # SMTP sending logic
│   └── templates/
│       ├── critical_alert.html
│       ├── daily_digest.html
│       └── weekly_report.html
├── protection/
│   ├── __init__.py
│   ├── ip_blocker.py           # iptables rule manager
│   ├── block_manager.py        # Block lifecycle (temp/permanent)
│   └── list_manager.py         # Blacklist/whitelist operations
```

## Database Changes
- alerts table fully operational
- email_notifications table receives jobs
- ip_blocks, blacklist, whitelist tables updated

## APIs Required
- `GET /api/v1/alerts` — List alerts with filters
- `GET /api/v1/alerts/{id}` — Alert details
- `PATCH /api/v1/alerts/{id}/status` — Update status
- `POST /api/v1/alerts/{id}/comment` — Add comment
- `GET /api/v1/blocks` — List active blocks
- `POST /api/v1/blocks` — Manual block IP
- `DELETE /api/v1/blocks/{ip}` — Unblock IP
- `GET /api/v1/blacklist` — Get blacklist
- `POST /api/v1/blacklist` — Add to blacklist
- `DELETE /api/v1/blacklist/{ip}` — Remove from blacklist
- `GET /api/v1/whitelist` — Get whitelist
- `POST /api/v1/whitelist` — Add to whitelist
- `DELETE /api/v1/whitelist/{ip}` — Remove from whitelist
- `POST /api/v1/notifications/test-email` — Send test email
- WebSocket events: `new_alert`, `alert_updated`, `ip_blocked`

## Testing Strategy
- Test email delivery to test SMTP server (use Mailhog in Docker)
- Test iptables block: verify blocked IP gets no response
- Test auto-expiry: set short block (60 seconds), verify auto-unblock
- Test whitelist protection: whitelist an IP, trigger attack from it, verify no alert
- Test blacklist cascade: add IP to blacklist, verify +20 score modifier

## Security Considerations
- Subprocess calls to iptables must use list args (not shell=True) to prevent command injection
- iptables changes require root — run protection module as privileged service, rest of app as normal user
- Email templates must sanitize all inserted data to prevent HTML injection in emails
- Rate limit block/unblock APIs to prevent DoS via repeated firewall rule changes

## Expected Deliverables
- Real-time alert center with WebSocket streaming
- Email notification system with queue and retry
- iptables-based automatic IP blocking
- Blacklist/whitelist management with bulk import/export
- 16 API endpoints

## Estimated Timeline
- Days 1–2: Alert center (CRUD, WebSocket, statistics)
- Days 3–4: Email system (templates, queue, retry)
- Days 5–6: IP blocking (iptables, temporary blocks, persistence)
- Day 7: Blacklist/whitelist management

## Success Criteria
- Alert appears on dashboard within 2 seconds of attack detection
- Email delivered within 30 seconds of CRITICAL alert
- iptables rule added within 1 second of auto-block decision
- Blocked IP gets no network response (verified with ping/curl)

---

<a name="phase-8"></a>
# PHASE 8: Search, Investigation & Reporting
**Duration:** Week 8–9 | **Complexity:** Medium-High | **Depends On:** Phase 3, Phase 4, Phase 7

---

## Objective
Build the investigation toolkit that enables security analysts to search packet logs, filter traffic by various criteria, investigate specific attack events in detail, and generate downloadable reports.

---

## Concepts to Learn Before Starting

- **Full-Text Search in PostgreSQL:** `tsvector`, `tsquery`, GIN indexes for text search; `pg_trgm` extension for fuzzy INET matching; `ILIKE` vs full-text for IP search
- **Database Query Optimization:** EXPLAIN ANALYZE to understand query plans; importance of composite indexes; covering indexes; pagination with LIMIT/OFFSET vs cursor-based pagination
- **ReportLab for PDF:** Python library for programmatic PDF generation; creating tables, charts, headers; embedding matplotlib charts as images in PDF
- **CSV Generation in Python:** `csv` module, streaming CSV for large exports (avoid loading 1M rows into memory), `io.StringIO` for in-memory CSV
- **Data Pagination:** Cursor-based pagination for large datasets (more efficient than OFFSET for millions of rows)
- **Matplotlib for Charts:** Creating time-series charts, bar charts, pie charts; saving as PNG bytes for PDF embedding

---

## Technologies Used
- PostgreSQL (full-text search, EXPLAIN ANALYZE)
- ReportLab (PDF generation)
- Matplotlib (charts for reports)
- Pandas (data manipulation for reports)
- Python csv module (CSV export)
- Flask (streaming responses for large file downloads)

---

## Milestone 8.1: Packet Search Engine

### Tasks
1. **Implement Multi-Parameter Packet Search**
   - Search by source IP (exact or CIDR range): `src_ip <<= network_cidr::inet`
   - Search by destination IP (exact or CIDR range)
   - Search by port number (source or destination)
   - Search by protocol (TCP/UDP/ICMP/HTTP/DNS)
   - Search by time range (from_datetime, to_datetime)
   - Search by packet size range (min_bytes, max_bytes)
   - Combine all filters with AND logic
   - Return paginated results (default 50/page, max 200/page)

2. **Implement Cursor-Based Pagination**
   - For packet_logs (potentially billions of rows), OFFSET pagination is too slow after page 1000
   - Use cursor: last seen packet ID as cursor
   - `WHERE id > {cursor} ORDER BY id LIMIT 50` — constant performance regardless of page number
   - Return next_cursor in API response for client to use

3. **Implement Search Indexing**
   - Verify composite indexes exist for all common search combinations
   - Add partial index for high-frequency search: all SYN packets in last 24 hours
   - Add pg_trgm extension for substring IP search (find all IPs matching "192.168")

4. **Implement Saved Searches**
   - Allow analysts to save frequently used search queries
   - Save: {name, filters, created_by, created_at}
   - Load saved search populates filter form automatically
   - Share saved searches with team members

---

## Milestone 8.2: Traffic Analysis Filters

### Tasks
1. **Implement Attack-Correlated Search**
   - Given an attack_event_id, retrieve all packet_logs that contributed to the attack detection
   - "Show me all packets from this attacker in the last 1 hour"
   - "Show me all packets targeting this victim IP"
   - Timeline view: packets in chronological order with attack detection markers

2. **Implement Protocol-Specific Filters**
   - HTTP filter: filter by method, status code, URI pattern, User-Agent
   - DNS filter: filter by query name, query type, response code
   - ICMP filter: filter by type and code
   - TCP filter: filter by specific flag combinations

3. **Implement Geolocation Filter**
   - Filter packets by source country
   - Filter packets by source ASN
   - Map-based filter: all traffic from specific geographic region

---

## Milestone 8.3: Attack Investigation Tools

### Tasks
1. **Implement Attack Timeline View**
   - Given attack_event_id: display chronological timeline of all evidence packets
   - Show packet-level details: flags, size, inter-arrival times
   - Highlight anomalous packets within the flow
   - Show detection trigger: which packet pushed the count over threshold

2. **Implement IP Investigation View**
   - Given IP address: show complete history
   - All attack_events involving this IP
   - All packet_logs from this IP (paginated)
   - Reputation score and sources
   - Geolocation and ASN information
   - Block history and current status
   - Similar IPs: same /24 subnet that have also been flagged

3. **Implement Network Flow Reconstruction**
   - Reconstruct TCP conversation between two IPs
   - Display packet sequence with direction (→ / ←)
   - Useful for investigating brute force: see all connection attempts
   - Export flow as Wireshark-compatible PCAP file

---

## Milestone 8.4: Reporting System

### Tasks
1. **Implement PDF Report Generator**
   - Executive Summary Report: 1-page overview, KPIs (total attacks, blocked IPs, most targeted services)
   - Incident Report: detailed single attack event, timeline, evidence, analyst notes, remediation steps
   - Weekly Security Report: attack trends, top attackers, anomaly statistics, ML model performance

   PDF structure for each report:
   - Header with logo and date range
   - Table of contents
   - Executive summary section
   - Data tables with attack details
   - Matplotlib charts: attack timeline, protocol distribution, severity pie chart
   - Footer with page numbers and classification

2. **Implement CSV Export**
   - Export attack_events to CSV (all columns or selected)
   - Export packet_logs to CSV with date range filter (streaming for large exports)
   - Export alerts to CSV with status filter
   - Export blocked IPs list
   - All exports include metadata header: generated_at, filters_applied, record_count

3. **Implement Report Scheduling**
   - Daily digest report: generated at 06:00 UTC, emailed to configured recipients
   - Weekly report: generated Monday 06:00 UTC
   - On-demand: generate any report immediately via API
   - Report history: store last 30 generated reports for download

4. **Implement Report API**
   - `GET /api/v1/reports/generate?type={type}&from={date}&to={date}` — Generate and return report
   - `GET /api/v1/reports/history` — List previous reports
   - `GET /api/v1/reports/{id}/download` — Download specific report
   - Large reports (>10MB) generated async: return job_id, poll for completion

---

## Folder Structure After Phase 8
```
app/
├── search/
│   ├── __init__.py
│   ├── packet_search.py         # Multi-parameter packet search
│   ├── attack_search.py         # Attack-correlated search
│   ├── saved_searches.py        # Saved search management
│   └── filters.py               # Filter validation and building
├── investigation/
│   ├── __init__.py
│   ├── timeline.py              # Attack timeline reconstruction
│   ├── ip_investigator.py       # IP history and profiling
│   └── flow_reconstructor.py    # TCP flow reconstruction
├── reports/
│   ├── __init__.py
│   ├── pdf_generator.py         # ReportLab PDF generation
│   ├── csv_exporter.py          # Streaming CSV export
│   ├── chart_builder.py         # Matplotlib chart generation
│   └── scheduler.py             # Report scheduling
```

## APIs Required
- `GET /api/v1/search/packets` — Packet search with filters
- `GET /api/v1/search/attacks` — Attack search with filters
- `POST /api/v1/search/saved` — Save a search
- `GET /api/v1/search/saved` — List saved searches
- `GET /api/v1/investigation/ip/{ip}` — IP investigation profile
- `GET /api/v1/investigation/attack/{id}/timeline` — Attack timeline
- `GET /api/v1/reports/generate` — Generate report
- `GET /api/v1/reports/history` — Report history
- `GET /api/v1/reports/{id}/download` — Download report

## Testing Strategy
- Test each search filter individually and in combination
- Test pagination: verify cursor correctly returns next page
- Test report generation: verify PDF is valid and contains correct data
- Test large export: export 100,000 packet records without memory error
- Performance test: packet search with date range returns in <3 seconds

## Security Considerations
- All search inputs validated and sanitized (prevent SQL injection via INET casting)
- Reports must be access-controlled: viewers can only download their own reports; analysts can share
- Streaming CSV exports must be rate-limited (can expose large amounts of data)

## Expected Deliverables
- Multi-parameter packet search with cursor pagination
- Attack investigation tools (timeline, IP profile, flow reconstruction)
- PDF and CSV report generation
- Report scheduling (daily/weekly)
- 9 API endpoints

## Estimated Timeline
- Days 1–2: Packet search engine
- Days 3–4: Attack investigation tools
- Days 5–7: PDF and CSV report generation

## Success Criteria
- Packet search returns results in <3 seconds for date ranges up to 7 days
- PDF report generated in <30 seconds
- CSV export of 1M rows streams without OOM error
- All search combinations return correct results

---

<a name="phase-9"></a>
# PHASE 9: Authentication & Dashboard
**Duration:** Week 9–10 | **Complexity:** High | **Depends On:** All previous phases

---

## Objective
Build the secure web dashboard with user authentication, role-based access control, and a complete visual interface for all system capabilities. This is the primary user touchpoint.

---

## Concepts to Learn Before Starting

- **Flask-Login:** User session management, `@login_required` decorator, `current_user`, remember-me tokens
- **Password Security:** bcrypt hashing (never MD5/SHA1 for passwords), password strength validation, HIBP API for breach checking
- **JWT Tokens:** Structure (header.payload.signature), when to use JWT vs sessions for APIs, token expiry and refresh
- **CSRF Protection:** Cross-site request forgery; Flask-WTF CSRF tokens; SameSite cookie attribute
- **Content Security Policy (CSP):** Browser security policy preventing XSS; define allowed script/style sources
- **JavaScript (ES6+):** Async/await, fetch API, WebSocket client (socket.io-client), DOM manipulation for live updates
- **Chart.js:** Interactive charts for traffic visualization; time-series data, real-time updates
- **Tailwind CSS or Bootstrap:** Rapid UI development; responsive design; dark theme for security dashboards

---

## Technologies Used
- Flask-Login, Flask-WTF (CSRF), Flask-Bcrypt
- PyJWT (API token authentication)
- Jinja2 (server-side templates)
- JavaScript + Chart.js + Socket.io-client
- Tailwind CSS (recommended) or Bootstrap 5

---

## Milestone 9.1: Authentication System

### Tasks
1. **Implement User Registration & Login**
   - Registration: username, email, password, role (admin creates accounts; no public registration)
   - Password requirements: 12+ chars, uppercase, lowercase, number, special character
   - bcrypt hashing: `bcrypt.generate_password_hash(password, rounds=12)`
   - Login: verify credentials, update last_login, reset failed_login_count on success

2. **Implement Account Lockout**
   - Track failed_login_count and locked_until in users table
   - Lock account for 15 minutes after 5 consecutive failures
   - Reset counter on successful login
   - Admin can manually unlock accounts via admin API

3. **Implement Session Management**
   - Flask-Login session: secure HttpOnly cookie, 8-hour timeout
   - Session fixation prevention: regenerate session ID on login
   - Concurrent session limit: max 3 active sessions per user; revoke oldest on 4th login
   - Session revocation: immediate logout all sessions for a user (admin capability)

4. **Implement API Token Authentication**
   - Generate JWT token on login for API access (for programmatic clients)
   - Token payload: {user_id, role, iat, exp (1 hour)}
   - Refresh token: longer-lived (7 days), stored in sessions table
   - Revoke token: add to in-memory revocation list (fast check before DB hit)

5. **Implement Two-Factor Authentication (2FA)**
   - TOTP-based (Google Authenticator compatible) using pyotp library
   - Enable 2FA: show QR code, verify first TOTP code, save encrypted secret
   - Login with 2FA: password → TOTP code (30-second window, allow 1 window drift)
   - Backup codes: generate 10 one-time backup codes on 2FA setup

---

## Milestone 9.2: Role-Based Access Control (RBAC)

### Tasks
1. **Implement Permission System**
   - Define permissions as constants: VIEW_ALERTS, ACKNOWLEDGE_ALERTS, CLOSE_ALERTS, VIEW_PACKETS, SEARCH_PACKETS, MANAGE_BLOCKS, MANAGE_WHITELIST, MANAGE_BLACKLIST, VIEW_REPORTS, GENERATE_REPORTS, MANAGE_USERS, MANAGE_SYSTEM_CONFIG, VIEW_AUDIT_LOGS
   - Role-permission mapping:
     - Viewer: VIEW_ALERTS, VIEW_PACKETS, VIEW_REPORTS
     - Analyst: All Viewer perms + ACKNOWLEDGE_ALERTS, CLOSE_ALERTS, SEARCH_PACKETS, GENERATE_REPORTS
     - Admin: All permissions

2. **Implement Permission Decorators**
   - `@require_permission('MANAGE_BLOCKS')` — check permission before route handler
   - `@require_role('admin')` — check role before route handler
   - Return 403 JSON for API routes, redirect to 403 page for web routes
   - Log unauthorized access attempts to audit_logs

3. **Implement Admin User Management**
   - Create/deactivate users (admin only)
   - Change user role (admin only)
   - View user list with last login, status, role
   - Force password reset (admin can trigger, user must reset on next login)
   - View user's active sessions and revoke specific sessions

---

## Milestone 9.3: Dashboard UI

### Tasks
1. **Implement Main Dashboard Page**
   - Live statistics widgets: packets/sec, alerts today, active blocks, threat score gauge
   - Real-time attack feed: last 20 alerts with severity color coding, live-updating via WebSocket
   - Traffic chart: Chart.js line chart, packets/sec over last 60 minutes, updates every 5 seconds
   - Protocol distribution: doughnut chart, updates every 30 seconds
   - Top Threats panel: top 5 active attacks by threat score
   - Recent Blocks: last 5 auto-blocked IPs

2. **Implement Alert Center Page**
   - Filterable alert table: columns: severity, type, source IP, score, status, time, assigned to
   - Filter bar: severity, status, time range, search by IP
   - Bulk operations: select multiple → acknowledge all / assign all
   - Alert detail modal: full attack details, timeline, evidence, comments, status controls
   - Real-time badge counter on tab/nav icon

3. **Implement Packet Monitor Page**
   - Live packet table (WebSocket feed): newest packets at top, pause/resume toggle
   - Protocol breakdown bar chart
   - Top talkers table: top 10 IPs by traffic volume
   - Search interface: all filters from Phase 8, with results table

4. **Implement Attack Investigation Page**
   - IP Lookup: enter IP → get full investigation profile (reputation, history, geolocation map)
   - Attack Timeline: visual timeline for specific attack events
   - Flow Reconstruction: display TCP conversation

5. **Implement Threat Intelligence Page**
   - ML Model status card: version, AUC, last trained, prediction count
   - Anomaly detection history: chart of anomaly scores over time
   - IP Reputation lookup widget
   - Blocklist/whitelist management tables with add/remove/import/export

6. **Implement Reports Page**
   - Report generator: select type, date range, generate button
   - Report history table with download links
   - Scheduled report configuration

7. **Implement Admin Panel**
   - User management table
   - System configuration: detection thresholds (sliders), email settings, capture interface
   - Audit log viewer
   - System health: database size, packet capture status, ML model status

---

## Folder Structure After Phase 9
```
app/
├── auth/
│   ├── __init__.py
│   ├── routes.py               # /login, /logout, /register, /2fa
│   ├── user_manager.py         # User CRUD, password handling
│   ├── session_manager.py      # Session lifecycle
│   ├── token_manager.py        # JWT handling
│   └── rbac.py                 # Permission system and decorators
├── dashboard/
│   ├── __init__.py
│   └── routes.py               # All page routes
├── static/
│   ├── css/
│   │   └── app.css
│   ├── js/
│   │   ├── dashboard.js        # Main dashboard WebSocket + Chart.js
│   │   ├── alerts.js
│   │   ├── packets.js
│   │   └── utils.js
│   └── img/
│       └── logo.svg
└── templates/
    ├── base.html               # Base template with nav, sidebar
    ├── auth/
    │   ├── login.html
    │   └── 2fa.html
    └── dashboard/
        ├── index.html          # Main dashboard
        ├── alerts.html
        ├── packets.html
        ├── investigation.html
        ├── intelligence.html
        ├── reports.html
        └── admin.html
```

## APIs Required
- `POST /auth/login` — Login
- `POST /auth/logout` — Logout
- `POST /auth/2fa/setup` — Enable 2FA
- `POST /auth/2fa/verify` — Verify TOTP
- `GET /api/v1/users` (admin) — List users
- `POST /api/v1/users` (admin) — Create user
- `PATCH /api/v1/users/{id}` (admin) — Update user role/status
- `DELETE /api/v1/users/{id}/sessions` (admin) — Revoke user sessions

## Testing Strategy
- Test login with correct, incorrect, and locked credentials
- Test RBAC: analyst cannot access admin endpoint (expect 403)
- Test CSRF: POST without CSRF token returns 400
- Test session timeout: session expires after 8 hours
- Test 2FA: correct and incorrect TOTP codes
- Cross-browser test: Chrome, Firefox, Safari

## Security Considerations
- Passwords hashed with bcrypt rounds=12 (not MD5, SHA1, or even SHA256)
- All dashboard routes behind `@login_required`
- CSRF tokens on all POST forms
- Content Security Policy header: `default-src 'self'; script-src 'self' cdn.jsdelivr.net`
- Secure + HttpOnly cookie flags
- No user passwords or tokens in logs

## Expected Deliverables
- Complete authentication system (login, 2FA, sessions, JWT)
- RBAC with 3 roles and 13 permissions
- 7 dashboard pages covering all system capabilities
- Responsive dark-themed security dashboard UI

## Estimated Timeline
- Days 1–3: Authentication system (login, 2FA, RBAC)
- Days 4–5: Dashboard main page and alert center
- Days 6–7: Packet monitor, investigation, admin panel

## Success Criteria
- Login works with bcrypt verification
- 2FA challenge blocks access without valid TOTP
- Viewer cannot see admin panel (403)
- Dashboard loads in <2 seconds
- Alert updates appear within 2 seconds via WebSocket

---

<a name="phase-10"></a>
# PHASE 10: System Integration & Testing
**Duration:** Week 11–12 | **Complexity:** High | **Depends On:** All Phases 1–9

---

## Objective
Integrate all modules into a cohesive system, perform comprehensive testing including unit tests, integration tests, attack simulation tests, and false positive analysis. Fix all integration bugs and verify end-to-end flows.

---

## Concepts to Learn Before Starting

- **Pytest:** Fixtures, parametrize, mock (unittest.mock), conftest.py for shared fixtures
- **Test Coverage:** pytest-cov for coverage reports; target >80% coverage
- **Integration Testing:** Testing multiple components working together, using Docker Compose test environment
- **Network Testing Tools:** Nmap, Hydra, hping3, Scapy for packet injection
- **PCAP Replay:** tcpreplay for replaying captured network traffic for reproducible tests
- **Wireshark:** Analyze captured traffic to verify detection is seeing what we think it sees
- **False Positive Analysis:** Statistical analysis of alert accuracy; building confusion matrix for IDS

---

## Milestone 10.1: Unit Testing

### Tasks
1. **Write Tests for All Detector Modules**
   - Port scan detector: inject SYN packets to 20 ports → verify alert generated; inject 5 ports → verify no alert
   - Brute force detector: simulate 10 failed SSH connections → verify alert; simulate 4 → verify no alert
   - DDoS detector: inject 1000 UDP/sec → verify alert; inject 100 → verify no alert
   - ML predictor: feed known attack feature vector → verify anomaly_score > 0.7

2. **Write Tests for Scoring Engine**
   - DDoS attack → verify score ≥ 70
   - Port scan → verify score between 25–45
   - Whitelisted IP → verify score = 0 always
   - IP on blacklist → verify +20 modifier applied

3. **Write Tests for Authentication**
   - Correct credentials → verify login succeeds
   - Wrong password × 5 → verify account locked
   - Expired JWT → verify 401 returned
   - CSRF missing → verify 400 returned

4. **Write Tests for Search**
   - Search by src_ip → verify only matching packets returned
   - Search by protocol = TCP → verify no UDP results
   - Combined filters → verify AND logic applied
   - Cursor pagination → verify page 2 returns correct records

---

## Milestone 10.2: Integration Testing

### Tasks
1. **Test Complete Packet-to-Alert Pipeline**
   - Start system → inject synthetic attack packets via Scapy → verify: packet captured → parsed → detection triggered → threat scored → alert created → WebSocket event emitted
   - Measure end-to-end latency: target <2 seconds from packet injection to alert creation

2. **Test Email Notification Pipeline**
   - CRITICAL attack detected → verify email queued → verify email sent within 30 seconds → verify email content correct (Mailhog SMTP for testing)

3. **Test IP Blocking Pipeline**
   - High-severity attack detected → verify auto-block triggered → verify iptables rule added → verify IP cannot reach system

4. **Test Database Cascade**
   - Delete user → verify user's alerts are not deleted (forensic data preserved), but user_id set to null
   - Delete attack_event → verify threat_score and alert also updated/deleted appropriately

---

## Milestone 10.3: Attack Simulation Testing

### Tasks
1. **Port Scan Simulation Suite**
   - Test 1: Nmap -sS -T4 (fast SYN scan) → must detect within 10 seconds
   - Test 2: Nmap -sS -T1 (slow/paranoid scan) → must detect within 5 minutes
   - Test 3: Nmap -sF (FIN scan) → must detect, even single packet
   - Test 4: Nmap -sV (service version scan) → must detect
   - Test 5: Scanning from 3 different IPs toward same target → must detect as distributed scan

2. **Brute Force Simulation Suite**
   - Test 1: Hydra SSH attack at 10 attempts/sec → detect after 6th attempt
   - Test 2: Hydra HTTP POST attack → detect after 11th attempt
   - Test 3: Slow brute force (1 attempt/minute over 30 minutes) → detect within 30 minutes
   - Test 4: Distributed brute force (5 IPs, 3 attempts each) → detect as campaign

3. **DDoS Simulation Suite (Isolated Test Network Only)**
   - Test 1: hping3 SYN flood at 1000 pps → detect within 5 seconds
   - Test 2: UDP flood → detect within 5 seconds
   - Test 3: HTTP flood using Apache Benchmark (ab -n 10000 -c 500) → detect within 30 seconds

4. **False Positive Test Suite**
   - 30-minute baseline: normal web browsing, file downloads, video streaming → zero alerts expected
   - Large file download (10GB) → traffic spike → verify no false DDoS alert
   - Port scanner scan own machine (loopback) → verify whitelisted, no alert
   - Nmap scan immediately after adding to whitelist → verify no alert

---

## Milestone 10.4: Performance Testing

### Tasks
1. **Packet Capture Performance**
   - Replay high-speed PCAP at 10k pps → verify <1% packet drop
   - Monitor memory usage over 4-hour run → verify no memory leak
   - Monitor CPU usage → should stay <70% at 10k pps

2. **Database Performance**
   - Query packet_logs with 10 million records → verify search returns in <5 seconds
   - Concurrent writes (10 worker threads) → verify no deadlocks
   - DB connection pool exhaustion → verify graceful degradation (queue rather than error)

3. **Dashboard Performance**
   - Load dashboard with 10,000 alerts in DB → page load <2 seconds
   - 50 concurrent WebSocket connections → all receive updates within 3 seconds

---

## Folder Structure After Phase 10
```
tests/
├── conftest.py                  # Fixtures: test DB, test packets, mock SMTP
├── unit/
│   ├── test_detection/
│   │   ├── test_port_scan.py
│   │   ├── test_brute_force.py
│   │   └── test_ddos.py
│   ├── test_scoring/
│   │   └── test_threat_scorer.py
│   ├── test_auth/
│   │   └── test_authentication.py
│   └── test_search/
│       └── test_packet_search.py
├── integration/
│   ├── test_packet_to_alert.py
│   ├── test_email_pipeline.py
│   └── test_block_pipeline.py
└── simulation/
    ├── attack_generator.py      # Synthetic attack packet generator
    └── test_attack_scenarios.py
```

## Testing Strategy
- Coverage target: >80% line coverage on detection modules, >70% overall
- All critical paths must have integration tests
- All attack simulation tests run in isolated Docker network (no external traffic)
- False positive rate target: <5% across all detection modules

## Security Considerations
- Attack simulation tests must run in isolated environment (cannot accidentally attack real systems)
- Test SMTP must be local (Mailhog) — no real email addresses in tests
- Test database must be separate from development database

## Expected Deliverables
- Complete test suite: unit + integration + simulation tests
- Coverage report showing >80% detection module coverage
- Attack simulation results document
- False positive rate analysis document
- List of all bugs found and fixed

## Estimated Timeline
- Days 1–3: Unit tests for all modules
- Days 4–5: Integration tests
- Days 6–7: Attack simulation testing and false positive analysis

## Success Criteria
- All unit tests pass
- End-to-end pipeline latency <2 seconds
- Attack simulation: 100% detection rate for standard attacks
- False positive rate <5% in 30-minute baseline test
- No memory leaks in 4-hour run

---

<a name="phase-11"></a>
# PHASE 11: Performance Optimization & Security Hardening
**Duration:** Week 13–14 | **Complexity:** High | **Depends On:** Phase 10

---

## Objective
Optimize system performance for production workloads and harden all security surfaces. Address bottlenecks identified in Phase 10 testing and apply industry-standard security hardening to the application, API, and infrastructure.

---

## Concepts to Learn Before Starting

- **PostgreSQL Query Optimization:** EXPLAIN ANALYZE output interpretation, index scan vs sequential scan, materialized views for expensive aggregations, VACUUM and ANALYZE
- **Python Profiling:** cProfile for CPU profiling, tracemalloc for memory profiling, line_profiler for line-level profiling
- **Caching Strategies:** Redis cache, cache-aside pattern, cache invalidation, TTL selection
- **Rate Limiting:** Token bucket algorithm, Flask-Limiter, per-user and per-IP rate limits
- **HTTP Security Headers:** HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy
- **Gunicorn + Nginx:** Production WSGI deployment, worker count configuration, upstream proxy, SSL termination

---

## Milestone 11.1: Database Optimization

### Tasks
1. **Query Optimization**
   - Run EXPLAIN ANALYZE on all 20+ API query patterns
   - Identify sequential scans on large tables and add appropriate indexes
   - Create materialized views for dashboard statistics (refresh every 5 minutes)
   - Rewrite N+1 queries: use SQLAlchemy joinedload() for related data
   - Add covering indexes for common search + sort patterns

2. **Connection Pool Tuning**
   - Profile connection wait times during peak load simulation
   - Tune pool_size and max_overflow based on actual concurrency observed
   - Add PgBouncer as connection pooler between application and PostgreSQL (transaction pooling mode)

3. **Data Archiving Pipeline**
   - Implement automated archiving: packet_logs older than 30 days → compressed CSV in /archive/
   - Drop old partitions after archiving (reclaim disk space)
   - Verify archive files are readable and complete before dropping partition

---

## Milestone 11.2: Application Performance

### Tasks
1. **Implement Redis Caching**
   - Cache: top-talkers, protocol distribution, dashboard statistics (TTL: 30 seconds)
   - Cache: IP reputation lookups (TTL: 24 hours)
   - Cache: user permissions (TTL: 5 minutes — invalidate on role change)
   - Implement cache warming: pre-populate cache at startup with frequently accessed data

2. **Optimize Packet Processing Pipeline**
   - Profile packet processing thread — identify slowest step
   - Batch database inserts already in place (Phase 3) — verify batch size is optimal
   - Consider moving detection state from Python dict to Redis (enables multiple workers in future)
   - Use memoryview objects instead of bytes copies for packet data

3. **Optimize Detection Modules**
   - Replace Python dict-based sliding windows with more efficient deque
   - Precompile IP address comparisons using Python's ipaddress module
   - Use NumPy for feature extraction vectorization in ML pipeline

---

## Milestone 11.3: API Security Hardening

### Tasks
1. **Implement Rate Limiting**
   - Login endpoint: 5 attempts per 15 minutes per IP
   - API endpoints: 1000 requests/hour per authenticated user
   - Search endpoints: 100 requests/minute per user (expensive DB queries)
   - WebSocket: 1 connection per user; reject additional connections
   - Return 429 Too Many Requests with Retry-After header

2. **Implement Input Validation**
   - All API inputs validated with Marshmallow or Pydantic schemas
   - IP address validation: reject malformed IPs before DB query
   - Date range validation: reject ranges >90 days (prevent expensive queries)
   - String field length limits on all text inputs
   - Enumerate-only fields (protocol, severity) validated against allowed values

3. **Implement HTTP Security Headers**
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
   - `Content-Security-Policy: default-src 'self'; ...`
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: camera=(), microphone=(), geolocation=()`

4. **Implement API Request Signing (Optional Advanced)**
   - HMAC-based request signing for programmatic API clients
   - Prevents replay attacks with timestamp nonce
   - Used by external integrations (SIEM tools, scripts)

---

## Milestone 11.4: Infrastructure Security Hardening

### Tasks
1. **Harden Docker Configuration**
   - Run application containers as non-root user
   - Use read-only root filesystem where possible
   - Drop all Linux capabilities except CAP_NET_RAW for capture container
   - Use Docker secrets for sensitive environment variables
   - Pin all base image versions (no :latest tags)

2. **Harden PostgreSQL**
   - Disable remote superuser access
   - Enable SSL for database connections
   - Create separate DB user for application (limited to application's tables only)
   - Enable pg_audit for database access auditing
   - Disable PostgreSQL logging of passwords (pg_log settings)

3. **Implement Log Security**
   - Logs stored with 640 permissions (owner:group read, others none)
   - Log rotation with secure deletion of rotated files
   - Ensure no sensitive data (passwords, full packet payloads) in logs
   - Implement log integrity: append-only rsyslog configuration

---

## Folder Structure After Phase 11
```
app/
├── core/
│   ├── cache.py                 # Redis cache client and decorators
│   └── rate_limiter.py          # Rate limiting configuration
├── middleware/
│   ├── security_headers.py      # HTTP security header middleware
│   └── request_validator.py     # Input validation middleware
docker/
├── Dockerfile                   # Updated with non-root user
├── docker-compose.yml           # Updated with security settings
└── nginx/
    ├── nginx.conf
    └── ssl/                     # SSL certificate location
```

## APIs Required
- `GET /api/v1/system/performance` (admin) — Current performance metrics
- `GET /api/v1/system/cache/stats` (admin) — Cache hit/miss rates

## Testing Strategy
- Re-run all attack simulation tests — verify no regressions from optimization
- Performance test: verify 10k pps with no packet drop after optimization
- Security scan: OWASP ZAP active scan against API — fix all HIGH and CRITICAL findings
- Header test: Mozilla Observatory or securityheaders.com — target A+ rating

## Security Considerations
- Every security header must be tested in browser (CSP violations appear in dev console)
- Rate limiting must be tested: verify 429 returned correctly
- Docker security scan: use `docker scout` or `trivy` to check image vulnerabilities

## Expected Deliverables
- Redis caching for all expensive operations
- Rate limiting on all API endpoints
- Full HTTP security header suite
- Docker security hardening
- Performance benchmarks: before vs after comparison
- OWASP ZAP scan report with all HIGH+ issues resolved

## Estimated Timeline
- Days 1–3: Database optimization (indexes, materialized views, PgBouncer)
- Days 4–5: Application caching and pipeline optimization
- Days 6–7: API security hardening and infrastructure hardening

## Success Criteria
- Dashboard page load: <2 seconds (down from any higher baseline)
- API response time: 95th percentile <200ms for all endpoints
- Zero HIGH or CRITICAL findings in OWASP ZAP scan
- Mozilla Observatory score: A+
- Docker image: zero CRITICAL CVEs (trivy scan)

---

<a name="phase-12"></a>
# PHASE 12: Deployment, Documentation & Future Enhancements
**Duration:** Week 15–16 | **Complexity:** Medium | **Depends On:** All phases

---

## Objective
Package the complete system for production deployment, write comprehensive documentation, and plan future enhancements. This phase transforms the project from "running on a laptop" to "deployable anywhere."

---

## Concepts to Learn Before Starting

- **Docker Multi-Stage Builds:** Reduce final image size; separate build and runtime dependencies
- **Docker Compose Production Config:** Override files, production environment variables, health checks
- **Nginx as Reverse Proxy:** SSL termination, proxy_pass to Gunicorn, static file serving, WebSocket proxying
- **Gunicorn:** WSGI server for Flask; worker types (sync, eventlet for SocketIO); worker count = (2 × CPU cores) + 1
- **Linux System Service (systemd):** Create .service file to run IDS as system service; auto-restart on failure
- **Markdown Documentation:** README standards, API documentation with request/response examples
- **Architecture Diagrams as Code:** Mermaid.js for diagrams in Markdown

---

## Milestone 12.1: Docker Production Setup

### Tasks
1. **Implement Multi-Service Docker Compose**
   Services: nginx, flask_app (2 replicas), packet_capture (privileged), celery_worker, redis, postgres, mailhog (dev only)
   - Define depends_on with health checks (postgres must be healthy before flask starts)
   - Named volumes: postgres_data, redis_data, ml_models, packet_archive, logs
   - Custom network: internal bridge, only nginx exposed to host

2. **Implement Multi-Stage Dockerfile**
   - Stage 1 (builder): install build dependencies, compile Python packages
   - Stage 2 (runtime): copy only compiled packages, no build tools; run as non-root user ids_user
   - Result: significantly smaller final image

3. **Implement Health Checks**
   - Flask app: `HEALTHCHECK GET /health` — checks DB, Redis connectivity
   - Postgres: `pg_isready` command
   - Redis: `redis-cli ping`
   - Packet capture: check if sniff thread is alive

4. **Implement Environment Configuration**
   - docker-compose.prod.yml with production overrides
   - docker-compose.dev.yml with development tools (Mailhog, pgAdmin)
   - .env.production.example with all required variables documented

---

## Milestone 12.2: Nginx & SSL Configuration

### Tasks
1. **Configure Nginx as Reverse Proxy**
   - Proxy HTTP → Gunicorn upstream
   - WebSocket proxy: `proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade"`
   - Static file serving: Nginx serves /static/ directly (bypasses Flask)
   - Rate limiting: Nginx-level rate limit on login endpoint (complements Flask rate limiting)

2. **Configure SSL/TLS**
   - Let's Encrypt with certbot for production (domain required)
   - Self-signed certificate generation script for development
   - TLS 1.2 minimum, TLS 1.3 preferred
   - Strong cipher suites; disable RC4, DES, 3DES
   - HSTS header: 1 year, includeSubDomains, preload

3. **Implement Nginx Security Hardening**
   - Hide Nginx version: `server_tokens off`
   - Limit request size: `client_max_body_size 10M` (prevent large upload attacks)
   - Request rate limiting: 10 req/sec per IP for API

---

## Milestone 12.3: Linux Production Deployment Guide

### Tasks
1. **Write Deployment Guide**
   - Server requirements: Ubuntu 22.04 LTS, 8GB RAM, 4 cores, 500GB SSD
   - Pre-deployment checklist: update system, create non-root deploy user, configure firewall (ufw)
   - Step-by-step: clone repo → configure .env → docker compose up → verify health → configure SSL

2. **Implement systemd Service**
   - Create `/etc/systemd/system/ids.service`
   - ExecStart: `docker compose -f docker-compose.prod.yml up`
   - Restart=on-failure, RestartSec=5
   - Auto-start on boot: `systemctl enable ids`

3. **Implement Backup & Restore**
   - Daily PostgreSQL backup: `pg_dump` to compressed .sql.gz file
   - Weekly backup to remote location (S3-compatible storage)
   - Backup retention: 7 daily, 4 weekly, 12 monthly
   - Restore procedure documented and tested

---

## Milestone 12.4: Documentation

### Tasks
1. **Write README.md**
   - Project overview with screenshots
   - Architecture diagram (Mermaid)
   - Quick start (Docker Compose): 3-command setup
   - Configuration reference: all .env variables explained
   - Module descriptions
   - Contributing guide

2. **Write API Documentation**
   - OpenAPI 3.0 specification (YAML) covering all endpoints
   - Generate interactive docs with Swagger UI or Redoc
   - Request/response examples for every endpoint
   - Authentication guide for API clients
   - Rate limit documentation

3. **Write Architecture Documentation**
   - System architecture guide explaining design decisions
   - Data flow walkthrough: trace a packet from capture to alert
   - ML model documentation: features, algorithm, retraining process
   - Security model documentation: threat model, controls, assumptions
   - Database schema documentation with ER diagram

4. **Write Operations Guide**
   - Log file locations and interpretation
   - Common issues and troubleshooting steps
   - Performance tuning guide
   - Backup and restore procedures
   - Alert threshold tuning guide

5. **Write Developer Guide**
   - Setting up development environment
   - Adding a new detection module (extension guide with template)
   - Running tests
   - Code style guide (follow PEP 8, use Black formatter)
   - Git workflow and commit message conventions

---

## Milestone 12.5: Future Enhancement Planning

### Document the following planned enhancements:
1. **IPv6 Full Support** — Current system has partial IPv6; full dual-stack monitoring
2. **SIEM Integration** — CEF/Syslog output format for Splunk/QRadar/Elastic SIEM
3. **Kubernetes Deployment** — Helm chart for K8s deployment; horizontal pod autoscaling for detection workers
4. **Deep Packet Inspection** — Layer 7 content inspection for malware signatures
5. **Encrypted Traffic Analysis** — JA3/JA3S fingerprinting to identify malicious TLS clients without decryption
6. **Network Forensics** — Full PCAP capture and storage for incident response (Zeek/Suricata integration)
7. **Threat Hunting** — Proactive query interface for hunting IoCs across historical data
8. **Multi-Sensor Architecture** — Deploy multiple capture sensors, centralize to single analysis backend
9. **SOAR Integration** — Automated playbooks triggered by alert types (Shuffle or XSOAR)
10. **Mobile Alert App** — Push notifications to mobile device for CRITICAL alerts

---

## Folder Structure — Final Complete Structure
```
ids_project/
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── extensions.py
│   ├── models/
│   ├── core/
│   ├── middleware/
│   ├── capture/
│   ├── detection/
│   ├── ml/
│   ├── intelligence/
│   ├── scoring/
│   ├── alerts/
│   ├── notifications/
│   ├── protection/
│   ├── search/
│   ├── investigation/
│   ├── reports/
│   ├── auth/
│   ├── dashboard/
│   ├── api/
│   │   └── v1/
│   ├── static/
│   └── templates/
├── migrations/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── simulation/
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── docker-compose.prod.yml
│   ├── docker-compose.dev.yml
│   └── nginx/
├── docs/
│   ├── architecture/
│   ├── api/
│   ├── operations/
│   └── developer/
├── scripts/
│   ├── backup.sh
│   ├── restore.sh
│   └── setup_dev.sh
├── .env.example
├── requirements.txt
├── requirements-dev.txt
├── openapi.yaml
└── README.md
```

---

<a name="architecture"></a>
# COMPLETE SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION LAYER                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │     NGINX (SSL Termination, Static Files, Rate Limiting)    │   │
│  └────────────────────────┬─────────────────────────────────────┘   │
│                           │                                         │
│  ┌────────────────────────▼─────────────────────────────────────┐   │
│  │                 FLASK APPLICATION (Gunicorn)                 │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐   │   │
│  │  │Dashboard │ │ REST API │ │Auth/RBAC │ │WebSocket(SocketIO)│  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘   │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                   │
┌─────────────────────────────────────────────────────────────────────┐
│                       DETECTION LAYER                               │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │               DETECTION ORCHESTRATOR                       │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐   │     │
│  │  │Port Scan │ │  Brute   │ │  DDoS    │ │  Traffic   │   │     │
│  │  │Detector  │ │  Force   │ │ Detector │ │  Pattern   │   │     │
│  │  │          │ │ Detector │ │          │ │  Analysis  │   │     │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬───────┘   │     │
│  └───────┼────────────┼────────────┼────────────┼────────────┘     │
│          └────────────┴────────────┴────────────┘                   │
│                               │                                     │
│  ┌────────────────────────────▼───────────────────────────────┐     │
│  │               INTELLIGENCE LAYER                           │     │
│  │  ┌──────────────────┐      ┌───────────────────────────┐   │     │
│  │  │ ML Anomaly Engine │      │    IP Reputation Checker  │   │     │
│  │  │ (Isolation Forest)│      │  (AbuseIPDB + Blacklists) │   │     │
│  │  └──────────┬────────┘      └────────────┬──────────────┘   │     │
│  └─────────────┼───────────────────────────┼────────────────┘     │
│                └───────────────────────────┘                       │
│                               │                                     │
│  ┌────────────────────────────▼───────────────────────────────┐     │
│  │               THREAT SCORING ENGINE                        │     │
│  │  Base Score + Rate Modifier + IP Reputation + ML Score    │     │
│  │  → Final Score (0–100) → Severity (LOW/MED/HIGH/CRITICAL) │     │
│  └────────────────────────────┬───────────────────────────────┘     │
└───────────────────────────────┼─────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                       RESPONSE LAYER                                │
│  ┌─────────────────────┐   ┌─────────────────┐  ┌────────────────┐ │
│  │   Alert Center      │   │ Email Notifier  │  │  IP Blocker    │ │
│  │  (WebSocket Push)   │   │  (SMTP Queue)   │  │  (iptables)    │ │
│  └─────────────────────┘   └─────────────────┘  └────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                       CAPTURE LAYER                                 │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │             PACKET CAPTURE ENGINE                            │   │
│  │  ┌────────────────┐         ┌──────────────────────────┐    │   │
│  │  │  Scapy Sniffer │         │   PyShark App-Layer      │    │   │
│  │  │  (Layer 2-4)   │         │   Capture (HTTP/DNS)     │    │   │
│  │  └────────┬───────┘         └──────────────────────────┘    │   │
│  │           │ Thread-Safe Queue (10,000 capacity)              │   │
│  │           ▼                                                  │   │
│  │  ┌─────────────────────────────────┐                        │   │
│  │  │   Protocol Parser + Enricher    │                        │   │
│  │  │   Flow Tracker + Feature Extract│                        │   │
│  │  └─────────────────────────────────┘                        │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                         Network Interface (eth0)                    │
└─────────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                       DATA LAYER                                    │
│  ┌─────────────────┐   ┌─────────────┐   ┌──────────────────────┐  │
│  │   PostgreSQL    │   │    Redis    │   │    File Storage      │  │
│  │  (Primary DB)   │   │   (Cache)   │   │  (ML Models/Archive) │  │
│  └─────────────────┘   └─────────────┘   └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

<a name="er-diagram"></a>
# DATABASE ER DIAGRAM (Key Relationships)

```
users (1) ──────────────────── (*) sessions
  │                                     
  │ (1)                                 
  ├──────────── (*) alerts              
  │               │                    
  │               │ (1)                
  │               └──── (*) alert_comments
  │                                    
  │ (1)                                
  ├──────────── (*) audit_logs         
  │                                    
  │ (1)                                
  ├──────────── (*) ip_blocks          
  │                                    
  │ (1)                                
  ├──────────── (*) blacklist          
  │                                    
  └──────────── (*) whitelist          
                                       
attack_events (1) ──────────── (1) port_scan_details
      │ (1) ──────────────────── (1) brute_force_details
      │ (1) ──────────────────── (1) ddos_details
      │                                   
      │ (1)                               
      ├──────────── (1) threat_scores     
      │                   │              
      │                   │ (1)          
      │                   └──── (1) alerts
      │                                   
      │ (1)                               
      └──────────── (*) ml_predictions   
                                       
packet_logs (*) ── [partitioned by month]

ip_reputation (standalone, keyed by INET address)
protocol_stats (standalone, time-series)
system_stats (standalone, time-series)
email_notifications (*) → (1) alerts
```

---

<a name="api-blueprint"></a>
# COMPLETE API BLUEPRINT

## Authentication Endpoints
```
POST   /auth/login                    Login with username/password
POST   /auth/logout                   Logout (revoke session)
POST   /auth/2fa/setup                Enable 2FA (admin/analyst)
POST   /auth/2fa/verify               Verify TOTP code during login
POST   /auth/password/change          Change own password
```

## Packet Monitoring Endpoints
```
GET    /api/v1/packets/live           Live packet statistics (last 60s)
GET    /api/v1/packets/protocols      Protocol distribution
GET    /api/v1/packets/top-talkers    Top 10 source IPs by volume
GET    /api/v1/packets/stats          Current pps, bps metrics
GET    /api/v1/capture/status         Capture engine status
POST   /api/v1/capture/start          Start packet capture [admin]
POST   /api/v1/capture/stop           Stop packet capture [admin]
```

## Attack & Detection Endpoints
```
GET    /api/v1/attacks                List attack events (with filters)
GET    /api/v1/attacks/{id}           Attack event details
PATCH  /api/v1/attacks/{id}/status    Update attack status [analyst+]
GET    /api/v1/attacks/stats          Attack count by type/severity
GET    /api/v1/attacks/active         Currently active attacks
```

## Threat Intelligence Endpoints
```
GET    /api/v1/reputation/{ip}        IP reputation data
POST   /api/v1/reputation/check-bulk  Check multiple IPs
POST   /api/v1/reputation/{ip}/override  Manual reputation override [admin]
GET    /api/v1/ml/model/status        ML model version and metrics
POST   /api/v1/ml/model/retrain       Trigger model retraining [admin]
```

## Threat Scoring Endpoints
```
GET    /api/v1/threats/score/{attack_event_id}  Score breakdown
GET    /api/v1/threats/high-priority            Active HIGH/CRITICAL threats
GET    /api/v1/threats/statistics               Score distribution data
```

## Alert Endpoints
```
GET    /api/v1/alerts                 List alerts (with filters)
GET    /api/v1/alerts/{id}            Alert details
PATCH  /api/v1/alerts/{id}/status     Update status [analyst+]
POST   /api/v1/alerts/{id}/comment    Add comment [analyst+]
POST   /api/v1/alerts/bulk-acknowledge  Bulk acknowledge [analyst+]
GET    /api/v1/alerts/statistics      MTTA, MTTR, false positive rate
```

## Protection Endpoints
```
GET    /api/v1/blocks                 List active IP blocks
POST   /api/v1/blocks                 Manual block IP [analyst+]
DELETE /api/v1/blocks/{ip}            Unblock IP [analyst+]
GET    /api/v1/blacklist              Get blacklist
POST   /api/v1/blacklist              Add to blacklist [analyst+]
POST   /api/v1/blacklist/import       Import CSV blacklist [admin]
DELETE /api/v1/blacklist/{ip}         Remove from blacklist [admin]
GET    /api/v1/whitelist              Get whitelist
POST   /api/v1/whitelist              Add to whitelist [admin]
DELETE /api/v1/whitelist/{ip}         Remove from whitelist [admin]
```

## Search Endpoints
```
GET    /api/v1/search/packets         Search packet logs (multi-filter)
GET    /api/v1/search/attacks         Search attack events (multi-filter)
POST   /api/v1/search/saved           Save a search query [analyst+]
GET    /api/v1/search/saved           List saved searches
```

## Investigation Endpoints
```
GET    /api/v1/investigation/ip/{ip}           IP investigation profile
GET    /api/v1/investigation/attack/{id}/timeline  Attack timeline
GET    /api/v1/investigation/flow/{src}/{dst}   TCP flow reconstruction
```

## Reporting Endpoints
```
GET    /api/v1/reports/generate       Generate report (type, date range)
GET    /api/v1/reports/history        List generated reports
GET    /api/v1/reports/{id}/download  Download report file
```

## Administration Endpoints
```
GET    /api/v1/users                  List users [admin]
POST   /api/v1/users                  Create user [admin]
PATCH  /api/v1/users/{id}             Update user [admin]
DELETE /api/v1/users/{id}/sessions    Revoke user sessions [admin]
GET    /api/v1/config/thresholds      Get detection thresholds [admin]
PATCH  /api/v1/config/thresholds      Update thresholds [admin]
GET    /api/v1/audit/logs             View audit logs [admin]
GET    /api/v1/system/health          System health status
GET    /api/v1/system/performance     Performance metrics [admin]
POST   /api/v1/notifications/test-email  Send test email [admin]
```

## WebSocket Events (Flask-SocketIO)
```
Namespace: /alerts
  Server → Client:
    new_alert        {alert_id, title, severity, source_ip, threat_score, created_at}
    alert_updated    {alert_id, status, updated_at}
    ip_blocked       {ip, reason, threat_score, blocked_at}

Namespace: /packets
  Server → Client:
    packet_event     {protocol, src_ip, dst_ip, src_port, dst_port, size, timestamp}
    traffic_stats    {pps, bps, protocol_dist, top_talkers, timestamp}
```

---

<a name="timeline"></a>
# WEEK-BY-WEEK TIMELINE

```
WEEK 1:  Phase 1 + Phase 2 (start)
  Mon-Tue: Requirements, architecture diagrams, STRIDE threat model
  Wed-Thu: Project structure, Flask factory, configuration
  Fri-Sun: Database schema design, model definitions

WEEK 2:  Phase 2 (finish) + Phase 3 (start)
  Mon-Tue: Alembic migrations, seed data, Docker setup
  Wed-Thu: Scapy capture engine, packet queue
  Fri-Sun: Protocol parser, TCP flag parser, feature extractor

WEEK 3:  Phase 3 (finish) + Phase 4 (start)
  Mon-Tue: Batch writer, statistics aggregator, capture APIs
  Wed-Thu: Detection framework (BaseDetector, Orchestrator, StateManager)
  Fri-Sun: Port scan detection (SYN, stealth, UDP)

WEEK 4:  Phase 4 (finish)
  Mon-Tue: Brute force detection (SSH, HTTP, distributed)
  Wed-Thu: Traffic pattern analysis, baseline builder
  Fri-Sun: DDoS detection, severity classifier, detection APIs

WEEK 5:  Phase 5 (Feature Engineering + Training)
  Mon-Tue: Flow feature extractor (25 features), feature store
  Wed-Thu: Training dataset creation, Isolation Forest training
  Fri-Sun: Inference engine, model versioning, drift detection

WEEK 6:  Phase 5 (finish) + Phase 6
  Mon-Tue: IP reputation system (AbuseIPDB + blocklists)
  Wed-Thu: Threat scoring algorithm, modifier system
  Fri-Sun: Alert prioritization, response engine, score decay

WEEK 7:  Phase 7 (start)
  Mon-Tue: Alert center (CRUD, WebSocket streaming)
  Wed-Thu: Email notification system (templates, queue, retry)
  Fri-Sun: Automatic IP blocking (iptables rules, persistence)

WEEK 8:  Phase 7 (finish) + Phase 8 (start)
  Mon-Tue: Blacklist/whitelist management
  Wed-Thu: Packet search engine (multi-filter, cursor pagination)
  Fri-Sun: Attack investigation tools (timeline, IP profiler)

WEEK 9:  Phase 8 (finish) + Phase 9 (start)
  Mon-Tue: PDF report generator, CSV exporter, report scheduling
  Wed-Thu: Authentication system (login, bcrypt, session management)
  Fri-Sun: 2FA implementation, JWT API tokens

WEEK 10: Phase 9 (finish)
  Mon-Tue: RBAC permission system, decorators, admin user management
  Wed-Thu: Dashboard UI (main page, alert center, packet monitor)
  Fri-Sun: Investigation page, admin panel, responsive design

WEEK 11: Phase 10
  Mon-Tue: Unit tests for all detection modules
  Wed-Thu: Integration tests (pipeline tests)
  Fri-Sun: Attack simulation testing (Nmap, Hydra, hping3)

WEEK 12: Phase 10 (finish) + Phase 11 (start)
  Mon-Tue: False positive analysis, bug fixing
  Wed-Thu: Database optimization (indexes, materialized views, PgBouncer)
  Fri-Sun: Redis caching, packet pipeline optimization

WEEK 13: Phase 11 (finish)
  Mon-Tue: API security hardening (rate limiting, input validation)
  Wed-Thu: HTTP security headers, Docker hardening
  Fri-Sun: OWASP ZAP scan, security fix pass

WEEK 14: Phase 12 (start)
  Mon-Tue: Docker multi-stage build, production compose
  Wed-Thu: Nginx SSL configuration, systemd service
  Fri-Sun: Backup/restore scripts, deployment testing

WEEK 15: Phase 12 (finish)
  Mon-Tue: README, API documentation (OpenAPI 3.0)
  Wed-Thu: Architecture documentation, operations guide
  Fri-Sun: Developer guide, final review

WEEK 16: Polish & Demo Prep
  Mon-Tue: Final bug fixes, performance verification
  Wed-Thu: Demo environment setup, portfolio screenshots
  Fri-Sun: GitHub cleanup, tag v1.0.0 release
```

---

<a name="repo-structure"></a>
# GITHUB REPOSITORY STRUCTURE

```
ids_project/                         # Root
├── README.md                        # Project overview, screenshots, quickstart
├── CONTRIBUTING.md                  # How to contribute
├── CHANGELOG.md                     # Version history
├── LICENSE                          # MIT or Apache 2.0
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                   # GitHub Actions: test + lint on PR
│   │   └── security-scan.yml        # Trivy image scan on push
│   └── PULL_REQUEST_TEMPLATE.md
├── app/                             # Main application package
├── migrations/                      # Alembic migrations
├── tests/                           # All test files
├── docker/                          # Docker configs
├── docs/                            # Documentation
├── scripts/                         # Utility scripts
├── .env.example                     # Environment variable template
├── requirements.txt                 # Production dependencies (pinned)
├── requirements-dev.txt             # Development/test dependencies
├── openapi.yaml                     # Full API specification
├── pytest.ini                       # Pytest configuration
├── .flake8                          # Linting configuration
└── pyproject.toml                   # Black formatter, isort config
```

### GitHub Actions CI Pipeline
```yaml
# On every PR: lint → test → coverage check
# On merge to main: build Docker image → security scan → push to registry
# Weekly: dependency vulnerability scan (Safety/Dependabot)
```

---

<a name="resume"></a>
# RESUME-WORTHY FEATURES

## Technical Achievements to Highlight

1. **Real-Time Packet Analysis Engine**
   *"Built a packet capture engine using Scapy and PyShark processing 10,000+ packets/second with <1% packet loss, utilizing a thread-safe producer-consumer architecture with async batch PostgreSQL writes"*

2. **Multi-Vector Attack Detection**
   *"Implemented 5 distinct attack detection algorithms (SYN/stealth/UDP port scan, multi-service brute force, DDoS flooding, traffic anomaly, ML-based) with configurable thresholds and <2 second detection latency"*

3. **Machine Learning Anomaly Detection**
   *"Trained an Isolation Forest model on 25 network flow features achieving AUC > 0.85; implemented online retraining pipeline with concept drift detection and model versioning"*

4. **Automated Threat Response**
   *"Built automated incident response pipeline: threat scoring (0–100 scale) → priority alerting → iptables-based IP blocking, reducing response time from minutes to under 5 seconds for critical threats"*

5. **Production-Grade Security**
   *"Applied OWASP security hardening: bcrypt password hashing, JWT authentication, RBAC with 13 granular permissions, CSRF protection, rate limiting, full HTTP security headers achieving A+ Mozilla Observatory score"*

6. **Full-Stack Security Dashboard**
   *"Designed and built a real-time security dashboard with WebSocket live updates (Flask-SocketIO), interactive Chart.js traffic visualization, and PDF/CSV report generation serving 3 user roles"*

7. **Containerized Microservice Architecture**
   *"Deployed using Docker Compose with 6 services (Nginx, Flask/Gunicorn, PostgreSQL, Redis, Packet Capture, Celery), multi-stage builds, health checks, and non-root container execution"*

---

<a name="interview"></a>
# INTERVIEW QUESTIONS & ANSWERS

## Network Security Fundamentals

**Q: How does your SYN scan detector distinguish between a port scan and legitimate connection attempts?**

A: Legitimate connections attempt SYN to a specific port and then complete the handshake (SYN → SYN-ACK → ACK). Port scanners, particularly Nmap in SYN mode, send SYN packets to many different destination ports from the same source IP without completing the handshake. My detector uses a sliding time window (10 seconds) and triggers when the same source IP sends SYN packets to more than 15 unique destination ports within that window. The key differentiator is *unique destination port count*, not total SYN count — a legitimate busy server might receive thousands of SYNs, but they go to the same port (e.g., port 443).

**Q: How did you handle evasion techniques like slow port scans?**

A: Standard threshold detection fails against slow scans because the attacker spaces probes below the per-window threshold. I implemented dual-window detection: a short window (10 seconds) for fast scans and a long window (5 minutes) for slow scans with a lower threshold (>8 unique ports in 5 minutes). I also implemented a persistent tracking dictionary that accumulates evidence across windows, so a scan at 1 probe/minute across 30 minutes is still detected.

## System Design

**Q: How did you design the system to handle 10,000 packets per second without dropping packets?**

A: Three key decisions: First, I run packet capture in a completely dedicated thread using Scapy's sniff() — this thread does nothing except capture and enqueue packets. Second, I use a thread-safe queue as a buffer between capture and processing — if processing momentarily falls behind, packets queue up rather than drop. Third, I use async batch inserts rather than individual ORM inserts — batching 500 packets per DB write at 500ms intervals reduces DB round trips by 100x. The capture thread is never blocked by slow DB operations.

**Q: Why did you use an Isolation Forest instead of a supervised classifier?**

A: In production IDS environments, you rarely have reliable labeled attack data. Supervised models require labeled examples of every attack type you want to detect — but unknown attacks won't be in your training set. Isolation Forest is unsupervised: it learns what "normal" looks like and flags deviations. This means it can potentially detect novel attacks. The tradeoff is higher false positive rate, which I mitigated by using it as a *modifier* to the rule-based scoring rather than a standalone alert trigger.

## Security Architecture

**Q: How did you prevent the IP blocking system from being abused to block legitimate IPs?**

A: Multiple layers: First, the whitelist check is the absolute last gate before any block — if an IP is whitelisted, it can never be blocked regardless of threat score. Second, I implemented safeguards that prevent blocking the admin's current session IP, localhost, and any RFC 1918 private address. Third, automatic blocks are only triggered at CRITICAL score (≥75) — this requires a combination of signals (attack type + IP reputation + ML signal), not a single indicator. Fourth, all blocks are logged to audit_logs with full reasoning, enabling rapid review and reversal.

**Q: What security vulnerabilities did you specifically defend against in your dashboard?**

A: SQLi: all database queries use parameterized statements via SQLAlchemy ORM. XSS: Jinja2 auto-escaping on all template variables; CSP header blocks inline scripts. CSRF: Flask-WTF CSRF tokens on all POST forms. Session fixation: session ID regenerated on login. Brute force on own login: account lockout after 5 failures + rate limiting via Flask-Limiter. Privilege escalation: RBAC decorators on every route that checks permission at runtime, not cached at login. Command injection in iptables calls: subprocess.run() with list args, never shell=True.

---

<a name="future"></a>
# INDUSTRY-LEVEL FUTURE ENHANCEMENTS

## Tier 1: Near-Term (3–6 Months)

### 1. SIEM Integration
- Output alerts in CEF (Common Event Format) or JSON via syslog
- Direct integration with Splunk (HTTP Event Collector), Elastic (Logstash), QRadar
- Enables correlating IDS events with other security tools

### 2. Threat Hunting Interface
- SQL-like query language for hunting IoCs across historical data
- "Find all IPs that contacted port 4444 in the last 30 days" (common C2 port)
- Saved hunt templates for common threat actor TTPs (MITRE ATT&CK mapping)

### 3. MITRE ATT&CK Framework Mapping
- Map each detection to ATT&CK technique IDs (e.g., port scan = T1046 Network Service Discovery)
- Display ATT&CK navigator heatmap showing which techniques you detect vs miss
- Gap analysis: highlight attack techniques with no current detection coverage

## Tier 2: Medium-Term (6–12 Months)

### 4. Encrypted Traffic Analysis (JA3/JA3S Fingerprinting)
- Identify malicious TLS clients by SSL/TLS handshake fingerprint without decryption
- JA3 hash identifies: TLS version, ciphers, extensions, elliptic curves
- Known JA3 hashes for Cobalt Strike, Metasploit, common malware families
- Zero performance impact — metadata only, no DPI required

### 5. Kubernetes Deployment
- Helm chart for complete IDS deployment on K8s
- Horizontal Pod Autoscaler for detection worker pods based on queue depth
- StatefulSet for PostgreSQL with persistent volumes
- ConfigMap/Secrets for configuration management

### 6. Multi-Sensor Architecture
- Deploy lightweight capture sensors at multiple network segments (DMZ, internal, cloud)
- Sensors forward enriched flow data to central analysis server
- Eliminates blind spots in segmented networks
- Sensor authentication with mutual TLS

## Tier 3: Advanced (12+ Months)

### 7. SOAR (Security Orchestration, Automation, Response)
- Playbook automation triggered by alert types
- Example playbook: DDoS detected → query threat intel → block IPs → notify team → create ticket in Jira → update firewall rules → track resolution time
- Integration with Shuffle (open-source SOAR) or Palo Alto XSOAR
- Reduce mean time to respond from minutes to seconds

### 8. Network Behavioral Analysis
- Build per-device behavioral profiles: "This server normally receives HTTP, SSH; seeing RDP is anomalous"
- Detect lateral movement: internal IP scanning internal IPs (post-compromise behavior)
- Detect data exfiltration: unusually large outbound transfers to unusual destinations

### 9. Deep Packet Inspection with Malware Signature Matching
- Integrate Suricata rules for payload signature matching
- Detect known malware C2 communication patterns in packet payloads
- Match against Emerging Threats ruleset (50,000+ rules)
- Sandbox integration: suspicious files extracted from HTTP sessions → VirusTotal scan

### 10. Federated Threat Intelligence
- Share anonymized IoCs with partner organizations
- Receive community threat feeds in real-time
- Contribute to ISAC (Information Sharing and Analysis Center)
- STIX/TAXII protocol for standardized threat indicator exchange

---

*End of Roadmap | Version 1.0 | Network Traffic Monitoring & Attack Detection System*
*Total Estimated Development Time: 16 Weeks | 15 Modules | 12 Phases | 40+ API Endpoints*
