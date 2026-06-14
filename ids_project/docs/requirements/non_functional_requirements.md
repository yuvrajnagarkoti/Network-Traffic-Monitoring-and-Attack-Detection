# Non-Functional Requirements

> **Network Traffic Monitoring & Attack Detection System**
> Version 1.0 | Phase 1 — Milestone 1.1

---

## 1. Performance Requirements

### 1.1 Packet Processing Throughput
| Metric | Requirement | Measurement Method |
|--------|------------|-------------------|
| **Sustained capture rate** | ≥10,000 packets/second | Replay high-rate PCAP, measure captured vs source count |
| **Packet drop rate** | <1% at 10k pps | Monitor kernel drop counter + queue overflow counter |
| **Parse latency (per packet)** | <500 µs average | Profile PacketParser.parse() across 100k packets |
| **Batch insert latency** | <1 second per batch (500 packets) | Measure SQLAlchemy bulk_insert_mappings() execution time |
| **Queue depth tolerance** | 10,000 packets in-flight | Queue.maxsize=10000; monitor fill rate |

### 1.2 Detection Latency
| Metric | Requirement |
|--------|------------|
| **Rule-based detection** | Alert generated within 2 seconds of threshold breach |
| **ML inference** | Prediction within 500ms per batch (100 flow vectors) |
| **Threat scoring** | Score calculated within 200ms of attack event creation |
| **Alert delivery (WebSocket)** | Dashboard receives alert within 1 second of creation |
| **Email alert dispatch** | Queued within 5 seconds; delivered within 30 seconds of CRITICAL detection |

### 1.3 API Response Times
| Endpoint Category | 95th Percentile Target |
|------------------|----------------------|
| Dashboard statistics | <200ms |
| Alert list (paginated) | <300ms |
| Packet search (date-scoped) | <3 seconds |
| Report generation (PDF) | <30 seconds |
| IP reputation lookup (cached) | <50ms |
| IP reputation lookup (API) | <2 seconds |

### 1.4 Dashboard Performance
| Metric | Requirement |
|--------|------------|
| Initial page load | <2 seconds |
| WebSocket reconnection | <3 seconds |
| Chart update interval | 5 seconds (traffic chart), 30 seconds (protocol chart) |
| Concurrent WebSocket connections | ≥50 simultaneous clients |

---

## 2. Availability Requirements

| Metric | Requirement |
|--------|------------|
| **Monitoring daemon uptime** | 99.5% (allows ~3.65 hours downtime/month) |
| **Dashboard availability** | 99.0% (maintenance windows permitted) |
| **Graceful degradation** | If database is temporarily unreachable, buffer up to 50k packets in memory |
| **Auto-restart** | systemd restarts application within 5 seconds of crash |
| **Health check interval** | Docker health check every 30 seconds |

---

## 3. Storage Requirements

### 3.1 Data Retention Policies
| Data Type | Retention Period | Storage Tier |
|-----------|-----------------|-------------|
| Raw packet logs | 30 days | PostgreSQL (partitioned by month) |
| Attack events | 1 year | PostgreSQL (standard tables) |
| Threat scores | 1 year | PostgreSQL |
| Alerts | 1 year | PostgreSQL |
| Audit logs | 2 years (compliance) | PostgreSQL (append-only) |
| System statistics | 90 days | PostgreSQL (time-series) |
| ML model files | Last 3 versions | File system |
| Generated reports | 30 days | File system |
| Archived packet logs | 1 year | Compressed CSV (cold storage) |

### 3.2 Storage Capacity Estimates
| Component | Estimated Size (per day) | 30-day Total |
|-----------|-------------------------|-------------|
| packet_logs (10k pps sustained) | ~8.6 GB | ~258 GB |
| packet_logs (1k pps typical) | ~860 MB | ~25.8 GB |
| attack_events + details | ~10 MB | ~300 MB |
| system_stats (1-min buckets) | ~5 MB | ~150 MB |
| audit_logs | ~2 MB | ~60 MB |
| ML feature vectors | ~50 MB | ~1.5 GB |

### 3.3 Database Sizing
| Configuration | Recommended |
|--------------|-------------|
| **Minimum disk** | 500 GB SSD |
| **Recommended disk** | 1 TB SSD (NVMe preferred) |
| **PostgreSQL shared_buffers** | 256 MB (¼ of available RAM) |
| **PostgreSQL work_mem** | 16 MB |
| **PostgreSQL max_connections** | 200 |
| **Connection pool (SQLAlchemy)** | pool_size=10, max_overflow=20 |

---

## 4. Scalability Requirements

### 4.1 Horizontal Scaling Design
| Component | Scaling Strategy |
|-----------|-----------------|
| **Packet capture** | Single instance per network interface; multiple interfaces via configuration |
| **Detection modules** | Thread pool (4–8 workers); designed for future process-based parallelism |
| **API/Dashboard** | Multiple Gunicorn workers behind Nginx; session shared via Redis |
| **Database** | Read replicas for dashboard queries; write primary for packet inserts |
| **Detection state** | In-memory dict → Redis migration path for multi-worker scaling |

### 4.2 Growth Capacity
| Metric | Current Design | Growth Path |
|--------|---------------|-------------|
| Packets/second | 10k sustained | Packet sampling above threshold; Redis-backed state for multi-process |
| Tracked source IPs | 100,000 max | LRU eviction; sharded tracking per detection module |
| Concurrent users | 50 WebSocket | Redis pub/sub for cross-worker broadcasting |
| Database size | Single PostgreSQL | TimescaleDB extension for time-series; read replicas |

---

## 5. Reliability Requirements

| Requirement | Implementation |
|-------------|---------------|
| **No data loss on crash** | Write-ahead buffer for packet inserts; flush before shutdown |
| **Transaction integrity** | All multi-table writes in database transactions |
| **Idempotent operations** | Duplicate packet deduction (SHA-256 hash); attack event deduplication |
| **Error isolation** | Single detector failure does not crash other detectors or capture |
| **Logging on failure** | All exceptions logged with full stack trace and context |

---

## 6. Security Requirements (Non-Functional)

| Requirement | Specification |
|-------------|--------------|
| **Encryption at rest** | PostgreSQL tablespace encryption (optional, OS-level) |
| **Encryption in transit** | TLS 1.2+ for all HTTP/WebSocket connections |
| **Password storage** | bcrypt with 12 rounds; never plaintext, MD5, or SHA |
| **Session timeout** | 8 hours inactivity; 24 hours absolute maximum |
| **Account lockout** | 15-minute lock after 5 consecutive failed logins |
| **Audit trail** | All admin actions logged with user ID, IP, timestamp, old/new values |
| **Least privilege** | Database user has no DROP/CREATE permissions in production |
| **Secret management** | All secrets via environment variables; never in code or logs |

---

## 7. Maintainability Requirements

| Requirement | Specification |
|-------------|--------------|
| **Code structure** | Flask Application Factory pattern; Blueprint-based route organization |
| **Dependency management** | Pinned versions in requirements.txt; separate dev dependencies |
| **Database migrations** | Alembic with reversible up/down migrations |
| **Configuration** | Environment-based (development, testing, production); YAML for thresholds |
| **Logging** | Structured JSON logging; rotating file handlers (10 MB max, 5 backups) |
| **Testing** | >80% coverage on detection modules; >70% overall |
| **Documentation** | API docs (OpenAPI 3.0); architecture docs; operations guide |

---

## 8. Compatibility Requirements

| Requirement | Specification |
|-------------|--------------|
| **Operating system** | Ubuntu 22.04 LTS (primary); Debian 12 (supported) |
| **Python version** | 3.11+ |
| **PostgreSQL version** | 15+ |
| **Browser support** | Chrome 100+, Firefox 100+, Safari 16+, Edge 100+ |
| **Docker** | Docker Engine 24+, Docker Compose v2 |
| **Network** | IPv4 (full support); IPv6 (partial — capture only) |
