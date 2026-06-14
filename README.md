# Network Traffic Monitoring & Attack Detection System

> **A full-stack cybersecurity platform for real-time network intrusion detection, threat scoring, and automated response.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Week](https://img.shields.io/badge/Week%201-✅%20Complete-success.svg)](#week-1-progress)

---

## 📋 Project Overview

This is a **16-week development project** building a production-grade Network Intrusion Detection System (IDS) from scratch. The system monitors live network traffic, detects attacks in real time, and provides an interactive security dashboard.

### Key Capabilities

| Feature | Description |
|---------|-------------|
| 📡 **Real-time Capture** | Scapy + PyShark capturing 10,000+ packets/second |
| 🔍 **Attack Detection** | Port scan, brute force, DDoS, traffic anomaly detection |
| 🤖 **ML Engine** | Isolation Forest anomaly detection with online learning |
| 🧠 **Threat Intelligence** | AbuseIPDB IP reputation + GeoIP enrichment |
| 📊 **Threat Scoring** | 0–100 scoring with auto severity classification |
| 🚨 **Auto Response** | Email alerts + iptables IP blocking |
| 🖥️ **Live Dashboard** | WebSocket-powered real-time visualization |
| 📄 **Reporting** | PDF/CSV export with investigation tools |
| 🔐 **Auth & RBAC** | bcrypt + JWT + TOTP 2FA, 3-tier role system |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                        │
│     Nginx → Flask/Gunicorn → Dashboard + REST API           │
│     WebSocket (Flask-SocketIO) for live alert streaming      │
├─────────────────────────────────────────────────────────────┤
│                    DETECTION LAYER                           │
│  Port Scan │ Brute Force │ DDoS │ Traffic Pattern Analysis  │
│  Detection Orchestrator (parallel thread pool execution)     │
├─────────────────────────────────────────────────────────────┤
│                    INTELLIGENCE LAYER                        │
│  ML Anomaly Engine │ IP Reputation │ Threat Scoring Engine  │
├─────────────────────────────────────────────────────────────┤
│                    RESPONSE LAYER                            │
│  Alert Center │ Email Notifier │ IP Blocker (iptables)      │
├─────────────────────────────────────────────────────────────┤
│                    CAPTURE LAYER                             │
│  Scapy Sniffer │ PyShark │ Protocol Parser                  │
│  Flow Tracker │ Batch Writer │ Stats Aggregator              │
├─────────────────────────────────────────────────────────────┤
│                    DATA LAYER                                │
│  PostgreSQL 15+ (partitioned) │ Redis │ File Storage         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Python 3.11+, Flask 3.x |
| **Database** | PostgreSQL 15+ with date partitioning |
| **Cache** | Redis |
| **Packet Capture** | Scapy, PyShark, libpcap |
| **Machine Learning** | Scikit-Learn (Isolation Forest) |
| **Real-time** | Flask-SocketIO (WebSocket) |
| **Frontend** | HTML5/CSS3/JavaScript, Chart.js |
| **Deployment** | Docker Compose, Nginx, Gunicorn |
| **Authentication** | bcrypt, JWT, TOTP 2FA |
| **Containerization** | Docker, Docker Compose |

---

## 📁 Repository Structure

```
Network-Traffic-Monitoring-and-Attack-Detection/
└── ids_project/
    ├── app/                    # Main Flask application
    │   ├── models/             # SQLAlchemy database models (15+ tables)
    │   ├── core/               # Database, logging, exceptions
    │   ├── capture/            # Packet capture engine (Scapy + PyShark)
    │   ├── detection/          # Attack detection modules
    │   ├── ml/                 # Machine learning pipeline
    │   ├── intelligence/       # IP reputation & threat intel
    │   ├── scoring/            # Threat scoring engine
    │   ├── alerts/             # Alert management system
    │   ├── notifications/      # Email notification system
    │   ├── protection/         # IP blocking, blacklist/whitelist
    │   ├── search/             # Packet search engine
    │   ├── investigation/      # Attack investigation tools
    │   ├── reports/            # PDF/CSV report generation
    │   ├── auth/               # Authentication & RBAC
    │   ├── dashboard/          # Web dashboard routes
    │   ├── api/v1/             # REST API (versioned endpoints)
    │   ├── static/             # CSS, JS, chart assets
    │   └── templates/          # Jinja2 HTML templates
    ├── migrations/             # Alembic database migrations
    ├── tests/                  # Unit, integration, simulation tests
    ├── docker/                 # Docker, Nginx, PostgreSQL config
    ├── docs/                   # Week 1 planning & architecture docs
    │   ├── requirements/       # Functional & non-functional specs
    │   ├── architecture/       # System & data flow diagrams
    │   └── threat_model/       # STRIDE threat analysis
    └── scripts/                # Utility & automation scripts
```

---

## 📅 Development Progress

| Week | Phase | Description | Status |
|------|-------|-------------|--------|
| **1** | Phase 1 | Project Planning & System Architecture | ✅ Completed |
| **1** | Phase 2 | Development Environment & Database Design | ✅ Completed |
| **2–3** | Phase 3 | Packet Monitoring Engine | 🔄 In Progress |
| **3–4** | Phase 4 | Core Attack Detection Engine | ⬜ Planned |
| **4–5** | Phase 5 | Machine Learning & Threat Intelligence | ⬜ Planned |
| **5–6** | Phase 6 | Threat Scoring & Response Engine | ⬜ Planned |
| **6–7** | Phase 7 | Alerting & Protection System | ⬜ Planned |
| **8** | Phase 8 | Search, Investigation & Reporting | ⬜ Planned |
| **9** | Phase 9 | Authentication & Dashboard | ⬜ Planned |
| **10** | Phase 10 | System Integration & Testing | ⬜ Planned |
| **11** | Phase 11 | Performance Optimization & Security Hardening | ⬜ Planned |
| **12** | Phase 12 | Deployment, Documentation & Future Enhancements | ⬜ Planned |

---

## ✅ Week 1 — Completed

### What Was Accomplished

**Phase 1: Project Planning & System Architecture**
- ✅ Defined all 15 detection modules with input/output specifications
- ✅ Established attack detection thresholds (port scan, brute force, DDoS)
- ✅ Designed 5-layer system architecture (Capture → Processing → Detection → Intelligence → Presentation)
- ✅ Mapped complete data flow from raw packet to alert generation
- ✅ Designed concurrency model (dedicated capture thread, detection thread pool, async batch writes)
- ✅ Applied STRIDE threat model to all critical system components
- ✅ Defined 3-tier RBAC permission matrix (Admin, Analyst, Viewer)

**Phase 2: Development Environment & Database Design**
- ✅ Flask Application Factory pattern with Blueprint architecture
- ✅ Configuration classes (Development, Testing, Production)
- ✅ Complete PostgreSQL schema: 15+ tables across 8 categories
- ✅ Alembic migrations initialized with rollback support
- ✅ Multi-channel structured JSON logging system
- ✅ Docker Compose development environment
- ✅ `/health` endpoint for DB connectivity verification

### Week 1 Deliverables

| Deliverable | Location |
|-------------|----------|
| Functional Requirements | [docs/requirements/functional_requirements.md](ids_project/docs/requirements/functional_requirements.md) |
| Non-Functional Requirements | [docs/requirements/non_functional_requirements.md](ids_project/docs/requirements/non_functional_requirements.md) |
| Permission Matrix (RBAC) | [docs/requirements/permission_matrix.md](ids_project/docs/requirements/permission_matrix.md) |
| System Architecture | [docs/architecture/system_architecture.md](ids_project/docs/architecture/system_architecture.md) |
| Data Flow Design | [docs/architecture/data_flow.md](ids_project/docs/architecture/data_flow.md) |
| STRIDE Threat Model | [docs/threat_model/stride_analysis.md](ids_project/docs/threat_model/stride_analysis.md) |
| Flask App Factory | [app/\_\_init\_\_.py](ids_project/app/__init__.py) |
| Database Models | [app/models/](ids_project/app/models/) |
| Docker Environment | [docker/docker-compose.yml](ids_project/docker/docker-compose.yml) |
| Logging Framework | [app/core/logging.py](ids_project/app/core/) |

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yuvrajnagarkoti/Network-Traffic-Monitoring-and-Attack-Detection.git
cd Network-Traffic-Monitoring-and-Attack-Detection/ids_project

# Copy environment template
cp .env.example .env
# Edit .env with your database credentials and secret keys

# Start with Docker Compose
docker compose up -d

# Run database migrations
docker compose exec web flask db upgrade

# Access dashboard
open http://localhost:8080
```

---

## 📖 Documentation

- 📄 [Functional Requirements](ids_project/docs/requirements/functional_requirements.md)
- 📄 [Non-Functional Requirements](ids_project/docs/requirements/non_functional_requirements.md)
- 🔐 [Permission Matrix](ids_project/docs/requirements/permission_matrix.md)
- 🏗️ [System Architecture](ids_project/docs/architecture/system_architecture.md)
- 🔄 [Data Flow Design](ids_project/docs/architecture/data_flow.md)
- ⚠️ [STRIDE Threat Model](ids_project/docs/threat_model/stride_analysis.md)

---

## 🔒 Security

- All connection strings loaded from environment variables only
- Database user has principle of least privilege (no DROP/CREATE in production)
- Packet payloads stored as SHA-256 hash only (first 64 bytes max)
- All admin actions written to immutable audit log
- Input validation on all search/filter fields with parameterized queries

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

*Built as a 16-week senior-level cybersecurity development project.*
