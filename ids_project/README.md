# Network Traffic Monitoring & Attack Detection System

> **A full-stack cybersecurity platform for real-time network intrusion detection, threat scoring, and automated response.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.x-green.svg)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

This system provides enterprise-grade network intrusion detection with:

- **Real-time packet capture** using Scapy and PyShark (10,000+ pps)
- **Multi-vector attack detection** — port scans, brute force, DDoS, traffic anomalies
- **Machine learning anomaly detection** via Isolation Forest
- **IP reputation intelligence** with AbuseIPDB integration
- **Threat scoring engine** (0–100 scale) with automated severity classification
- **Automated response** — real-time alerting, email notifications, IP blocking via iptables
- **Security dashboard** with WebSocket live updates, Chart.js visualization
- **Search & investigation tools** with PDF/CSV reporting
- **Role-based access control** with 2FA support

## Architecture

```
┌─────────────────────────────────────────────────┐
│              PRESENTATION LAYER                  │
│   Nginx → Flask/Gunicorn → Dashboard + REST API │
│   WebSocket (Flask-SocketIO) for live updates    │
├─────────────────────────────────────────────────┤
│              DETECTION LAYER                     │
│   Port Scan │ Brute Force │ DDoS │ Traffic      │
│   Detection Orchestrator (parallel execution)    │
├─────────────────────────────────────────────────┤
│              INTELLIGENCE LAYER                  │
│   ML Anomaly Engine │ IP Reputation │ Scoring    │
├─────────────────────────────────────────────────┤
│              RESPONSE LAYER                      │
│   Alert Center │ Email Notifier │ IP Blocker     │
├─────────────────────────────────────────────────┤
│              CAPTURE LAYER                       │
│   Scapy Sniffer │ PyShark │ Protocol Parser      │
│   Flow Tracker │ Batch Writer                    │
├─────────────────────────────────────────────────┤
│              DATA LAYER                          │
│   PostgreSQL │ Redis │ File Storage (ML/Archive) │
└─────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11+, Flask 3.x |
| Database | PostgreSQL 15+ with partitioning |
| Cache | Redis |
| Packet Capture | Scapy, PyShark |
| ML | Scikit-Learn (Isolation Forest) |
| Real-time | Flask-SocketIO (WebSocket) |
| Frontend | HTML/CSS/JS, Chart.js |
| Deployment | Docker Compose, Nginx, Gunicorn |
| Auth | bcrypt, JWT, TOTP 2FA |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yuvrajnagarkoti/Network-Traffic-Monitoring-and-Attack-Detection.git
cd Network-Traffic-Monitoring-and-Attack-Detection/ids_project

# Copy environment template
cp .env.example .env

# Start with Docker Compose
docker compose up -d

# Access dashboard
open http://localhost:8080
```

## Project Structure

```
ids_project/
├── app/                    # Main application package
│   ├── models/             # SQLAlchemy database models
│   ├── core/               # Database, logging, exceptions
│   ├── capture/            # Packet capture engine
│   ├── detection/          # Attack detection modules
│   ├── ml/                 # Machine learning pipeline
│   ├── intelligence/       # IP reputation, threat intel
│   ├── scoring/            # Threat scoring engine
│   ├── alerts/             # Alert management
│   ├── notifications/      # Email notification system
│   ├── protection/         # IP blocking, blacklist/whitelist
│   ├── search/             # Packet search engine
│   ├── investigation/      # Attack investigation tools
│   ├── reports/            # PDF/CSV report generation
│   ├── auth/               # Authentication & RBAC
│   ├── dashboard/          # Web dashboard routes
│   ├── api/v1/             # REST API endpoints
│   ├── static/             # CSS, JS, images
│   └── templates/          # Jinja2 HTML templates
├── migrations/             # Alembic database migrations
├── tests/                  # Unit, integration, simulation tests
├── docker/                 # Docker & Nginx configuration
├── docs/                   # Project documentation
└── scripts/                # Utility scripts
```

## Documentation

- [Functional Requirements](docs/requirements/functional_requirements.md)
- [Non-Functional Requirements](docs/requirements/non_functional_requirements.md)
- [Permission Matrix](docs/requirements/permission_matrix.md)
- [System Architecture](docs/architecture/system_architecture.md)
- [Data Flow Design](docs/architecture/data_flow.md)
- [STRIDE Threat Model](docs/threat_model/stride_analysis.md)

## Development Status

| Phase | Description | Status |
|-------|------------|--------|
| 1 | Project Planning & System Architecture | ✅ Completed |
| 2 | Development Environment & Database Design | ✅ Completed |
| 3 | Packet Monitoring Engine | ⬜ Planned |
| 4 | Core Attack Detection Engine | ⬜ Planned |
| 5 | Machine Learning & Threat Intelligence | ⬜ Planned |
| 6 | Threat Scoring & Response Engine | ⬜ Planned |
| 7 | Alerting & Protection System | ⬜ Planned |
| 8 | Search, Investigation & Reporting | ⬜ Planned |
| 9 | Authentication & Dashboard | ⬜ Planned |
| 10 | System Integration & Testing | ⬜ Planned |
| 11 | Performance Optimization & Security Hardening | ⬜ Planned |
| 12 | Deployment, Documentation & Future Enhancements | ⬜ Planned |

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
