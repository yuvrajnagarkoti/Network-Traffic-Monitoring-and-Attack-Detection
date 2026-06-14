# Functional Requirements

> **Network Traffic Monitoring & Attack Detection System**
> Version 1.0 | Phase 1 — Milestone 1.1

---

## 1. Module Specifications

The system consists of 15 modules organized across 5 architectural layers. Each module has defined inputs, outputs, and detection criteria.

### 1.1 Capture Layer Modules

#### Module 1: Packet Capture Engine
| Attribute | Specification |
|-----------|--------------|
| **Input** | Raw network frames from network interface (eth0/configurable) |
| **Output** | Parsed PacketEvent objects pushed to processing queue |
| **Capacity** | ≥10,000 packets/second sustained |
| **Technology** | Scapy (Layer 2–4), PyShark (Layer 7 — HTTP, DNS) |
| **Dependencies** | libpcap, network interface with CAP_NET_RAW capability |

#### Module 2: Protocol Analyzer
| Attribute | Specification |
|-----------|--------------|
| **Input** | Raw PacketEvent from capture queue |
| **Output** | Enriched PacketEvent with protocol identification, parsed headers, extracted flags |
| **Protocols** | IPv4, IPv6, ARP, TCP, UDP, ICMP, HTTP, HTTPS, DNS, FTP, SSH, SMTP, RDP, SMB |
| **Unknown** | Log IP protocol number for unrecognized protocols |

#### Module 3: Flow Tracker
| Attribute | Specification |
|-----------|--------------|
| **Input** | Enriched PacketEvents |
| **Output** | FlowRecord objects (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol) |
| **Flow window** | 30-second inactivity timeout |
| **Metrics** | Packets/flow, bytes/flow, duration, flag ratios, inter-arrival times |

### 1.2 Detection Layer Modules

#### Module 4: Port Scan Detector
| Attribute | Specification |
|-----------|--------------|
| **Input** | TCP SYN packets from flow tracker |
| **Output** | AttackEvent (type: port_scan) with scanned ports, scan rate, technique |
| **Detection** | SYN scan, Connect scan, FIN scan, NULL scan, Xmas scan, UDP scan |
| **Classification** | Vertical (single host, many ports), Horizontal (many hosts, single port), Network sweep |

#### Module 5: Brute Force Detector
| Attribute | Specification |
|-----------|--------------|
| **Input** | Connection patterns to authentication services |
| **Output** | AttackEvent (type: brute_force) with targeted service, attempt count, rate |
| **Services** | SSH (port 22), HTTP (POST to auth endpoints), FTP (port 21), SMTP (port 25/587), RDP (port 3389) |
| **Variants** | Single-source, distributed (multi-IP credential stuffing), username enumeration |

#### Module 6: DDoS Detector
| Attribute | Specification |
|-----------|--------------|
| **Input** | Traffic rate metrics, per-destination packet counts |
| **Output** | AttackEvent (type: ddos) with attack vector, PPS, BPS, contributing IPs |
| **Vectors** | SYN flood, UDP flood, HTTP flood (Layer 7), DNS/NTP amplification |
| **Severity** | LOW (<500 pps) → MEDIUM (500–2000 pps) → HIGH (2000–10000 pps) → CRITICAL (>10000 pps) |

#### Module 7: Traffic Pattern Analyzer
| Attribute | Specification |
|-----------|--------------|
| **Input** | Aggregated traffic statistics (1-minute buckets) |
| **Output** | AttackEvent (type: traffic_anomaly) with z-score, deviation metrics |
| **Baseline** | Rolling 24-hour average per metric |
| **Detection** | Traffic spikes (>3σ), protocol distribution anomalies, connection tracking anomalies |

### 1.3 Intelligence Layer Modules

#### Module 8: ML Anomaly Detector
| Attribute | Specification |
|-----------|--------------|
| **Input** | 25-feature flow vectors from Feature Extractor |
| **Output** | AnomalyPrediction (is_anomaly, anomaly_score 0–1, confidence) |
| **Algorithm** | Isolation Forest (unsupervised), contamination=0.01 |
| **Retraining** | Weekly on last 7 days of normal traffic; concept drift triggers emergency retrain |
| **Validation** | AUC-ROC > 0.85 required for model deployment |

#### Module 9: IP Reputation Engine
| Attribute | Specification |
|-----------|--------------|
| **Input** | Source IP addresses from attack events and packet stream |
| **Output** | ReputationScore (0–100), risk classification (clean/suspicious/likely malicious/confirmed malicious) |
| **Sources** | AbuseIPDB (40% weight), local blacklists (40%), external feeds (20%) |
| **Cache** | 24-hour TTL in ip_reputation table; API-checked IPs cached to avoid rate limits |

### 1.4 Scoring & Response Layer Modules

#### Module 10: Threat Scoring Engine
| Attribute | Specification |
|-----------|--------------|
| **Input** | AttackEvent + IP reputation + ML prediction |
| **Output** | ThreatScore (0–100) with severity classification and human-readable explanation |
| **Components** | Base score (attack type) + rate modifier + duration modifier + recurrence + IP reputation + ML confidence + blacklist/whitelist override |
| **Severity mapping** | 0–24=LOW, 25–49=MEDIUM, 50–74=HIGH, 75–100=CRITICAL |

#### Module 11: Alert Manager
| Attribute | Specification |
|-----------|--------------|
| **Input** | Scored threats (MEDIUM and above) |
| **Output** | Alert records with lifecycle tracking |
| **Lifecycle** | NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED / FALSE_POSITIVE |
| **Real-time** | WebSocket push via Flask-SocketIO on `/alerts` namespace |

#### Module 12: Email Notification System
| Attribute | Specification |
|-----------|--------------|
| **Input** | CRITICAL and HIGH alerts |
| **Output** | HTML email delivered via SMTP |
| **Templates** | Critical alert, daily digest, weekly report |
| **Retry** | 3 attempts with exponential backoff (5min, 25min, 2hr) |
| **Throttle** | Max 10 emails/hour per recipient |

#### Module 13: IP Blocking Engine
| Attribute | Specification |
|-----------|--------------|
| **Input** | CRITICAL threats (score ≥75) or manual admin action |
| **Output** | iptables DROP rules (INPUT + FORWARD chains) |
| **Safeguards** | Never block localhost, whitelist IPs, admin's current IP |
| **Expiry** | Configurable auto-expiry (default 24h); permanent blocks supported |
| **Persistence** | Rules reapplied from database on system restart |

### 1.5 Presentation Layer Modules

#### Module 14: REST API
| Attribute | Specification |
|-----------|--------------|
| **Endpoints** | 40+ endpoints across 10 resource groups |
| **Versioning** | `/api/v1/` prefix |
| **Auth** | JWT token (API clients) + Flask-Login session (dashboard) |
| **Format** | JSON request/response |
| **Rate limiting** | Per-user and per-IP limits |

#### Module 15: Web Dashboard
| Attribute | Specification |
|-----------|--------------|
| **Pages** | Main dashboard, Alert center, Packet monitor, Investigation, Intelligence, Reports, Admin |
| **Real-time** | WebSocket live updates for alerts, traffic stats, packet feed |
| **Charts** | Chart.js — traffic timeline, protocol distribution, threat score gauges |
| **Auth** | Flask-Login with RBAC; 2FA support (TOTP) |

---

## 2. Attack Detection Definitions

Each attack type has a precise definition of what constitutes a "detected attack":

| Attack Type | Detection Criteria | Confidence |
|------------|-------------------|------------|
| **SYN Port Scan** | Same src_ip sends SYN to >15 unique dst_ports within 10 seconds | 0.85 |
| **Stealth Scan (FIN)** | TCP packets with only FIN flag to multiple ports | 0.95 |
| **Stealth Scan (NULL)** | TCP packets with no flags set to multiple ports | 0.95 |
| **Stealth Scan (Xmas)** | TCP packets with FIN+PSH+URG flags to multiple ports | 0.95 |
| **UDP Port Scan** | Same src_ip sends UDP to >10 unique ports within 30 seconds | 0.80 |
| **Slow Port Scan** | Same src_ip sends SYN to >8 unique ports within 5 minutes | 0.70 |
| **SSH Brute Force** | >5 short-lived TCP connections to port 22 within 60 seconds from same IP | 0.85 |
| **HTTP Brute Force** | >10 POST requests to auth endpoint with 401/403 responses within 30 seconds | 0.85 |
| **Distributed Brute Force** | >50 failed auth to same service from >5 IPs within 5 minutes | 0.80 |
| **SYN Flood (DDoS)** | >500 SYN pps to single IP with <10% handshake completion | 0.90 |
| **UDP Flood (DDoS)** | >1000 UDP pps to single IP | 0.85 |
| **HTTP Flood (DDoS)** | >500 HTTP req/sec to single endpoint from >50 unique IPs | 0.80 |
| **DNS Amplification** | Massive DNS response traffic to IP that didn't request it | 0.85 |
| **Traffic Spike** | Current rate > baseline_mean + (3 × baseline_stddev) | 0.70 |
| **ML Anomaly** | Isolation Forest anomaly_score > threshold (0.7) | 0.60–0.90 |

---

## 3. Alert Thresholds (Default Configuration)

All thresholds are configurable via YAML configuration file and admin dashboard API.

```yaml
detection_thresholds:
  port_scan:
    syn_scan:
      unique_ports: 15
      time_window_seconds: 10
    slow_scan:
      unique_ports: 8
      time_window_seconds: 300
    stealth_scan:
      min_ports: 3
      time_window_seconds: 60

  brute_force:
    ssh:
      failed_connections: 5
      time_window_seconds: 60
    http:
      failed_requests: 10
      time_window_seconds: 30
    distributed:
      total_failures: 50
      min_source_ips: 5
      time_window_seconds: 300

  ddos:
    syn_flood:
      pps_threshold: 500
      completion_rate_max: 0.10
    udp_flood:
      pps_threshold: 1000
    http_flood:
      rps_threshold: 500
      min_unique_ips: 50

  traffic_anomaly:
    spike_z_score: 3.0
    icmp_ratio_max: 0.30
    max_connections_per_ip: 200
    half_open_threshold: 500
```

---

## 4. Report Formats

### 4.1 PDF Reports

| Report Type | Contents | Schedule |
|------------|----------|----------|
| **Executive Summary** | 1-page KPIs: total attacks, blocked IPs, most targeted services, severity distribution | On-demand |
| **Incident Report** | Single attack: timeline, evidence packets, analyst notes, remediation steps | On-demand |
| **Weekly Security Report** | Attack trends, top attackers, anomaly stats, ML model performance, comparison to prior week | Weekly (Monday 06:00 UTC) |
| **Daily Digest** | Alert count by severity, top attacking IPs, new blocks | Daily (06:00 UTC) |

**PDF Structure:**
- Header: System logo, report title, date range
- Table of contents (for multi-page reports)
- Executive summary section
- Data tables with attack details
- Matplotlib charts: attack timeline (line), protocol distribution (doughnut), severity breakdown (pie)
- Footer: page numbers, classification level

### 4.2 CSV Exports

| Export Type | Columns | Max Range |
|------------|---------|-----------|
| **Attack Events** | id, attack_type, source_ip, target_ip, target_port, confidence_score, severity, first_seen, last_seen, status | 90 days |
| **Packet Logs** | id, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, flags, captured_at | 30 days |
| **Alerts** | id, title, severity, status, source_ip, threat_score, created_at, acknowledged_at, resolved_at | 90 days |
| **Blocked IPs** | ip_address, block_type, reason, blocked_at, expires_at, is_active | All |

All CSV exports include metadata header: `# Generated: {timestamp}, Filters: {applied_filters}, Records: {count}`

---

## 5. Email Alert Content Structure

### Critical Alert Email
```
Subject: [CRITICAL] {attack_type} detected from {source_ip} — Score: {threat_score}

Body:
- Threat Score: {score}/100 (CRITICAL)
- Attack Type: {type}
- Source IP: {ip} ({country}, {ASN})
- Target: {target_ip}:{target_port}
- First Seen: {timestamp}
- Duration: {duration}
- Evidence: {packet_count} packets
- IP Reputation: {reputation_score}/100
- Action Taken: {auto_block_status}
- [Acknowledge Alert] (link to dashboard)
- [View Details] (link to investigation page)
```

### Daily Digest Email
```
Subject: IDS Daily Digest — {date} — {critical_count} Critical, {high_count} High

Body:
- Alert Summary Table (by severity)
- Top 5 Attacking IPs (with reputation and block status)
- New Blocks Today: {count}
- Comparison to Previous Day (+/- percentages)
- [Open Dashboard] (link)
```
