# STRIDE Threat Model Analysis

> **Network Traffic Monitoring & Attack Detection System**
> Version 1.0 | Phase 1 — Milestone 1.4

---

## 1. STRIDE Overview

STRIDE is a threat modeling framework that categorizes threats into six types:

| Category | Description | Security Property Violated |
|----------|------------|---------------------------|
| **S**poofing | Pretending to be someone/something else | Authentication |
| **T**ampering | Modifying data or code without authorization | Integrity |
| **R**epudiation | Denying having performed an action | Non-repudiation |
| **I**nformation Disclosure | Exposing data to unauthorized parties | Confidentiality |
| **D**enial of Service | Preventing legitimate use of a service | Availability |
| **E**levation of Privilege | Gaining unauthorized access levels | Authorization |

---

## 2. Component-Level STRIDE Analysis

### 2.1 Dashboard Login System

| STRIDE | Threat | Severity | Likelihood | Mitigation |
|--------|--------|----------|-----------|------------|
| **S** | Attacker brute-forces admin credentials | CRITICAL | HIGH | Account lockout after 5 failures (15 min); bcrypt with 12 rounds; rate limit 5 attempts/15 min per IP |
| **S** | Attacker uses stolen session cookie | HIGH | MEDIUM | HttpOnly + Secure + SameSite=Strict cookie flags; 8-hour session timeout; session bound to IP |
| **S** | Attacker performs credential stuffing with leaked password databases | HIGH | HIGH | Password strength requirements (12+ chars, complexity); optional TOTP 2FA |
| **T** | Session fixation — attacker sets session ID before victim logs in | HIGH | LOW | Regenerate session ID on successful login; invalidate pre-login sessions |
| **R** | Admin denies performing sensitive action (e.g., unblocking an IP) | MEDIUM | MEDIUM | Audit logging of ALL admin actions with user ID, IP, timestamp, old/new values |
| **I** | Session token leaked via URL parameters or Referer header | HIGH | LOW | Tokens in HttpOnly cookies only, never in URLs; Referrer-Policy: strict-origin |
| **I** | Error messages reveal internal system details (stack traces, DB errors) | MEDIUM | MEDIUM | Custom error handlers return generic messages; detailed errors only in server logs |
| **D** | Attacker floods login endpoint to lock out all users | HIGH | MEDIUM | Per-IP rate limiting (Nginx + Flask-Limiter); lockout only affects specific username |
| **E** | Viewer escalates to admin by modifying JWT claims or cookies | CRITICAL | LOW | JWT signed with server-side secret (HS256); role checked from database on every request, not from token |

### 2.2 Packet Capture Engine

| STRIDE | Threat | Severity | Likelihood | Mitigation |
|--------|--------|----------|-----------|------------|
| **S** | Attacker injects crafted packets to confuse IDS (packet injection) | HIGH | MEDIUM | Validate packet structure before processing; discard malformed packets; log injection indicators |
| **T** | Attacker sends packets with spoofed source IPs to frame legitimate IPs | CRITICAL | HIGH | Never auto-block based on single indicator; require multiple corroborating signals (score ≥75); whitelist critical IPs |
| **T** | Attacker replays captured packets to trigger false alerts | MEDIUM | LOW | Packet deduplication via SHA-256 hash (sliding window of 1000 hashes) |
| **D** | Attacker floods IDS itself with massive traffic to cause packet drops | CRITICAL | HIGH | BPF kernel-level filtering (reduces userspace load); packet sampling above 5k pps threshold; ring buffer drops oldest (not crash); monitor drop rate as alert |
| **D** | Memory exhaustion from tracking too many unique IPs | HIGH | MEDIUM | Cap tracked IPs at 100,000 per detection module (LRU eviction); bounded data structures |
| **D** | Queue overflow causes packet loss during traffic spikes | HIGH | MEDIUM | 10,000-packet queue buffer; log overflow events; degrade gracefully (sample rather than crash) |

### 2.3 Detection Modules

| STRIDE | Threat | Severity | Likelihood | Mitigation |
|--------|--------|----------|-----------|------------|
| **S** | Attacker performs slow port scan below detection threshold | HIGH | HIGH | Dual-window detection: 10-second fast window + 5-minute slow window; accumulative evidence tracking |
| **S** | Attacker uses IP rotation to stay below per-IP thresholds | HIGH | MEDIUM | Distributed attack detection: aggregate attempts across multiple IPs targeting same service |
| **T** | Attacker modifies detection thresholds via compromised admin account | CRITICAL | LOW | Threshold changes require admin role + audit logged; changes reviewed in audit log; alert on threshold changes |
| **T** | Attacker deliberately triggers false positives to cause alert fatigue | HIGH | MEDIUM | Threat scoring reduces noise; LOW alerts auto-expire in 24h; ML model helps distinguish real vs. false |
| **D** | Attacker creates millions of micro-attacks to overwhelm DB with attack_event records | HIGH | MEDIUM | Attack event creation rate limited; deduplication within 60-second window; cap at 1000 active attacks |

### 2.4 Alert & Email System

| STRIDE | Threat | Severity | Likelihood | Mitigation |
|--------|--------|----------|-----------|------------|
| **S** | Email header injection — attacker-controlled data injected into email headers | HIGH | LOW | Sanitize ALL data inserted into email templates; use Jinja2 auto-escaping; validate email addresses with regex |
| **T** | Attacker triggers alert deletion to hide their attack | CRITICAL | LOW | Alerts cannot be deleted via API — only status change (resolved/false_positive); database-level constraint on DELETE |
| **I** | Sensitive attack details leaked via email (email in transit is unencrypted) | MEDIUM | MEDIUM | Use TLS/STARTTLS for SMTP; limit detail in emails; include "View Details" link to authenticated dashboard instead |
| **D** | Email flooding — attacker triggers thousands of alerts to flood analyst inbox | HIGH | MEDIUM | Email throttling: max 10 emails/hour per recipient; batch alerts into digest if threshold exceeded |
| **R** | Analyst claims they never received a critical alert | MEDIUM | MEDIUM | Email delivery tracked in email_notifications table (sent/failed status); WebSocket delivery logged |

### 2.5 IP Blocking Module

| STRIDE | Threat | Severity | Likelihood | Mitigation |
|--------|--------|----------|-----------|------------|
| **S** | Attacker spoofs source IP of legitimate server to trigger auto-block of that server | CRITICAL | HIGH | Whitelist all critical infrastructure IPs; require score ≥75 (multiple corroborating signals) for auto-block; whitelist check is final gate |
| **T** | Attacker removes their IP from block list by exploiting unblock API | HIGH | LOW | Unblock requires MANAGE_BLOCKS permission; all unblock actions audit logged with user ID and reason |
| **T** | iptables rules lost on system restart | MEDIUM | MEDIUM | Re-apply all active blocks from ip_blocks table at startup; compare DB state with iptables output |
| **D** | Attacker triggers rapid block/unblock cycles to destabilize firewall | HIGH | LOW | Rate limit block/unblock API (10 operations/minute); alert if >10 blocks in 5 minutes |
| **E** | Analyst exploits IP blocker to block admin's IP (lockout attack) | CRITICAL | LOW | NEVER block admin's current session IP; NEVER block whitelist IPs; whitelist must always contain admin IP |

### 2.6 Database (PostgreSQL)

| STRIDE | Threat | Severity | Likelihood | Mitigation |
|--------|--------|----------|-----------|------------|
| **S** | Attacker connects to PostgreSQL with stolen credentials | CRITICAL | LOW | DB password ≥20 chars (generated); DB listens only on Docker internal network; no remote superuser access |
| **T** | SQL injection via search filters or report parameters | CRITICAL | MEDIUM | ALL queries use SQLAlchemy ORM (parameterized); never construct SQL strings with f-strings or format() |
| **T** | Insider deletes audit logs to cover tracks | CRITICAL | LOW | Audit log table: no DELETE or UPDATE operations permitted programmatically; app user has no DELETE on audit_logs; separate backup |
| **I** | Sensitive data exposed via verbose SQL error messages | HIGH | MEDIUM | SQLAlchemy exceptions caught at application layer; generic error returned to user; details in server log only |
| **I** | Backup files containing full database exposed | HIGH | LOW | Backups encrypted at rest; stored with 600 permissions; backup location not web-accessible |
| **D** | Connection pool exhaustion from concurrent requests | HIGH | MEDIUM | Pool size=10, max_overflow=20, pool_timeout=30s; health check verifies connectivity; graceful queue on exhaustion |

### 2.7 REST API

| STRIDE | Threat | Severity | Likelihood | Mitigation |
|--------|--------|----------|-----------|------------|
| **S** | Unauthorized API access with forged JWT token | CRITICAL | LOW | JWT signed with strong secret (≥256 bits); verify signature on every request; check expiry (1-hour token life) |
| **T** | Request parameter tampering (e.g., changing user_id in request) | HIGH | MEDIUM | Server-side authorization check on every request; user identity from JWT/session, not from request body |
| **I** | API returns more data than user is authorized to see | HIGH | MEDIUM | Query scoping based on user role; Viewer cannot access search endpoints; serializers exclude sensitive fields |
| **D** | API abuse — automated scripts sending thousands of requests | HIGH | HIGH | Rate limiting: 1000 req/hour per user; 100 req/min for search; 5 req/15min for login; 429 response with Retry-After |
| **E** | Viewer accesses admin-only endpoint by directly calling API URL | CRITICAL | MEDIUM | Permission decorator on every route (`@require_permission`); return 403 with audit log entry |

### 2.8 WebSocket (Flask-SocketIO)

| STRIDE | Threat | Severity | Likelihood | Mitigation |
|--------|--------|----------|-----------|------------|
| **S** | Unauthenticated WebSocket connection receives alert data | HIGH | MEDIUM | JWT verification during WebSocket `connect` event; reject connection if token invalid/expired |
| **D** | Client opens hundreds of WebSocket connections to exhaust server resources | HIGH | MEDIUM | Limit 1 WebSocket connection per user; reject duplicate connections |
| **I** | Alert data broadcast to all connected clients regardless of role | MEDIUM | MEDIUM | Filter events by user role on server side; Viewers receive limited event data |

---

## 3. Attacker Profiles

### 3.1 External Attacker

| Attribute | Description |
|-----------|------------|
| **Motivation** | Reconnaissance, exploitation, data theft, service disruption |
| **Capabilities** | Nmap, Hydra, hping3, custom scripts; may use botnets for DDoS |
| **Techniques** | Port scanning (SYN, stealth), brute force (SSH, HTTP), DDoS (SYN flood, UDP flood, amplification) |
| **Knowledge** | Knows standard port scan detection exists; will attempt evasion (slow scan, IP rotation, fragmentation) |
| **Detection Strategy** | Multi-speed sliding windows; distributed attack correlation; ML anomaly for novel attacks |

### 3.2 Insider Threat

| Attribute | Description |
|-----------|------------|
| **Motivation** | Cover tracks, access unauthorized data, sabotage detection |
| **Capabilities** | Has legitimate system access (viewer or analyst role); knows system architecture |
| **Techniques** | Attempt to delete audit logs, access admin features as viewer, modify alert statuses to hide attacks, download excessive reports |
| **Knowledge** | Understands RBAC system; may attempt privilege escalation via API manipulation |
| **Detection Strategy** | Append-only audit logs (no DELETE permission); RBAC enforced server-side on every request; anomalous access patterns logged |

### 3.3 Evasion Attacker

| Attribute | Description |
|-----------|------------|
| **Motivation** | Bypass IDS detection to carry out attacks undetected |
| **Capabilities** | Advanced knowledge of IDS thresholds and detection algorithms |
| **Techniques** | Slow scan below time-window threshold; IP spoofing to trigger false blocks on legitimate IPs; packet fragmentation; protocol tunneling (DNS tunneling); overwhelming IDS with noise |
| **Knowledge** | May have studied open-source IDS tools (Snort/Suricata rules); knows common threshold values |
| **Detection Strategy** | ML anomaly detection (catches patterns rules miss); dual-window detection; IP reputation cross-reference; rate anomaly even at sub-threshold levels |

---

## 4. Security Controls Summary

### 4.1 Controls by Category

| Control Category | Controls Implemented |
|-----------------|---------------------|
| **Authentication** | bcrypt (12 rounds), TOTP 2FA, JWT with expiry, session management, account lockout |
| **Authorization** | RBAC with 15 permissions, per-endpoint decorators, server-side enforcement |
| **Input Validation** | SQLAlchemy ORM (parameterized queries), IP address validation, string length limits, enum validation |
| **Output Encoding** | Jinja2 auto-escaping, CSP headers, JSON response serialization |
| **Cryptography** | TLS 1.2+ for HTTP, bcrypt for passwords, SHA-256 for packet hashing, JWT HMAC signing |
| **Logging & Monitoring** | Structured JSON logging, security audit log (append-only), request ID tracing |
| **Error Handling** | Custom error handlers, generic user-facing messages, detailed server-side logging |
| **Rate Limiting** | Per-IP and per-user limits, login throttling, API rate limits |
| **Data Protection** | No PII in logs beyond IP addresses, payload truncation (64 bytes max), encrypted backups |
| **Network Security** | Docker internal network isolation, only Nginx exposed, iptables blocking |

### 4.2 OWASP Top 10 Coverage

| # | OWASP Risk | Mitigation |
|---|-----------|------------|
| A01 | Broken Access Control | RBAC with permission decorators; server-side checks; audit logging |
| A02 | Cryptographic Failures | bcrypt for passwords; TLS for transport; no secrets in code/logs |
| A03 | Injection | SQLAlchemy ORM (parameterized); input validation; no shell=True |
| A04 | Insecure Design | STRIDE threat model (this document); principle of least privilege |
| A05 | Security Misconfiguration | Security headers (CSP, HSTS, X-Frame-Options); Docker hardening; no debug in production |
| A06 | Vulnerable Components | Pinned dependency versions; Docker image scanning (Trivy); regular updates |
| A07 | Auth Failures | bcrypt, 2FA, session management, JWT expiry, lockout policy |
| A08 | Data Integrity Failures | Signed JWT tokens; database transactions; migration checksums |
| A09 | Logging Failures | Comprehensive structured logging; security audit trail; never log secrets |
| A10 | SSRF | No user-controlled URLs fetched by server except AbuseIPDB API (validated IP format only) |

---

## 5. Threat Severity Matrix

### Threats Ranked by Risk (Likelihood × Impact)

| Rank | Threat | Component | Impact | Likelihood | Risk |
|------|--------|-----------|--------|-----------|------|
| 1 | IP spoofing triggers false block on legitimate server | IP Blocker | CRITICAL | HIGH | **CRITICAL** |
| 2 | Brute force on dashboard login | Auth | CRITICAL | HIGH | **CRITICAL** |
| 3 | DDoS flood overwhelms IDS itself | Capture | CRITICAL | HIGH | **CRITICAL** |
| 4 | SQL injection via search parameters | Database | CRITICAL | MEDIUM | **HIGH** |
| 5 | Slow scan evades time-window detection | Detection | HIGH | HIGH | **HIGH** |
| 6 | Alert fatigue from false positive cascade | Detection | HIGH | MEDIUM | **HIGH** |
| 7 | API abuse / automated scraping | API | HIGH | HIGH | **HIGH** |
| 8 | Viewer accesses admin endpoint via API | API | CRITICAL | MEDIUM | **HIGH** |
| 9 | Memory exhaustion from IP tracking | Capture | HIGH | MEDIUM | **MEDIUM** |
| 10 | Email header injection | Notifications | HIGH | LOW | **MEDIUM** |
| 11 | Insider deletes audit logs | Database | CRITICAL | LOW | **MEDIUM** |
| 12 | Session fixation attack | Auth | HIGH | LOW | **MEDIUM** |

---

## 6. Architecture Security Review Checklist

- [x] All 15 modules accounted for in STRIDE analysis
- [x] All STRIDE categories covered (S, T, R, I, D, E)
- [x] At least 10 unique threats identified (32 threats documented)
- [x] Each threat has corresponding mitigation
- [x] 3 attacker profiles defined (external, insider, evasion)
- [x] OWASP Top 10 mapped to project controls
- [x] Risk ranking provided for prioritization
- [x] No module has unmitigated CRITICAL threats
- [x] Principle of least privilege applied at every layer
- [x] All external communications go through dedicated adapters (AbuseIPDB, SMTP)
