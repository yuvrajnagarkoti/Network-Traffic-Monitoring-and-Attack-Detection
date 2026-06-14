# Role-Based Access Control — Permission Matrix

> **Network Traffic Monitoring & Attack Detection System**
> Version 1.0 | Phase 1 — Milestone 1.1

---

## 1. Role Definitions

| Role | Description | Intended User |
|------|------------|---------------|
| **Administrator** | Full system access — configure thresholds, manage users, view all data, block IPs, manage system settings | System administrator, security team lead |
| **Security Analyst** | Read/write access — view alerts, run investigations, generate reports, manage blocks, acknowledge alerts | SOC analyst, incident responder |
| **Viewer** | Read-only access — view dashboard, alerts, and reports; no modifications | Management, compliance auditor, junior staff |

---

## 2. Permission Definitions

| Permission ID | Permission Name | Description |
|--------------|----------------|-------------|
| `VIEW_DASHBOARD` | View Dashboard | Access the main dashboard with live statistics |
| `VIEW_ALERTS` | View Alerts | View alert list and alert details |
| `ACKNOWLEDGE_ALERTS` | Acknowledge Alerts | Change alert status to acknowledged/investigating |
| `CLOSE_ALERTS` | Close Alerts | Resolve alerts or mark as false positive |
| `VIEW_PACKETS` | View Packets | View packet monitor and live packet feed |
| `SEARCH_PACKETS` | Search Packets | Use packet search with advanced filters |
| `MANAGE_BLOCKS` | Manage IP Blocks | Manually block/unblock IP addresses |
| `MANAGE_WHITELIST` | Manage Whitelist | Add/remove IPs from whitelist |
| `MANAGE_BLACKLIST` | Manage Blacklist | Add/remove IPs from blacklist, import external lists |
| `VIEW_REPORTS` | View Reports | View and download generated reports |
| `GENERATE_REPORTS` | Generate Reports | Create new PDF/CSV reports on demand |
| `MANAGE_USERS` | Manage Users | Create/deactivate users, change roles, manage sessions |
| `MANAGE_SYSTEM_CONFIG` | Manage System Config | Modify detection thresholds, email settings, capture config |
| `VIEW_AUDIT_LOGS` | View Audit Logs | Access audit trail of all admin actions |
| `MANAGE_ML_MODEL` | Manage ML Model | Trigger model retraining, view model metrics |

---

## 3. Role-Permission Matrix

| Permission | Administrator | Security Analyst | Viewer |
|-----------|:---:|:---:|:---:|
| `VIEW_DASHBOARD` | ✅ | ✅ | ✅ |
| `VIEW_ALERTS` | ✅ | ✅ | ✅ |
| `ACKNOWLEDGE_ALERTS` | ✅ | ✅ | ❌ |
| `CLOSE_ALERTS` | ✅ | ✅ | ❌ |
| `VIEW_PACKETS` | ✅ | ✅ | ✅ |
| `SEARCH_PACKETS` | ✅ | ✅ | ❌ |
| `MANAGE_BLOCKS` | ✅ | ✅ | ❌ |
| `MANAGE_WHITELIST` | ✅ | ❌ | ❌ |
| `MANAGE_BLACKLIST` | ✅ | ✅ | ❌ |
| `VIEW_REPORTS` | ✅ | ✅ | ✅ |
| `GENERATE_REPORTS` | ✅ | ✅ | ❌ |
| `MANAGE_USERS` | ✅ | ❌ | ❌ |
| `MANAGE_SYSTEM_CONFIG` | ✅ | ❌ | ❌ |
| `VIEW_AUDIT_LOGS` | ✅ | ❌ | ❌ |
| `MANAGE_ML_MODEL` | ✅ | ❌ | ❌ |

---

## 4. API Endpoint Access Matrix

### Authentication Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Unauthenticated |
|----------|--------|:---:|:---:|:---:|:---:|
| `/auth/login` | POST | ✅ | ✅ | ✅ | ✅ |
| `/auth/logout` | POST | ✅ | ✅ | ✅ | ❌ |
| `/auth/2fa/setup` | POST | ✅ | ✅ | ❌ | ❌ |
| `/auth/2fa/verify` | POST | ✅ | ✅ | ✅ | ❌ |
| `/auth/password/change` | POST | ✅ | ✅ | ✅ | ❌ |

### Packet Monitoring Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Permission Required |
|----------|--------|:---:|:---:|:---:|-----------|
| `/api/v1/packets/live` | GET | ✅ | ✅ | ✅ | `VIEW_PACKETS` |
| `/api/v1/packets/protocols` | GET | ✅ | ✅ | ✅ | `VIEW_PACKETS` |
| `/api/v1/packets/top-talkers` | GET | ✅ | ✅ | ✅ | `VIEW_PACKETS` |
| `/api/v1/packets/stats` | GET | ✅ | ✅ | ✅ | `VIEW_PACKETS` |
| `/api/v1/capture/status` | GET | ✅ | ✅ | ✅ | `VIEW_PACKETS` |
| `/api/v1/capture/start` | POST | ✅ | ❌ | ❌ | `MANAGE_SYSTEM_CONFIG` |
| `/api/v1/capture/stop` | POST | ✅ | ❌ | ❌ | `MANAGE_SYSTEM_CONFIG` |

### Attack & Detection Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Permission Required |
|----------|--------|:---:|:---:|:---:|-----------|
| `/api/v1/attacks` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/attacks/{id}` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/attacks/{id}/status` | PATCH | ✅ | ✅ | ❌ | `ACKNOWLEDGE_ALERTS` |
| `/api/v1/attacks/stats` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/attacks/active` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |

### Threat Intelligence Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Permission Required |
|----------|--------|:---:|:---:|:---:|-----------|
| `/api/v1/reputation/{ip}` | GET | ✅ | ✅ | ❌ | `SEARCH_PACKETS` |
| `/api/v1/reputation/check-bulk` | POST | ✅ | ✅ | ❌ | `SEARCH_PACKETS` |
| `/api/v1/reputation/{ip}/override` | POST | ✅ | ❌ | ❌ | `MANAGE_SYSTEM_CONFIG` |
| `/api/v1/ml/model/status` | GET | ✅ | ✅ | ❌ | `VIEW_ALERTS` |
| `/api/v1/ml/model/retrain` | POST | ✅ | ❌ | ❌ | `MANAGE_ML_MODEL` |

### Threat Scoring Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Permission Required |
|----------|--------|:---:|:---:|:---:|-----------|
| `/api/v1/threats/score/{id}` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/threats/high-priority` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/threats/statistics` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |

### Alert Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Permission Required |
|----------|--------|:---:|:---:|:---:|-----------|
| `/api/v1/alerts` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/alerts/{id}` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/alerts/{id}/status` | PATCH | ✅ | ✅ | ❌ | `ACKNOWLEDGE_ALERTS` |
| `/api/v1/alerts/{id}/comment` | POST | ✅ | ✅ | ❌ | `ACKNOWLEDGE_ALERTS` |
| `/api/v1/alerts/bulk-acknowledge` | POST | ✅ | ✅ | ❌ | `ACKNOWLEDGE_ALERTS` |
| `/api/v1/alerts/statistics` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |

### Protection Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Permission Required |
|----------|--------|:---:|:---:|:---:|-----------|
| `/api/v1/blocks` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/blocks` | POST | ✅ | ✅ | ❌ | `MANAGE_BLOCKS` |
| `/api/v1/blocks/{ip}` | DELETE | ✅ | ✅ | ❌ | `MANAGE_BLOCKS` |
| `/api/v1/blacklist` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/blacklist` | POST | ✅ | ✅ | ❌ | `MANAGE_BLACKLIST` |
| `/api/v1/blacklist/import` | POST | ✅ | ❌ | ❌ | `MANAGE_BLACKLIST` |
| `/api/v1/blacklist/{ip}` | DELETE | ✅ | ❌ | ❌ | `MANAGE_BLACKLIST` |
| `/api/v1/whitelist` | GET | ✅ | ✅ | ✅ | `VIEW_ALERTS` |
| `/api/v1/whitelist` | POST | ✅ | ❌ | ❌ | `MANAGE_WHITELIST` |
| `/api/v1/whitelist/{ip}` | DELETE | ✅ | ❌ | ❌ | `MANAGE_WHITELIST` |

### Search & Investigation Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Permission Required |
|----------|--------|:---:|:---:|:---:|-----------|
| `/api/v1/search/packets` | GET | ✅ | ✅ | ❌ | `SEARCH_PACKETS` |
| `/api/v1/search/attacks` | GET | ✅ | ✅ | ❌ | `SEARCH_PACKETS` |
| `/api/v1/search/saved` | POST | ✅ | ✅ | ❌ | `SEARCH_PACKETS` |
| `/api/v1/search/saved` | GET | ✅ | ✅ | ❌ | `SEARCH_PACKETS` |
| `/api/v1/investigation/ip/{ip}` | GET | ✅ | ✅ | ❌ | `SEARCH_PACKETS` |
| `/api/v1/investigation/attack/{id}/timeline` | GET | ✅ | ✅ | ❌ | `SEARCH_PACKETS` |

### Reporting Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Permission Required |
|----------|--------|:---:|:---:|:---:|-----------|
| `/api/v1/reports/generate` | GET | ✅ | ✅ | ❌ | `GENERATE_REPORTS` |
| `/api/v1/reports/history` | GET | ✅ | ✅ | ✅ | `VIEW_REPORTS` |
| `/api/v1/reports/{id}/download` | GET | ✅ | ✅ | ✅ | `VIEW_REPORTS` |

### Administration Endpoints

| Endpoint | Method | Admin | Analyst | Viewer | Permission Required |
|----------|--------|:---:|:---:|:---:|-----------|
| `/api/v1/users` | GET | ✅ | ❌ | ❌ | `MANAGE_USERS` |
| `/api/v1/users` | POST | ✅ | ❌ | ❌ | `MANAGE_USERS` |
| `/api/v1/users/{id}` | PATCH | ✅ | ❌ | ❌ | `MANAGE_USERS` |
| `/api/v1/users/{id}/sessions` | DELETE | ✅ | ❌ | ❌ | `MANAGE_USERS` |
| `/api/v1/config/thresholds` | GET | ✅ | ❌ | ❌ | `MANAGE_SYSTEM_CONFIG` |
| `/api/v1/config/thresholds` | PATCH | ✅ | ❌ | ❌ | `MANAGE_SYSTEM_CONFIG` |
| `/api/v1/audit/logs` | GET | ✅ | ❌ | ❌ | `VIEW_AUDIT_LOGS` |
| `/api/v1/system/health` | GET | ✅ | ✅ | ✅ | (any authenticated) |
| `/api/v1/system/performance` | GET | ✅ | ❌ | ❌ | `MANAGE_SYSTEM_CONFIG` |
| `/api/v1/notifications/test-email` | POST | ✅ | ❌ | ❌ | `MANAGE_SYSTEM_CONFIG` |

---

## 5. Access Control Implementation Notes

### Authentication Mechanism
- **Dashboard (browser):** Flask-Login session with HttpOnly secure cookie; 8-hour timeout
- **API (programmatic):** JWT Bearer token in Authorization header; 1-hour expiry with 7-day refresh token
- **WebSocket:** JWT verified during connection handshake; disconnected on token expiry

### Permission Enforcement
- Every route decorated with `@require_permission('PERMISSION_NAME')` or `@require_role('role_name')`
- API routes return HTTP 403 JSON: `{"error": "Forbidden", "message": "Missing permission: MANAGE_USERS"}`
- Dashboard routes redirect to 403 error page
- All unauthorized access attempts logged to `audit_logs` table

### Account Management
- Only administrators can create new user accounts (no public registration)
- Only administrators can change user roles
- Users can change their own password (all roles)
- Administrators can force password reset on any account
- Administrators can revoke all sessions for any user (immediate lockout)

### Audit Trail
The following actions are recorded in `audit_logs` with user ID, IP address, and timestamp:
- Login / logout / failed login
- User created / deactivated / role changed
- IP blocked / unblocked
- Whitelist / blacklist changes
- Alert status changes
- Detection threshold modifications
- Report generation
- ML model retraining trigger
