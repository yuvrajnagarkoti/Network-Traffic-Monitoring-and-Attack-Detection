# Data Flow Design

> **Network Traffic Monitoring & Attack Detection System**
> Version 1.0 | Phase 1 — Milestone 1.3

---

## 1. Complete Data Flow Map

### 1.1 Primary Data Pipeline: Packet → Alert

```
Network Interface (eth0)
        │
        ▼
┌───────────────────────┐
│  Scapy/PyShark        │    Thread: capture_thread (dedicated, never blocked)
│  sniff(prn=callback)  │    BPF Filter: "not (ether broadcast or ether multicast)"
│                       │
│  Output: Raw packet   │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  Thread-Safe Queue    │    queue.Queue(maxsize=10,000)
│  (Ring Buffer)        │    Overflow: drop + increment drop_counter
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  Packet Parser        │    Thread pool: 4 workers consuming from queue
│                       │
│  • Identify protocol  │    Steps:
│  • Extract headers    │    1. Protocol identification (L3/L4/L7)
│  • Parse TCP flags    │    2. Header extraction (IP, TCP/UDP, ICMP)
│  • Extract features   │    3. TCP flag parsing (SYN/ACK/FIN/RST/PSH/URG)
│  • Compute hash       │    4. Feature extraction (for ML pipeline)
│  • Dedup check        │    5. SHA-256 hash computation
│                       │    6. Dedup against sliding window (last 1000 hashes)
│  Output: PacketEvent  │
└───────────┬───────────┘
            │
            ├──────────────────────────────────┐
            │                                  │
            ▼                                  ▼
┌───────────────────────┐         ┌─────────────────────────┐
│  Batch Insert Manager │         │  Detection Orchestrator  │
│                       │         │                          │
│  Collect in memory    │         │  Dispatch to all         │
│  Flush conditions:    │         │  registered detectors    │
│  • 500 packets OR     │         │  in parallel (thread     │
│  • 500ms elapsed      │         │  pool)                   │
│                       │         │                          │
│  Target: packet_logs  │         │  Detectors:              │
│  Method: bulk_insert  │         │  • PortScanDetector      │
│                       │         │  • BruteForceDetector    │
│  Fallback: WAL buffer │         │  • DDoSDetector          │
│  (50k packets if DB   │         │  • TrafficAnalyzer       │
│   is unavailable)     │         │  • MLAnomalyDetector     │
└───────────┬───────────┘         └──────────┬──────────────┘
            │                                 │
            ▼                                 │ List[AttackIndicator]
┌───────────────────────┐                     │
│  PostgreSQL           │                     ▼
│  packet_logs table    │         ┌─────────────────────────┐
│  (partitioned)        │         │  Attack State Manager   │
└───────────────────────┘         │                         │
                                  │  Dedup: same attack_type│
            ┌────────────────┐    │  + src_ip within 60s    │
            │                │    │  → update existing      │
            │                │    │                         │
            │                │    │  New attack:            │
            │                │    │  → create AttackEvent   │
            │                │    │                         │
            │                │    │  Resolved: no evidence  │
            │                │    │  for 5 min → persist    │
            │                │    └──────────┬──────────────┘
            │                │               │
            ▼                │               │ AttackEvent
┌───────────────────────┐    │               ▼
│  Stats Aggregator     │    │    ┌─────────────────────────┐
│  (every 60 seconds)   │    │    │  PostgreSQL              │
│                       │    │    │  attack_events table     │
│  • packets/sec        │    │    │  + detail tables:        │
│  • bytes/sec          │    │    │    port_scan_details     │
│  • top 10 src IPs     │    │    │    brute_force_details   │
│  • top 10 dst IPs     │    │    │    ddos_details          │
│  • protocol dist      │    │    └──────────┬──────────────┘
│                       │    │               │
│  Target:              │    │               ▼
│  • protocol_stats     │    │    ┌─────────────────────────┐
│  • system_stats       │    │    │  Threat Scoring Engine   │
└───────────────────────┘    │    │                         │
                             │    │  Inputs:                │
                             │    │  • AttackEvent          │
                             │    │  • IP reputation score  │◀─── ip_reputation table
                             │    │  • ML confidence        │◀─── ml_predictions table
                             │    │  • Blacklist match      │◀─── blacklist table
                             │    │  • Whitelist check      │◀─── whitelist table
                             │    │                         │
                             │    │  Output: ThreatScore    │
                             │    │  (0–100, severity enum) │
                             │    └──────────┬──────────────┘
                             │               │
                             │               ▼
                             │    ┌─────────────────────────┐
                             │    │  PostgreSQL              │
                             │    │  threat_scores table     │
                             │    └──────────┬──────────────┘
                             │               │
                             │               ▼
                             │    ┌─────────────────────────┐
                             │    │  Response Decision       │
                             │    │  Engine                  │
                             │    │                         │
                             │    │  Score ≥75 (CRITICAL):  │
                             │    │  → auto-block IP        │──▶ iptables -I INPUT -s {ip} -j DROP
                             │    │  → immediate email      │──▶ SMTP queue
                             │    │  → create alert         │──▶ alerts table
                             │    │                         │
                             │    │  Score 50–74 (HIGH):    │
                             │    │  → email alert          │──▶ SMTP queue
                             │    │  → create alert         │──▶ alerts table
                             │    │                         │
                             │    │  Score 25–49 (MEDIUM):  │
                             │    │  → create alert         │──▶ alerts table
                             │    │                         │
                             │    │  Score 0–24 (LOW):      │
                             │    │  → log only             │──▶ application log
                             │    └──────────┬──────────────┘
                             │               │
                             │               ▼
                             │    ┌─────────────────────────┐
                             │    │  Alert Manager          │
                             │    │                         │
                             │    │  • Write to alerts table│
                             │    │  • WebSocket emit:      │
                             │    │    new_alert event      │──▶ Dashboard (real-time)
                             │    │  • Queue email job      │──▶ email_notifications table
                             │    └─────────────────────────┘
                             │
                             │    ┌─────────────────────────┐
                             └───▶│  IP Blocking Module     │
                                  │                         │
                                  │  • Add iptables rule    │
                                  │  • Record in ip_blocks  │
                                  │  • WebSocket emit:      │
                                  │    ip_blocked event     │──▶ Dashboard
                                  │  • Audit log entry      │──▶ audit_logs table
                                  └─────────────────────────┘
```

### 1.2 ML Pipeline Data Flow

```
┌─────────────────────┐
│  Flow Tracker       │    From Capture Layer (Module 3)
│  (30-sec windows)   │
└─────────┬───────────┘
          │ Expired FlowRecord
          ▼
┌─────────────────────┐
│  Feature Extractor  │    Extract 25 numerical features per flow
│                     │    (see Functional Requirements for full feature list)
│  Output: float[25]  │
└─────────┬───────────┘
          │
          ├────────────────────────────────┐
          │                                │
          ▼                                ▼
┌─────────────────────┐       ┌──────────────────────┐
│  Feature Store      │       │  Anomaly Detector    │
│  (ml_predictions    │       │  (Isolation Forest)  │
│   table + JSONB)    │       │                      │
└─────────────────────┘       │  Batch: 100 vectors  │
                              │  every 10 seconds    │
                              │                      │
                              │  Output:             │
                              │  • is_anomaly: bool  │
                              │  • anomaly_score: 0–1│
                              │  • confidence: float │
                              └──────────┬───────────┘
                                         │
                                         ▼
                              ┌──────────────────────┐
                              │  ml_predictions table│
                              │                      │
                              │  If anomalous:       │
                              │  → Create AttackEvent│
                              │    (type: ml_anomaly)│
                              │  → Feed to Scoring   │
                              └──────────────────────┘
```

### 1.3 IP Reputation Data Flow

```
┌──────────────────────────┐
│  New source IP detected  │    From packet stream (first encounter)
│  in packet capture       │
└────────────┬─────────────┘
             │
             ▼
┌──────────────────────────┐
│  Check ip_reputation     │    Cache lookup (24h TTL)
│  table (cache)           │
└────────────┬─────────────┘
             │
      ┌──────┴──────┐
      │             │
   CACHE HIT     CACHE MISS
      │             │
      ▼             ▼
   Return        ┌──────────────────────┐
   cached        │  Priority Check:     │
   score         │  Is IP in attack     │
                 │  event? → Immediate  │
                 │  Otherwise → Batch   │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │  AbuseIPDB API       │    GET /api/v2/check?ipAddress={ip}
                 │  (1,000 checks/day   │    Headers: Key: {api_key}
                 │   on free tier)      │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │  Local Blacklist     │    Check blacklist table
                 │  Check               │    Check imported feeds
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │  Reputation          │    Weighted aggregation:
                 │  Aggregator          │    AbuseIPDB (40%) + Blacklist (40%)
                 │                      │    + External feeds (20%)
                 │  Output:             │
                 │  reputation_score    │    0 (clean) → 100 (malicious)
                 │  risk_level          │    clean/suspicious/likely/confirmed
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │  ip_reputation table │    Cached for 24 hours
                 └──────────────────────┘
```

---

## 2. Message & Event Schemas

### 2.1 PacketEvent

The fundamental data unit produced by the Capture Layer.

```json
{
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "packet_size": 1460,
    "flags": "SYN",
    "payload_hash": "a3f2b8c9d1e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0",
    "captured_at": "2024-01-15T14:30:00.123456Z",
    "ip_version": 4,
    "ttl": 64,
    "window_size": 65535,
    "tcp_options": ["MSS", "SACK", "Timestamps"],
    "flow_id": "192.168.1.100:54321-10.0.0.1:443-TCP"
}
```

### 2.2 FlowRecord

Aggregated statistics for a 5-tuple flow (30-second window).

```json
{
    "flow_id": "192.168.1.100:54321-10.0.0.1:443-TCP",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.0.1",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "packet_count": 145,
    "byte_count": 186420,
    "first_seen": "2024-01-15T14:30:00.123456Z",
    "last_seen": "2024-01-15T14:30:28.654321Z",
    "duration_seconds": 28.53,
    "syn_count": 1,
    "ack_count": 72,
    "fin_count": 1,
    "rst_count": 0,
    "unique_dst_ports": 1,
    "feature_vector": [145, 186420, 1285.7, 312.4, ...]
}
```

### 2.3 AttackEvent

Generated by detection modules when an attack is identified.

```json
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "attack_type": "port_scan",
    "source_ip": "203.0.113.50",
    "target_ip": "10.0.0.5",
    "target_port": null,
    "evidence": {
        "scanned_ports": [22, 80, 443, 445, 3389, 8080, 8443, 3306, 5432, 6379, 27017, 1433, 5900, 8888, 9090, 161],
        "scan_rate": 2.3,
        "scan_pattern": "random",
        "technique": "syn",
        "first_syn_at": "2024-01-15T14:30:00Z",
        "last_syn_at": "2024-01-15T14:30:07Z"
    },
    "confidence_score": 0.85,
    "packet_count": 16,
    "duration_seconds": 7,
    "first_seen": "2024-01-15T14:30:00Z",
    "last_seen": "2024-01-15T14:30:07Z",
    "status": "active"
}
```

### 2.4 ThreatScore

Output of the Threat Scoring Engine.

```json
{
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "attack_event_id": "550e8400-e29b-41d4-a716-446655440000",
    "base_score": 20,
    "rate_modifier": 5,
    "duration_modifier": 0,
    "recurrence_modifier": 0,
    "ip_reputation_modifier": 15,
    "ml_confidence_modifier": 10,
    "blacklist_modifier": 0,
    "whitelist_override": false,
    "final_score": 50,
    "severity": "high",
    "explanation": "Score: 50 (HIGH). Base: 20 (Port Scan), Rate: +5 (2.3 ports/sec), IP Reputation: +15 (abuseConfidence=82), ML: +10 (anomaly confirmed)",
    "calculated_at": "2024-01-15T14:30:08Z"
}
```

### 2.5 AlertEvent

Created when a ThreatScore warrants human attention (score ≥ 25).

```json
{
    "id": "770e8400-e29b-41d4-a716-446655440002",
    "attack_event_id": "550e8400-e29b-41d4-a716-446655440000",
    "threat_score_id": "660e8400-e29b-41d4-a716-446655440001",
    "title": "SYN Port Scan from 203.0.113.50",
    "message": "16 ports scanned in 7 seconds at 2.3 ports/sec. Source IP has abuse confidence score of 82.",
    "severity": "high",
    "status": "new",
    "assigned_to": null,
    "created_at": "2024-01-15T14:30:08Z",
    "acknowledged_at": null,
    "resolved_at": null
}
```

---

## 3. Concurrency Model

### 3.1 Thread Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    MAIN PROCESS                          │
│                                                         │
│  Thread 1: CAPTURE (daemon)                             │
│  ├── Scapy sniff() — never blocked                      │
│  ├── Enqueue to packet_queue                            │
│  └── Priority: HIGHEST (real-time constraint)           │
│                                                         │
│  Thread 2: PYSHARK CAPTURE (daemon)                     │
│  ├── AsyncLiveCapture for HTTP/DNS                      │
│  ├── Enqueue app-layer events                           │
│  └── Merged with Scapy events by correlation            │
│                                                         │
│  Threads 3–6: PROCESSING WORKERS (daemon, pool=4)       │
│  ├── Dequeue from packet_queue                          │
│  ├── Parse → Enrich → Push to batch_queue               │
│  ├── Feed to detection orchestrator                     │
│  └── Lock: per-flow state updates use threading.RLock   │
│                                                         │
│  Thread 7: BATCH WRITER (daemon)                        │
│  ├── Collect parsed packets in memory list              │
│  ├── Flush: every 500ms OR 500 packets                  │
│  ├── Uses SQLAlchemy session (dedicated)                │
│  └── Write-ahead buffer on DB failure                   │
│                                                         │
│  Thread 8: DETECTION DISPATCHER (daemon)                │
│  ├── Receives enriched packets                          │
│  ├── Dispatches to detector thread pool                 │
│  └── Collects AttackIndicators                          │
│                                                         │
│  Threads 9–12: DETECTOR WORKERS (pool=4)                │
│  ├── Each runs all registered detectors on packet       │
│  ├── Thread-safe: each detector has own state + RLock   │
│  └── Returns List[AttackIndicator]                      │
│                                                         │
│  Thread 13: ALERT DISPATCHER (daemon)                   │
│  ├── Consumes from PriorityQueue                        │
│  ├── Creates alerts, queues emails                      │
│  ├── Emits WebSocket events                             │
│  └── Retry queue for failed operations                  │
│                                                         │
│  Thread 14: STATS AGGREGATOR (daemon, timer)            │
│  ├── Runs every 60 seconds                              │
│  ├── Aggregates protocol_stats, system_stats            │
│  └── Updates Redis cache for dashboard                  │
│                                                         │
│  Thread 15: EMAIL WORKER (daemon, timer)                │
│  ├── Polls email_notifications table every 30 seconds   │
│  ├── Sends via SMTP with TLS                            │
│  └── Retry with exponential backoff                     │
│                                                         │
│  Thread 16: BLOCK EXPIRY CHECKER (daemon, timer)        │
│  ├── Runs every 5 minutes                               │
│  ├── Checks ip_blocks for expired temporary blocks      │
│  └── Removes iptables rules for expired blocks          │
│                                                         │
│  MAIN THREAD: Flask/Gunicorn                            │
│  ├── Handles HTTP requests                              │
│  ├── Serves dashboard pages                             │
│  └── Flask-SocketIO event loop                          │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Thread Safety Mechanisms

| Shared Resource | Protection Mechanism | Access Pattern |
|----------------|---------------------|---------------|
| `packet_queue` | `queue.Queue(maxsize=10000)` | Producer: capture thread; Consumers: processing workers |
| `batch_queue` | `queue.Queue(maxsize=2000)` | Producers: processing workers; Consumer: batch writer |
| `active_attacks` dict | `threading.RLock` per entry | Read: multiple detectors; Write: state manager |
| `flow_table` dict | `threading.RLock` per flow | Read/Write: processing workers |
| `dedup_cache` | `collections.deque(maxlen=1000)` | Append: processing workers (deque is thread-safe for append/pop) |
| `alert_queue` | `queue.PriorityQueue` | Producer: scoring engine; Consumer: alert dispatcher |
| SQLAlchemy sessions | Scoped sessions (`scoped_session`) | Each thread gets its own session |
| Detection state | Per-detector `threading.RLock` | Each detector manages own lock |

### 3.3 Buffer Sizes and Queue Depths

| Queue / Buffer | Max Size | Overflow Behavior | Rationale |
|---------------|----------|-------------------|-----------|
| `packet_queue` | 10,000 packets | Drop + log warning | Prevents memory exhaustion; dropped packets logged as metric |
| `batch_queue` | 2,000 packets | Block producer (backpressure) | Forces processing workers to slow down if DB can't keep up |
| `write_ahead_buffer` | 50,000 packets | Drop oldest packets | Emergency buffer when DB is temporarily unavailable |
| `alert_queue` | Unlimited (PriorityQueue) | No overflow | Alerts are rare relative to packets; must never be dropped |
| `dedup_cache` | 1,000 hashes | Evict oldest (deque) | Fixed memory; older packets already committed to DB |
| `tracked_ips` (detection) | 100,000 entries | LRU eviction | Prevents memory exhaustion from IP spoofing attacks |

### 3.4 Async Batch Insert Timing

```
Time ──────────────────────────────────────────────────▶

Packets arrive: |||||||||||||||||||||||||||||||||||||||||||

Batch 1:        [  collect  ][flush]
                 0ms          500ms

Batch 2:                            [  collect  ][flush]
                                     501ms        1000ms

Batch 3 (early):                                       [collect][flush]
                                                        1001ms  1250ms
                                                        (hit 500 packets
                                                         before 500ms)
```

**Flush triggers (whichever comes first):**
1. Timer: 500ms since last flush
2. Count: 500 packets accumulated
3. Shutdown: application shutting down (drain all remaining)
