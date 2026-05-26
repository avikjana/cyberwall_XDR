# CyberWall XDR Threat Detection Engine

This document details the signature detection algorithms running within the Python IDS/IPS engine.

## 1. Port Scan Detection (`PortScanDetector`)
- **Objective**: Detect when an attacker is probing open ports on a server.
- **Algorithm**:
  1. The engine monitors incoming TCP packets.
  2. For each unique source IP, it tracks the set of destination ports accessed.
  3. It cleans up ports accessed outside of the `time_window` (default: 10 seconds).
  4. If the number of unique destination ports from a single IP exceeds the `port_threshold` (default: 15), a `Port Scan` alert is triggered.
  5. The attacker's IP is submitted to the auto-blocking queue.

## 2. SYN Flood Detection (`SYNFloodDetector`)
- **Objective**: Detect TCP SYN flooding DDoS attacks.
- **Algorithm**:
  1. The engine tracks TCP packets where the flags consist of pure SYN (`S`).
  2. For each source IP, it maintains a list of packet arrival timestamps.
  3. When a SYN arrives, older timestamps outside the `time_window` (default: 5 seconds) are discarded.
  4. If the number of SYN packets in the queue exceeds `rate_threshold` (default: 40), it triggers a `SYN Flood` alarm and drops subsequent traffic.

## 3. DNS Anomaly & Tunneling Detector (`DNSAnomalyDetector`)
- **Objective**: Detect DNS-based exfiltration and flood.
- **Algorithm**:
  1. Parses UDP port 53 traffic matching `DNS` query records.
  2. Tracks query string lengths. If a subdomain queries a name longer than `length_threshold` (default: 60 characters), it flags it as a potential DNS Tunneling exfiltration channel.
  3. Tracks query counts per IP. If requests exceed `rate_threshold` (default: 20 in 10s), it alerts DNS Query Flood.
