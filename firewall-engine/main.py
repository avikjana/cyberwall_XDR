import os
import time
import logging
import threading
from collections import deque
import requests
import socketio
from dotenv import load_dotenv

from packet_capture.sniffer import PacketSniffer
from blocking.blocking_manager import BlockingManager
from detection.detectors import (
  PortScanDetector,
  SYNFloodDetector,
  DNSAnomalyDetector,
  BruteForceDetector,
  TrafficSpikeDetector
)
from detection.ai_threat_engine import AITreatDetectionEngine
from detection.advanced_threat_engine import AdvancedThreatEngine
from detection.ti_client import ThreatIntelClient

# Load env variables
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("FirewallEngine")

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")
API_KEY = os.getenv("API_KEY", "cyberwall-xdr-engine-secret-token")

# ─── Connection-pooled HTTP session (reuses TCP connections) ──────────────────
_http_session = requests.Session()
_http_session.headers.update({"Content-Type": "application/json"})
# Connection pool tuning — up to 10 concurrent connections to backend
adapter = requests.adapters.HTTPAdapter(pool_connections=5, pool_maxsize=10, max_retries=2)
_http_session.mount("http://", adapter)
_http_session.mount("https://", adapter)

# ─── Traffic batch buffer ─────────────────────────────────────────────────────
_traffic_buffer = deque(maxlen=500)  # Safety cap to prevent unbounded growth
_traffic_buffer_lock = threading.Lock()
_BATCH_SIZE = 50
_BATCH_INTERVAL = 2.0  # seconds
_batch_stop_event = threading.Event()

# Initialize modules
blocking_mgr = BlockingManager()
ai_engine = AITreatDetectionEngine()
adv_engine = AdvancedThreatEngine()
ti_client = ThreatIntelClient()

# Keep original detectors as fallback/legacy references
port_scan_det = PortScanDetector()
syn_flood_det = SYNFloodDetector()
dns_anomaly_det = DNSAnomalyDetector()
brute_force_det = BruteForceDetector()
traffic_spike_det = TrafficSpikeDetector()

# Socket.IO Client for real-time bi-directional messaging
sio = socketio.Client()

def _flush_traffic_buffer():
  """Drain pending traffic entries and POST them in a single batch."""
  with _traffic_buffer_lock:
    if not _traffic_buffer:
      return
    batch = list(_traffic_buffer)
    _traffic_buffer.clear()

  if not batch:
    return

  try:
    url = f"{BACKEND_URL}/api/traffic/batch"
    _http_session.post(url, json={"entries": batch}, timeout=5)
  except Exception:
    # Fallback: try sending individually via original endpoint
    try:
      url = f"{BACKEND_URL}/api/traffic"
      for entry in batch:
        _http_session.post(url, json=entry, timeout=2)
    except Exception:
      pass  # Fail silently to avoid throttling log stdout

def _traffic_flush_loop():
  """Background thread that periodically flushes the traffic buffer."""
  while not _batch_stop_event.is_set():
    _batch_stop_event.wait(timeout=_BATCH_INTERVAL)
    _flush_traffic_buffer()

def register_threat_with_backend(src_ip, dst_ip, threat_type, severity, description, packet_details=None):
  """
  Submits an incident report back to Express backend REST endpoint.
  Uses connection-pooled session for efficiency.
  """
  try:
    url = f"{BACKEND_URL}/api/alerts"
    payload = {
      "sourceIp": src_ip,
      "destIp": dst_ip,
      "threatType": threat_type,
      "severity": severity,
      "description": description,
      "packetDetails": packet_details or {}
    }
    res = _http_session.post(url, json=payload, timeout=5)
    if res.status_code == 201:
      logger.info(f"Registered threat alert on backend: {threat_type} from {src_ip}")
    else:
      logger.error(f"Failed to post alert to backend: {res.status_code} {res.text}")
  except Exception as e:
    logger.error(f"Error registering threat: {e}")

def request_ip_block_rule(ip, reason):
  """
  Instructs backend to register IP as a system rule.
  Skips HTTP call if IP is already blocked locally.
  """
  # Early return if already blocked — avoids redundant HTTP calls
  if ip in blocking_mgr.active_blocks:
    return

  try:
    blocking_mgr.block_ip(ip, reason)
  except Exception as e:
    logger.error(f"Error blocking IP: {e}")

def log_traffic_to_backend(packet_data):
  """
  Queues traffic data for batched submission instead of per-packet HTTP POST.
  """
  with _traffic_buffer_lock:
    _traffic_buffer.append(packet_data)
    # Flush immediately if buffer hits batch size threshold
    if len(_traffic_buffer) >= _BATCH_SIZE:
      batch = list(_traffic_buffer)
      _traffic_buffer.clear()

  # If we got a batch to flush, do it outside the lock
  if 'batch' in dir():
    try:
      url_batch = f"{BACKEND_URL}/api/traffic/batch"
      _http_session.post(url_batch, json={"entries": batch}, timeout=5)
    except Exception:
      try:
        url = f"{BACKEND_URL}/api/traffic"
        for entry in batch:
          _http_session.post(url, json=entry, timeout=2)
      except Exception:
        pass

def packet_callback(packet_data):
  """
  Main packet handler triggered for every captured packet.
  Executes AdvancedThreatEngine stateful IDS/IPS detectors.
  """
  src_ip = packet_data["sourceIp"]
  dst_ip = packet_data["destIp"]
  protocol = packet_data["protocol"]
  dst_port = packet_data["destPort"]
  flags = packet_data["flags"]
  dns_query = packet_data["dnsQuery"]
  size = packet_data["packetSize"]

  # Check if source IP is blocked locally. If so, drop processing.
  if src_ip in blocking_mgr.active_blocks:
    return

  # Submit traffic record (now batched — non-blocking)
  log_traffic_to_backend(packet_data)

  # Helper to submit alerts with rich threat metadata mapping
  def trigger_alert(threat_name, details):
    pkt_details = {
      **packet_data,
      "mitre_id": details.get("mitre_id", ""),
      "mitre_name": details.get("mitre_name", ""),
      "tags": ",".join(details.get("tags", []))
    }
    # Clean None values for DB schema compatibility
    pkt_details = {k: str(v) for k, v in pkt_details.items() if v is not None}
    
    register_threat_with_backend(
      src_ip,
      dst_ip,
      threat_name,
      details.get("severity", "medium"),
      details.get("description", ""),
      pkt_details
    )
    # Block immediately if severity is high/critical
    if details.get("severity") in ("high", "critical"):
      request_ip_block_rule(src_ip, details.get("description", ""))

  # 0. Threat Intelligence — instant check against known-bad IOCs
  if ti_client.is_known_malicious(src_ip):
    trigger_alert("Threat Intel Match", {
      "severity": "critical",
      "description": f"Source IP {src_ip} matches known-malicious IOC from threat intelligence feeds",
      "mitre_id": "TA0001",
      "mitre_name": "Initial Access",
      "tags": ["threat-intel", "ioc-match", "blocklist"]
    })
    return

  # Fire async TI enrichment for all observed IPs (non-blocking, populates session cache)
  ti_client.enrich_ip_async(src_ip)

  # 1. ARP Spoofing Detection
  is_arp_spoof, arp_details = adv_engine.analyze_arp_spoofing(packet_data)
  if is_arp_spoof:
    trigger_alert("Custom Rule Violation", arp_details)
    return

  # 2. Port Scan Detection
  is_scan, scan_details = adv_engine.analyze_port_scanning(src_ip, dst_port)
  if is_scan:
    trigger_alert("Port Scan", scan_details)
    return

  # 3. SYN Flood Detection
  is_syn_flood, syn_details = adv_engine.analyze_syn_flood(src_ip, flags)
  if is_syn_flood:
    trigger_alert("SYN Flood", syn_details)
    return

  # 4. DNS Tunneling & DNS Query Flood Detection OR Web Content Filter Block
  if protocol == "DNS" or protocol == "UDP":
    if dns_query:
      query_lower = dns_query.lower().strip('.')
      is_blocked = False
      matched_domain = None
      for blocked in blocking_mgr.blocked_domains:
        if query_lower == blocked or query_lower.endswith('.' + blocked):
          is_blocked = True
          matched_domain = blocked
          break

      if is_blocked:
        logger.info(f"DNS query for blocked website detected: {dns_query} (matched rule: {matched_domain})")
        # Trigger alert
        trigger_alert("Custom Rule Violation", {
          "severity": "high",
          "description": f"Web Content Filter: Blocked access attempt to website {dns_query}",
          "mitre_id": "T1567",
          "mitre_name": "Exfiltration Over Web Service",
          "tags": ["content-filter", "policy-violation", "blocked-website"]
        })

        # Dynamically resolve IP and block it to prevent access to the website
        def resolve_and_block(domain_to_resolve):
          try:
            import socket
            addr_info = socket.getaddrinfo(domain_to_resolve, None)
            resolved_ips = {info[4][0] for info in addr_info if ':' not in info[4][0]} # Only IPv4
            for r_ip in resolved_ips:
              if r_ip != "127.0.0.1" and r_ip != "0.0.0.0":
                logger.info(f"Content Filter: Dynamically blocking IP {r_ip} for domain {domain_to_resolve}")
                request_ip_block_rule(r_ip, f"Content Filter: Resolved IP for blocked domain {domain_to_resolve}")
          except Exception as e:
            logger.error(f"Failed to dynamically resolve and block IPs for {domain_to_resolve}: {e}")

        threading.Thread(target=resolve_and_block, args=(dns_query,), daemon=True).start()
        return

    is_dns, dns_details = adv_engine.analyze_dns_tunneling(src_ip, dns_query)
    if is_dns:
      trigger_alert("DNS Anomaly", dns_details)
      return

  # 5. C2 Beaconing Detection
  is_beacon, beacon_details = adv_engine.analyze_beaconing(src_ip, dst_ip)
  if is_beacon:
    trigger_alert("Malicious IP Activity", beacon_details)
    return

  # 6. Suspicious Traffic Spike Detection
  is_spike, spike_details = adv_engine.analyze_traffic_spike(size)
  if is_spike:
    trigger_alert("Suspicious Traffic Spike", spike_details)
    return

  # 7. AI Anomaly Engine analysis
  is_ai_anomaly, ai_score, ai_conf, ai_reason = ai_engine.analyze(packet_data)
  if is_ai_anomaly:
    description = f"AI Anomaly Engine: {ai_reason} (Score: {ai_score}%, Confidence: {ai_conf}%)"
    severity = "medium"
    if ai_score > 90:
      severity = "critical"
    elif ai_score > 80:
      severity = "high"
    
    details = {
      "severity": severity,
      "description": description,
      "mitre_id": "T1071",
      "mitre_name": "Application Layer Protocol",
      "tags": ["anomaly-detection", "ai"]
    }
    trigger_alert("Malicious IP Activity", details)


# WebSocket triggers from Backend for manual controls
@sio.on('block_ip')
def on_block_ip(data):
  ip = data.get('ip')
  rule_type = data.get('type', 'IP')
  reason = data.get('reason', 'Manual Block')
  logger.info(f"Received WebSocket instruction to block {rule_type}: {ip}")
  if rule_type == 'DOMAIN':
    blocking_mgr.block_domain(ip)
    resolved_ip = data.get('resolvedIp')
    if resolved_ip and resolved_ip != 'N/A' and resolved_ip != '0.0.0.0':
      blocking_mgr.block_ip(resolved_ip, f"Domain Block ({ip}): {reason}")
  else:
    blocking_mgr.block_ip(ip, reason)

@sio.on('unblock_ip')
def on_unblock_ip(data):
  ip = data.get('ip')
  rule_type = data.get('type', 'IP')
  logger.info(f"Received WebSocket instruction to unblock {rule_type}: {ip}")
  if rule_type == 'DOMAIN':
    blocking_mgr.unblock_domain(ip)
    resolved_ip = data.get('resolvedIp')
    if resolved_ip and resolved_ip != 'N/A' and resolved_ip != '0.0.0.0':
      blocking_mgr.unblock_ip(resolved_ip)
  else:
    blocking_mgr.unblock_ip(ip)

def sync_active_rules():
  """
  Periodically pull active rules from the backend.
  Uses connection-pooled session.
  """
  try:
    url = f"{BACKEND_URL}/api/rules"
    res = _http_session.get(url, timeout=5)
    if res.status_code == 200:
      rules = res.json().get('data', [])
      blocking_mgr.sync_rules(rules)
      logger.info(f"Rules synced with backend. Active blocked IPs: {len(blocking_mgr.active_blocks)}")
  except Exception as e:
    logger.error(f"Failed to sync rules from backend: {e}")

def main():
  logger.info("Starting CyberWall XDR Firewall Engine...")

  # Start the background traffic flush thread
  flush_thread = threading.Thread(target=_traffic_flush_loop, daemon=True)
  flush_thread.start()
  logger.info("Traffic batch flush thread started.")

  # Initialize connection to backend socket server
  connected = False
  for i in range(5):
    try:
      sio.connect(BACKEND_URL, auth={"apiKey": API_KEY})
      sio.emit('join_soc')
      logger.info(f"Connected to backend WebSocket server at {BACKEND_URL}")
      connected = True
      break
    except Exception as e:
      logger.warning(f"WebSocket connection failed (attempt {i+1}/5): {e}. Retrying in 3 seconds...")
      time.sleep(3)

  # Sync initial blocking rules
  sync_active_rules()

  # Start Packet Sniffer
  interface = os.getenv("NETWORK_INTERFACE", "")
  sniffer = PacketSniffer(packet_callback)
  sniffer.start(interface=interface if interface else None)

  try:
    while True:
      # Keep main loop running and periodically sync rules
      time.sleep(30)
      sync_active_rules()
  except KeyboardInterrupt:
    logger.info("Shutdown signal received.")
  finally:
    # Signal batch flush thread to stop and do final flush
    _batch_stop_event.set()
    _flush_traffic_buffer()
    flush_thread.join(timeout=3)
    sniffer.stop()
    if sio.connected:
      sio.disconnect()
    _http_session.close()
    logger.info("Firewall Engine stopped cleanly.")

if __name__ == "__main__":
  main()
