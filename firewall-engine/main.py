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

  # Run threat analytics
  # 1. Port scan detection
  is_scan, scan_desc = port_scan_det.analyze(src_ip, dst_port)
  if is_scan:
    register_threat_with_backend(src_ip, dst_ip, "Port Scan", "high", scan_desc, packet_data)
    request_ip_block_rule(src_ip, scan_desc)
    return

  # 2. SYN Flood detection
  is_syn_flood, syn_desc = syn_flood_det.analyze(src_ip, flags)
  if is_syn_flood:
    register_threat_with_backend(src_ip, dst_ip, "SYN Flood", "critical", syn_desc, packet_data)
    request_ip_block_rule(src_ip, syn_desc)
    return

  # 3. DNS Anomaly
  if protocol in ("UDP", "DNS") and dns_query:
    is_dns_anomaly, dns_desc = dns_anomaly_det.analyze(src_ip, dns_query)
    if is_dns_anomaly:
      register_threat_with_backend(src_ip, dst_ip, "DNS Anomaly", "medium", dns_desc, packet_data)
      request_ip_block_rule(src_ip, dns_desc)
      return

  # 4. Traffic Spike Detector
  is_spike, spike_desc = traffic_spike_det.analyze(size)
  if is_spike:
    register_threat_with_backend(src_ip, dst_ip, "Suspicious Traffic Spike", "low", spike_desc, packet_data)


# WebSocket triggers from Backend for manual controls
@sio.on('block_ip')
def on_block_ip(data):
  ip = data.get('ip')
  reason = data.get('reason', 'Manual Block')
  logger.info(f"Received WebSocket instruction to block IP: {ip}")
  blocking_mgr.block_ip(ip, reason)

@sio.on('unblock_ip')
def on_unblock_ip(data):
  ip = data.get('ip')
  logger.info(f"Received WebSocket instruction to unblock IP: {ip}")
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
      sio.connect(BACKEND_URL)
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
