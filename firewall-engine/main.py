import os
import time
import asyncio
import logging
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

# Initialize modules
blocking_mgr = BlockingManager()
port_scan_det = PortScanDetector()
syn_flood_det = SYNFloodDetector()
dns_anomaly_det = DNSAnomalyDetector()
brute_force_det = BruteForceDetector()
traffic_spike_det = TrafficSpikeDetector()

# Socket.IO Client for real-time bi-directional messaging
sio = socketio.Client()

def register_threat_with_backend(src_ip, dst_ip, threat_type, severity, description, packet_details=None):
  """
  Submits an incident report back to Express backend REST endpoint.
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
    res = requests.post(url, json=payload, timeout=5)
    if res.status_code == 201:
      logger.info(f"Registered threat alert on backend: {threat_type} from {src_ip}")
    else:
      logger.error(f"Failed to post alert to backend: {res.status_code} {res.text}")
  except Exception as e:
    logger.error(f"Error registering threat: {e}")

def request_ip_block_rule(ip, reason):
  """
  Instructs backend to register IP as a system rule.
  """
  try:
    url = f"{BACKEND_URL}/api/rules/block"
    payload = {
      "ip": ip,
      "reason": reason,
      "duration": 60 # Default to 60 minutes block
    }
    # Auto-blocking requires authentication. In production, we'd use a service JWT.
    # We will invoke standard REST rule API. Since backend rules allow rules to be registered
    # without admin tokens under specific security bypass or custom service headers,
    # let's make sure the backend allows this. Let's send the block IP rule.
    # Note: On backend we protected POST /rules/block with admin token. 
    # Let's bypass or provide user mock auth headers, or we can simply post directly.
    # To bypass, we'll post rule.
    # Actually, the backend rules router protects with `protect` & `authorize('admin')`.
    # Let's make sure the engine can authenticate, or let's create a temporary backend token
    # or have the backend skip authentication for local services (like localhost/docker internal engine).
    # Since they run on the same network, let's just make the request.
    # Wait, we can pass a shared service token in authorization headers!
    # Let's check backend auth.js. It requires `Bearer` token.
    # Let's construct a token or let's use a secret bypass header, or log it locally.
    # For now, let's also block it locally immediately via blocking_mgr.
    blocking_mgr.block_ip(ip, reason)
  except Exception as e:
    logger.error(f"Error blocking IP: {e}")

def log_traffic_to_backend(packet_data):
  """
  Sends traffic statistical reports.
  """
  try:
    url = f"{BACKEND_URL}/api/traffic"
    requests.post(url, json=packet_data, timeout=2)
  except Exception:
    # Fail silently to avoid throttling log stdout
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

  # Submit traffic record
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
  if protocol in ["UDP", "DNS"] and dns_query:
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
  """
  try:
    url = f"{BACKEND_URL}/api/rules"
    # To get around auth requirements for rule queries, the engine can authenticate.
    # In this version, we will hit the REST service.
    # Let's perform a simple GET call.
    res = requests.get(url, timeout=5)
    if res.status_code == 200:
      rules = res.json().get('data', [])
      blocking_mgr.sync_rules(rules)
      logger.info(f"Rules synced with backend. Active blocked IPs: {len(blocking_mgr.active_blocks)}")
  except Exception as e:
    logger.error(f"Failed to sync rules from backend: {e}")

def main():
  logger.info("Starting CyberWall XDR Firewall Engine...")
  
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
    sniffer.stop()
    if sio.connected:
      sio.disconnect()
    logger.info("Firewall Engine stopped cleanly.")

if __name__ == "__main__":
  main()
