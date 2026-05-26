import json
import os
import time
import math
from collections import defaultdict, deque

class AdvancedThreatEngine:
  def __init__(self, rule_config_path=None):
    if rule_config_path is None:
      rule_config_path = os.path.join(os.path.dirname(__file__), "rules.json")
    
    self.rule_config_path = rule_config_path
    self.load_rules()
    
    # State tracking histories for stateful detection modules
    self.port_scan_history = defaultdict(deque) # src_ip -> deque of (timestamp, port)
    self.port_scan_sets = defaultdict(set) # src_ip -> set of unique ports
    
    self.syn_flood_history = defaultdict(deque) # src_ip -> deque of timestamps
    
    self.dns_tunnel_history = defaultdict(deque) # src_ip -> deque of (timestamp, length)
    
    self.brute_force_history = defaultdict(deque) # src_ip -> deque of timestamps
    
    self.traffic_spike_history = deque() # deque of (timestamp, size)
    self._traffic_spike_total = 0
    
    # Beaconing history: src_ip -> dst_ip -> deque of timestamps
    self.beaconing_history = defaultdict(lambda: defaultdict(deque))
    
    # ARP spoofing resolution state: IP -> MAC address
    self.arp_cache = {}

  def load_rules(self):
    try:
      with open(self.rule_config_path, "r") as f:
        self.rules = json.load(f).get("rules", {})
    except Exception as e:
      print(f"Failed to load threat detection rules JSON: {e}. Using hardcoded fallback values.")
      self.rules = {}

  def get_rule(self, rule_name):
    return self.rules.get(rule_name, {"enabled": False})

  def analyze_port_scanning(self, src_ip, dst_port):
    cfg = self.get_rule("port_scanning")
    if not cfg.get("enabled") or not dst_port:
      return False, None

    current_time = time.time()
    cutoff = current_time - cfg.get("time_window", 10)
    history = self.port_scan_history[src_ip]
    ports = self.port_scan_sets[src_ip]

    while history and history[0][0] <= cutoff:
      _, expired_port = history.popleft()
      if not any(p == expired_port for _, p in history):
        ports.discard(expired_port)

    history.append((current_time, dst_port))
    ports.add(dst_port)

    threshold = cfg.get("port_threshold", 15)
    if len(ports) >= threshold:
      desc = f"Port Scan detected: IP {src_ip} scanned {len(ports)} unique ports in {cfg.get('time_window')}s."
      alert_details = {
        "severity": cfg.get("severity", "high"),
        "mitre_id": cfg.get("mitre_id"),
        "mitre_name": cfg.get("mitre_name"),
        "tags": cfg.get("tags", []),
        "description": desc
      }
      return True, alert_details

    return False, None

  def analyze_syn_flood(self, src_ip, flags):
    cfg = self.get_rule("syn_flood")
    if not cfg.get("enabled") or "S" not in flags or "A" in flags:
      return False, None

    current_time = time.time()
    cutoff = current_time - cfg.get("time_window", 5)
    history = self.syn_flood_history[src_ip]

    while history and history[0] <= cutoff:
      history.popleft()

    history.append(current_time)
    
    threshold = cfg.get("rate_threshold", 40)
    if len(history) >= threshold:
      desc = f"SYN Flood attack detected: IP {src_ip} sent {len(history)} SYN packets in {cfg.get('time_window')}s."
      alert_details = {
        "severity": cfg.get("severity", "critical"),
        "mitre_id": cfg.get("mitre_id"),
        "mitre_name": cfg.get("mitre_name"),
        "tags": cfg.get("tags", []),
        "description": desc
      }
      return True, alert_details

    return False, None

  def analyze_dns_tunneling(self, src_ip, dns_query):
    cfg = self.get_rule("dns_tunneling")
    if not cfg.get("enabled") or not dns_query:
      return False, None

    current_time = time.time()
    cutoff = current_time - cfg.get("time_window", 10)
    history = self.dns_tunnel_history[src_ip]

    while history and history[0][0] <= cutoff:
      history.popleft()

    qlen = len(dns_query)
    history.append((current_time, qlen))

    # Length Anomaly Check
    if qlen >= cfg.get("length_threshold", 60):
      desc = f"DNS Tunneling anomaly detected: IP {src_ip} queried abnormally long domain ({qlen} chars): '{dns_query[:30]}...'"
      alert_details = {
        "severity": cfg.get("severity", "medium"),
        "mitre_id": cfg.get("mitre_id"),
        "mitre_name": cfg.get("mitre_name"),
        "tags": cfg.get("tags", []),
        "description": desc
      }
      return True, alert_details

    # Frequency Query Flood Check
    rate_threshold = cfg.get("rate_threshold", 20)
    if len(history) >= rate_threshold:
      desc = f"DNS Query Flood anomaly detected: IP {src_ip} generated {len(history)} DNS queries in {cfg.get('time_window')}s."
      alert_details = {
        "severity": cfg.get("severity", "medium"),
        "mitre_id": cfg.get("mitre_id"),
        "mitre_name": cfg.get("mitre_name"),
        "tags": cfg.get("tags", []),
        "description": desc
      }
      return True, alert_details

    return False, None

  def analyze_brute_force(self, src_ip, is_failed_login):
    cfg = self.get_rule("brute_force")
    if not cfg.get("enabled") or not is_failed_login:
      return False, None

    current_time = time.time()
    cutoff = current_time - cfg.get("time_window", 60)
    history = self.brute_force_history[src_ip]

    while history and history[0] <= cutoff:
      history.popleft()

    history.append(current_time)

    threshold = cfg.get("login_threshold", 5)
    if len(history) >= threshold:
      desc = f"Brute Force attack detected: IP {src_ip} had {len(history)} failed login attempts in {cfg.get('time_window')}s."
      alert_details = {
        "severity": cfg.get("severity", "high"),
        "mitre_id": cfg.get("mitre_id"),
        "mitre_name": cfg.get("mitre_name"),
        "tags": cfg.get("tags", []),
        "description": desc
      }
      return True, alert_details

    return False, None

  def analyze_traffic_spike(self, size_bytes):
    cfg = self.get_rule("traffic_spike")
    if not cfg.get("enabled"):
      return False, None

    current_time = time.time()
    cutoff = current_time - cfg.get("time_window", 5)
    
    while self.traffic_spike_history and self.traffic_spike_history[0][0] <= cutoff:
      _, expired_size = self.traffic_spike_history.popleft()
      self._traffic_spike_total -= expired_size

    self.traffic_spike_history.append((current_time, size_bytes))
    self._traffic_spike_total += size_bytes

    threshold = cfg.get("bytes_threshold", 5000000)
    if self._traffic_spike_total >= threshold:
      desc = f"Suspicious Traffic Spike: Network throughput exceeded {(self._traffic_spike_total/1024/1024):.2f} MB in {cfg.get('time_window')}s."
      alert_details = {
        "severity": cfg.get("severity", "low"),
        "mitre_id": cfg.get("mitre_id"),
        "mitre_name": cfg.get("mitre_name"),
        "tags": cfg.get("tags", []),
        "description": desc
      }
      return True, alert_details

    return False, None

  def analyze_beaconing(self, src_ip, dst_ip):
    """
    Stateful analytics engine looking for periodic beaconing patterns typical of C2 agents.
    Measures the standard deviation of packet interval delays.
    """
    cfg = self.get_rule("beaconing")
    if not cfg.get("enabled") or not dst_ip:
      return False, None

    current_time = time.time()
    cutoff = current_time - cfg.get("time_window", 60)
    history = self.beaconing_history[src_ip][dst_ip]

    while history and history[0] <= cutoff:
      history.popleft()

    history.append(current_time)

    min_hits = cfg.get("min_hits", 8)
    if len(history) < min_hits:
      return False, None

    # Compute delta intervals between sequential packets
    intervals = []
    for i in range(1, len(history)):
      intervals.append(history[i] - history[i-1])

    # Calculate Mean and standard deviation of intervals
    mean_interval = sum(intervals) / len(intervals)
    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)

    # Coefficient of variation (low values indicate regular, periodic, machine-like traffic intervals)
    coef_variation = std_dev / mean_interval if mean_interval > 0 else 1.0

    tolerance = cfg.get("interval_tolerance", 0.15)
    if coef_variation <= tolerance:
      desc = f"C2 Beaconing Pattern detected: {src_ip} -> {dst_ip} at highly regular intervals (~{mean_interval:.2f}s, variance CV={coef_variation:.2f})"
      alert_details = {
        "severity": cfg.get("severity", "medium"),
        "mitre_id": cfg.get("mitre_id"),
        "mitre_name": cfg.get("mitre_name"),
        "tags": cfg.get("tags", []),
        "description": desc
      }
      return True, alert_details

    return False, None

  def analyze_arp_spoofing(self, packet_data):
    """
    Detects ARP cache anomalies by mapping local physical MAC changes to registered IPs.
    """
    cfg = self.get_rule("arp_spoofing")
    if not cfg.get("enabled"):
      return False, None

    # Check if packet contains ARP headers
    op = packet_data.get("arp_op")  # 1 for request, 2 for reply
    if not op:
      return False, None

    src_ip = packet_data.get("sourceIp")
    src_mac = packet_data.get("sourceMac")

    if not src_ip or not src_mac:
      return False, None

    # If the IP is already mapped to a different MAC address, trigger alert
    if src_ip in self.arp_cache and self.arp_cache[src_ip] != src_mac:
      old_mac = self.arp_cache[src_ip]
      desc = f"ARP Poisoning detected: IP {src_ip} claimed by MAC address {src_mac} (Previously associated with {old_mac})"
      alert_details = {
        "severity": cfg.get("severity", "high"),
        "mitre_id": cfg.get("mitre_id"),
        "mitre_name": cfg.get("mitre_name"),
        "tags": cfg.get("tags", []),
        "description": desc
      }
      return True, alert_details

    self.arp_cache[src_ip] = src_mac
    return False, None
