import time
from collections import defaultdict

class PortScanDetector:
  def __init__(self, port_threshold=15, time_window=10):
    self.port_threshold = port_threshold
    self.time_window = time_window
    # Maps source_ip -> set of (destination_port, timestamp)
    self.history = defaultdict(set)

  def analyze(self, src_ip, dst_port):
    if not dst_port:
      return False, None
    
    current_time = time.time()
    # Cleanup old records
    self.history[src_ip] = {
      (port, ts) for port, ts in self.history[src_ip]
      if current_time - ts <= self.time_window
    }
    
    self.history[src_ip].add((dst_port, current_time))
    
    unique_ports = {port for port, ts in self.history[src_ip]}
    if len(unique_ports) >= self.port_threshold:
      return True, f"Port Scan detected: IP {src_ip} scanned {len(unique_ports)} unique ports in {self.time_window}s."
    
    return False, None


class SYNFloodDetector:
  def __init__(self, rate_threshold=40, time_window=5):
    self.rate_threshold = rate_threshold
    self.time_window = time_window
    # Maps source_ip -> list of timestamps of SYN packets
    self.history = defaultdict(list)

  def analyze(self, src_ip, flags):
    if 'S' not in flags or 'A' in flags: # Only pure SYN packets
      return False, None
    
    current_time = time.time()
    # Cleanup old records
    self.history[src_ip] = [
      ts for ts in self.history[src_ip]
      if current_time - ts <= self.time_window
    ]
    
    self.history[src_ip].append(current_time)
    
    syn_count = len(self.history[src_ip])
    if syn_count >= self.rate_threshold:
      return True, f"SYN Flood attack detected: IP {src_ip} sent {syn_count} SYN packets in {self.time_window}s."
    
    return False, None


class DNSAnomalyDetector:
  def __init__(self, length_threshold=60, rate_threshold=20, time_window=10):
    self.length_threshold = length_threshold
    self.rate_threshold = rate_threshold
    self.time_window = time_window
    # Maps source_ip -> list of (query_len, timestamp)
    self.history = defaultdict(list)

  def analyze(self, src_ip, dns_query):
    if not dns_query:
      return False, None
    
    current_time = time.time()
    # Cleanup old records
    self.history[src_ip] = [
      (qlen, ts) for qlen, ts in self.history[src_ip]
      if current_time - ts <= self.time_window
    ]
    
    qlen = len(dns_query)
    self.history[src_ip].append((qlen, current_time))
    
    # Check 1: DNS Tunneling query length
    if qlen >= self.length_threshold:
      return True, f"DNS Tunneling anomaly detected: IP {src_ip} queried abnormally long domain ({qlen} chars): '{dns_query[:30]}...'"
    
    # Check 2: High frequency of requests
    req_count = len(self.history[src_ip])
    if req_count >= self.rate_threshold:
      return True, f"DNS Query Flood anomaly detected: IP {src_ip} generated {req_count} DNS queries in {self.time_window}s."
    
    return False, None


class BruteForceDetector:
  def __init__(self, login_threshold=5, time_window=60):
    self.login_threshold = login_threshold
    self.time_window = time_window
    # Maps source_ip -> list of failure timestamps
    self.history = defaultdict(list)

  def analyze(self, src_ip, is_failed_login):
    if not is_failed_login:
      return False, None
    
    current_time = time.time()
    self.history[src_ip] = [
      ts for ts in self.history[src_ip]
      if current_time - ts <= self.time_window
    ]
    
    self.history[src_ip].append(current_time)
    
    fail_count = len(self.history[src_ip])
    if fail_count >= self.login_threshold:
      return True, f"Brute Force attack detected: IP {src_ip} had {fail_count} failed login attempts in {self.time_window}s."
    
    return False, None


class TrafficSpikeDetector:
  def __init__(self, bytes_threshold=5000000, time_window=5): # 5MB threshold
    self.bytes_threshold = bytes_threshold
    self.time_window = time_window
    self.history = []

  def analyze(self, size_bytes):
    current_time = time.time()
    self.history = [
      (size, ts) for size, ts in self.history
      if current_time - ts <= self.time_window
    ]
    
    self.history.append((size_bytes, current_time))
    
    total_bytes = sum(size for size, ts in self.history)
    if total_bytes >= self.bytes_threshold:
      return True, f"Suspicious Traffic Spike: Network throughput exceeded {(total_bytes/1024/1024):.2f} MB in {self.time_window}s."
    
    return False, None
