import time
from collections import defaultdict, deque


class PortScanDetector:
  def __init__(self, port_threshold=15, time_window=10):
    self.port_threshold = port_threshold
    self.time_window = time_window
    # Maps source_ip -> deque of (timestamp, port) sorted by time
    self.history = defaultdict(deque)
    # Maps source_ip -> set of unique ports in the current window
    self.port_sets = defaultdict(set)

  def analyze(self, src_ip, dst_port):
    if not dst_port:
      return False, None

    current_time = time.time()
    cutoff = current_time - self.time_window
    ip_history = self.history[src_ip]
    ip_ports = self.port_sets[src_ip]

    # Evict expired entries from the left (oldest first) — O(k) where k = expired
    while ip_history and ip_history[0][0] <= cutoff:
      _, expired_port = ip_history.popleft()
      # Only remove from port set if no other entry references this port
      if not any(p == expired_port for _, p in ip_history):
        ip_ports.discard(expired_port)

    ip_history.append((current_time, dst_port))
    ip_ports.add(dst_port)

    if len(ip_ports) >= self.port_threshold:
      return True, f"Port Scan detected: IP {src_ip} scanned {len(ip_ports)} unique ports in {self.time_window}s."

    return False, None


class SYNFloodDetector:
  def __init__(self, rate_threshold=40, time_window=5):
    self.rate_threshold = rate_threshold
    self.time_window = time_window
    # Maps source_ip -> deque of timestamps (sorted ascending)
    self.history = defaultdict(deque)

  def analyze(self, src_ip, flags):
    if 'S' not in flags or 'A' in flags: # Only pure SYN packets
      return False, None

    current_time = time.time()
    cutoff = current_time - self.time_window
    ip_history = self.history[src_ip]

    # Evict expired timestamps from the left — O(k) where k = expired
    while ip_history and ip_history[0] <= cutoff:
      ip_history.popleft()

    ip_history.append(current_time)

    syn_count = len(ip_history)
    if syn_count >= self.rate_threshold:
      return True, f"SYN Flood attack detected: IP {src_ip} sent {syn_count} SYN packets in {self.time_window}s."

    return False, None


class DNSAnomalyDetector:
  def __init__(self, length_threshold=60, rate_threshold=20, time_window=10):
    self.length_threshold = length_threshold
    self.rate_threshold = rate_threshold
    self.time_window = time_window
    # Maps source_ip -> deque of (timestamp, query_len)
    self.history = defaultdict(deque)

  def analyze(self, src_ip, dns_query):
    if not dns_query:
      return False, None

    current_time = time.time()
    cutoff = current_time - self.time_window
    ip_history = self.history[src_ip]

    # Evict expired entries from the left — O(k) where k = expired
    while ip_history and ip_history[0][0] <= cutoff:
      ip_history.popleft()

    qlen = len(dns_query)
    ip_history.append((current_time, qlen))

    # Check 1: DNS Tunneling query length
    if qlen >= self.length_threshold:
      return True, f"DNS Tunneling anomaly detected: IP {src_ip} queried abnormally long domain ({qlen} chars): '{dns_query[:30]}...'"

    # Check 2: High frequency of requests
    req_count = len(ip_history)
    if req_count >= self.rate_threshold:
      return True, f"DNS Query Flood anomaly detected: IP {src_ip} generated {req_count} DNS queries in {self.time_window}s."

    return False, None


class BruteForceDetector:
  def __init__(self, login_threshold=5, time_window=60):
    self.login_threshold = login_threshold
    self.time_window = time_window
    # Maps source_ip -> deque of failure timestamps
    self.history = defaultdict(deque)

  def analyze(self, src_ip, is_failed_login):
    if not is_failed_login:
      return False, None

    current_time = time.time()
    cutoff = current_time - self.time_window
    ip_history = self.history[src_ip]

    # Evict expired timestamps — O(k)
    while ip_history and ip_history[0] <= cutoff:
      ip_history.popleft()

    ip_history.append(current_time)

    fail_count = len(ip_history)
    if fail_count >= self.login_threshold:
      return True, f"Brute Force attack detected: IP {src_ip} had {fail_count} failed login attempts in {self.time_window}s."

    return False, None


class TrafficSpikeDetector:
  def __init__(self, bytes_threshold=5000000, time_window=5): # 5MB threshold
    self.bytes_threshold = bytes_threshold
    self.time_window = time_window
    self.history = deque()
    # Running sum accumulator — O(1) per packet instead of O(n) sum()
    self._running_total = 0

  def analyze(self, size_bytes):
    current_time = time.time()
    cutoff = current_time - self.time_window

    # Evict expired entries and subtract from running total — O(k)
    while self.history and self.history[0][0] <= cutoff:
      _, expired_size = self.history.popleft()
      self._running_total -= expired_size

    self.history.append((current_time, size_bytes))
    self._running_total += size_bytes

    if self._running_total >= self.bytes_threshold:
      return True, f"Suspicious Traffic Spike: Network throughput exceeded {(self._running_total/1024/1024):.2f} MB in {self.time_window}s."

    return False, None
