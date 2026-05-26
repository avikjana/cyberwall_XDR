import time
import math
import logging
from collections import defaultdict, deque

logger = logging.getLogger("AITransformer")

class AITreatDetectionEngine:
  """
  An enterprise-grade, lightweight Machine Learning & Behavioral analysis engine.
  Uses an online, resource-optimized Isolation Forest approximation (Streaming Data Anomaly detection)
  and sequential packet entropy tracking to calculate real-time threat scores and AI confidence.
  """
  def __init__(self, time_window=10, history_size=200):
    self.time_window = time_window
    self.history_size = history_size
    
    # Store recent packet features per Source IP for behavioral profiles
    # Maps src_ip -> deque of dictionaries containing extracted features
    self.ip_profiles = defaultdict(lambda: deque(maxlen=history_size))
    
    # Simple online Isolation Forest approximation: track statistical feature limits
    # to measure how far a packet deviates from running network averages
    self.running_stats = {
      "packet_size": {"mean": 500.0, "variance": 10000.0, "count": 1},
      "dest_port_diversity": {"mean": 1.0, "variance": 0.5, "count": 1},
      "pps": {"mean": 2.0, "variance": 4.0, "count": 1}
    }
    
  def _update_running_stat(self, stat_name, val):
    stats = self.running_stats[stat_name]
    count = stats["count"] + 1
    delta = val - stats["mean"]
    mean = stats["mean"] + delta / count
    delta2 = val - mean
    variance = (stats["variance"] * (count - 2) + delta * delta2) / (count - 1) if count > 1 else stats["variance"]
    
    stats["count"] = count
    stats["mean"] = mean
    stats["variance"] = max(variance, 0.001)

  def extract_features(self, packet_data):
    """
    Parses a raw packet dictionary into numerical features for anomaly calculation.
    """
    src_ip = packet_data.get("sourceIp")
    dst_port = packet_data.get("destPort") or 0
    packet_size = packet_data.get("packetSize") or 64
    protocol = packet_data.get("protocol") or "OTHER"
    flags = packet_data.get("flags") or ""
    
    current_time = time.time()
    profile = self.ip_profiles[src_ip]
    
    # Purge expired profile entries
    cutoff = current_time - self.time_window
    while profile and profile[0]["ts"] < cutoff:
      profile.popleft()
      
    # 1. Feature: Packets Per Second (PPS) for this IP
    pps = len(profile) + 1
    
    # 2. Feature: Destination Port Diversity
    unique_ports = set(p["dstPort"] for p in profile)
    unique_ports.add(dst_port)
    port_diversity = len(unique_ports)
    
    # Add new telemetry point
    profile.append({
      "ts": current_time,
      "dstPort": dst_port,
      "packetSize": packet_size,
      "protocol": protocol,
      "flags": flags
    })
    
    # Update global running network statistics for normalization
    self._update_running_stat("packet_size", packet_size)
    self._update_running_stat("dest_port_diversity", port_diversity)
    self._update_running_stat("pps", pps)
    
    return {
      "pps": pps,
      "port_diversity": port_diversity,
      "packet_size": packet_size,
      "is_syn": 1 if ("S" in flags and "A" not in flags) else 0,
      "is_dns": 1 if (protocol == "DNS" or dst_port == 53) else 0
    }

  def calculate_anomaly_score(self, features):
    """
    Simulates Isolation Forest path lengths by measuring the distance (standard deviations)
    of current features from the running network distribution.
    Returns: score (float 0.0 to 1.0)
    """
    deviations = []
    
    for key in ["packet_size", "dest_port_diversity", "pps"]:
      val = features["packet_size"] if key == "packet_size" else (features["port_diversity"] if key == "dest_port_diversity" else features["pps"])
      stats = self.running_stats[key]
      std_dev = math.sqrt(stats["variance"])
      
      # Z-score represents distance down isolation trees (extreme values isolate closer to the root)
      z_score = abs(val - stats["mean"]) / std_dev
      # Map to [0, 1] using Sigmoid
      score = 1 / (1 + math.exp(-z_score + 2.5))
      deviations.append(score)
      
    # Combined anomaly score is the max deviation
    return max(deviations)

  def analyze(self, packet_data):
    """
    Examines packet data in real-time.
    Returns: is_anomaly (bool), threat_score (float), confidence (float), reasoning (str)
    """
    features = self.extract_features(packet_data)
    anomaly_score = self.calculate_anomaly_score(features)
    
    is_anomaly = anomaly_score > 0.70
    threat_score = round(anomaly_score * 100, 1)
    
    # Confidence scales with size of history (needs a baseline count of packets to be highly confident)
    src_ip = packet_data.get("sourceIp")
    history_len = len(self.ip_profiles[src_ip])
    confidence_multiplier = min(history_len / 10.0, 1.0)
    confidence = round((0.7 + (anomaly_score * 0.25)) * confidence_multiplier * 100, 1)
    
    reasoning = []
    if features["pps"] > self.running_stats["pps"]["mean"] + 3 * math.sqrt(self.running_stats["pps"]["variance"]):
      reasoning.append(f"Rate spike detected ({features['pps']} pps)")
    if features["port_diversity"] > 5 and features["pps"] > 10:
      reasoning.append(f"Suspicious port exploration targeting {features['port_diversity']} ports")
    if features["is_syn"] and features["pps"] > 15:
      reasoning.append("High-volume half-open connection attempts (SYN)")
      
    reasoning_str = " | ".join(reasoning) if reasoning else "Statistical outlier in packet header distribution."
    
    return is_anomaly, threat_score, confidence, reasoning_str
