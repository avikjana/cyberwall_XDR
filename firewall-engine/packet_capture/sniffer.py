import logging
import random
import threading
import time
# pyrefly: ignore [missing-import]
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PacketSniffer")

class PacketSniffer:
  def __init__(self, callback):
    self.callback = callback
    self.running = False
    self.thread = None
    # Use Event for cancellable waits instead of time.sleep()
    self._stop_event = threading.Event()

  def start(self, interface=None):
    self.running = True
    self._stop_event.clear()
    self.thread = threading.Thread(target=self._run_sniff, args=(interface,), daemon=True)
    self.thread.start()
    logger.info("PacketSniffer thread started.")

  def stop(self):
    self.running = False
    self._stop_event.set()  # Wake up any sleeping simulation thread immediately
    if self.thread:
      self.thread.join(timeout=2)
    logger.info("PacketSniffer stopped.")

  def _process_packet(self, packet):
    if not self.running:
      return

    # Use getlayer() for efficient layer access — avoids repeated internal dict lookups
    ip_layer = packet.getlayer(IP)
    if ip_layer is None:
      return

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = "OTHER"
    src_port = None
    dst_port = None
    flags = ""
    dns_query = None

    # TCP Layer
    tcp_layer = packet.getlayer(TCP)
    if tcp_layer is not None:
      protocol = "TCP"
      src_port = tcp_layer.sport
      dst_port = tcp_layer.dport
      flags = str(tcp_layer.flags)

    else:
      # UDP Layer
      udp_layer = packet.getlayer(UDP)
      if udp_layer is not None:
        protocol = "UDP"
        src_port = udp_layer.sport
        dst_port = udp_layer.dport

        # DNS query parsing
        dns_layer = packet.getlayer(DNS)
        if dns_layer is not None and dns_layer.qd:
          protocol = "DNS"
          try:
            dnsqr_layer = packet.getlayer(DNSQR)
            if dnsqr_layer is not None and dnsqr_layer.qname:
              qname = dnsqr_layer.qname
              if isinstance(qname, bytes):
                dns_query = qname.decode('utf-8', errors='ignore').strip('.')
              else:
                dns_query = str(qname).strip('.')
          except Exception as dns_err:
            logger.debug(f"Failed to parse DNS query name: {dns_err}")

      else:
        # ICMP Layer
        if packet.getlayer(ICMP) is not None:
          protocol = "ICMP"

    packet_data = {
      "sourceIp": src_ip,
      "destIp": dst_ip,
      "protocol": protocol,
      "sourcePort": src_port,
      "destPort": dst_port,
      "packetSize": len(packet),
      "flags": flags,
      "dnsQuery": dns_query
    }

    try:
      self.callback(packet_data)
    except Exception as callback_err:
      logger.error(f"Packet callback execution failed: {callback_err}")

  def _run_sniff(self, interface):
    try:
      logger.info(f"Sniffer binding to interface: {interface or 'default'}")
      # Run scapy sniff with lfilter to pre-filter only IP packets
      sniff(
        iface=interface,
        prn=self._process_packet,
        store=0,
        lfilter=lambda p: p.haslayer(IP),
        stop_filter=lambda p: not self.running
      )
    except Exception as e:
      logger.error(f"Scapy sniffing encountered error: {e}. Falling back to simulation mode.")
      self._run_simulation()

  def _run_simulation(self):
    """
    Simulation mode generator to generate valid look-alike traffic for development platforms.
    """
    logger.info("Initializing high-fidelity packet flow simulation.")
    protocols = ["TCP", "UDP", "ICMP", "DNS"]
    common_ips = ["192.168.1.10", "192.168.1.15", "10.0.0.4", "10.0.0.8", "8.8.8.8", "1.1.1.1", "185.120.44.12", "45.89.2.14"]
    local_ip = "192.168.1.100"

    # Pre-defined simulation states to trigger detectors
    scan_state = {"active": False, "attacker": "", "ports": list(range(1000, 1050)), "idx": 0}
    syn_flood_state = {"active": False, "attacker": "", "count": 0}
    dns_tunnel_state = {"active": False, "attacker": "", "count": 0}
    attacker_pool = ["198.51.100.42", "203.0.113.88", "192.0.2.17"]

    while self.running:
      # Randomly decide to trigger a simulated attack event to show platform capabilities
      trigger_dice = random.random()

      if not scan_state["active"] and not syn_flood_state["active"] and not dns_tunnel_state["active"] and trigger_dice < 0.03:
        attack_choice = random.choice(["scan", "syn", "dns"])
        attacker_ip = random.choice(attacker_pool)
        if attack_choice == "scan":
          scan_state["active"] = True
          scan_state["attacker"] = attacker_ip
          scan_state["idx"] = 0
          logger.info(f"Simulating Port Scan attack from {attacker_ip}")
        elif attack_choice == "syn":
          syn_flood_state["active"] = True
          syn_flood_state["attacker"] = attacker_ip
          syn_flood_state["count"] = 0
          logger.info(f"Simulating SYN Flood attack from {attacker_ip}")
        elif attack_choice == "dns":
          dns_tunnel_state["active"] = True
          dns_tunnel_state["attacker"] = attacker_ip
          dns_tunnel_state["count"] = 0
          logger.info(f"Simulating DNS Tunneling anomaly from {attacker_ip}")

      # Execute attack step or generate standard background traffic
      if scan_state["active"]:
        src_ip = scan_state["attacker"]
        dst_ip = local_ip
        protocol = "TCP"
        src_port = random.randint(40000, 60000)
        dst_port = scan_state["ports"][scan_state["idx"]]
        flags = "S"
        dns_query = None

        scan_state["idx"] += 1
        if scan_state["idx"] >= len(scan_state["ports"]):
          scan_state["active"] = False

      elif syn_flood_state["active"]:
        src_ip = syn_flood_state["attacker"]
        dst_ip = local_ip
        protocol = "TCP"
        src_port = random.randint(40000, 60000)
        dst_port = 80
        flags = "S"
        dns_query = None

        syn_flood_state["count"] += 1
        if syn_flood_state["count"] >= 50:
          syn_flood_state["active"] = False

      elif dns_tunnel_state["active"]:
        src_ip = dns_tunnel_state["attacker"]
        dst_ip = "8.8.8.8"
        protocol = "DNS"
        src_port = random.randint(40000, 60000)
        dst_port = 53
        flags = ""
        # Extremely long subdomain
        dns_query = f"a{random.randint(1000000000,9999999999)}b{random.randint(1000000000,9999999999)}c{random.randint(1000000000,9999999999)}.exfiltration-data.attacker.com"

        dns_tunnel_state["count"] += 1
        if dns_tunnel_state["count"] >= 3:
          dns_tunnel_state["active"] = False

      else:
        # Background standard traffic
        src_ip = random.choice(common_ips)
        dst_ip = local_ip if src_ip != local_ip else random.choice(common_ips)
        protocol = random.choice(protocols)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53, 3000, 5000, 27017])
        flags = "PA" if protocol == "TCP" else ""
        dns_query = "google.com" if protocol == "DNS" else None

      packet_data = {
        "sourceIp": src_ip,
        "destIp": dst_ip,
        "protocol": protocol,
        "sourcePort": src_port,
        "destPort": dst_port,
        "packetSize": random.randint(64, 1500),
        "flags": flags,
        "dnsQuery": dns_query
      }

      self.callback(packet_data)
      # Use Event.wait() for cancellable sleep — stops instantly on shutdown
      sleep_duration = 0.1 if (scan_state["active"] or syn_flood_state["active"]) else 0.5
      if self._stop_event.wait(timeout=sleep_duration):
        break  # Stop event was set — exit immediately
