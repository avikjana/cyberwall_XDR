import os
import platform
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BlockingManager")

class BlockingManager:
  def __init__(self):
    self.is_linux = platform.system().lower() == "linux"
    self.active_blocks = set()
    logger.info(f"BlockingManager initialized. Platform: {platform.system()} (Linux: {self.is_linux})")

  def block_ip(self, ip, reason=""):
    if ip in self.active_blocks:
      logger.info(f"IP {ip} is already blocked. Skipping.")
      return True

    logger.info(f"Blocking IP: {ip}. Reason: {reason}")
    self.active_blocks.add(ip)

    if self.is_linux:
      try:
        # Append rule to iptables INPUT chain to DROP all packets from source IP
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Successfully added iptables drop rule for {ip}")
        return True
      except Exception as e:
        logger.error(f"Failed to add iptables drop rule for {ip}: {e}")
        return False
    else:
      logger.info(f"[DRY-RUN/SIMULATION] Mocked iptables drop rule added for {ip} on non-Linux platform")
      return True

  def unblock_ip(self, ip):
    if ip not in self.active_blocks:
      logger.info(f"IP {ip} is not in the active blocklist. Skipping.")
      return True

    logger.info(f"Unblocking IP: {ip}")
    self.active_blocks.discard(ip)

    if self.is_linux:
      try:
        # Delete rule from iptables INPUT chain
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Successfully deleted iptables drop rule for {ip}")
        return True
      except Exception as e:
        logger.error(f"Failed to delete iptables drop rule for {ip}: {e}")
        return False
    else:
      logger.info(f"[DRY-RUN/SIMULATION] Mocked iptables drop rule removed for {ip} on non-Linux platform")
      return True

  def sync_rules(self, active_rules_from_backend):
    """
    Syncs local blocking rules with the list from the database.
    """
    backend_ips = {rule['ip'] for rule in active_rules_from_backend}
    
    # Unblock rules not in backend list
    to_unblock = self.active_blocks - backend_ips
    for ip in list(to_unblock):
      self.unblock_ip(ip)

    # Block new rules from backend
    for rule in active_rules_from_backend:
      ip = rule['ip']
      reason = rule.get('reason', 'Synced from SOC')
      if ip not in self.active_blocks:
        self.block_ip(ip, reason)
