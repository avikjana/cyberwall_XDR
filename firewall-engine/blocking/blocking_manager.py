import platform
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BlockingManager")

# Cache platform detection at module level — called once, not per-instance
_PLATFORM = platform.system().lower()

class BlockingManager:
  def __init__(self):
    self.is_linux = _PLATFORM == "linux"
    self.is_windows = _PLATFORM == "windows"
    self.active_blocks = set()
    logger.info(f"BlockingManager initialized. Platform: {_PLATFORM} (Linux: {self.is_linux}, Windows: {self.is_windows})")

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
    elif self.is_windows:
      try:
        # Add rule to Windows Defender Firewall to block inbound and outbound traffic
        rule_name = f"CyberWall_Block_{ip}"
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={ip}'
        subprocess.run(cmd_in, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(cmd_out, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Successfully added Windows Defender block rule for {ip}")
        return True
      except Exception as e:
        logger.error(f"Failed to add Windows Defender block rule for {ip}: {e}")
        return False
    else:
      logger.info(f"[DRY-RUN/SIMULATION] Mocked firewall drop rule added for {ip} on unsupported platform")
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
    elif self.is_windows:
      try:
        # Delete rule from Windows Defender Firewall
        cmd = f'netsh advfirewall firewall delete rule name="CyberWall_Block_{ip}"'
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info(f"Successfully deleted Windows Defender block rule for {ip}")
        return True
      except Exception as e:
        logger.error(f"Failed to delete Windows Defender block rule for {ip}: {e}")
        return False
    else:
      logger.info(f"[DRY-RUN/SIMULATION] Mocked firewall drop rule removed for {ip} on unsupported platform")
      return True

  def sync_rules(self, active_rules_from_backend):
    """
    Syncs local blocking rules with the list from the database.
    Uses set operations for efficient diff calculation.
    """
    backend_ips = {rule['ip'] for rule in active_rules_from_backend}
    backend_reasons = {rule['ip']: rule.get('reason', 'Synced from SOC') for rule in active_rules_from_backend}

    # Unblock rules not in backend list
    to_unblock = self.active_blocks - backend_ips
    for ip in to_unblock:
      self.unblock_ip(ip)

    # Block new rules from backend — only IPs not already blocked
    to_block = backend_ips - self.active_blocks
    for ip in to_block:
      self.block_ip(ip, backend_reasons.get(ip, 'Synced from SOC'))
