import os
import sys
import time
import socket
import logging
import asyncio
import platform
import requests
import psutil
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] EDR-Agent: %(message)s")
logger = logging.getLogger("EDRAgent")

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")
HEARTBEAT_INTERVAL = 15  # seconds
PROCESS_CHECK_INTERVAL = 5  # seconds

# List of signature patterns for blacklisted hacker executables/utilities
SUSPICIOUS_EXECUTABLES = {
  "mimikatz", "nc", "netcat", "nmap", "wireshark", "tcpdump", 
  "hydra", "john", "hashcat", "gobuster", "dirbuster", "metasploit"
}

# Directories to monitor for File Integrity
MONITORED_PATHS = {
  "linux": ["/etc", "/tmp", "/var/spool/cron"],
  "windows": [os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "Temp"), "C:\\Users\\Public"]
}

class FileIntegrityHandler(FileSystemEventHandler):
  def __init__(self, loop, callback):
    self.loop = loop
    self.callback = callback

  def on_modified(self, event):
    if not event.is_directory:
      self.loop.call_soon_threadsafe(self.callback, "MODIFIED", event.src_path)

  def on_created(self, event):
    if not event.is_directory:
      self.loop.call_soon_threadsafe(self.callback, "CREATED", event.src_path)


class EDRAgent:
  def __init__(self):
    self.hostname = socket.gethostname()
    self.local_ip = self._get_local_ip()
    self.os_type = platform.system().lower()
    self.running = False
    self.observed_pids = set()

    # Session connection pool configuration
    self.session = requests.Session()
    self.session.headers.update({"Content-Type": "application/json"})

  def _get_local_ip(self):
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect(("8.8.8.8", 80))
      ip = s.getsockname()[0]
      s.close()
      return ip
    except Exception:
      return "127.0.0.1"

  def send_alert(self, threat_type, severity, description, details=None):
    """
    Assembles EDR metrics and POSTs directly to Central API Gateway / Threat Service.
    """
    payload = {
      "sourceIp": self.local_ip,
      "destIp": "127.0.0.1",
      "threatType": threat_type,
      "severity": severity,
      "description": f"[EDR Host: {self.hostname}] {description}",
      "packetDetails": {
        "hostname": self.hostname,
        "os_type": self.os_type,
        **(details or {})
      }
    }
    
    # Clean up None values for DB schema compatibility
    payload["packetDetails"] = {k: str(v) for k, v in payload["packetDetails"].items() if v is not None}

    try:
      res = self.session.post(f"{BACKEND_URL}/api/alerts", json=payload, timeout=5)
      if res.status_code == 201:
        logger.info(f"Registered EDR alert: {threat_type} - {description}")
      else:
        logger.error(f"Failed to post EDR alert to gateway: {res.status_code}")
    except Exception as e:
      logger.error(f"Error communicating with security gateway: {e}")

  async def process_monitor_loop(self):
    """
    Scans process space to flag suspicious executables and CPU spikes.
    """
    logger.info("Initializing process space heuristics monitor...")
    while self.running:
      try:
        current_pids = set()
        for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'username', 'exe']):
          try:
            pinfo = proc.info
            pid = pinfo['pid']
            name = pinfo['name'].lower()
            cpu = pinfo['cpu_percent']
            exe = pinfo['exe'] or ""
            current_pids.add(pid)

            # Check 1: Suspicious Executable Name Signature Match
            base_name = os.path.basename(exe).lower()
            if any(sig in name or sig in base_name for sig in SUSPICIOUS_EXECUTABLES):
              if pid not in self.observed_pids:
                desc = f"Hacker tools/utility executable running: {pinfo['name']} (PID: {pid}, Executed by: {pinfo['username']})"
                self.send_alert(
                  threat_type="Malicious IP Activity",
                  severity="high",
                  description=desc,
                  details={"pid": pid, "process_name": pinfo['name'], "executable": exe, "username": pinfo['username']}
                )

            # Check 2: Resource Hog Spike Detection
            if cpu > 85.0:
              desc = f"Process CPU exhaustion spike: {pinfo['name']} running at {cpu}% CPU (PID: {pid})"
              self.send_alert(
                threat_type="Suspicious Traffic Spike",
                severity="low",
                description=desc,
                details={"pid": pid, "process_name": pinfo['name'], "cpu_percent": cpu}
              )

          except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        self.observed_pids = current_pids
      except Exception as e:
        logger.error(f"Process monitoring exception: {e}")
      
      await asyncio.sleep(PROCESS_CHECK_INTERVAL)

  def file_integrity_callback(self, action, path):
    """
    Processes FIM events captured in the observer thread and registers alerts.
    """
    # Exclude temporary log lock files
    if path.endswith((".log", ".tmp", "~")):
      return

    desc = f"File Integrity Violation: sensitive file {action} - {path}"
    self.send_alert(
      threat_type="Custom Rule Violation",
      severity="medium",
      description=desc,
      details={"file_action": action, "file_path": path}
    )

  def start_fim(self, loop):
    """
    Binds Watchdog observers on target paths based on platform.
    """
    paths = MONITORED_PATHS.get(self.os_type, [])
    if not paths:
      logger.warning("No file integrity paths configured for this OS.")
      return None

    observer = Observer()
    event_handler = FileIntegrityHandler(loop, self.file_integrity_callback)
    
    active_watches = 0
    for path in paths:
      if os.path.exists(path):
        observer.schedule(event_handler, path, recursive=True)
        logger.info(f"FIM monitoring active on: {path}")
        active_watches += 1
      else:
        logger.warning(f"FIM monitor target path does not exist: {path}")

    if active_watches > 0:
      observer.start()
      return observer
    return None

  async def heartbeat_loop(self):
    """
    Submits periodic heartbeat node telemetry to gateway.
    """
    logger.info("Initializing heartbeat telemetry loop...")
    while self.running:
      try:
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        logger.info(f"Node Heartbeat: CPU: {cpu}%, RAM: {ram}%")
        
        # POST node health telemetry to analytics endpoint
        payload = {
          "hostname": self.hostname,
          "ip": self.local_ip,
          "os": self.os_type,
          "cpu": cpu,
          "ram": ram,
          "timestamp": time.time()
        }
        # In a real environment, we would post this to a dedicated endpoint,
        # but since we are keeping backend logic intact, logging it is sufficient.
      except Exception as e:
        logger.error(f"Heartbeat exception: {e}")
      
      await asyncio.sleep(HEARTBEAT_INTERVAL)

  async def start(self):
    logger.info(f"Starting EDR host agent on {self.hostname} ({self.local_ip})...")
    self.running = True

    loop = asyncio.get_running_loop()
    
    # 1. File Integrity Observer Setup
    fim_observer = self.start_fim(loop)

    # 2. Spawn concurrent worker pipelines
    await asyncio.gather(
      self.process_monitor_loop(),
      self.heartbeat_loop()
    )

    if fim_observer:
      fim_observer.stop()
      fim_observer.join()

if __name__ == "__main__":
  agent = EDRAgent()
  try:
    asyncio.run(agent.start())
  except KeyboardInterrupt:
    logger.info("EDR Agent shutdown requested.")
