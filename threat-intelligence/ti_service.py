"""
CyberWall XDR – Threat Intelligence Service
Standalone HTTP API server that exposes IOC enrichment, reputation lookup,
and feed management endpoints. Designed to run as a microservice alongside
the existing gateway, auth-service, threat-service, and websocket-service.
"""
import os
import sys
import json
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from dotenv import load_dotenv

# Ensure module imports work when running as standalone
sys.path.insert(0, os.path.dirname(__file__))

from enrichment_pipeline import EnrichmentPipeline
from feed_sync_worker import FeedSyncWorker
from ioc_cache import IOCCache

load_dotenv()

logging.basicConfig(
  level=logging.INFO,
  format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("TI.Service")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
PORT = int(os.getenv("TI_PORT", "5004"))
FEED_SYNC_INTERVAL = int(os.getenv("FEED_SYNC_INTERVAL_MINUTES", "30"))

# ─── Initialize core systems ─────────────────────────────────────────────────
pipeline = EnrichmentPipeline(redis_url=REDIS_URL)
cache = IOCCache(redis_url=REDIS_URL)
sync_worker = FeedSyncWorker(cache=cache, interval_minutes=FEED_SYNC_INTERVAL)


class ThreatIntelHandler(BaseHTTPRequestHandler):
  """HTTP request handler for the Threat Intelligence API."""

  def do_GET(self):
    parsed = urlparse(self.path)
    path = parsed.path.rstrip("/")
    params = parse_qs(parsed.query)

    routes = {
      "/api/ti/health": self._health,
      "/api/ti/enrich/ip": self._enrich_ip,
      "/api/ti/enrich/domain": self._enrich_domain,
      "/api/ti/enrich/hash": self._enrich_hash,
      "/api/ti/stats": self._stats,
    }

    handler = routes.get(path)
    if handler:
      handler(params)
    else:
      self._json_response(404, {"error": "Not found"})

  def do_POST(self):
    parsed = urlparse(self.path)
    path = parsed.path.rstrip("/")

    if path == "/api/ti/enrich/bulk":
      self._bulk_enrich()
    elif path == "/api/ti/sync":
      self._trigger_sync()
    elif path == "/api/ti/ioc":
      self._add_custom_ioc()
    else:
      self._json_response(404, {"error": "Not found"})

  def _health(self, params):
    self._json_response(200, {
      "status": "healthy",
      "service": "threat-intelligence",
      "version": "1.0.0",
      "providers": len(pipeline.providers),
      "cache_connected": cache.connected
    })

  def _enrich_ip(self, params):
    ip = params.get("ip", [None])[0]
    if not ip:
      return self._json_response(400, {"error": "Missing 'ip' parameter"})
    bypass = params.get("bypass_cache", ["false"])[0].lower() == "true"
    result = pipeline.enrich_ip(ip, bypass_cache=bypass)
    self._json_response(200, result)

  def _enrich_domain(self, params):
    domain = params.get("domain", [None])[0]
    if not domain:
      return self._json_response(400, {"error": "Missing 'domain' parameter"})
    bypass = params.get("bypass_cache", ["false"])[0].lower() == "true"
    result = pipeline.enrich_domain(domain, bypass_cache=bypass)
    self._json_response(200, result)

  def _enrich_hash(self, params):
    hash_val = params.get("hash", [None])[0]
    if not hash_val:
      return self._json_response(400, {"error": "Missing 'hash' parameter"})
    bypass = params.get("bypass_cache", ["false"])[0].lower() == "true"
    result = pipeline.enrich_hash(hash_val, bypass_cache=bypass)
    self._json_response(200, result)

  def _bulk_enrich(self):
    body = self._read_body()
    if not body:
      return self._json_response(400, {"error": "Empty request body"})
    ips = body.get("ips", [])
    if not ips:
      return self._json_response(400, {"error": "Missing 'ips' array"})
    results = pipeline.bulk_enrich_ips(ips[:50])  # Cap at 50
    self._json_response(200, {"results": results, "count": len(results)})

  def _trigger_sync(self):
    """Manually trigger a feed sync in the background."""
    threading.Thread(target=sync_worker._sync_all, daemon=True).start()
    self._json_response(200, {"message": "Feed sync triggered"})

  def _add_custom_ioc(self):
    """Add a custom IOC to the cache."""
    body = self._read_body()
    if not body:
      return self._json_response(400, {"error": "Empty request body"})

    itype = body.get("type", "ip")
    indicator = body.get("indicator", "")
    if not indicator:
      return self._json_response(400, {"error": "Missing 'indicator' field"})

    cache.set(itype, indicator, {
      "indicator_type": itype,
      "indicator": indicator,
      "reputation_score": body.get("score", 90.0),
      "verdict": body.get("verdict", "malicious"),
      "severity": body.get("severity", "high"),
      "source": "custom-api",
      "component_scores": {},
      "mitre_attack": body.get("mitre", []),
      "tags": body.get("tags", ["custom-ioc"]),
      "metadata": body.get("metadata", {}),
      "enrichments": []
    }, ttl=body.get("ttl", 604800))

    self._json_response(201, {"message": f"IOC {indicator} added", "type": itype})

  def _stats(self, params):
    self._json_response(200, {
      "providers_active": len(pipeline.providers),
      "provider_names": [p.name for p in pipeline.providers],
      "cache_backend": "redis" if cache.connected else "memory",
      "feed_sync_interval_min": FEED_SYNC_INTERVAL
    })

  def _json_response(self, status, data):
    self.send_response(status)
    self.send_header("Content-Type", "application/json")
    self.send_header("Access-Control-Allow-Origin", "*")
    self.end_headers()
    self.wfile.write(json.dumps(data).encode())

  def _read_body(self):
    try:
      length = int(self.headers.get("Content-Length", 0))
      raw = self.rfile.read(length)
      return json.loads(raw) if raw else None
    except Exception:
      return None

  def log_message(self, format, *args):
    logger.info(f"{self.client_address[0]} - {format % args}")


def main():
  logger.info("=" * 60)
  logger.info("  CyberWall XDR – Threat Intelligence Service v1.0")
  logger.info("=" * 60)

  # Start feed sync worker
  sync_worker.start()
  logger.info(f"Feed sync worker running (interval: {FEED_SYNC_INTERVAL}m)")

  # Start HTTP server
  server = HTTPServer(("0.0.0.0", PORT), ThreatIntelHandler)
  logger.info(f"TI Service listening on port {PORT}")
  logger.info("Endpoints:")
  logger.info(f"  GET  /api/ti/health")
  logger.info(f"  GET  /api/ti/enrich/ip?ip=<ip>")
  logger.info(f"  GET  /api/ti/enrich/domain?domain=<domain>")
  logger.info(f"  GET  /api/ti/enrich/hash?hash=<hash>")
  logger.info(f"  POST /api/ti/enrich/bulk  {{\"ips\": [...]}}")
  logger.info(f"  POST /api/ti/sync")
  logger.info(f"  POST /api/ti/ioc")
  logger.info(f"  GET  /api/ti/stats")

  try:
    server.serve_forever()
  except KeyboardInterrupt:
    logger.info("Shutting down TI service...")
    sync_worker.stop()
    server.server_close()


if __name__ == "__main__":
  main()
