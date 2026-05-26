"""
Feed Providers – Adapter modules for VirusTotal, AbuseIPDB, and AlienVault OTX.
Each provider normalizes raw API responses into a unified IOC enrichment schema.
"""
import os
import time
import logging
import requests

logger = logging.getLogger("TI.Providers")


class BaseFeedProvider:
  """Abstract base class for all threat intelligence feed providers."""
  def __init__(self, name, config):
    self.name = name
    self.enabled = config.get("enabled", False)
    self.base_url = config.get("base_url", "")
    self.api_key = os.getenv(config.get("api_key_env", ""), "")
    self.cache_ttl = config.get("cache_ttl_seconds", 3600)
    self.rate_limit = config.get("rate_limit_per_min", 60)
    self.endpoints = config.get("endpoints", {})
    self._last_call_ts = 0
    self._call_count = 0

    self.session = requests.Session()

  def _throttle(self):
    """Simple sliding-window rate limiter — waits until rate quota resets."""
    now = time.time()
    if now - self._last_call_ts > 60:
      self._call_count = 0
      self._last_call_ts = now
    if self._call_count >= self.rate_limit:
      sleep_for = 60 - (now - self._last_call_ts)
      if sleep_for > 0:
        logger.info(f"[{self.name}] Rate limit reached, sleeping {sleep_for:.1f}s")
        time.sleep(sleep_for)
      self._call_count = 0
      self._last_call_ts = time.time()
    self._call_count += 1

  def lookup_ip(self, ip):
    raise NotImplementedError

  def lookup_domain(self, domain):
    raise NotImplementedError

  def lookup_hash(self, file_hash):
    raise NotImplementedError


class VirusTotalProvider(BaseFeedProvider):
  def __init__(self, config):
    super().__init__("VirusTotal", config)

  def _request(self, endpoint, indicator):
    if not self.enabled or not self.api_key:
      return None
    self._throttle()
    url = self.base_url + endpoint.replace("{indicator}", indicator)
    try:
      res = self.session.get(url, headers={"x-apikey": self.api_key}, timeout=10)
      if res.status_code == 200:
        return res.json()
      logger.warning(f"[VirusTotal] API returned {res.status_code} for {indicator}")
    except Exception as e:
      logger.error(f"[VirusTotal] Request error: {e}")
    return None

  def lookup_ip(self, ip):
    raw = self._request(self.endpoints.get("ip", ""), ip)
    if not raw:
      return None
    stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    return {
      "provider": "virustotal",
      "indicator": ip,
      "type": "ip",
      "malicious_detections": malicious,
      "total_engines": total,
      "detection_ratio": round(malicious / total * 100, 1),
      "reputation": raw.get("data", {}).get("attributes", {}).get("reputation", 0),
      "tags": raw.get("data", {}).get("attributes", {}).get("tags", [])
    }

  def lookup_domain(self, domain):
    raw = self._request(self.endpoints.get("domain", ""), domain)
    if not raw:
      return None
    stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    return {
      "provider": "virustotal",
      "indicator": domain,
      "type": "domain",
      "malicious_detections": malicious,
      "total_engines": total,
      "detection_ratio": round(malicious / total * 100, 1),
      "categories": raw.get("data", {}).get("attributes", {}).get("categories", {})
    }

  def lookup_hash(self, file_hash):
    raw = self._request(self.endpoints.get("hash", ""), file_hash)
    if not raw:
      return None
    stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) or 1
    return {
      "provider": "virustotal",
      "indicator": file_hash,
      "type": "hash",
      "malicious_detections": malicious,
      "total_engines": total,
      "detection_ratio": round(malicious / total * 100, 1),
      "file_type": raw.get("data", {}).get("attributes", {}).get("type_description", ""),
      "tags": raw.get("data", {}).get("attributes", {}).get("tags", [])
    }


class AbuseIPDBProvider(BaseFeedProvider):
  def __init__(self, config):
    super().__init__("AbuseIPDB", config)

  def lookup_ip(self, ip):
    if not self.enabled or not self.api_key:
      return None
    self._throttle()
    url = self.base_url + self.endpoints.get("ip_check", "/check")
    try:
      res = self.session.get(url,
        headers={"Key": self.api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        timeout=10
      )
      if res.status_code == 200:
        data = res.json().get("data", {})
        return {
          "provider": "abuseipdb",
          "indicator": ip,
          "type": "ip",
          "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
          "total_reports": data.get("totalReports", 0),
          "country_code": data.get("countryCode", ""),
          "isp": data.get("isp", ""),
          "is_tor": data.get("isTor", False),
          "is_whitelisted": data.get("isWhitelisted", False),
          "usage_type": data.get("usageType", ""),
          "domain": data.get("domain", "")
        }
      logger.warning(f"[AbuseIPDB] API returned {res.status_code} for {ip}")
    except Exception as e:
      logger.error(f"[AbuseIPDB] Request error: {e}")
    return None

  def lookup_domain(self, domain):
    return None  # AbuseIPDB is IP-only

  def lookup_hash(self, file_hash):
    return None  # AbuseIPDB is IP-only


class AlienVaultOTXProvider(BaseFeedProvider):
  def __init__(self, config):
    super().__init__("AlienVault OTX", config)

  def _request(self, endpoint, indicator):
    if not self.enabled or not self.api_key:
      return None
    self._throttle()
    url = self.base_url + endpoint.replace("{indicator}", indicator)
    try:
      res = self.session.get(url, headers={"X-OTX-API-KEY": self.api_key}, timeout=10)
      if res.status_code == 200:
        return res.json()
      logger.warning(f"[OTX] API returned {res.status_code} for {indicator}")
    except Exception as e:
      logger.error(f"[OTX] Request error: {e}")
    return None

  def lookup_ip(self, ip):
    raw = self._request(self.endpoints.get("ip", ""), ip)
    if not raw:
      return None
    return {
      "provider": "alienvault_otx",
      "indicator": ip,
      "type": "ip",
      "pulse_count": raw.get("pulse_info", {}).get("count", 0),
      "country": raw.get("country_name", ""),
      "asn": raw.get("asn", ""),
      "reputation": raw.get("reputation", 0),
      "tags": list(set(t for p in raw.get("pulse_info", {}).get("pulses", []) for t in p.get("tags", [])))[:15]
    }

  def lookup_domain(self, domain):
    raw = self._request(self.endpoints.get("domain", ""), domain)
    if not raw:
      return None
    return {
      "provider": "alienvault_otx",
      "indicator": domain,
      "type": "domain",
      "pulse_count": raw.get("pulse_info", {}).get("count", 0),
      "alexa_rank": raw.get("alexa", ""),
      "whois": raw.get("whois", "")[:200] if raw.get("whois") else ""
    }

  def lookup_hash(self, file_hash):
    raw = self._request(self.endpoints.get("hash", ""), file_hash)
    if not raw:
      return None
    return {
      "provider": "alienvault_otx",
      "indicator": file_hash,
      "type": "hash",
      "pulse_count": raw.get("pulse_info", {}).get("count", 0)
    }
