"""
Reputation Scoring Engine – Multi-source weighted scoring with MITRE ATT&CK tagging.
Consumes normalized provider data and produces a unified reputation verdict.
"""
import logging

logger = logging.getLogger("TI.ReputationEngine")


class ReputationEngine:
  def __init__(self, scoring_config, mitre_config):
    self.thresholds = scoring_config.get("thresholds", {})
    self.weights = scoring_config.get("weights", {})
    self.mitre_map = mitre_config or {}

  def score_ip(self, enrichments):
    """
    Compute a unified reputation score for an IP from multi-source enrichments.

    :param enrichments: list of normalized provider dicts
    :return: dict with reputation verdict
    """
    if not enrichments:
      return self._empty_verdict("ip")

    vt_score = 0.0
    abuse_score = 0.0
    otx_score = 0.0
    tags = set()
    metadata = {}

    for e in enrichments:
      provider = e.get("provider", "")
      if provider == "virustotal":
        vt_score = min(e.get("detection_ratio", 0), 100)
        tags.update(e.get("tags", []))
      elif provider == "abuseipdb":
        abuse_score = min(e.get("abuse_confidence_score", 0), 100)
        metadata["isp"] = e.get("isp", "")
        metadata["country"] = e.get("country_code", "")
        metadata["is_tor"] = e.get("is_tor", False)
        metadata["total_reports"] = e.get("total_reports", 0)
      elif provider == "alienvault_otx":
        pulse_count = e.get("pulse_count", 0)
        # Normalize: 10+ pulses = 100 score
        otx_score = min(pulse_count * 10, 100)
        tags.update(e.get("tags", []))
        metadata["asn"] = e.get("asn", "")

    weighted = (
      vt_score * self.weights.get("virustotal_detections", 0.4) +
      abuse_score * self.weights.get("abuseipdb_confidence", 0.35) +
      otx_score * self.weights.get("otx_pulse_count", 0.25)
    )
    final_score = round(weighted, 1)
    verdict = self._classify(final_score)
    severity = self._severity(final_score)
    mitre = self._match_mitre(tags)

    return {
      "indicator_type": "ip",
      "reputation_score": final_score,
      "verdict": verdict,
      "severity": severity,
      "component_scores": {
        "virustotal": round(vt_score, 1),
        "abuseipdb": round(abuse_score, 1),
        "otx": round(otx_score, 1)
      },
      "mitre_attack": mitre,
      "tags": list(tags)[:20],
      "metadata": metadata
    }

  def score_domain(self, enrichments):
    if not enrichments:
      return self._empty_verdict("domain")

    vt_score = 0.0
    otx_score = 0.0
    tags = set()
    metadata = {}

    for e in enrichments:
      provider = e.get("provider", "")
      if provider == "virustotal":
        vt_score = min(e.get("detection_ratio", 0), 100)
        metadata["categories"] = e.get("categories", {})
      elif provider == "alienvault_otx":
        pulse_count = e.get("pulse_count", 0)
        otx_score = min(pulse_count * 10, 100)

    weighted = (
      vt_score * 0.6 +
      otx_score * 0.4
    )
    final_score = round(weighted, 1)
    verdict = self._classify(final_score)
    severity = self._severity(final_score)

    return {
      "indicator_type": "domain",
      "reputation_score": final_score,
      "verdict": verdict,
      "severity": severity,
      "component_scores": {
        "virustotal": round(vt_score, 1),
        "otx": round(otx_score, 1)
      },
      "mitre_attack": self._match_mitre(tags),
      "tags": list(tags)[:20],
      "metadata": metadata
    }

  def score_hash(self, enrichments):
    if not enrichments:
      return self._empty_verdict("hash")

    vt_score = 0.0
    otx_score = 0.0
    tags = set()
    metadata = {}

    for e in enrichments:
      provider = e.get("provider", "")
      if provider == "virustotal":
        vt_score = min(e.get("detection_ratio", 0), 100)
        metadata["file_type"] = e.get("file_type", "")
        tags.update(e.get("tags", []))
      elif provider == "alienvault_otx":
        pulse_count = e.get("pulse_count", 0)
        otx_score = min(pulse_count * 10, 100)

    weighted = (
      vt_score * 0.7 +
      otx_score * 0.3
    )
    final_score = round(weighted, 1)
    verdict = self._classify(final_score)
    severity = self._severity(final_score)

    return {
      "indicator_type": "hash",
      "reputation_score": final_score,
      "verdict": verdict,
      "severity": severity,
      "component_scores": {
        "virustotal": round(vt_score, 1),
        "otx": round(otx_score, 1)
      },
      "mitre_attack": self._match_mitre(tags),
      "tags": list(tags)[:20],
      "metadata": metadata
    }

  def _classify(self, score):
    if score >= self.thresholds.get("malicious", 70):
      return "malicious"
    elif score >= self.thresholds.get("suspicious", 40):
      return "suspicious"
    return "benign"

  def _severity(self, score):
    if score >= 80:
      return "critical"
    elif score >= 60:
      return "high"
    elif score >= 40:
      return "medium"
    elif score >= 15:
      return "low"
    return "info"

  def _match_mitre(self, tags):
    """Best-effort MITRE ATT&CK mapping from threat tags."""
    tags_lower = {t.lower() for t in tags}
    matches = []
    for keyword, mitre in self.mitre_map.items():
      if keyword in tags_lower or any(keyword in t for t in tags_lower):
        matches.append(mitre)
    return matches if matches else [{"id": "TA0043", "name": "Reconnaissance"}]

  def _empty_verdict(self, indicator_type):
    return {
      "indicator_type": indicator_type,
      "reputation_score": 0.0,
      "verdict": "unknown",
      "severity": "info",
      "component_scores": {},
      "mitre_attack": [],
      "tags": [],
      "metadata": {}
    }
