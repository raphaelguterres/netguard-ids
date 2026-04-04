"""
NetGuard — IP Enrichment Engine
Shodan + WHOIS + ASN + Geolocation enrichment.

Dados coletados por IP:
  - ASN / organização / ISP (via ipinfo.io — grátis, sem key)
  - WHOIS registrar e datas (via rdap.org — sem key)
  - Shodan InternetDB (sem API key — dados de exposição pública)
  - Geolocalização (via ip-api.com — grátis)
  - Portas abertas conhecidas do Shodan
  - CVEs associados ao IP
  - Tags de reputação (tor, vpn, proxy, scanner, etc.)
"""

import json
import time
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Dict, Optional, Any  # noqa: F401

logger = logging.getLogger("netguard.enrichment")

# Private IP ranges — skip enrichment
PRIVATE_RANGES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.0.0.0", "::1", "fe80:", "fc00:", "fd",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_RANGES)


def _fetch(url: str, timeout: int = 6) -> Optional[dict]:
    """Fetch JSON from URL, return None on error."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NetGuard-IDS/3.0 (security research)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as e:
        logger.debug("Fetch failed %s: %s", url, e)
        return None


class IPEnrichment:
    """Full IP enrichment: Shodan InternetDB + ipinfo + ip-api."""

    def __init__(self):
        self._cache: Dict[str, dict] = {}
        self._cache_ttl: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._cache_duration = 3600  # 1 hour
        self._stats = {"total_enriched": 0, "cache_hits": 0, "api_calls": 0}
        logger.info("IPEnrichment iniciado | Shodan InternetDB + ipinfo + ip-api")

    def enrich(self, ip: str, force: bool = False) -> dict:
        """
        Enrich an IP address with all available data.
        Returns enrichment dict (cached for 1h).
        """
        if _is_private(ip):
            return self._private_result(ip)

        with self._lock:
            cached = self._cache.get(ip)
            cached_at = self._cache_ttl.get(ip, 0)
            if cached and not force and (time.monotonic() - cached_at) < self._cache_duration:
                self._stats["cache_hits"] += 1
                return cached

        result = self._fetch_all(ip)

        with self._lock:
            self._cache[ip] = result
            self._cache_ttl[ip] = time.monotonic()
            self._stats["total_enriched"] += 1
            # Keep cache bounded
            if len(self._cache) > 2000:
                oldest = sorted(self._cache_ttl, key=self._cache_ttl.get)[:200]
                for k in oldest:
                    self._cache.pop(k, None)
                    self._cache_ttl.pop(k, None)

        return result

    def _fetch_all(self, ip: str) -> dict:
        """Fetch from all sources and merge."""
        result = {
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "private": False,
            # Geo
            "country": "", "country_code": "", "city": "", "region": "",
            "lat": 0.0, "lon": 0.0, "timezone": "",
            # Network
            "asn": "", "org": "", "isp": "", "domain": "",
            # Shodan
            "ports": [], "vulns": [], "tags": [], "hostnames": [],
            "cpes": [],
            # Risk
            "risk_score": 0,
            "risk_tags": [],
            # WHOIS
            "registrar": "", "created": "", "updated": "",
        }

        with self._lock:
            self._stats["api_calls"] += 1

        # ── 1. Shodan InternetDB (free, no key) ───────────────────
        shodan_data = _fetch(f"https://internetdb.shodan.io/{ip}")
        if shodan_data:
            result["ports"] = shodan_data.get("ports", [])[:20]
            result["vulns"] = shodan_data.get("vulns", [])[:10]
            result["tags"] = shodan_data.get("tags", [])
            result["hostnames"] = shodan_data.get("hostnames", [])[:5]
            result["cpes"] = shodan_data.get("cpes", [])[:10]

            # Risk scoring from Shodan
            vuln_count = len(result["vulns"])
            if vuln_count > 0:
                result["risk_score"] += min(40, vuln_count * 10)
                result["risk_tags"].append(f"{vuln_count} CVEs")
            if "compromised" in result["tags"]:
                result["risk_score"] += 30
                result["risk_tags"].append("compromised host")
            if "malware" in result["tags"]:
                result["risk_score"] += 40
                result["risk_tags"].append("malware")
            if "tor" in result["tags"]:
                result["risk_score"] += 20
                result["risk_tags"].append("Tor exit node")

        # ── 2. ipinfo.io (free tier, no key needed) ───────────────
        ipinfo = _fetch(f"https://ipinfo.io/{ip}/json")
        if ipinfo:
            result["org"] = ipinfo.get("org", "")
            result["city"] = ipinfo.get("city", "")
            result["region"] = ipinfo.get("region", "")
            result["country_code"] = ipinfo.get("country", "")
            result["timezone"] = ipinfo.get("timezone", "")
            result["domain"] = ipinfo.get("hostname", "")
            # Parse ASN from org (format: "AS1234 Org Name")
            org = result["org"]
            if org.startswith("AS"):
                parts = org.split(" ", 1)
                result["asn"] = parts[0]
                result["isp"] = parts[1] if len(parts) > 1 else org
            # Abuse/VPN detection
            abuse = ipinfo.get("abuse", {})
            if abuse:
                result["risk_tags"].append("abuse contact found")
            privacy = ipinfo.get("privacy", {})
            if privacy.get("vpn"):
                result["risk_score"] += 10
                result["risk_tags"].append("VPN")
            if privacy.get("proxy"):
                result["risk_score"] += 15
                result["risk_tags"].append("proxy")
            if privacy.get("tor"):
                result["risk_score"] += 20
                result["risk_tags"].append("Tor")

        # ── 3. ip-api.com (free, no key, geo) ─────────────────────
        geoapi = _fetch(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
            f"regionName,city,lat,lon,isp,org,as,query"
        )
        if geoapi and geoapi.get("status") == "success":
            result["country"] = geoapi.get("country", "")
            if not result["country_code"]:
                result["country_code"] = geoapi.get("countryCode", "")
            if not result["city"]:
                result["city"] = geoapi.get("city", "")
            result["lat"] = geoapi.get("lat", 0.0)
            result["lon"] = geoapi.get("lon", 0.0)
            if not result["isp"]:
                result["isp"] = geoapi.get("isp", "")
            if not result["org"]:
                result["org"] = geoapi.get("org", "")
            if not result["asn"]:
                result["asn"] = geoapi.get("as", "").split(" ")[0]

        # ── 4. RDAP WHOIS (for domain registration info) ──────────
        # Only for IPs with known hostname
        if result["domain"] and not result["registrar"]:
            # Get TLD from domain
            parts = result["domain"].split(".")
            if len(parts) >= 2:
                rdap = _fetch(
                    f"https://rdap.org/domain/{result['domain']}",
                    timeout=4
                )
                if rdap:
                    result["registrar"] = (
                        rdap.get("entities", [{}])[0]
                        .get("vcardArray", [[], [{}]])[1]
                        .get("fn", [""])[1] if rdap.get("entities") else ""
                    )
                    events = rdap.get("events", [])
                    for ev in events:
                        if ev.get("eventAction") == "registration":
                            result["created"] = ev.get("eventDate", "")[:10]
                        elif ev.get("eventAction") == "last changed":
                            result["updated"] = ev.get("eventDate", "")[:10]

        result["risk_score"] = min(100, result["risk_score"])
        return result

    def _private_result(self, ip: str) -> dict:
        return {
            "ip": ip, "private": True,
            "country": "Local", "country_code": "LAN",
            "city": "Internal Network", "region": "",
            "lat": 0.0, "lon": 0.0, "timezone": "",
            "asn": "private", "org": "Internal Network",
            "isp": "LAN", "domain": "",
            "ports": [], "vulns": [], "tags": ["private"],
            "hostnames": [], "cpes": [],
            "risk_score": 0, "risk_tags": ["private IP"],
            "registrar": "", "created": "", "updated": "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def bulk_enrich(self, ips: list, max_concurrent: int = 5) -> Dict[str, dict]:
        """Enrich multiple IPs with rate limiting."""
        results = {}
        for ip in ips[:50]:  # cap at 50
            results[ip] = self.enrich(ip)
            time.sleep(0.3)  # rate limit
        return results

    def stats(self) -> dict:
        with self._lock:
            return {
                **dict(self._stats),
                "cache_size": len(self._cache),
            }
