"""
NetGuard Threat Feeds v1.0
Integração com AbuseIPDB e ThreatFox (Abuse.ch).

AbuseIPDB: https://www.abuseipdb.com/api — chave gratuita, 1000 req/dia
ThreatFox:  https://threatfox.abuse.ch/api — sem chave, gratuito

Como configurar AbuseIPDB:
  1. Crie conta em https://www.abuseipdb.com/register
  2. Vá em Account → API Keys → Create Key
  3. Defina a variável de ambiente:
     set IDS_ABUSEIPDB_KEY=sua_chave_aqui
  Ou coloque direto no .env
"""

import os
import json
import time
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import Dict, Optional

logger = logging.getLogger("ids.feeds")

# ── Config ────────────────────────────────────────────────────────
ABUSEIPDB_KEY  = os.environ.get("IDS_ABUSEIPDB_KEY", "")
ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"
THREATFOX_URL  = "https://threatfox-api.abuse.ch/api/v1/"

# Cache TTL: não reconsultar o mesmo IP por 1 hora
CACHE_TTL = 3600

# ── Cache de resultados ────────────────────────────────────────────
_abuse_cache: Dict[str, dict] = {}
_threatfox_ioc_cache: Dict[str, dict] = {}
_cache_lock = threading.Lock()

# ── AbuseIPDB ─────────────────────────────────────────────────────

def check_abuseipdb(ip: str) -> dict:
    """
    Consulta AbuseIPDB para reputação de um IP.
    Retorna dict com score de abuso (0-100), país, ISP, etc.
    Requer IDS_ABUSEIPDB_KEY configurada.
    """
    if not ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_KEY não configurada", "available": False}

    # Cache
    with _cache_lock:
        cached = _abuse_cache.get(ip)
        if cached and time.time() - cached.get("_ts", 0) < CACHE_TTL:
            return cached

    try:
        url = f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90&verbose"
        req = urllib.request.Request(url, headers={
            "Key":    ABUSEIPDB_KEY,
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())

        d = data.get("data", {})
        result = {
            "ip":              ip,
            "abuse_score":     d.get("abuseConfidenceScore", 0),
            "country":         d.get("countryCode", "??"),
            "isp":             d.get("isp", "Unknown"),
            "domain":          d.get("domain", ""),
            "total_reports":   d.get("totalReports", 0),
            "last_reported":   d.get("lastReportedAt", ""),
            "is_tor":          d.get("isTor", False),
            "is_public":       d.get("isPublic", True),
            "usage_type":      d.get("usageType", ""),
            "categories":      [],
            "available":       True,
            "_ts":             time.time(),
        }

        # Categorias em texto
        cat_map = {
            1:"DNS Compromise", 2:"DNS Poisoning", 3:"Fraud Orders",
            4:"DDoS Attack", 5:"FTP Brute-Force", 6:"Ping of Death",
            7:"Phishing", 8:"Fraud VoIP", 9:"Open Proxy", 10:"Web Spam",
            11:"Email Spam", 12:"Blog Spam", 13:"VPN IP", 14:"Port Scan",
            15:"Hacking", 16:"SQL Injection", 17:"Spoofing",
            18:"Brute Force", 19:"Bad Web Bot", 20:"Exploited Host",
            21:"Web App Attack", 22:"SSH", 23:"IoT Targeted",
        }
        for cat in d.get("reports", []):
            for c in cat.get("categories", []):
                txt = cat_map.get(c, str(c))
                if txt not in result["categories"]:
                    result["categories"].append(txt)

        with _cache_lock:
            _abuse_cache[ip] = result

        logger.info("AbuseIPDB | ip=%s | score=%d | reports=%d",
                    ip, result["abuse_score"], result["total_reports"])
        return result

    except urllib.error.HTTPError as e:
        logger.warning("AbuseIPDB HTTP error %d for %s", e.code, ip)
        return {"error": f"HTTP {e.code}", "available": False}
    except Exception as e:
        logger.warning("AbuseIPDB error for %s: %s", ip, e)
        return {"error": str(e), "available": False}


def is_malicious_abuseipdb(ip: str, threshold: int = 50) -> bool:
    """Retorna True se o IP tem score >= threshold no AbuseIPDB."""
    result = check_abuseipdb(ip)
    return result.get("abuse_score", 0) >= threshold


# ── ThreatFox ─────────────────────────────────────────────────────

def check_threatfox_ip(ip: str) -> dict:
    """
    Consulta ThreatFox (Abuse.ch) por IOCs relacionados a um IP.
    Sem chave de API — gratuito e aberto.
    """
    with _cache_lock:
        cached = _threatfox_ioc_cache.get(ip)
        if cached and time.time() - cached.get("_ts", 0) < CACHE_TTL:
            return cached

    try:
        payload = json.dumps({
            "query":    "search_ioc",
            "search_term": ip,
        }).encode()

        req = urllib.request.Request(
            THREATFOX_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())

        iocs = data.get("data", []) or []
        result = {
            "ip":          ip,
            "found":       len(iocs) > 0,
            "ioc_count":   len(iocs),
            "malware":     [],
            "threat_type": [],
            "tags":        [],
            "reporter":    [],
            "first_seen":  "",
            "last_seen":   "",
            "available":   True,
            "_ts":         time.time(),
        }

        for ioc in iocs[:5]:  # Máximo 5 IOCs
            mw = ioc.get("malware", "")
            if mw and mw not in result["malware"]:
                result["malware"].append(mw)
            tt = ioc.get("threat_type", "")
            if tt and tt not in result["threat_type"]:
                result["threat_type"].append(tt)
            for tag in ioc.get("tags", []) or []:
                if tag and tag not in result["tags"]:
                    result["tags"].append(tag)
            if not result["first_seen"]:
                result["first_seen"] = ioc.get("first_seen", "")
            result["last_seen"] = ioc.get("last_seen", "")

        with _cache_lock:
            _threatfox_ioc_cache[ip] = result

        if result["found"]:
            logger.warning("ThreatFox | ip=%s | malware=%s | type=%s",
                          ip, result["malware"], result["threat_type"])
        return result

    except Exception as e:
        logger.warning("ThreatFox error for %s: %s", ip, e)
        return {"error": str(e), "available": False, "found": False}


def check_threatfox_hash(hash_value: str) -> dict:
    """Consulta ThreatFox por hash de arquivo (MD5/SHA256)."""
    try:
        payload = json.dumps({
            "query":    "search_hash",
            "hash":     hash_value,
        }).encode()
        req = urllib.request.Request(
            THREATFOX_URL, data=payload,
            headers={"Content-Type":"application/json"}, method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())

        iocs = data.get("data") or []
        return {
            "hash":        hash_value,
            "found":       len(iocs) > 0,
            "malware":     [i.get("malware","") for i in iocs[:3]],
            "threat_type": [i.get("threat_type","") for i in iocs[:3]],
            "available":   True,
        }
    except Exception as e:
        return {"error": str(e), "available": False, "found": False}


# ── Enriquecimento combinado ──────────────────────────────────────

def enrich_ip(ip: str) -> dict:
    """
    Enriquece um IP com dados de AbuseIPDB + ThreatFox.
    Retorna um dict consolidado com score, categorias, malware, etc.
    """
    if not ip or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return {"ip": ip, "private": True, "score": 0}

    result = {"ip": ip, "private": False}

    # AbuseIPDB
    if ABUSEIPDB_KEY:
        abuse = check_abuseipdb(ip)
        if abuse.get("available"):
            result["abuse_score"]   = abuse.get("abuse_score", 0)
            result["abuse_reports"] = abuse.get("total_reports", 0)
            result["isp"]           = abuse.get("isp", "")
            result["country"]       = abuse.get("country", "")
            result["is_tor"]        = abuse.get("is_tor", False)
            result["categories"]    = abuse.get("categories", [])
            result["last_reported"] = abuse.get("last_reported", "")

    # ThreatFox (sempre disponível)
    fox = check_threatfox_ip(ip)
    if fox.get("available") and fox.get("found"):
        result["threatfox_found"]  = True
        result["malware_families"] = fox.get("malware", [])
        result["threat_types"]     = fox.get("threat_type", [])
        result["ioc_tags"]         = fox.get("tags", [])

    # Score consolidado
    abuse_s  = result.get("abuse_score", 0)
    fox_s    = 80 if result.get("threatfox_found") else 0
    result["consolidated_score"] = max(abuse_s, fox_s)
    result["malicious"] = result["consolidated_score"] >= 50

    return result


# ── Batch async enrichment ────────────────────────────────────────

def enrich_async(ip: str, callback=None):
    """Enriquece um IP em thread separada (não bloqueia)."""
    def _run():
        r = enrich_ip(ip)
        if callback:
            callback(ip, r)
    threading.Thread(target=_run, daemon=True).start()


# ── Stats ─────────────────────────────────────────────────────────

def stats() -> dict:
    with _cache_lock:
        return {
            "abuseipdb_cached":  len(_abuse_cache),
            "threatfox_cached":  len(_threatfox_ioc_cache),
            "abuseipdb_enabled": bool(ABUSEIPDB_KEY),
            "threatfox_enabled": True,
        }
