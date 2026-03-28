"""
NetGuard — VirusTotal Integration
Lookup automático de hashes de processos suspeitos.

API gratuita: 4 requests/minuto, 500/dia.
Chave gratuita em: https://www.virustotal.com/gui/sign-in
"""

import os
import time
import hashlib
import logging
import threading
from datetime import datetime, timezone
from collections import deque
from typing import Optional

logger = logging.getLogger("netguard.virustotal")

# Importação condicional — não quebra se requests não instalado
try:
    import urllib.request
    import json
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class VirusTotalClient:
    """
    Cliente para VirusTotal API v3.
    Rate limit automático: 4 req/min (free tier).
    Cache em memória para não repetir lookups.

    Uso:
        vt = VirusTotalClient()
        result = vt.lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
        if result and result["malicious"] > 0:
            print(f"MALICIOSO: {result['malicious']} engines detectaram")
    """

    VT_API_BASE = "https://www.virustotal.com/api/v3"
    RATE_LIMIT   = 4    # requests por minuto (free tier)
    CACHE_SIZE   = 500  # hashes em cache
    CACHE_TTL    = 3600 # 1 hora

    def __init__(self, api_key: str = ""):
        self._api_key  = api_key or os.environ.get("IDS_VIRUSTOTAL_KEY", "")
        self._lock     = threading.RLock()
        self._cache    : dict = {}
        self._req_times: deque = deque(maxlen=10)
        self._total_lookups  = 0
        self._cache_hits     = 0
        self._detections     = 0
        self._enabled        = bool(self._api_key)

        if self._enabled:
            logger.info("VirusTotal iniciado | rate_limit=%d/min", self.RATE_LIMIT)
        else:
            logger.info("VirusTotal: sem chave API — desativado. "
                        "Configure: $env:IDS_VIRUSTOTAL_KEY='sua_chave'")

    def lookup_hash(self, file_hash: str) -> Optional[dict]:
        """
        Consulta hash no VirusTotal.
        Retorna dict com resultado ou None se não disponível.
        """
        if not self._enabled:
            return None

        file_hash = file_hash.lower().strip()
        if not file_hash or len(file_hash) not in (32, 40, 64):
            return None

        # Check cache
        cached = self._get_cache(file_hash)
        if cached is not None:
            self._cache_hits += 1
            return cached

        # Rate limit
        self._wait_rate_limit()

        try:
            url = f"{self.VT_API_BASE}/files/{file_hash}"
            req = urllib.request.Request(
                url,
                headers={
                    "x-apikey": self._api_key,
                    "Accept":   "application/json",
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            result = self._parse_response(data, file_hash)
            self._set_cache(file_hash, result)
            self._total_lookups += 1

            if result.get("malicious", 0) > 0:
                self._detections += 1
                logger.warning(
                    "VT DETECTION | hash=%s | malicious=%d | name=%s",
                    file_hash[:16], result["malicious"], result.get("name","")
                )

            return result

        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Hash não encontrado na base do VT
                result = {"hash": file_hash, "found": False, "malicious": 0}
                self._set_cache(file_hash, result)
                return result
            elif e.code == 429:
                logger.warning("VirusTotal rate limit atingido")
                return None
            else:
                logger.debug("VirusTotal HTTP error: %s", e)
                return None
        except Exception as e:
            logger.debug("VirusTotal lookup error: %s", e)
            return None

    def lookup_process(self, process_info: dict) -> Optional[dict]:
        """
        Conveniência: faz lookup dado um dict de processo.
        Extrai o hash do campo 'hash', 'md5', 'sha256' ou calcula do exe path.
        """
        # Tenta hash direto
        for field in ("sha256", "md5", "hash", "sha1"):
            h = process_info.get(field, "")
            if h and len(h) >= 32:
                result = self.lookup_hash(h)
                if result:
                    result["process"] = process_info.get("name", "")
                    return result

        # Tenta calcular hash do executável
        exe = process_info.get("exe", "")
        if exe:
            h = self._hash_file(exe)
            if h:
                result = self.lookup_hash(h)
                if result:
                    result["process"] = process_info.get("name", "")
                    result["exe"]     = exe
                    return result

        return None

    def generate_alert(self, vt_result: dict, process_info: dict) -> Optional[dict]:
        """Gera alerta padronizado se processo for malicioso."""
        if not vt_result or vt_result.get("malicious", 0) == 0:
            return None

        malicious  = vt_result.get("malicious", 0)
        total      = vt_result.get("total_engines", 0)
        name       = vt_result.get("name", "")
        proc       = process_info.get("name", "")
        file_hash  = vt_result.get("hash", "")

        severity = "CRITICAL" if malicious >= 5 else "HIGH" if malicious >= 2 else "MEDIUM"

        return {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "host_id":    process_info.get("host_id", ""),
            "rule_id":    "VT-1",
            "rule_name":  "VirusTotal — Processo Malicioso Detectado",
            "event_type": "virustotal_detection",
            "severity":   severity,
            "source":     "engine.virustotal",
            "description": (f"Processo '{proc}' detectado como malicioso por "
                            f"{malicious}/{total} engines no VirusTotal. "
                            f"{f'Nome da ameaça: {name}' if name else ''}"),
            "details": {
                "process":       proc,
                "exe":           process_info.get("exe", ""),
                "hash":          file_hash,
                "malicious":     malicious,
                "suspicious":    vt_result.get("suspicious", 0),
                "total_engines": total,
                "threat_name":   name,
                "vt_link":       f"https://www.virustotal.com/gui/file/{file_hash}",
            },
            "mitre": {"tactic": "execution", "technique": "T1204"},
            "tags": ["virustotal", "malware", "process", "threat-intel"],
            "type": "VT_DETECTION",
        }

    def stats(self) -> dict:
        with self._lock:
            return {
                "enabled":       self._enabled,
                "total_lookups": self._total_lookups,
                "cache_hits":    self._cache_hits,
                "cache_size":    len(self._cache),
                "detections":    self._detections,
                "api_key_set":   bool(self._api_key),
            }

    # ── Private ───────────────────────────────────────────────────

    def _parse_response(self, data: dict, file_hash: str) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        names = attrs.get("meaningful_name") or \
                attrs.get("popular_threat_name") or \
                attrs.get("suggested_threat_label", "")
        return {
            "hash":          file_hash,
            "found":         True,
            "malicious":     stats.get("malicious", 0),
            "suspicious":    stats.get("suspicious", 0),
            "harmless":      stats.get("harmless", 0),
            "undetected":    stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "name":          names,
            "type":          attrs.get("type_description", ""),
            "size":          attrs.get("size", 0),
            "first_seen":    attrs.get("first_submission_date", ""),
        }

    def _wait_rate_limit(self):
        """Garante que não excede 4 requests por minuto."""
        with self._lock:
            now = time.time()
            minute_ago = now - 60
            recent = [t for t in self._req_times if t > minute_ago]
            if len(recent) >= self.RATE_LIMIT:
                sleep_time = 60 - (now - recent[0]) + 0.1
                if sleep_time > 0:
                    logger.debug("VT rate limit — aguardando %.1fs", sleep_time)
                    time.sleep(sleep_time)
            self._req_times.append(time.time())

    def _get_cache(self, key: str) -> Optional[dict]:
        with self._lock:
            entry = self._cache.get(key)
            if entry and time.time() - entry["_ts"] < self.CACHE_TTL:
                return entry["data"]
            return None

    def _set_cache(self, key: str, value: dict):
        with self._lock:
            if len(self._cache) >= self.CACHE_SIZE:
                oldest = min(self._cache, key=lambda k: self._cache[k]["_ts"])
                del self._cache[oldest]
            self._cache[key] = {"data": value, "_ts": time.time()}

    @staticmethod
    def _hash_file(path: str) -> Optional[str]:
        """Calcula SHA-256 de um arquivo."""
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None
