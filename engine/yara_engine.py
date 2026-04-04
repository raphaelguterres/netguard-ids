"""
NetGuard — YARA Rules Engine
Detecção de malware por padrões em arquivos e strings.

Suporte a:
  - Regras YARA embutidas (curadas, sem dependências externas)
  - Scan de arquivos executáveis (.exe, .dll, .ps1, .bat)
  - Scan de strings/buffers em memória
  - Fallback para pattern matching quando yara-python não instalado

Instalar yara-python (opcional, para performance máxima):
  pip install yara-python

Regras embutidas cobrem:
  - Mimikatz, Metasploit, Cobalt Strike
  - PowerShell obfuscado
  - Reverse shells
  - Droppers e downloaders
  - Web shells PHP/ASPX
"""

import os
import re
import hashlib
import logging
import threading
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any  # noqa: F401
from pathlib import Path

logger = logging.getLogger("netguard.yara")

# Tenta importar yara-python
try:
    import yara
    YARA_NATIVE = True
    logger.info("YARA: yara-python disponível — performance máxima")
except ImportError:
    YARA_NATIVE = False
    logger.info("YARA: usando regex fallback (instale yara-python para melhor performance)")


# ── Regras YARA embutidas ─────────────────────────────────────────
BUILTIN_RULES_SOURCE = r"""
rule Mimikatz_Strings {
    meta:
        description = "Detecta strings características do Mimikatz"
        severity    = "CRITICAL"
        mitre       = "T1003.001"
        author      = "NetGuard"
    strings:
        $s1 = "sekurlsa" nocase
        $s2 = "kerberos" nocase
        $s3 = "lsadump" nocase
        $s4 = "mimikatz" nocase
        $s5 = "WDigest" nocase
        $s6 = "privilege::debug" nocase
    condition:
        2 of them
}

rule PowerShell_Obfuscated {
    meta:
        description = "PowerShell com encoding suspeito ou ofuscação"
        severity    = "HIGH"
        mitre       = "T1059.001"
    strings:
        $e1 = "-EncodedCommand" nocase
        $e2 = "-enc " nocase
        $e3 = "FromBase64String" nocase
        $e4 = "IEX(" nocase
        $e5 = "Invoke-Expression" nocase
        $s1 = "System.Net.WebClient" nocase
        $s2 = "DownloadString" nocase
        $s3 = "DownloadFile" nocase
        $d1 = "bypass" nocase
        $d2 = "-nop" nocase
        $d3 = "-windowstyle hidden" nocase
    condition:
        (1 of ($e*)) and (1 of ($s*) or 1 of ($d*))
}

rule Reverse_Shell_Strings {
    meta:
        description = "Padrões de reverse shell"
        severity    = "CRITICAL"
        mitre       = "T1059"
    strings:
        $r1 = "/dev/tcp/" nocase
        $r2 = "bash -i" nocase
        $r3 = "nc -e" nocase
        $r4 = "ncat --exec" nocase
        $r5 = "socket.connect(" nocase
        $r6 = "0>&1" nocase
        $r7 = "cmd.exe /c" nocase
        $r8 = "powershell -nop -c" nocase
    condition:
        2 of them
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Possível Cobalt Strike Beacon"
        severity    = "CRITICAL"
        mitre       = "T1071.001"
    strings:
        $c1 = "beacon" nocase
        $c2 = "BeaconJitter" nocase
        $c3 = "cobaltstrike" nocase
        $s1 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }  // MZ header variant
        $p1 = "sleep_mask" nocase
        $p2 = "prepend_append_sender" nocase
    condition:
        2 of ($c*) or ($p1 and $p2)
}

rule Dropper_Downloader {
    meta:
        description = "Dropper ou downloader suspeito"
        severity    = "HIGH"
        mitre       = "T1105"
    strings:
        $d1 = "http://" nocase
        $d2 = "https://" nocase
        $e1 = ".exe" nocase
        $e2 = ".dll" nocase
        $e3 = ".ps1" nocase
        $w1 = "WScript.Shell" nocase
        $w2 = "Shell.Application" nocase
        $w3 = "CreateObject" nocase
        $c1 = "cmd /c" nocase
        $c2 = "curl" nocase
        $c3 = "wget" nocase
    condition:
        (1 of ($d*)) and (1 of ($e*)) and (1 of ($w*) or 1 of ($c*))
}

rule WebShell_PHP {
    meta:
        description = "Web shell PHP"
        severity    = "CRITICAL"
        mitre       = "T1505.003"
    strings:
        $p1 = "<?php" nocase
        $e1 = "eval(" nocase
        $e2 = "exec(" nocase
        $e3 = "system(" nocase
        $e4 = "passthru(" nocase
        $e5 = "shell_exec(" nocase
        $b1 = "base64_decode(" nocase
        $b2 = "str_rot13(" nocase
        $g1 = "$_GET" nocase
        $g2 = "$_POST" nocase
        $g3 = "$_REQUEST" nocase
    condition:
        $p1 and (1 of ($e*)) and (1 of ($b*) or 1 of ($g*))
}

rule Metasploit_Payload {
    meta:
        description = "Possível payload Metasploit"
        severity    = "CRITICAL"
        mitre       = "T1587.001"
    strings:
        $m1 = "metsrv" nocase
        $m2 = "meterpreter" nocase
        $m3 = "Metasploit" nocase
        $m4 = "MSF_PAYLOAD" nocase
        $p1 = "payload" nocase
        $s1 = "SHELLCODE" nocase
    condition:
        1 of ($m*) or ($p1 and $s1)
}

rule Credential_Harvester {
    meta:
        description = "Tentativa de coleta de credenciais"
        severity    = "HIGH"
        mitre       = "T1555"
    strings:
        $s1 = "password" nocase
        $s2 = "passwd" nocase
        $s3 = "credentials" nocase
        $f1 = "/etc/shadow" nocase
        $f2 = "SAM" nocase
        $f3 = "NTDS.dit" nocase
        $t1 = "LaZagne" nocase
        $t2 = "hashdump" nocase
    condition:
        1 of ($t*) or (1 of ($f*)) or (2 of ($s*) and 1 of ($f*))
}
"""


class YaraMatch:
    """Resultado de um match YARA."""
    def __init__(self, rule_name: str, meta: dict,
                 matched_strings: List[str], file_path: str = "",
                 scanned_text: str = ""):
        self.rule_name       = rule_name
        self.meta            = meta
        self.matched_strings = matched_strings
        self.file_path       = file_path
        self.scanned_text    = scanned_text[:100]
        self.severity        = meta.get("severity", "MEDIUM")
        self.mitre_tech      = meta.get("mitre", "")
        self.description     = meta.get("description", rule_name)
        self.timestamp       = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "rule":            self.rule_name,
            "severity":        self.severity,
            "description":     self.description,
            "mitre_technique": self.mitre_tech,
            "matched_strings": self.matched_strings[:10],
            "file_path":       self.file_path,
            "timestamp":       self.timestamp,
            "event_type":      "yara_match",
            "tags":            ["yara", "malware", self.rule_name.lower()],
        }


# ── Regex fallback rules (quando yara-python não disponível) ──────
REGEX_RULES = [
    {
        "name":       "Mimikatz_Strings",
        "patterns":   [r"sekurlsa", r"lsadump", r"mimikatz", r"privilege::debug"],
        "min_match":  2,
        "meta":       {"severity": "CRITICAL", "mitre": "T1003.001",
                       "description": "Strings características do Mimikatz"},
    },
    {
        "name":       "PowerShell_Obfuscated",
        "patterns":   [r"-EncodedCommand", r"FromBase64String", r"IEX\(",
                       r"Invoke-Expression", r"DownloadString", r"-windowstyle\s+hidden"],
        "min_match":  2,
        "meta":       {"severity": "HIGH", "mitre": "T1059.001",
                       "description": "PowerShell obfuscado"},
    },
    {
        "name":       "Reverse_Shell",
        "patterns":   [r"/dev/tcp/", r"bash\s+-i", r"nc\s+-e", r"0>&1",
                       r"socket\.connect\("],
        "min_match":  1,
        "meta":       {"severity": "CRITICAL", "mitre": "T1059",
                       "description": "Padrões de reverse shell"},
    },
    {
        "name":       "WebShell_PHP",
        "patterns":   [r"<\?php", r"eval\s*\(", r"base64_decode\s*\(",
                       r"\$_GET", r"\$_POST", r"system\s*\("],
        "min_match":  3,
        "meta":       {"severity": "CRITICAL", "mitre": "T1505.003",
                       "description": "Web shell PHP"},
    },
    {
        "name":       "Credential_Harvester",
        "patterns":   [r"/etc/shadow", r"NTDS\.dit", r"LaZagne",
                       r"hashdump", r"SAM\b"],
        "min_match":  1,
        "meta":       {"severity": "HIGH", "mitre": "T1555",
                       "description": "Coleta de credenciais"},
    },
    {
        "name":       "Dropper_Downloader",
        "patterns":   [r"WScript\.Shell", r"CreateObject",
                       r"curl\s+http", r"wget\s+http",
                       r"DownloadFile"],
        "min_match":  1,
        "meta":       {"severity": "HIGH", "mitre": "T1105",
                       "description": "Dropper / downloader"},
    },
    {
        "name":       "Metasploit_Payload",
        "patterns":   [r"meterpreter", r"metsrv", r"Metasploit",
                       r"MSF_PAYLOAD"],
        "min_match":  1,
        "meta":       {"severity": "CRITICAL", "mitre": "T1587.001",
                       "description": "Payload Metasploit"},
    },
]


class YaraEngine:
    """
    Motor YARA para detecção de malware.
    Usa yara-python nativamente se disponível, fallback para regex.
    """

    def __init__(self):
        self._lock        = threading.RLock()
        self._compiled    = None
        self._total_scans = 0
        self._total_hits  = 0
        self._scan_cache  : Dict[str, List[YaraMatch]] = {}
        self._cache_size  = 200

        self._compile_rules()

    def _compile_rules(self):
        """Compila regras YARA ou prepara regex patterns."""
        if YARA_NATIVE:
            try:
                self._compiled = yara.compile(source=BUILTIN_RULES_SOURCE)
                logger.info("YARA: %d regras compiladas", len(REGEX_RULES))
            except Exception as e:
                logger.error("YARA compile error: %s", e)
                self._compiled = None
        else:
            # Compile regex patterns
            self._regex_compiled = []
            for rule in REGEX_RULES:
                compiled = [re.compile(p, re.IGNORECASE | re.DOTALL)
                            for p in rule["patterns"]]
                self._regex_compiled.append({**rule, "compiled": compiled})
            logger.info("YARA fallback: %d regex rules compiladas", len(self._regex_compiled))

    def scan_string(self, data: str, context: str = "") -> List[YaraMatch]:
        """Escaneia uma string/buffer."""
        self._total_scans += 1

        if YARA_NATIVE and self._compiled:
            return self._scan_yara_string(data.encode("utf-8", errors="replace"), context)
        else:
            return self._scan_regex_string(data, context)

    def scan_file(self, file_path: str) -> List[YaraMatch]:
        """Escaneia um arquivo."""
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return []

        # Check cache by hash
        cache_key = self._file_hash(str(path))
        cached = self._scan_cache.get(cache_key)
        if cached is not None:
            return cached

        self._total_scans += 1

        try:
            if YARA_NATIVE and self._compiled:
                matches = self._scan_yara_file(str(path))
            else:
                # Read first 64KB for regex scan
                content = path.read_bytes()[:65536]
                try:
                    text = content.decode("utf-8", errors="replace")
                except Exception:
                    text = str(content)
                matches = self._scan_regex_string(text, str(path))

            # Set file_path on all matches
            for m in matches:
                m.file_path = str(path)

            # Cache result
            if len(self._scan_cache) >= self._cache_size:
                oldest = next(iter(self._scan_cache))
                del self._scan_cache[oldest]
            self._scan_cache[cache_key] = matches

            if matches:
                self._total_hits += 1
                for m in matches:
                    logger.warning("YARA HIT | rule=%s | sev=%s | file=%s",
                                   m.rule_name, m.severity, path.name)

            return matches

        except Exception as e:
            logger.error("YARA scan error (%s): %s", file_path, e)
            return []

    def scan_process(self, process_info: dict) -> List[YaraMatch]:
        """Escaneia informações de um processo."""
        text_parts = []

        # Scan exe path
        exe = process_info.get("exe", "")
        if exe and os.path.exists(exe):
            matches = self.scan_file(exe)
            if matches:
                return matches

        # Scan process name + command line
        for field in ("name", "cmdline", "exe"):
            val = process_info.get(field, "")
            if val:
                text_parts.append(str(val))

        if text_parts:
            combined = " ".join(text_parts)
            return self.scan_string(combined, f"process:{process_info.get('name','')}")

        return []

    def _scan_yara_string(self, data: bytes, context: str) -> List[YaraMatch]:
        """Scan com yara-python nativo."""
        try:
            hits = self._compiled.match(data=data)
            results = []
            for hit in hits:
                matched_strs = [str(s) for s in hit.strings][:10]
                results.append(YaraMatch(
                    rule_name       = hit.rule,
                    meta            = dict(hit.meta),
                    matched_strings = matched_strs,
                    scanned_text    = context,
                ))
            return results
        except Exception as e:
            logger.debug("YARA scan error: %s", e)
            return []

    def _scan_yara_file(self, file_path: str) -> List[YaraMatch]:
        """Scan de arquivo com yara-python."""
        try:
            hits = self._compiled.match(filepath=file_path)
            results = []
            for hit in hits:
                matched_strs = [str(s) for s in hit.strings][:10]
                results.append(YaraMatch(
                    rule_name       = hit.rule,
                    meta            = dict(hit.meta),
                    matched_strings = matched_strs,
                    file_path       = file_path,
                ))
            return results
        except Exception as e:
            logger.debug("YARA file scan error: %s", e)
            return []

    def _scan_regex_string(self, text: str, context: str) -> List[YaraMatch]:
        """Fallback: scan com regex."""
        results = []
        for rule in self._regex_compiled:
            matched = []
            for pat in rule["compiled"]:
                m = pat.search(text)
                if m:
                    matched.append(m.group(0)[:30])
            if len(matched) >= rule["min_match"]:
                results.append(YaraMatch(
                    rule_name       = rule["name"],
                    meta            = rule["meta"],
                    matched_strings = matched,
                    scanned_text    = context,
                ))
        return results

    def stats(self) -> dict:
        return {
            "available":    True,
            "native":       YARA_NATIVE,
            "rules_count":  len(REGEX_RULES),
            "total_scans":  self._total_scans,
            "total_hits":   self._total_hits,
            "cache_size":   len(self._scan_cache),
            "backend":      "yara-python" if YARA_NATIVE else "regex-fallback",
        }

    @staticmethod
    def _file_hash(path: str) -> str:
        try:
            h = hashlib.md5()
            with open(path, "rb") as f:
                h.update(f.read(32768))
            return h.hexdigest()
        except Exception:
            return path
