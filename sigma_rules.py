"""
NetGuard Sigma Rules Engine v1.0
Carrega e executa regras Sigma contra logs em tempo real.
Sigma é o padrão open source para detecção em logs — equivalente ao YARA para eventos.

Repositório oficial: https://github.com/SigmaHQ/sigma
"""

import re
import os  # noqa: F401
import json  # noqa: F401
import yaml
import logging
from typing import List, Dict, Optional  # noqa: F401
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("ids.sigma")

# ── Estrutura de uma regra Sigma ──────────────────────────────────

@dataclass
class SigmaRule:
    id:          str
    title:       str
    description: str
    level:       str          # informational, low, medium, high, critical
    status:      str          # experimental, test, stable
    tags:        List[str]    # MITRE ATT&CK tags
    detection:   dict
    logsource:   dict
    patterns:    List[re.Pattern] = field(default_factory=list)
    mitre_tactic: str = ""
    mitre_technique: str = ""

    def __post_init__(self):
        # Parse MITRE tags
        for tag in self.tags:
            if tag.startswith("attack.t"):
                self.mitre_technique = tag.replace("attack.","").upper()
            elif tag.startswith("attack."):
                self.mitre_tactic = tag.replace("attack.","").replace("_"," ").title()

# ── Regras Sigma embutidas (top 40 mais relevantes) ───────────────
# Fonte: SigmaHQ/sigma — Windows, Network, Web categories
# Convertidas para formato interno do NetGuard

BUILTIN_RULES = [
    # ── Credential Access ─────────────────────────────────────────
    {
        "id": "sigma-001",
        "title": "Mimikatz via Command Line",
        "description": "Detecta execução do Mimikatz por linha de comando — ferramenta de dump de credenciais",
        "level": "critical",
        "tags": ["attack.credential_access", "attack.t1003"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["mimikatz", "sekurlsa", "lsadump", "privilege::debug",
                        "sekurlsa::logonpasswords", "lsadump::sam", "lsadump::dcsync"]
        }
    },
    {
        "id": "sigma-002",
        "title": "LSASS Memory Dump",
        "description": "Acesso à memória do processo LSASS — extração de credenciais",
        "level": "critical",
        "tags": ["attack.credential_access", "attack.t1003.001"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["lsass.exe", "procdump", "comsvcs.dll", "minidump", "sqldumper"]
        }
    },
    {
        "id": "sigma-003",
        "title": "Windows Credential Editor",
        "description": "Uso do WCE para dump de hashes NTLM",
        "level": "critical",
        "tags": ["attack.credential_access", "attack.t1003"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["wce.exe", "wce -w", "wce -l", "pwdump", "fgdump", "gsecdump"]
        }
    },
    # ── Execution ─────────────────────────────────────────────────
    {
        "id": "sigma-010",
        "title": "PowerShell Encoded Command",
        "description": "PowerShell executando comando em Base64 — técnica comum de evasão",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["powershell", "-enc", "-encodedcommand", "-e "]
        }
    },
    {
        "id": "sigma-011",
        "title": "PowerShell Download Cradle",
        "description": "PowerShell baixando e executando código remotamente",
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["iex", "invoke-expression", "downloadstring", "webclient",
                        "invoke-webrequest", "bitstransfer", "bitsadmin"]
        }
    },
    {
        "id": "sigma-012",
        "title": "WMIC Remote Execution",
        "description": "WMIC usado para execução remota — técnica de movimento lateral",
        "level": "high",
        "tags": ["attack.execution", "attack.lateral_movement", "attack.t1047"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["wmic", "process call create", "wmic /node:", "wmic node:"]
        }
    },
    {
        "id": "sigma-013",
        "title": "Rundll32 Suspicious Execution",
        "description": "Rundll32 executando DLL suspeita — bypass de whitelisting",
        "level": "medium",
        "tags": ["attack.execution", "attack.defense_evasion", "attack.t1218.011"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["rundll32", "javascript:", "vbscript:", "shell32.dll,ShellExec_RunDLL",
                        "pcwutl.dll", "advpack.dll,RegisterOCX"]
        }
    },
    {
        "id": "sigma-014",
        "title": "Regsvr32 Execution",
        "description": "Regsvr32 carregando script remoto — técnica Squiblydoo",
        "level": "medium",
        "tags": ["attack.execution", "attack.defense_evasion", "attack.t1218.010"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["regsvr32", "/s", "/u", "/i:", "scrobj.dll"]
        }
    },
    # ── Defense Evasion ───────────────────────────────────────────
    {
        "id": "sigma-020",
        "title": "Windows Defender Disabled via Registry",
        "description": "Windows Defender desabilitado por registro — evasão de AV",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1562.001"],
        "logsource": {"category": "registry_event"},
        "detection": {
            "keywords": ["DisableAntiSpyware", "DisableRealtimeMonitoring",
                        "DisableBehaviorMonitoring", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"]
        }
    },
    {
        "id": "sigma-021",
        "title": "Clear Windows Event Logs",
        "description": "Limpeza de logs do Windows — ocultação de rastros",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1070.001"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["wevtutil cl", "Clear-EventLog", "wevtutil clear-log",
                        "ForEach-Object {Clear-EventLog"]
        }
    },
    {
        "id": "sigma-022",
        "title": "UAC Bypass via fodhelper",
        "description": "Bypass de UAC usando fodhelper.exe",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.privilege_escalation", "attack.t1548.002"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["fodhelper.exe", "computerdefaults.exe", "sdclt.exe",
                        "eventvwr.exe", "HKCU\\Software\\Classes\\ms-settings"]
        }
    },
    # ── Persistence ───────────────────────────────────────────────
    {
        "id": "sigma-030",
        "title": "Scheduled Task Creation",
        "description": "Criação de tarefa agendada suspeita — persistência",
        "level": "medium",
        "tags": ["attack.persistence", "attack.t1053.005"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["schtasks", "/create", "/tr", "/sc", "at.exe "]
        }
    },
    {
        "id": "sigma-031",
        "title": "Registry Run Key Persistence",
        "description": "Chave de registro Run usada para persistência",
        "level": "medium",
        "tags": ["attack.persistence", "attack.t1547.001"],
        "logsource": {"category": "registry_event"},
        "detection": {
            "keywords": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "CurrentVersion\\RunOnce"]
        }
    },
    {
        "id": "sigma-032",
        "title": "New Service Created",
        "description": "Criação de novo serviço Windows — técnica de persistência comum",
        "level": "medium",
        "tags": ["attack.persistence", "attack.t1543.003"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["sc create", "New-Service", "sc.exe create", "services.msc"]
        }
    },
    # ── Lateral Movement ─────────────────────────────────────────
    {
        "id": "sigma-040",
        "title": "PsExec Remote Execution",
        "description": "PsExec detectado — execução remota em outros hosts",
        "level": "high",
        "tags": ["attack.lateral_movement", "attack.t1570"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["psexec", "psexec64", "paexec", "\\\\PSEXESVC",
                        "RemoteExec", "\\admin$"]
        }
    },
    {
        "id": "sigma-041",
        "title": "Pass the Hash Attack",
        "description": "Técnica Pass-the-Hash detectada — autenticação com hash NTLM",
        "level": "critical",
        "tags": ["attack.lateral_movement", "attack.credential_access", "attack.t1550.002"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["sekurlsa::pth", "pth-winexe", "crackmapexec", "impacket",
                        "wmiexec.py", "smbexec.py", "psexec.py"]
        }
    },
    # ── Discovery ─────────────────────────────────────────────────
    {
        "id": "sigma-050",
        "title": "Network Reconnaissance",
        "description": "Reconhecimento de rede — enumeração de hosts e portas",
        "level": "medium",
        "tags": ["attack.discovery", "attack.t1046"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["nmap", "masscan", "netscan", "advanced port scanner",
                        "angry ip scanner", "portscan"]
        }
    },
    {
        "id": "sigma-051",
        "title": "Windows Account Enumeration",
        "description": "Enumeração de contas e grupos Windows",
        "level": "low",
        "tags": ["attack.discovery", "attack.t1087"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["net user", "net group", "net localgroup", "whoami /all",
                        "net accounts", "query user"]
        }
    },
    {
        "id": "sigma-052",
        "title": "System Information Discovery",
        "description": "Coleta de informações do sistema — fase de reconhecimento",
        "level": "low",
        "tags": ["attack.discovery", "attack.t1082"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["systeminfo", "hostname", "ipconfig /all", "wmic computersystem",
                        "Get-ComputerInfo", "msinfo32"]
        }
    },
    # ── Exfiltration ─────────────────────────────────────────────
    {
        "id": "sigma-060",
        "title": "Data Exfiltration via DNS",
        "description": "Possível exfiltração de dados via DNS tunneling",
        "level": "high",
        "tags": ["attack.exfiltration", "attack.t1048.003"],
        "logsource": {"category": "dns"},
        "detection": {
            "keywords": ["iodine", "dnscat", "dns2tcp", "dnstunnel", "base64"]
        }
    },
    {
        "id": "sigma-061",
        "title": "Suspicious Archive Creation",
        "description": "Criação de arquivo compactado contendo dados potencialmente sensíveis",
        "level": "medium",
        "tags": ["attack.exfiltration", "attack.collection", "attack.t1074"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["7z a", "rar a", "zip -r", "Compress-Archive",
                        "tar -czf", "winrar", "winzip"]
        }
    },
    # ── Command & Control ─────────────────────────────────────────
    {
        "id": "sigma-070",
        "title": "Cobalt Strike Beacon",
        "description": "Indicadores do Cobalt Strike Beacon detectados",
        "level": "critical",
        "tags": ["attack.command_and_control", "attack.t1071"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["cobaltstrike", "beacon.exe", "beacon.dll",
                        "artifact.exe", "artifact32.exe", "msf payload"]
        }
    },
    {
        "id": "sigma-071",
        "title": "Metasploit Framework",
        "description": "Metasploit Meterpreter ou payloads detectados",
        "level": "critical",
        "tags": ["attack.command_and_control", "attack.t1059"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["meterpreter", "msfvenom", "msfconsole", "msfpayload",
                        "reverse_tcp", "reverse_https", "shellcode"]
        }
    },
    # ── Web Attacks ───────────────────────────────────────────────
    {
        "id": "sigma-080",
        "title": "SQL Injection in Web Log",
        "description": "SQL Injection detectado em log de acesso web",
        "level": "high",
        "tags": ["attack.initial_access", "attack.t1190"],
        "logsource": {"category": "webserver"},
        "detection": {
            "keywords": ["union select", "' or '1'='1", "'; drop table",
                        "xp_cmdshell", "exec(", "benchmark(", "sleep("]
        }
    },
    {
        "id": "sigma-081",
        "title": "Path Traversal Attack",
        "description": "Tentativa de path traversal para acessar arquivos do sistema",
        "level": "high",
        "tags": ["attack.initial_access", "attack.t1190"],
        "logsource": {"category": "webserver"},
        "detection": {
            "keywords": ["../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f",
                        "/etc/passwd", "/etc/shadow", "windows/system32"]
        }
    },
    {
        "id": "sigma-082",
        "title": "XSS Attempt in Web Log",
        "description": "Tentativa de Cross-Site Scripting detectada",
        "level": "medium",
        "tags": ["attack.initial_access", "attack.t1190"],
        "logsource": {"category": "webserver"},
        "detection": {
            "keywords": ["<script>", "javascript:", "onerror=", "onload=",
                        "alert(", "document.cookie", "eval("]
        }
    },
    {
        "id": "sigma-083",
        "title": "Remote Code Execution via Web",
        "description": "Tentativa de RCE via parâmetro web",
        "level": "critical",
        "tags": ["attack.initial_access", "attack.t1190"],
        "logsource": {"category": "webserver"},
        "detection": {
            "keywords": ["cmd=", "exec=", "system(", "passthru(", "shell_exec(",
                        "|whoami", "|id", ";cat ", ";ls ", "$(", "`id`"]
        }
    },
    # ── Brute Force ───────────────────────────────────────────────
    {
        "id": "sigma-090",
        "title": "Hydra / Brute Force Tool",
        "description": "Ferramenta de brute force detectada",
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1110"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["hydra", "medusa", "ncrack", "thc-hydra", "crowbar",
                        "brutus", "aircrack-ng"]
        }
    },
    # ── Ransomware ────────────────────────────────────────────────
    {
        "id": "sigma-100",
        "title": "Shadow Copy Deletion",
        "description": "Deleção de shadow copies — comportamento típico de ransomware",
        "level": "critical",
        "tags": ["attack.impact", "attack.t1490"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["vssadmin delete shadows", "wmic shadowcopy delete",
                        "bcdedit /set recoveryenabled no", "wbadmin delete catalog",
                        "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject"]
        }
    },
    {
        "id": "sigma-101",
        "title": "Ransomware File Extension",
        "description": "Extensões de arquivo associadas a ransomware conhecidos",
        "level": "critical",
        "tags": ["attack.impact", "attack.t1486"],
        "logsource": {"category": "file_event"},
        "detection": {
            "keywords": [".locked", ".encrypted", ".crypted", ".cerber", ".locky",
                        ".zepto", ".wcry", ".wncry", ".wncryt", "_HOW_TO_DECRYPT"]
        }
    },
    # ── Antivirus / EDR Bypass ────────────────────────────────────
    {
        "id": "sigma-110",
        "title": "AMSI Bypass",
        "description": "Tentativa de bypass do Anti-Malware Scan Interface",
        "level": "high",
        "tags": ["attack.defense_evasion", "attack.t1562.001"],
        "logsource": {"category": "process_creation"},
        "detection": {
            "keywords": ["AmsiScanBuffer", "amsiInitFailed", "amsi.dll",
                        "[Ref].Assembly.GetType", "System.Management.Automation.AmsiUtils"]
        }
    },
    # ── Windows Event Log specific ────────────────────────────────
    {
        "id": "sigma-120",
        "title": "EventID 4625 — Failed Logon",
        "description": "Múltiplas falhas de logon — possível brute force",
        "level": "medium",
        "tags": ["attack.credential_access", "attack.t1110"],
        "logsource": {"category": "windows_security"},
        "detection": {
            "keywords": ["EventID=4625", "4625|", "An account failed to log on"]
        }
    },
    {
        "id": "sigma-121",
        "title": "EventID 4720 — User Account Created",
        "description": "Nova conta de usuário criada — possível backdoor",
        "level": "medium",
        "tags": ["attack.persistence", "attack.t1136"],
        "logsource": {"category": "windows_security"},
        "detection": {
            "keywords": ["EventID=4720", "4720|", "A user account was created"]
        }
    },
    {
        "id": "sigma-122",
        "title": "EventID 7045 — New Service Installed",
        "description": "Novo serviço instalado — técnica comum de persistência e movimento lateral",
        "level": "high",
        "tags": ["attack.persistence", "attack.t1543.003"],
        "logsource": {"category": "windows_system"},
        "detection": {
            "keywords": ["EventID=7045", "7045|", "A new service was installed"]
        }
    },
]


class SigmaEngine:
    """Engine que carrega e executa regras Sigma."""

    def __init__(self):
        self.rules: List[SigmaRule] = []
        self._load_builtin()
        logger.info("Sigma engine: %d regras carregadas", len(self.rules))

    def _load_builtin(self):
        """Carrega regras embutidas."""
        for r in BUILTIN_RULES:
            try:
                rule = self._parse_rule(r)
                self.rules.append(rule)
            except Exception as e:
                logger.warning("Regra %s inválida: %s", r.get("id","?"), e)

    def load_from_file(self, path: str):
        """Carrega regra Sigma de arquivo YAML."""
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            rule = self._parse_rule_yaml(data)
            self.rules.append(rule)
            logger.info("Regra Sigma carregada: %s", rule.title)
        except Exception as e:
            logger.warning("Falha ao carregar %s: %s", path, e)

    def load_from_directory(self, directory: str):
        """Carrega todas as regras .yml de um diretório."""
        p = Path(directory)
        if not p.exists():
            return
        count = 0
        for f in p.rglob("*.yml"):
            self.load_from_file(str(f))
            count += 1
        logger.info("Carregadas %d regras Sigma de %s", count, directory)

    def _parse_rule(self, data: dict) -> SigmaRule:
        """Converte dict interno para SigmaRule com padrões compilados."""
        keywords = data.get("detection", {}).get("keywords", [])
        patterns = [re.compile(re.escape(k), re.IGNORECASE) for k in keywords]
        return SigmaRule(
            id=data["id"],
            title=data["title"],
            description=data.get("description",""),
            level=data.get("level","medium"),
            status=data.get("status","stable"),
            tags=data.get("tags",[]),
            detection=data.get("detection",{}),
            logsource=data.get("logsource",{}),
            patterns=patterns,
        )

    def _parse_rule_yaml(self, data: dict) -> SigmaRule:
        """Converte YAML Sigma para SigmaRule."""
        detection = data.get("detection", {})
        # Extrai keywords de várias estruturas Sigma
        keywords = []
        for k, v in detection.items():
            if k in ("condition", "timeframe"):
                continue
            if isinstance(v, list):
                keywords.extend([str(x) for x in v])
            elif isinstance(v, dict):
                for _kk, vv in v.items():
                    if isinstance(vv, list):
                        keywords.extend([str(x) for x in vv])
                    elif isinstance(vv, str):
                        keywords.append(vv)
        patterns = [re.compile(re.escape(k), re.IGNORECASE) for k in keywords if k]
        return SigmaRule(
            id=data.get("id", "external"),
            title=data.get("title","Unknown"),
            description=data.get("description",""),
            level=data.get("level","medium"),
            status=data.get("status","test"),
            tags=data.get("tags",[]) or [],
            detection=detection,
            logsource=data.get("logsource",{}),
            patterns=patterns,
        )

    def match(self, log: str, context: dict = None) -> List[SigmaRule]:
        """
        Executa todas as regras contra um log.
        Retorna lista de regras que fizeram match.
        """
        if not log:
            return []
        matched = []
        for rule in self.rules:
            if not rule.patterns:
                continue
            # AND logic: precisa de pelo menos 1 keyword? ou ANY?
            # Sigma padrão: ANY keyword matches = hit
            for pattern in rule.patterns:
                if pattern.search(log):
                    matched.append(rule)
                    break
        return matched

    def stats(self) -> dict:
        levels = {}
        for r in self.rules:
            levels[r.level] = levels.get(r.level, 0) + 1
        return {
            "total": len(self.rules),
            "by_level": levels,
        }


# Instância global
sigma = SigmaEngine()
