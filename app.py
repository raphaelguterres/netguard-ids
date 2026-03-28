"""
NetGuard IDS v3.0 — Servidor completo
Monitor de rede real + API REST + Dashboard executivo.
Um único processo. Sem simulador. Sem dados falsos.
"""

import os, re, json, sys, time, logging, functools, pathlib, threading, subprocess, socket, ipaddress

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    psutil = None
    PSUTIL_OK = False
    logging.getLogger("ids.api").warning("psutil não instalado — instale com: pip install psutil")
from datetime import datetime
from flask import Flask, jsonify, request, Response
from flask_cors import CORS
from ids_engine import IDSEngine, LogProcessor

# SOC Detection Engine — arquivo único, sem subpacotes
try:
    from soc_engine import SOCEngine
    SOC_IMPORT_OK = True
except Exception as _se:
    SOCEngine = None
    SOC_IMPORT_OK = False
    print(f"[WARN] SOC Engine import failed: {_se}")

detection_engine = None
DE_AVAILABLE = False

# Threat Hunter
try:
    from engine.threat_hunter import ThreatHunter
    _threat_hunter = None
    HUNTER_AVAILABLE = True
except Exception as _th_err:
    ThreatHunter     = None
    _threat_hunter   = None
    HUNTER_AVAILABLE = False
    print(f"[WARN] ThreatHunter: {_th_err}")

# Lateral Movement Detector
try:
    from engine.lateral_movement import LateralMovementDetector
    _lateral_detector = LateralMovementDetector()
    LATERAL_AVAILABLE = True
except Exception as _lm_err:
    LateralMovementDetector = None
    _lateral_detector       = None
    LATERAL_AVAILABLE       = False
    print(f"[WARN] LateralMovement: {_lm_err}")

# YARA Engine
try:
    from engine.yara_engine import YaraEngine
    _yara_engine = YaraEngine()
    YARA_AVAILABLE = True
except Exception as _yr_err:
    YaraEngine   = None
    _yara_engine = None
    YARA_AVAILABLE = False
    print(f"[WARN] YaraEngine: {_yr_err}")

# Auto Block Engine
try:
    from engine.auto_block import auto_block, AutoBlockEngine, BLOCK_WHITELIST
    AUTOBLOCK_AVAILABLE = True
except Exception as _ab_err:
    auto_block = None
    AUTOBLOCK_AVAILABLE = False
    print(f"[WARN] AutoBlock: {_ab_err}")

# Auth + HTTPS
try:
    from auth import auth, AUTH_ENABLED, get_ssl_context, print_startup_info, HTTPS_PORT
    AUTH_MODULE_OK = True
except Exception as _auth_err:
    # Fallback: auth decorator que não faz nada
    def auth(f): return f
    AUTH_ENABLED   = False
    AUTH_MODULE_OK = False
    def get_ssl_context(): return None
    def print_startup_info(): pass
    print(f"[WARN] Auth module: {_auth_err}")

# Correlation Engine
try:
    from engine.correlation_engine import get_correlation_engine
    def _on_correlation(alert):
        try:
            log_ao_vivo({
                "type":   "correlation",
                "sev":    alert.get("severity","").lower(),
                "threat": f"[{alert.get('rule_id')}] {alert.get('rule_name')}",
                "ip":     alert.get("host_id",""),
                "msg":    alert.get("description","")[:80],
            })
        except Exception:
            pass
        logger.warning("CORRELATION | %s | conf=%d%% | %s",
                       alert.get("rule_id"), alert.get("confidence",0),
                       alert.get("rule_name"))
    _corr_engine = None
    CORR_AVAILABLE = True
except Exception as _ce:
    get_correlation_engine = None
    _corr_engine = None
    CORR_AVAILABLE = False
    print(f"[WARN] Correlation Engine: {_ce}")

# ML Baseline
try:
    from engine.ml_baseline import MLBaseline
    _ml_baseline = None
    ML_AVAILABLE = True
except Exception as _ml_err:
    MLBaseline   = None
    _ml_baseline = None
    ML_AVAILABLE = False
    print(f"[WARN] ML Baseline: {_ml_err}")

# Risk Engine
try:
    from engine.risk_engine import risk_engine
    RISK_AVAILABLE = True
except Exception as _re:
    risk_engine = None
    RISK_AVAILABLE = False
    print(f"[WARN] Risk Engine: {_re}")

# VirusTotal
try:
    from engine.virustotal import VirusTotalClient
    _vt_client = VirusTotalClient()
    VT_AVAILABLE = True
except Exception as _vt_err:
    VirusTotalClient = None
    _vt_client       = None
    VT_AVAILABLE     = False
    print(f"[WARN] VirusTotal: {_vt_err}")

# Fail2Ban Engine
try:
    from fail2ban_engine import fail2ban, JAILS as F2B_JAILS
    F2B_AVAILABLE = True
except ImportError:
    fail2ban = None
    F2B_JAILS = {}
    F2B_AVAILABLE = False

# Kill Chain Correlator
try:
    from killchain import correlator as kc_correlator, TACTIC_LABELS, TACTIC_COLORS
    KC_AVAILABLE = True
except ImportError:
    kc_correlator = None
    KC_AVAILABLE = False

# OWASP Engine
try:
    from owasp_engine import owasp as owasp_engine, TESTING_PAYLOADS
    OWASP_AVAILABLE = True
except ImportError:
    owasp_engine = None
    OWASP_AVAILABLE = False
    TESTING_PAYLOADS = {}

# Sigma Rules Engine
try:
    from sigma_rules import sigma as sigma_engine
    logger_sigma = logging.getLogger("ids.sigma")
except ImportError:
    sigma_engine = None

# Threat Feeds (AbuseIPDB + ThreatFox)
try:
    from threat_feeds import enrich_ip, enrich_async, check_threatfox_ip, stats as feed_stats
    FEEDS_AVAILABLE = True
except ImportError:
    FEEDS_AVAILABLE = False
    def enrich_ip(ip): return {}
    def enrich_async(ip, cb=None): pass

# ── Logging ───────────────────────────────────────────────────────
class JSONFormatter(logging.Formatter):
    def format(self, r):
        return json.dumps({"ts":datetime.now().isoformat()+"Z",
                           "level":r.levelname,"logger":r.name,"msg":r.getMessage()})

h = logging.StreamHandler()
h.setFormatter(JSONFormatter())
logging.basicConfig(handlers=[h], level=logging.INFO)
logger = logging.getLogger("ids.api")

# ── Hostname real da máquina ──────────────────────────────────────
def _get_real_hostname() -> str:
    try:
        import subprocess
        hn = subprocess.check_output("hostname", shell=True, text=True).strip()
        if hn and hn.lower() not in ("new", "localhost", ""):
            return hn
    except Exception:
        pass
    try:
        import socket
        hn = socket.gethostname()
        if hn and hn.lower() not in ("new", "localhost", ""):
            return hn
    except Exception:
        pass
    return "netguard-host"

REAL_HOSTNAME = _get_real_hostname()
logger.info("Hostname detectado: %s", REAL_HOSTNAME)

# ── App ───────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/api/*":{"origins":"*"}})

# ── Whitelist ─────────────────────────────────────────────────────
WHITELIST = ["127.0.0.1","::1","192.168.15.1","192.168.15.2"]
extras = os.environ.get("IDS_WHITELIST_IPS","")
if extras:
    WHITELIST += [ip.strip() for ip in extras.split(",") if ip.strip()]

AUTO_BLOCK = os.environ.get("IDS_AUTO_BLOCK","false").lower() == "true"

ids = IDSEngine(
    db_path=os.environ.get("IDS_DB_PATH","ids_detections.db"),
    whitelist_ips=WHITELIST,
    auto_block=AUTO_BLOCK,
)
log_proc = LogProcessor()

# ── Auth ──────────────────────────────────────────────────────────
API_KEY = os.environ.get("IDS_API_KEY","")

def auth(f):
    @functools.wraps(f)
    def d(*a,**kw):
        if not API_KEY: return f(*a,**kw)
        k = request.headers.get("X-API-Key") or request.args.get("api_key")
        if k != API_KEY: return jsonify({"error":"Unauthorized"}),401
        return f(*a,**kw)
    return d

# ── DNS cache ─────────────────────────────────────────────────────
_dns_cache: dict = {}

def resolve_ip(ip: str) -> str:
    if ip in _dns_cache: return _dns_cache[ip]
    try:
        host = socket.gethostbyaddr(ip)[0]
        _dns_cache[ip] = host
        return host
    except Exception:
        _dns_cache[ip] = ip
        return ip

# ── Descoberta de dispositivos ────────────────────────────────────
_dispositivos: list = []
_ultimo_scan: float = 0.0

def scan_rede_local(rede: str = "192.168.15.0/24") -> list:
    global _dispositivos, _ultimo_scan
    now = time.time()
    if now - _ultimo_scan < 60 and _dispositivos:
        return _dispositivos
    dispositivos = {}
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        for linha in r.stdout.split("\n"):
            partes = linha.strip().split()
            if len(partes) >= 3:
                ip = partes[0]; mac = partes[1]
                try:
                    addr = ipaddress.ip_address(ip)
                    if addr in ipaddress.ip_network(rede, strict=False):
                        if mac not in ("ff-ff-ff-ff-ff-ff","ff:ff:ff:ff:ff:ff"):
                            dispositivos[ip] = {
                                "ip": ip, "mac": mac.upper(), "hostname": "",
                                "status": "online", "tipo": _classificar_dispositivo(ip, mac),
                            }
                except Exception: pass
    except Exception as e:
        logger.warning("ARP scan erro: %s", e)

    def ping_ip(ip_str):
        try:
            r2 = subprocess.run(["ping","-n","1","-w","300",ip_str], capture_output=True, timeout=2)
            if r2.returncode == 0 and ip_str not in dispositivos:
                dispositivos[ip_str] = {"ip":ip_str,"mac":"—","hostname":"","status":"online","tipo":"dispositivo"}
        except Exception: pass

    net = ipaddress.ip_network(rede, strict=False)
    threads = [threading.Thread(target=ping_ip, args=(str(h),), daemon=True) for h in list(net.hosts())[:254]]
    for t in threads: t.start()
    for t in threads: t.join(timeout=0.5)

    def resolver_hostnames():
        for ip, d in list(dispositivos.items()):
            if d["hostname"] == "": d["hostname"] = resolve_ip(ip)
    threading.Thread(target=resolver_hostnames, daemon=True).start()

    gw = rede.replace("0/24","1"); me = rede.replace("0/24","2")
    if gw in dispositivos:
        dispositivos[gw]["tipo"] = "gateway"
        dispositivos[gw]["hostname"] = dispositivos[gw]["hostname"] or "Gateway/Roteador"
    if me in dispositivos:
        dispositivos[me]["tipo"] = "local"
        dispositivos[me]["hostname"] = dispositivos[me]["hostname"] or "Este computador"

    # Enrich with open ports for local IPs
    def enrich_device(d):
        ip = d["ip"]
        # Try to get open ports via nmap-style connect scan on common ports
        d["open_ports"] = []
        d["services"]   = []
        common = [21,22,23,25,53,80,110,135,139,143,443,445,3389,8080,8443]
        for port in common:
            try:
                s = __import__('socket').socket(__import__('socket').AF_INET, __import__('socket').SOCK_STREAM)
                s.settimeout(0.15)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    d["open_ports"].append(port)
                    svc_map = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",
                               110:"POP3",135:"RPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",
                               445:"SMB",3389:"RDP",8080:"HTTP-Alt",8443:"HTTPS-Alt"}
                    d["services"].append(svc_map.get(port, str(port)))
            except Exception:
                pass
        # MAC vendor lookup (first 3 octets)
        mac = d.get("mac","")
        if mac and mac != "—":
            prefix = mac.replace("-",":").upper()[:8]
            vendor_map = {
                "00:50:56":"VMware","00:0C:29":"VMware","00:1C:42":"Parallels",
                "B8:27:EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi",
                "E4:5F:01":"Raspberry Pi","28:CD:C1":"Apple","3C:22:FB":"Apple",
                "AC:BC:32":"Apple","00:1A:11":"Google","94:EB:2C":"TP-Link",
                "C4:E9:84":"TP-Link","50:C7:BF":"TP-Link","78:11:DC":"Huawei",
                "00:46:4B":"Huawei","54:89:98":"Huawei","B4:FB:E4":"ASUSTek",
                "04:D9:F5":"ASUSTek","10:78:D2":"ASUSTek","00:21:CC":"Dell",
                "F4:8E:38":"Dell","18:66:DA":"Dell","00:25:90":"Dell",
                "00:50:F2":"Microsoft","28:18:78":"Microsoft","00:15:5D":"Microsoft",
                "00:1B:21":"Intel","8C:8D:28":"Intel","A0:36:9F":"Intel",
                "00:23:AE":"Cisco","00:1E:F7":"Cisco","CC:46:D6":"Cisco",
            }
            d["vendor"] = vendor_map.get(prefix, "")

    # Run enrichment in parallel threads
    enrich_threads = [threading.Thread(target=enrich_device, args=(d,), daemon=True)
                      for d in dispositivos.values()]
    for t in enrich_threads: t.start()
    for t in enrich_threads: t.join(timeout=2.0)

    _dispositivos = sorted(dispositivos.values(), key=lambda x: [int(p) for p in x["ip"].split(".")])
    _ultimo_scan = now
    logger.info("Scan de rede: %d dispositivos encontrados", len(_dispositivos))
    return _dispositivos

def _classificar_dispositivo(ip: str, mac: str) -> str:
    mac_clean = mac.replace("-","").replace(":","").upper()
    oui = mac_clean[:6] if len(mac_clean) >= 6 else ""
    try:
        if int(mac_clean[1], 16) & 0x2: return "celular"
    except Exception: pass
    oui_map = {
        "900A62":"gateway","E8744A":"gateway","006755":"gateway",
        "001CB3":"apple","A45E60":"apple","F0B429":"apple","3C0754":"apple",
        "ACDE48":"apple","F0DCE2":"apple","8866A5":"apple","DC2B2A":"apple",
        "001632":"samsung","8C71F8":"samsung","E8D0FC":"samsung","F45298":"samsung",
        "F4F5D8":"google","54607E":"google","1C62B8":"google",
        "F0272D":"amazon","A002DC":"amazon","FC65DE":"amazon","74C246":"amazon",
        "286C07":"xiaomi","9C99A0":"xiaomi","F8A45F":"xiaomi",
        "B0487A":"tplink","C46E1F":"tplink","F8D111":"tplink","E8DE27":"tplink",
        "8C8D28":"pc","3413E8":"pc","A4C3F0":"pc","141416":"pc","A0A4C5":"pc",
        "00E04C":"pc","EC086B":"pc","145D34":"pc",
    }
    tipo = oui_map.get(oui, "dispositivo")
    if ip.endswith(".1"): tipo = "gateway"
    return tipo

# ── Sistema: info de processos/rede via psutil ────────────────────
def get_system_info() -> dict:
    """Coleta métricas detalhadas do sistema usando psutil."""
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('C:\\') if os.name == 'nt' else psutil.disk_usage('/')
        net_io = psutil.net_io_counters()
        boot = psutil.boot_time()
        uptime_s = int(time.time() - boot)
        uptime = f"{uptime_s//3600}h {(uptime_s%3600)//60}m"

        # Top processes by CPU
        procs = []
        for p in sorted(psutil.process_iter(['pid','name','cpu_percent','memory_percent','status']),
                        key=lambda x: x.info.get('cpu_percent') or 0, reverse=True)[:15]:
            try:
                try:
                    nconns = len(p.connections())
                except Exception:
                    nconns = 0
                procs.append({
                    "pid":    p.info['pid'],
                    "name":   p.info['name'],
                    "cpu":    round(p.info.get('cpu_percent') or 0, 1),
                    "mem":    round(p.info.get('memory_percent') or 0, 1),
                    "status": p.info.get('status','?'),
                    "conns":  nconns,
                })
            except Exception: pass

        # Network interfaces
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(name)
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces.append({
                        "name":  name,
                        "ip":    addr.address,
                        "mask":  addr.netmask,
                        "speed": stats.speed if stats else 0,
                        "up":    stats.isup if stats else False,
                    })

        # Open listening ports
        listening = []
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == 'LISTEN':
                try:
                    proc = psutil.Process(conn.pid).name() if conn.pid else '?'
                except Exception:
                    proc = f'pid:{conn.pid}'
                listening.append({
                    "port": conn.laddr.port,
                    "addr": conn.laddr.ip,
                    "pid":  conn.pid,
                    "process": proc,
                })
        listening.sort(key=lambda x: x['port'])

        return {
            "cpu_percent":   cpu,
            "mem_percent":   mem.percent,
            "mem_used_mb":   round(mem.used/1024/1024),
            "mem_total_mb":  round(mem.total/1024/1024),
            "disk_percent":  disk.percent,
            "disk_free_gb":  round(disk.free/1024/1024/1024, 1),
            "disk_total_gb": round(disk.total/1024/1024/1024, 1),
            "net_sent_mb":   round(net_io.bytes_sent/1024/1024, 1),
            "net_recv_mb":   round(net_io.bytes_recv/1024/1024, 1),
            "net_packets_sent": net_io.packets_sent,
            "net_packets_recv": net_io.packets_recv,
            "uptime":        uptime,
            "boot_time":     datetime.fromtimestamp(boot).isoformat(),
            "processes":     procs,
            "interfaces":    interfaces,
            "listening":     listening,
        }
    except Exception as e:
        logger.warning("System info error: %s", e)
        return {"error": str(e)}

# ── Monitor state ─────────────────────────────────────────────────
monitor_status = {
    "rodando":False,"ciclo":0,"ultimo_ciclo":None,
    "event_log":"aguardando","conexoes":"aguardando","processos":"aguardando",
    "captura":"iniciando",
}
conexoes_ativas: list = []

# ── Apps confiáveis ───────────────────────────────────────────────
BROWSERS_E_APPS = {
    "brave.exe","chrome.exe","firefox.exe","msedge.exe",
    "opera.exe","vivaldi.exe","chromium.exe","iexplore.exe",
    "svchost.exe","system","lsass.exe","services.exe","explorer.exe",
    "wininit.exe","winlogon.exe","taskhostw.exe","sihost.exe",
    "runtimebroker.exe","searchhost.exe","fontdrvhost.exe",
    "applicationframehost.exe","shellexperiencehost.exe",
    "wuauclt.exe","musnotification.exe","wsappx.exe",
    "onedrive.exe","teams.exe","slack.exe","discord.exe",
    "spotify.exe","zoom.exe","skype.exe","outlook.exe",
    "code.exe","cursor.exe","windowsterminal.exe",
    "python.exe","pythonw.exe","node.exe","git.exe",
    "dropbox.exe","googledrivefs.exe","steam.exe",
    "obs64.exe","vlc.exe","microsoftedgeupdate.exe",
    "steam.exe","steamwebhelper.exe","steamservice.exe","gameoverlayui.exe",
    "mpdefendercoreservice.exe","mpdefendercoreserv.exe","msmpeng.exe","nissrv.exe",
    "securityhealthsystray.exe","securityhealthservice.exe",
    "msedgewebview2.exe","webview2.exe",
    "claude.exe","notion.exe","figma.exe","linear.exe",
    "whatsapp.exe","signal.exe","telegram.exe",
    "postman.exe","insomnia.exe","1password.exe",
    "winstore.app.exe","winstoredraftapp.exe","microsoftstore.exe","widgets.exe",
    "msMpEng.exe","nisssrv.exe","securityhealthservice.exe",
    "csrss.exe","smss.exe","spoolsv.exe","RuntimeBroker.exe",
    "Teams.exe","Slack.exe","discord.exe",
}

PROCESSOS_SUSPEITOS = [
    "mimikatz","meterpreter","netcat","ncat","nc.exe",
    "pwdump","fgdump","wce.exe","gsecdump","procdump",
    "psexec","wmiexec","dcsync","bloodhound",
    "cobaltstrike","cobalt_strike","beacon.exe",
]

PORTAS_SUSPEITAS = {
    4444,1337,31337,8888,9001,9002,6666,6667,6668,1234,
    5555,7777,8989,12345,54321,65535,1111,2222,3333,
}

PORTAS_LEGITIMAS = {
    80,443,8080,8443,53,22,3389,21,25,587,465,993,995,
    110,143,389,636,3306,5432,1433,27017,6379,5672,
    5000,3000,8000,4200,9200,5601,8888,
}

REDE_LOCAL = "192.168.15."

_conexoes_vistas:   set = set()
_processos_alertados: set = set()
_pid_cache: dict = {}
_pid_cache_time: float = 0.0

def get_pid_name_cached(pid) -> str:
    global _pid_cache, _pid_cache_time
    now = time.time()
    if now - _pid_cache_time > 30:
        try:
            r = subprocess.run(["tasklist","/fo","csv","/nh"],capture_output=True,text=True,timeout=8)
            _pid_cache = {}
            for linha in r.stdout.strip().split("\n"):
                partes = linha.strip().split(",")
                if len(partes) >= 2:
                    nome = partes[0].strip('"').lower()
                    p = partes[1].strip('"')
                    if p.isdigit(): _pid_cache[p] = nome
            _pid_cache_time = now
        except Exception: pass
    return _pid_cache.get(str(pid), "")

def ip_ok(ip: str) -> bool:
    return ip.startswith(REDE_LOCAL) or ip in ("127.0.0.1","::1","0.0.0.0")

def analisar(log: str, ip: str = None, field: str = "raw", origem: str = ""):
    ctx = {"field": field}
    if origem: ctx["origem"] = origem
    eventos = ids.analyze(log, ip, ctx)

    # OWASP CRS — análise de payload web
    if owasp_engine and field in ("url","body","query_string","raw","apache"):
        owasp_matches = owasp_engine.analyze(log)
        for om in owasp_matches:
            already = any(e.threat_name == om.title for e in eventos)
            if not already:
                log_ao_vivo({
                    "type":   "owasp",
                    "sev":    om.severity,
                    "threat": f"[OWASP {om.rule_id}] {om.title}",
                    "ip":     ip or "—",
                    "msg":    f"{om.category} · {om.evidence[:60]}",
                })

    # Sigma Rules — análise adicional
    if sigma_engine:
        sigma_matches = sigma_engine.match(log, ctx)
        for rule in sigma_matches:
            # Evita duplicata com detecções do IDS
            already = any(e.threat_name == rule.title for e in eventos)
            if not already:
                # Injeta como detecção sintética
                from ids_engine import Detection
                try:
                    fake_ctx = {"field": field, "sigma": True}
                    synthetic = ids.analyze(
                        f"SIGMA:{rule.id} {log[:200]}", ip,
                        {"field": field, "sigma_rule": rule.title}
                    )
                    if not synthetic:
                        # Cria entrada de log direto
                        log_ao_vivo({
                            "type": "sigma",
                            "sev":  rule.level,
                            "threat": f"[Sigma] {rule.title}",
                            "ip":   ip or "—",
                            "msg":  rule.description,
                        })
                except Exception:
                    pass

    for e in eventos:
        logger.warning("DETECÇÃO | %s | sev=%s | ip=%s | %s", e.threat_name, e.severity, ip, log[:80])
        # Feed Fail2Ban
        if F2B_AVAILABLE and fail2ban and ip:
            try:
                ban = fail2ban.ingest({
                    "source_ip":   ip,
                    "threat_name": e.threat_name,
                    "severity":    e.severity,
                    "method":      "ids",
                    "timestamp":   datetime.now().isoformat() + "Z",
                })
                if ban:
                    log_ao_vivo({
                        "type": "fail2ban",
                        "sev":  "high",
                        "threat": f"🚫 BAN: {ip} ({ban.jail_label})",
                        "ip":   ip,
                        "msg":  f"Banido após {ban.count} tentativas — expira: {ban.time_remaining()}",
                    })
                    logger.warning("FAIL2BAN | ip=%s | jail=%s | count=%d", ip, ban.jail, ban.count)
            except Exception as _fe:
                pass

        # Feed kill chain correlator
        if kc_correlator and ip:
            try:
                kc_correlator.ingest({
                    "source_ip":     ip,
                    "threat_name":   e.threat_name,
                    "severity":      e.severity,
                    "mitre_tactic":  e.mitre_tactic if hasattr(e,'mitre_tactic') else "",
                    "mitre_technique": e.mitre_technique if hasattr(e,'mitre_technique') else "",
                    "method":        "ids",
                    "log_entry":     log[:200],
                    "confidence":    e.confidence if hasattr(e,'confidence') else 1.0,
                    "timestamp":     datetime.now().isoformat() + "Z",
                })
            except Exception:
                pass
    return eventos

# ── Monitor: Event Log ────────────────────────────────────────────
def checar_event_log():
    try:
        script = """
        $cutoff = (Get-Date).AddSeconds(-35)
        $ids = @(4625,4648,4720,4732,4740,4756,7045)
        $events = Get-WinEvent -FilterHashtable @{LogName='Security','System'; Id=$ids; StartTime=$cutoff} -ErrorAction SilentlyContinue
        if ($events) { $events | ForEach-Object { Write-Output "$($_.Id)|$($_.Message.Substring(0, [Math]::Min(200,$_.Message.Length)))" } }
        """
        r = subprocess.run(["powershell","-Command",script],capture_output=True,text=True,timeout=10)
        count = 0
        for linha in r.stdout.strip().split("\n"):
            if "|" in linha:
                eid, msg = linha.split("|",1)
                analisar(f"EventID={eid} {msg}","127.0.0.1","syslog","event_log")
                count += 1
        monitor_status["event_log"] = f"{count} eventos novos" if count else "sem eventos novos"
    except Exception as e:
        monitor_status["event_log"] = f"erro: {e}"

# ── Monitor: Conexões ─────────────────────────────────────────────
def checar_conexoes():
    try:
        pid_map_local = get_pid_name_cached(0) and _pid_cache
        r = subprocess.run(["netstat","-n","-o"],capture_output=True,text=True,timeout=10)
        sus=0; total=0; info_conexoes=[]; conn_map={}

        for linha in r.stdout.strip().split("\n"):
            if "ESTABLISHED" not in linha: continue
            p = linha.split()
            if len(p)<5: continue
            end = p[2]
            if ":" not in end: continue
            idx = end.rfind(":")
            ip_r = end[:idx].strip("[]")
            try:
                porta = int(end[idx+1:])
                pid   = p[4]
            except: continue
            total += 1

            proc_nome = get_pid_name_cached(pid)
            is_trusted = any(b in proc_nome for b in [x.lower() for x in BROWSERS_E_APPS])

            # Popula mapa de conexões
            if proc_nome not in conn_map:
                conn_map[proc_nome] = {
                    "process": proc_nome,
                    "connections": [],
                    "trusted": is_trusted,
                }
            conn_map[proc_nome]["connections"].append({
                "dst_ip":    ip_r,
                "dst_port":  porta,
                "local_port": int(p[1].rsplit(":",1)[-1]) if ":" in p[1] else 0,
                "hostname":  resolve_ip(ip_r) if not ip_r.startswith("127.") else "localhost",
            })

            if ip_ok(ip_r) or ip_r.startswith("127."): continue

            chave = f"{ip_r}:{porta}:{proc_nome}"
            if porta in PORTAS_SUSPEITAS and chave not in _conexoes_vistas:
                _conexoes_vistas.add(chave)
                analisar(f"SUSPICIOUS CONNECTION DST={ip_r} DPT={porta} PROC={proc_nome}", ip_r, "firewall")
                sus += 1
            elif (not ip_r.startswith(REDE_LOCAL) and porta not in PORTAS_LEGITIMAS
                  and porta < 1024 and not is_trusted and chave not in _conexoes_vistas):
                _conexoes_vistas.add(chave)
                analisar(f"EXTERNAL CONNECTION DST={ip_r} DPT={porta} PROC={proc_nome}", ip_r, "firewall")
                sus += 1

            if not is_trusted and not ip_ok(ip_r):
                info_conexoes.append(f"{proc_nome}→{ip_r}:{porta}")

        global conexoes_ativas
        conexoes_ativas = sorted(conn_map.values(), key=lambda x: (x["trusted"], x["process"]))
        resumo = f"{total} ativas | {sus} suspeitas"
        if info_conexoes: resumo += f" | {', '.join(info_conexoes[:3])}"
        monitor_status["conexoes"] = resumo
    except Exception as e:
        monitor_status["conexoes"] = f"erro: {e}"

# ── Monitor: Processos ────────────────────────────────────────────
def checar_processos():
    try:
        r = subprocess.run(["tasklist","/fo","csv","/nh"],capture_output=True,text=True,timeout=10)
        found=[]
        for linha in r.stdout.strip().split('\n'):
            p = linha.strip().split(',')
            if not p: continue
            nome = p[0].strip('"').lower()
            pid  = p[1].strip('"') if len(p)>1 else "?"
            for s in PROCESSOS_SUSPEITOS:
                if s.lower() in nome and nome not in _processos_alertados:
                    _processos_alertados.add(nome)
                    analisar(f"Suspicious process running: {nome} PID={pid}", "127.0.0.1","command","tasklist")
                    found.append(nome)
        monitor_status["processos"] = f"suspeitos: {found}" if found else "nenhum suspeito"
    except Exception as e:
        monitor_status["processos"] = f"erro: {e}"

def loop_monitor(intervalo=30):
    monitor_status["rodando"] = True
    logger.info("Monitor iniciado (intervalo=%ds)", intervalo)
    while monitor_status["rodando"]:
        monitor_status["ciclo"] += 1
        monitor_status["ultimo_ciclo"] = datetime.now().strftime('%H:%M:%S')
        checar_event_log()
        checar_conexoes()
        checar_processos()
        logger.info("Ciclo #%d | evlog=%s | rede=%s | proc=%s",
                    monitor_status["ciclo"],
                    monitor_status["event_log"],
                    monitor_status["conexoes"],
                    monitor_status["processos"])

        # ── Detection Engine — analisa snapshot do sistema ────────
        if DE_AVAILABLE and detection_engine:
            logger.debug("SOC snapshot: procs=%d ports=%d", len(conexoes_ativas or []), 0)
            try:
                # Coleta processos
                procs_snapshot = []
                if PSUTIL_OK:
                    for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent','exe']):
                        try:
                            procs_snapshot.append({
                                "name": p.info['name'],
                                "pid":  p.info['pid'],
                                "cpu":  p.info.get('cpu_percent') or 0,
                                "mem":  p.info.get('memory_percent') or 0,
                                "exe":  (p.info.get('exe') or '')[:120],
                            })
                        except Exception:
                            pass

                # Coleta portas
                ports_snapshot = []
                if PSUTIL_OK:
                    for conn in psutil.net_connections(kind='inet'):
                        if conn.status == 'LISTEN':
                            ports_snapshot.append({
                                "port":    conn.laddr.port,
                                "proto":   "tcp",
                                "addr":    str(conn.laddr.ip),
                                "process": get_pid_name_cached(str(conn.pid)) if conn.pid else "",
                            })

                # Coleta conexões ativas (flat list) — também via psutil para IPs externos
                conns_snapshot = []
                # De conexoes_ativas (já processadas pelo checar_conexoes)
                for proc_data in conexoes_ativas:
                    for conn in proc_data.get("connections", []):
                        conns_snapshot.append({
                            "process":  proc_data["process"],
                            "dst_ip":   conn.get("dst_ip",""),
                            "dst_port": conn.get("dst_port",0),
                        })
                # Também via psutil diretamente para garantir cobertura
                if PSUTIL_OK and not conns_snapshot:
                    try:
                        for conn in psutil.net_connections(kind='inet'):
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                pname = get_pid_name_cached(str(conn.pid)) if conn.pid else "system"
                                conns_snapshot.append({
                                    "process": pname,
                                    "dst_ip":  conn.raddr.ip,
                                    "dst_port": conn.raddr.port,
                                })
                    except Exception:
                        pass

                # Run sync for immediate results + async via queue
                try:
                    events = detection_engine.analyze(
                        processes   = procs_snapshot,
                        ports       = ports_snapshot,
                        connections = conns_snapshot,
                    )
                    if events:
                        logger.info("SOC | %d eventos gerados no ciclo", len(events))
                        # Feed lateral movement detector
                        if LATERAL_AVAILABLE and _lateral_detector:
                            try:
                                h_id = detection_engine.host_id
                                for ev in events:
                                    ed = ev.to_dict() if hasattr(ev,'to_dict') else dict(ev)
                                    lm_alerts = _lateral_detector.ingest(ed, host_id=h_id)
                                    for la in lm_alerts:
                                        log_ao_vivo({
                                            "type":   "lateral_movement",
                                            "sev":    la.severity.lower(),
                                            "threat": la.rule_name,
                                            "ip":     la.source_ip,
                                            "msg":    la.description[:80],
                                        })
                            except Exception: pass

                    # Feed ML baseline EVERY cycle (not just when events fire)
                    if ML_AVAILABLE and _ml_baseline:
                        try:
                            ml_alert = _ml_baseline.add_sample({
                                "processes":   procs_snapshot,
                                "connections": conns_snapshot,
                                "ports":       ports_snapshot,
                            })
                            if ml_alert:
                                log_ao_vivo({
                                    "type":   "ml_anomaly",
                                    "sev":    ml_alert["severity"].lower(),
                                    "threat": ml_alert["rule_name"],
                                    "ip":     ml_alert["host_id"],
                                    "msg":    ml_alert["description"][:80],
                                })
                                logger.warning("ML ANOMALY | %s", ml_alert["description"][:80])
                        except Exception: pass

                    if events:
                        # Feed correlation engine
                        if CORR_AVAILABLE and _corr_engine:
                            try:
                                def _fix_host(ed):
                                    if ed.get("host_id","").lower() in ("new","localhost",""):
                                        ed["host_id"] = _corr_engine.host_id
                                    return ed
                                corr_alerts = _corr_engine.ingest_batch([
                                    _fix_host(ev.to_dict() if hasattr(ev,'to_dict') else dict(ev))
                                    for ev in events
                                ])
                                if corr_alerts:
                                    logger.warning("CORR | %d padrões detectados", len(corr_alerts))
                            except Exception as _ca: pass
                        # Feed risk engine + auto block
                        if RISK_AVAILABLE and risk_engine:
                            try:
                                for ev in events:
                                    ed = ev.to_dict() if hasattr(ev,'to_dict') else dict(ev)
                                    # Fix hostname
                                    if ed.get("host_id","").lower() in ("new","localhost",""):
                                        ed["host_id"] = REAL_HOSTNAME
                                    risk_engine.ingest_event(ed)
                            except Exception: pass
                except Exception as _sync_e:
                    logger.debug("SOC sync analyze: %s", _sync_e)
                    detection_engine.enqueue_snapshot({
                        "processes":   procs_snapshot,
                        "ports":       ports_snapshot,
                        "connections": conns_snapshot,
                    })
            except Exception as _de_e:
                logger.debug("Detection engine snapshot error: %s", _de_e)

        # Alimenta o terminal ao vivo
        try:
            log_ao_vivo({
                "type": "monitor",
                "msg":  f"Ciclo #{monitor_status['ciclo']} · {monitor_status['event_log']} · {monitor_status['conexoes']}",
                "ip":   "127.0.0.1",
            })
        except Exception:
            pass
        time.sleep(intervalo)

# ── Middleware ────────────────────────────────────────────────────
@app.before_request
def before(): request._t = time.monotonic()

@app.after_request
def after(resp):
    ms = round((time.monotonic()-request._t)*1000,2)
    resp.headers["X-Request-Time-ms"] = str(ms)
    return resp

# ── API routes ────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({
        "status":"healthy","modo":"rede_real","simulador":"desativado",
        "timestamp":datetime.now().isoformat()+"Z",
        "total_detections":ids.store.count_total(),
        "whitelist_ips":list(ids.whitelist_ips),
        "signatures_loaded":len(ids.signatures),
        "auto_block":AUTO_BLOCK,
        "monitor":monitor_status,
        "captura":monitor_status.get("captura","indisponivel"),
    })

@app.route("/api/detections")
@auth
def get_detections():
    rows = ids.get_detections(
        limit=min(request.args.get("limit",100,int),500),
        offset=request.args.get("offset",0,int),
        severity=request.args.get("severity"),
        status=request.args.get("status"),
        source_ip=request.args.get("source_ip"),
    )
    return jsonify({"total":ids.store.count_total(),"returned":len(rows),"detections":rows})

@app.route("/api/detections/<did>")
@auth
def get_detection(did):
    for r in ids.store.query(limit=10000):
        if r["detection_id"]==did: return jsonify(r)
    return jsonify({"error":"not found"}),404

@app.route("/api/detections/<did>/status",methods=["PATCH"])
@auth
def update_status(did):
    body = request.get_json(force=True) or {}
    status = body.get("status")
    if status not in {"active","investigating","resolved","false_positive"}:
        return jsonify({"error":"status invalido"}),400
    ok = ids.update_status(did, status, body.get("analyst_note",""))
    return (jsonify({"success":True,"detection_id":did,"new_status":status})
            if ok else jsonify({"error":"not found"}),404)

@app.route("/api/analyze",methods=["POST"])
@auth
def analyze():
    body = request.get_json(force=True) or {}
    log  = body.get("log","").strip()
    if not log: return jsonify({"error":"log obrigatorio"}),400
    if len(log)>10000: return jsonify({"error":"log muito longo"}),413
    field = body.get("field","raw")
    events = ids.analyze(log, body.get("source_ip"), {"field": field})

    # OWASP CRS analysis
    owasp_matches = []
    if owasp_engine:
        for om in owasp_engine.analyze(log):
            owasp_matches.append({
                "threat_name":   f"[OWASP] {om.title}",
                "description":   om.description,
                "severity":      om.severity,
                "mitre_tactic":  om.category,
                "mitre_technique": om.cwe,
                "method":        "owasp_crs",
                "confidence":    0.9,
                "log_entry":     log[:200],
                "source_ip":     body.get("source_ip",""),
                "rule_id":       om.rule_id,
                "owasp_ref":     om.owasp_ref,
                "evidence":      om.evidence,
                "remediation":   om.remediation,
            })

    # Also run Sigma
    sigma_matches = []
    if sigma_engine:
        for rule in sigma_engine.match(log):
            sigma_matches.append({
                "id":            rule.id,
                "threat_name":   f"[Sigma] {rule.title}",
                "description":   rule.description,
                "severity":      rule.level,
                "mitre_tactic":  rule.mitre_tactic,
                "mitre_technique": rule.mitre_technique,
                "method":        "sigma",
                "confidence":    0.85,
                "log_entry":     log[:200],
                "source_ip":     body.get("source_ip",""),
            })

    all_detections = [e.to_dict() for e in events] + sigma_matches + owasp_matches
    return jsonify({
        "analyzed":       log[:200],
        "threats_found":  len(all_detections),
        "detections":     all_detections,
        "sigma_matches":  len(sigma_matches),
        "owasp_matches":  len(owasp_matches),
        "ids_matches":    len(events),
    })

@app.route("/api/statistics")
@auth
def statistics():
    return jsonify(ids.get_statistics())

@app.route("/api/export")
@auth
def export():
    fmt  = request.args.get("format","json")
    data = ids.export(fmt)
    ct   = "text/csv" if fmt=="csv" else "application/json"
    fn   = f"ids_export.{fmt}"
    return Response(data,mimetype=ct,headers={"Content-Disposition":f"attachment;filename={fn}"})

@app.route("/api/block",methods=["POST"])
@auth
def block_ip():
    body   = request.get_json(force=True) or {}
    ip     = body.get("ip","").strip()
    reason = body.get("reason","Manual via API")
    if not ip: return jsonify({"error":"ip obrigatorio"}),400
    if ip in ids.whitelist_ips:
        return jsonify({"error":"IP esta na whitelist — nao pode bloquear"}),409
    ok = ids.block_ip(ip, reason)
    return jsonify({"success":ok,"ip":ip,"reason":reason,
                    "note":"Requer privilégio de Administrador" if not ok else ""})

@app.route("/api/block",methods=["GET"])
@auth
def list_blocks():
    return jsonify({"blocked_ips":ids.blocker.list_blocked()})

@app.route("/api/block/<ip>",methods=["DELETE"])
@auth
def unblock_ip(ip):
    ok = ids.unblock_ip(ip)
    return jsonify({"success":ok,"ip":ip})


# ── Device enrichment helpers ──────────────────────────────────────

OUI_VENDOR_MAP = {
    "900A62":"Huawei","E8744A":"Huawei","006755":"Huawei","C8E2A4":"Huawei",
    "001CB3":"Apple","A45E60":"Apple","F0B429":"Apple","3C0754":"Apple",
    "ACDE48":"Apple","8C85C1":"Apple","F8A45F":"Xiaomi","286C07":"Xiaomi",
    "001632":"Samsung","8C71F8":"Samsung","E8D0FC":"Samsung",
    "F4F5D8":"Google","54607E":"Google","1C62B8":"Google",
    "F0272D":"Amazon","A002DC":"Amazon","FC65DE":"Amazon",
    "9CEB5A":"ASUS","F8AB05":"ASUS","1062E5":"Intel","8086F2":"Intel",
    "000C29":"VMware","005056":"VMware","001C14":"VMware",
    "B827EB":"Raspberry Pi","DC:A6:32":"Raspberry Pi",
    "708BCD":"Microsoft","3C1867":"Microsoft","0026B9":"Dell",
    "00259C":"Dell","1866DA":"HP","A0D3C1":"HP",
    "3417EB":"Realtek","A4AE12":"Realtek","04BFD0":"LG",
    "B4EED4":"LG","0CF3EE":"Intelbras","88548D":"Intelbras",
}

COMMON_PORT_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3389:"RDP", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 3306:"MySQL",
    5432:"PostgreSQL", 6379:"Redis", 27017:"MongoDB",
    5000:"Flask/Dev", 8888:"Jupyter", 4000:"Dev",
}

def _oui_vendor(mac: str) -> str:
    """Retorna fabricante do dispositivo pelo OUI do MAC."""
    if not mac or mac == "—":
        return "Desconhecido"
    clean = mac.replace("-","").replace(":","").upper()
    oui = clean[:6] if len(clean) >= 6 else ""
    return OUI_VENDOR_MAP.get(oui, "Desconhecido")

def _scan_device_ports(ip: str) -> list:
    """
    Verifica portas abertas num dispositivo local via conexões netstat.
    Rápido — não faz scan TCP real, usa apenas o estado da rede atual.
    """
    if not ip or ip == "192.168.15.2":  # própria máquina
        try:
            if PSUTIL_OK:
                ports = []
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'LISTEN' and conn.laddr:
                        p = conn.laddr.port
                        if p not in ports:
                            ports.append(p)
                return sorted(ports)[:20]
        except Exception:
            pass
        return []
    # Para outros dispositivos: tenta conexões TCP rápidas nas portas comuns
    open_ports = []
    check_ports = [22, 80, 443, 445, 3389, 8080, 21, 23, 25, 53]
    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
    threads = [threading.Thread(target=check_port, args=(p,), daemon=True) for p in check_ports]
    for t in threads: t.start()
    for t in threads: t.join(timeout=1.0)
    return sorted(open_ports)

def _ping_latency(ip: str) -> float:
    """Retorna latência em ms via ping. Retorna -1 se falhar."""
    try:
        r = subprocess.run(
            ["ping", "-n", "1", "-w", "500", ip],
            capture_output=True, text=True, timeout=2
        )
        for line in r.stdout.split("\n"):
            if "ms" in line.lower() and ("tempo" in line.lower() or "time" in line.lower() or "=" in line):
                parts = line.replace("<","=").split("=")
                for part in parts:
                    part = part.strip()
                    if part.endswith("ms"):
                        try:
                            return float(part[:-2].strip())
                        except ValueError:
                            pass
    except Exception:
        pass
    return -1.0

def _infer_services(ports: list) -> list:
    """Infere serviços pelo número de porta."""
    return [
        {"port": p, "service": COMMON_PORT_SERVICES.get(p, f"port/{p}")}
        for p in (ports or [])
    ]

@app.route("/api/devices")
@auth
def get_devices():
    dispositivos = scan_rede_local("192.168.15.0/24")
    # Enrich each device with extra info
    enriched = []
    for d in dispositivos:
        dev = dict(d)
        ip = dev.get("ip","")
        mac = dev.get("mac","")
        # OUI vendor lookup
        dev["vendor"] = _oui_vendor(mac)
        # Open ports via netstat (fast, local)
        dev["open_ports"] = _scan_device_ports(ip)
        # Latency via ping
        dev["latency_ms"] = _ping_latency(ip)
        # Services inferred from ports
        dev["services"] = _infer_services(dev["open_ports"])
        enriched.append(dev)
    return jsonify({
        "devices":   enriched,
        "total":     len(enriched),
        "rede":      "192.168.15.0/24",
        "timestamp": datetime.now().isoformat() + "Z",
    })

@app.route("/api/connections")
@auth
def get_connections():
    """Conexões ativas mapeadas por processo (com DNS e hostname)."""
    return jsonify({
        "connections": conexoes_ativas,
        "total":       len(conexoes_ativas),
        "timestamp":   datetime.now().isoformat() + "Z",
    })

@app.route("/api/system")
@auth
def system_info():
    if not PSUTIL_OK:
        return jsonify({"error": "psutil não instalado. Execute: pip install psutil"}), 503
    """Métricas detalhadas do sistema: CPU, RAM, disco, processos, portas abertas."""
    return jsonify(get_system_info())

@app.route("/api/processes")
@auth
def list_processes():
    if not PSUTIL_OK:
        return jsonify({"error": "psutil não instalado"}), 503
    """Lista todos os processos com CPU, RAM, conexões e classificação."""
    try:
        procs = []
        for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent',
                                       'status','username','exe']):
            try:
                name = (p.info['name'] or '').lower()
                trusted = any(b in name for b in [x.lower() for x in BROWSERS_E_APPS])
                suspicious = any(s.lower() in name for s in PROCESSOS_SUSPEITOS)
                try:
                    nconns = len(p.connections())
                except Exception:
                    nconns = 0
                procs.append({
                    "pid":        p.info['pid'],
                    "name":       p.info['name'],
                    "cpu":        round(p.info.get('cpu_percent') or 0, 1),
                    "mem":        round(p.info.get('memory_percent') or 0, 1),
                    "status":     p.info.get('status','?'),
                    "user":       (p.info.get('username') or '?').split('\\')[-1],
                    "conns":      nconns,
                    "trusted":    trusted,
                    "suspicious": suspicious,
                    "exe":        (p.info.get('exe') or '')[:80],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        procs.sort(key=lambda x: x['cpu'], reverse=True)
        return jsonify({"total": len(procs), "processes": procs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ports")
@auth
def list_ports():
    if not PSUTIL_OK:
        return jsonify({"error": "psutil não instalado"}), 503
    """Lista todas as portas abertas (LISTEN) com processo responsável."""
    try:
        listening = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status in ('LISTEN',''):
                try:
                    proc = psutil.Process(conn.pid).name() if conn.pid else '?'
                except Exception:
                    proc = f'pid:{conn.pid}'
                listening.append({
                    "port":     conn.laddr.port,
                    "addr":     conn.laddr.ip,
                    "proto":    "tcp" if conn.type == 1 else "udp",
                    "pid":      conn.pid,
                    "process":  proc,
                    "suspicious": conn.laddr.port in PORTAS_SUSPEITAS,
                })
        listening.sort(key=lambda x: x['port'])
        return jsonify({"total": len(listening), "ports": listening})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Live log buffer ──────────────────────────────────────────────
from collections import deque
_live_log: deque = deque(maxlen=200)
_live_log_lock = threading.Lock()

def log_ao_vivo(entry: dict):
    """Adiciona entrada ao buffer de log ao vivo."""
    entry["ts"] = datetime.now().strftime('%H:%M:%S.%f')[:12]
    with _live_log_lock:
        _live_log.append(entry)

# Patch analisar to also feed live log
_orig_analisar = analisar
def analisar(log: str, ip: str = None, field: str = "raw", origem: str = ""):
    eventos = _orig_analisar(log, ip, field, origem)
    if eventos:
        for e in eventos:
            log_ao_vivo({
                "type":    "detection",
                "sev":     e.severity,
                "threat":  e.threat_name,
                "ip":      ip or "—",
                "msg":     log[:80],
            })
    return eventos

@app.route("/api/live-log")
@auth
def live_log():
    """Retorna buffer de log ao vivo (últimas 200 entradas)."""
    with _live_log_lock:
        entries = list(_live_log)
    return jsonify({
        "entries":   entries,
        "total":     len(entries),
        "timestamp": datetime.now().isoformat() + "Z",
    })

@app.route("/api/graph")
@auth
def connection_graph():
    """Retorna grafo de conexões: nós (processos + IPs) e arestas."""
    # Busca conexões em tempo real (não depende do cache do monitor)
    live = []
    try:
        r = subprocess.run(["netstat","-n","-o"],capture_output=True,text=True,timeout=8)
        conn_map = {}
        for linha in r.stdout.strip().split("\n"):
            if "ESTABLISHED" not in linha: continue
            p = linha.split()
            if len(p) < 5: continue
            end = p[2]
            if ":" not in end: continue
            idx = end.rfind(":")
            ip2 = end[:idx].strip("[]")
            try:
                porta2 = int(end[idx+1:])
                pid2   = p[4]
            except: continue
            proc2 = get_pid_name_cached(pid2) or f"pid:{pid2}"
            if proc2 not in conn_map:
                conn_map[proc2] = {
                    "process":     proc2,
                    "connections": [],
                    "trusted":     any(b in proc2 for b in [x.lower() for x in BROWSERS_E_APPS]),
                }
            conn_map[proc2]["connections"].append({
                "dst_ip":   ip2,
                "dst_port": porta2,
                "hostname": resolve_ip(ip2) if not ip2.startswith("127.") else "localhost",
            })
        live = list(conn_map.values())
    except Exception:
        live = conexoes_ativas  # fallback para cache

    nodes = {}
    edges = []
    seen_edges = set()

    for proc_data in live:
        proc = proc_data["process"]
        trusted = proc_data["trusted"]
        pid = f"proc:{proc}"
        if pid not in nodes:
            nodes[pid] = {
                "id":      pid,
                "label":   proc,
                "type":    "process",
                "trusted": trusted,
                "conns":   len(proc_data["connections"]),
            }
        for conn in proc_data.get("connections", []):
            ip  = conn["dst_ip"]
            port= conn["dst_port"]
            hn  = conn.get("hostname", ip)
            iid = f"ip:{ip}"
            if iid not in nodes:
                i = {"ip": ip, "score": 0, "cat": "ok"}
                from threat_intel import intel as ti
                try:
                    r = ti.analisar(ip)
                    i = r
                except Exception:
                    pass
                nodes[iid] = {
                    "id":      iid,
                    "label":   hn if hn != ip else ip,
                    "ip":      ip,
                    "type":    "ip",
                    "score":   i.get("score", 0),
                    "cat":     i.get("categoria", "ok"),
                    "hostname": hn,
                }
            eid = f"{pid}->{iid}:{port}"
            if eid not in seen_edges:
                seen_edges.add(eid)
                edges.append({
                    "source": pid,
                    "target": iid,
                    "port":   port,
                })

    return jsonify({
        "nodes":     list(nodes.values()),
        "edges":     edges,
        "timestamp": datetime.now().isoformat() + "Z",
    })


# ── SOC Engine initialization (after log_ao_vivo is defined) ────────
if SOC_IMPORT_OK:
    try:
        def _soc_alert_live(event):
            try:
                log_ao_vivo({
                    "type":   "detection",
                    "sev":    event.severity.lower() if hasattr(event.severity, 'lower') else str(event.severity).lower(),
                    "threat": f"[{event.rule_id}] {event.rule_name}",
                    "ip":     event.details.get("source_ip", event.host_id),
                    "msg":    (event.raw[:80] if event.raw else str(event.details)[:80]),
                })
            except Exception:
                pass
            logger.warning("SOC ENGINE | rule=%s | sev=%s | %s",
                           event.rule_id, event.severity, event.rule_name)

        _db_path = os.environ.get("IDS_DB_PATH",
                      str(pathlib.Path(__file__).parent / "netguard_soc.db"))
        detection_engine = SOCEngine(
            db_path        = _db_path,
            alert_callback = _soc_alert_live,
            host_id        = REAL_HOSTNAME,
        )
        detection_engine.start()
        # Migrate legacy host_id='new' in DB
        try:
            detection_engine.storage._migrate(detection_engine.host_id)
        except Exception: pass
        DE_AVAILABLE = True
        logger.info("SOC Engine OK | 12 regras ativas")
        # Init Threat Hunter
        if HUNTER_AVAILABLE:
            try:
                _db = os.environ.get("IDS_DB_PATH",
                      str(pathlib.Path(__file__).parent / "netguard_soc.db"))
                _threat_hunter = ThreatHunter(db_path=_db)
                logger.info("ThreatHunter iniciado | db=%s", _db)
            except Exception as _th_init:
                logger.warning("ThreatHunter init: %s", _th_init)

        # Init ML baseline
        if ML_AVAILABLE:
            try:
                _ml_baseline = MLBaseline(
                    host_id     = detection_engine.host_id,
                    min_samples = 30,
                    contamination = 0.05,
                )
                logger.info("ML Baseline iniciado | min_samples=30")
            except Exception as _ml_init_err:
                logger.warning("ML Baseline init: %s", _ml_init_err)

        # Init correlation engine
        if CORR_AVAILABLE:
            try:
                _hn = detection_engine.host_id
                _corr_engine = get_correlation_engine(
                    host_id  = _hn,
                    callback = _on_correlation,
                )
                logger.info("Correlation Engine OK | 5 regras ativas | host=%s", _hn)
            except Exception as _corr_err:
                logger.warning("Correlation Engine init: %s", _corr_err)
    except Exception as _soc_init_err:
        detection_engine = None
        DE_AVAILABLE = False
        logger.warning("SOC Engine init failed: %s", _soc_init_err)


@app.route("/api/enrich/<ip>")
@auth
def enrich_ip_route(ip):
    """Enriquece um IP com AbuseIPDB + ThreatFox."""
    result = enrich_ip(ip)
    return jsonify(result)

@app.route("/api/threatfox/<ip>")
@auth
def threatfox_check(ip):
    """Consulta ThreatFox por IOCs do IP (sem chave de API)."""
    result = check_threatfox_ip(ip)
    return jsonify(result)

@app.route("/api/sigma/stats")
@auth
def sigma_stats():
    """Estatísticas do Sigma Rules Engine."""
    if not sigma_engine:
        return jsonify({"error": "Sigma não disponível"}), 503
    return jsonify({
        "engine":   "SigmaHQ compatible",
        "rules":    sigma_engine.stats(),
        "builtin":  True,
        "external": False,
    })

@app.route("/api/sigma/analyze", methods=["POST"])
@auth
def sigma_analyze():
    """Analisa um log contra todas as regras Sigma."""
    if not sigma_engine:
        return jsonify({"error": "Sigma não disponível"}), 503
    body = request.get_json(force=True) or {}
    log  = body.get("log", "").strip()
    if not log:
        return jsonify({"error": "log obrigatório"}), 400
    matches = sigma_engine.match(log)
    return jsonify({
        "log":          log[:200],
        "matches":      len(matches),
        "rules_matched": [{
            "id":          r.id,
            "title":       r.title,
            "level":       r.level,
            "description": r.description,
            "mitre_tactic": r.mitre_tactic,
            "mitre_technique": r.mitre_technique,
        } for r in matches],
    })

# ── Fail2Ban API ──────────────────────────────────────────────────

# ── Detection Engine API ──────────────────────────────────────────

# ── Threat Hunting API ────────────────────────────────────────────

@app.route("/api/hunt", methods=["POST"])
@auth
def hunt():
    if not HUNTER_AVAILABLE or not _threat_hunter:
        return jsonify({"error":"indisponível"}), 503
    data    = request.get_json(force=True) or {}
    query   = data.get("query","")
    limit   = min(int(data.get("limit",200)), 500)
    hours   = min(int(data.get("hours",24)), 168)
    host_id = data.get("host_id","")
    result  = _threat_hunter.hunt(query, limit=limit, hours=hours, host_id=host_id)
    return jsonify(result)

@app.route("/api/hunt/validate", methods=["POST"])
@auth
def hunt_validate():
    if not HUNTER_AVAILABLE or not _threat_hunter:
        return jsonify({"error":"indisponível"}), 503
    data  = request.get_json(force=True) or {}
    query = data.get("query","")
    return jsonify(_threat_hunter.validate(query))

@app.route("/api/hunt/suggestions")
@auth
def hunt_suggestions():
    if not HUNTER_AVAILABLE or not _threat_hunter:
        return jsonify({"suggestions":[]})
    return jsonify({"suggestions": _threat_hunter.suggest_queries()})

# ── Lateral Movement API ───────────────────────────────────────────

@app.route("/api/lateral/alerts")
@auth
def lateral_alerts():
    if not LATERAL_AVAILABLE or not _lateral_detector:
        return jsonify({"available":False,"alerts":[]})
    limit = int(request.args.get("limit",100))
    return jsonify({
        "available": True,
        "alerts":    _lateral_detector.get_alerts(limit),
        "stats":     _lateral_detector.stats(),
    })

@app.route("/api/lateral/demo", methods=["POST"])
@auth
def lateral_demo():
    if not LATERAL_AVAILABLE or not _lateral_detector:
        return jsonify({"error":"indisponível"}), 503
    alerts = _lateral_detector.inject_demo()
    return jsonify({"injected": len(alerts),
                    "alerts": [a.to_dict() for a in alerts]})

@app.route("/api/lateral/stats")
@auth
def lateral_stats():
    if not LATERAL_AVAILABLE or not _lateral_detector:
        return jsonify({"available":False})
    return jsonify(_lateral_detector.stats())

# ── YARA API ───────────────────────────────────────────────────────

@app.route("/api/yara/scan", methods=["POST"])
@auth
def yara_scan():
    if not YARA_AVAILABLE or not _yara_engine:
        return jsonify({"error":"indisponível"}), 503
    data    = request.get_json(force=True) or {}
    content = data.get("content","")
    context = data.get("context","api")
    if not content:
        return jsonify({"error":"content obrigatório"}), 400
    matches = _yara_engine.scan_string(content, context)
    return jsonify({
        "matches":     [m.to_dict() for m in matches],
        "match_count": len(matches),
        "scanned":     len(content),
    })

@app.route("/api/yara/scan-process", methods=["POST"])
@auth
def yara_scan_process():
    if not YARA_AVAILABLE or not _yara_engine:
        return jsonify({"error":"indisponível"}), 503
    proc = request.get_json(force=True) or {}
    matches = _yara_engine.scan_process(proc)
    return jsonify({
        "matches":     [m.to_dict() for m in matches],
        "match_count": len(matches),
        "process":     proc.get("name",""),
    })

@app.route("/api/yara/stats")
@auth
def yara_stats():
    if not YARA_AVAILABLE or not _yara_engine:
        return jsonify({"available":False})
    return jsonify(_yara_engine.stats())

# ── Agent Push API ────────────────────────────────────────────────

@app.route("/api/agent/push", methods=["POST"])
@auth
def agent_push():
    """Recebe snapshot de um agente distribuído."""
    try:
        data    = request.get_json(force=True)
        host_id = data.get("host_id","unknown")
        procs   = data.get("processes",[])
        conns   = data.get("connections",[])
        ports   = data.get("ports",[])

        # Feed SOC engine com dados do agente
        if DE_AVAILABLE and detection_engine:
            try:
                events = detection_engine.analyze(
                    processes=procs, ports=ports, connections=conns
                )
                if events and RISK_AVAILABLE and risk_engine:
                    for ev in events:
                        ed = ev.to_dict() if hasattr(ev,"to_dict") else dict(ev)
                        ed["host_id"] = host_id
                        risk_engine.ingest_event(ed)
            except Exception: pass

        # Feed ML baseline
        if ML_AVAILABLE and _ml_baseline:
            try:
                _ml_baseline.add_sample({"processes":procs,"connections":conns,"ports":ports})
            except Exception: pass

        logger.info("Agent push | host=%s | procs=%d conns=%d ports=%d",
                    host_id, len(procs), len(conns), len(ports))
        return jsonify({"status":"ok","host_id":host_id,"received":{
            "processes": len(procs), "connections": len(conns), "ports": len(ports)
        }})
    except Exception as e:
        logger.error("Agent push error: %s", e)
        return jsonify({"error":str(e)}), 400

@app.route("/api/agent/status")
@auth
def agent_status():
    """Lista agentes que fizeram push recentemente."""
    if not RISK_AVAILABLE or not risk_engine:
        return jsonify({"agents":[]})
    hosts = risk_engine.get_all_hosts()
    return jsonify({"agents": hosts, "total": len(hosts)})

# ── Auto Block API ─────────────────────────────────────────────────

@app.route("/api/autoblock/status")
@auth
def autoblock_status():
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"available":False}), 200
    return jsonify({**auto_block.stats(), "blocks": auto_block.get_blocks()})

@app.route("/api/autoblock/blocks")
@auth
def autoblock_blocks():
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"blocks":[]}), 200
    return jsonify({"blocks": auto_block.get_blocks(),
                    "history": auto_block.get_history(20)})

@app.route("/api/autoblock/block", methods=["POST"])
@auth
def autoblock_manual_block():
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"error":"indisponível"}), 503
    data  = request.get_json(force=True) or {}
    ip    = data.get("ip","")
    score = int(data.get("score",100))
    reason= data.get("reason","Manual block")
    if not ip:
        return jsonify({"error":"ip obrigatório"}), 400
    rec = auto_block.block(ip, score, reason)
    return jsonify({"status":"blocked","record": rec.to_dict() if rec else None})

@app.route("/api/autoblock/unblock/<ip>", methods=["POST"])
@auth
def autoblock_unblock(ip):
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"error":"indisponível"}), 503
    ok = auto_block.unblock(ip)
    return jsonify({"status":"unblocked" if ok else "error","ip":ip})

@app.route("/api/autoblock/config", methods=["POST"])
@auth
def autoblock_config():
    if not AUTOBLOCK_AVAILABLE:
        return jsonify({"error":"indisponível"}), 503
    data = request.get_json(force=True) or {}
    if "threshold" in data:
        auto_block.set_threshold(int(data["threshold"]))
    if "enabled" in data:
        auto_block.set_enabled(bool(data["enabled"]))
    return jsonify(auto_block.stats())

# ── ML Baseline API ───────────────────────────────────────────────

@app.route("/api/ml/stats")
@auth
def ml_stats():
    if not ML_AVAILABLE or not _ml_baseline:
        return jsonify({"available": False, "reason": "scikit-learn não instalado"}), 200
    return jsonify(_ml_baseline.stats())

@app.route("/api/ml/reset", methods=["POST"])
@auth
def ml_reset():
    if not ML_AVAILABLE or not _ml_baseline:
        return jsonify({"error": "indisponível"}), 503
    _ml_baseline.reset()
    return jsonify({"status": "reset", "message": "Baseline ML reiniciado"})

# ── VirusTotal API ─────────────────────────────────────────────────

@app.route("/api/vt/lookup/<file_hash>")
@auth
def vt_lookup(file_hash):
    if not VT_AVAILABLE or not _vt_client:
        return jsonify({"error": "indisponível"}), 503
    result = _vt_client.lookup_hash(file_hash)
    if not result:
        return jsonify({"error": "lookup falhou"}), 503
    return jsonify(result)

@app.route("/api/vt/stats")
@auth
def vt_stats():
    if not VT_AVAILABLE or not _vt_client:
        return jsonify({"available": False}), 200
    return jsonify(_vt_client.stats())

# ── Correlation Engine API ────────────────────────────────────────

@app.route("/api/correlation/alerts")
@auth
def correlation_alerts():
    if not CORR_AVAILABLE or not _corr_engine:
        return jsonify({"alerts": [], "error": "Correlation Engine indisponível"}), 200
    limit = int(request.args.get("limit", 100))
    return jsonify({
        "alerts": _corr_engine.get_alerts(limit),
        "stats":  _corr_engine.get_stats(),
    })

@app.route("/api/correlation/stats")
@auth
def correlation_stats():
    if not CORR_AVAILABLE or not _corr_engine:
        return jsonify({"error": "indisponível"}), 503
    return jsonify(_corr_engine.get_stats())

@app.route("/api/correlation/demo", methods=["POST"])
@auth
def correlation_demo():
    if not CORR_AVAILABLE or not _corr_engine:
        return jsonify({"error": "indisponível"}), 503
    alerts = _corr_engine.inject_demo()
    return jsonify({"triggered": len(alerts),
                    "alerts": [a.to_dict() for a in alerts]})

# ── Risk Score API ────────────────────────────────────────────────

@app.route("/api/risk/hosts")
@auth
def risk_hosts():
    if not RISK_AVAILABLE:
        return jsonify({"error": "Risk Engine indisponível"}), 503
    return jsonify({"hosts": risk_engine.get_all_hosts(),
                    "summary": risk_engine.get_summary()})

@app.route("/api/risk/host/<host_id>")
@auth
def risk_host(host_id):
    if not RISK_AVAILABLE:
        return jsonify({"error": "Risk Engine indisponível"}), 503
    data = risk_engine.get_host(host_id)
    if not data:
        return jsonify({"error": "Host não encontrado"}), 404
    return jsonify(data)

@app.route("/api/risk/report/<host_id>")
@auth
def risk_report(host_id):
    if not RISK_AVAILABLE:
        return jsonify({"error": "Risk Engine indisponível"}), 503
    return jsonify(risk_engine.generate_report(host_id))

@app.route("/api/risk/summary")
@auth
def risk_summary():
    if not RISK_AVAILABLE:
        return jsonify({"error": "Risk Engine indisponível"}), 503
    return jsonify(risk_engine.get_summary())

@app.route("/api/soc/events")
@auth
def soc_events():
    """Lista eventos do Detection Engine."""
    if not DE_AVAILABLE:
        return jsonify({"error": "Detection Engine indisponível"}), 503
    limit    = min(int(request.args.get("limit", 100)), 500)
    offset   = int(request.args.get("offset", 0))
    severity = request.args.get("severity")
    etype    = request.args.get("event_type")
    since    = request.args.get("since")
    events   = detection_engine.get_events(
        limit=limit, offset=offset,
        severity=severity, event_type=etype, since=since
    )
    return jsonify({"events": events, "total": len(events)})

@app.route("/api/soc/stats")
@auth
def soc_stats():
    """Estatísticas do Detection Engine."""
    if not DE_AVAILABLE:
        return jsonify({"error": "Detection Engine indisponível"}), 503
    return jsonify({**detection_engine.get_stats(), "available": True})

@app.route("/api/soc/analyze", methods=["POST"])
@auth
def soc_analyze_web():
    """Analisa payload web contra regras R10/R11/R12."""
    if not DE_AVAILABLE:
        return jsonify({"error": "Detection Engine indisponível"}), 503
    body       = request.get_json(force=True) or {}
    payload    = body.get("payload","")
    source_ip  = body.get("source_ip","")
    user_agent = body.get("user_agent","")
    events     = detection_engine.analyze_web_payload(
        payload=payload, source_ip=source_ip, user_agent=user_agent
    )
    return jsonify({
        "events_generated": len(events),
        "events": [e.to_dict() for e in events],
    })

@app.route("/api/fail2ban/status")
@auth
def f2b_status():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    return jsonify({**fail2ban.stats(), "available": True})

@app.route("/api/fail2ban/bans")
@auth
def f2b_bans():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    return jsonify({
        "bans":      fail2ban.get_active_bans(),
        "history":   fail2ban.get_history(limit=50),
        "timestamp": datetime.now().isoformat() + "Z",
    })

@app.route("/api/fail2ban/unban/<ip>", methods=["POST"])
@auth
def f2b_unban(ip):
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    ok = fail2ban.unban(ip, reason="manual_dashboard")
    return jsonify({"success": ok, "ip": ip})

@app.route("/api/fail2ban/ban", methods=["POST"])
@auth
def f2b_manual_ban():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    body = request.get_json(force=True) or {}
    ip   = body.get("ip","").strip()
    jail = body.get("jail","brute-force")
    if not ip:
        return jsonify({"error": "ip obrigatório"}), 400
    # Inject fake detections to trigger ban
    jail_cfg = F2B_JAILS.get(jail, {})
    for _ in range(jail_cfg.get("maxretry", 5)):
        fail2ban.ingest({
            "source_ip":   ip,
            "threat_name": jail_cfg.get("triggers",["Brute Force"])[0],
            "severity":    "high",
        })
    return jsonify({"success": True, "ip": ip, "jail": jail})

@app.route("/api/fail2ban/whitelist", methods=["GET"])
@auth
def f2b_whitelist_get():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    return jsonify({"whitelist": sorted(fail2ban.whitelist)})

@app.route("/api/fail2ban/whitelist", methods=["POST"])
@auth
def f2b_whitelist_add():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    body = request.get_json(force=True) or {}
    ip = body.get("ip","").strip()
    if ip:
        fail2ban.add_whitelist(ip)
    return jsonify({"success": True, "ip": ip})

@app.route("/api/fail2ban/whitelist/<ip>", methods=["DELETE"])
@auth
def f2b_whitelist_remove(ip):
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    fail2ban.remove_whitelist(ip)
    return jsonify({"success": True, "ip": ip})

@app.route("/api/fail2ban/toggle", methods=["POST"])
@auth
def f2b_toggle():
    if not F2B_AVAILABLE:
        return jsonify({"error": "Fail2Ban não disponível"}), 503
    body = request.get_json(force=True) or {}
    enabled = body.get("enabled", True)
    fail2ban.set_enabled(enabled)
    return jsonify({"success": True, "enabled": enabled})

@app.route("/api/killchain/incidents")
@auth
def kc_incidents():
    """Lista incidentes de Kill Chain ativos."""
    if not KC_AVAILABLE:
        return jsonify({"error": "Kill Chain não disponível"}), 503
    min_e = int(request.args.get("min_events", 2))
    return jsonify({
        "incidents":  kc_correlator.get_incidents(min_events=min_e),
        "stats":      kc_correlator.stats(),
        "timestamp":  datetime.now().isoformat() + "Z",
    })

@app.route("/api/killchain/report/<ip>")
@auth
def kc_report(ip):
    """Gera Incident Report completo para um IP."""
    if not KC_AVAILABLE:
        return jsonify({"error": "Kill Chain não disponível"}), 503
    report = kc_correlator.generate_report(ip)
    return jsonify(report)

@app.route("/api/killchain/stats")
@auth
def kc_stats():
    if not KC_AVAILABLE:
        return jsonify({"error": "Kill Chain não disponível"}), 503
    return jsonify({**kc_correlator.stats(), "available": True})

@app.route("/api/killchain/inject", methods=["POST"])
@auth
def kc_inject():
    """Injeta evento manual no correlador (para demo/teste)."""
    if not KC_AVAILABLE:
        return jsonify({"error": "Kill Chain não disponível"}), 503
    body = request.get_json(force=True) or {}
    kc_correlator.ingest({**body, "timestamp": datetime.now().isoformat()+"Z"})
    return jsonify({"ok": True})

@app.route("/api/owasp/stats")
@auth
def owasp_stats():
    if not OWASP_AVAILABLE:
        return jsonify({"error": "OWASP não disponível"}), 503
    return jsonify({**owasp_engine.stats(), "available": True})

@app.route("/api/owasp/analyze", methods=["POST"])
@auth
def owasp_analyze():
    if not OWASP_AVAILABLE:
        return jsonify({"error": "OWASP não disponível"}), 503
    body = request.get_json(force=True) or {}
    log  = body.get("log","").strip()
    hdrs = body.get("headers",{})
    if not log and not hdrs:
        return jsonify({"error": "log ou headers obrigatório"}), 400
    payload_matches = owasp_engine.analyze(log) if log else []
    header_matches  = owasp_engine.analyze_headers(hdrs) if hdrs else []
    all_m = payload_matches + header_matches
    return jsonify({
        "payload_matches": len(payload_matches),
        "header_matches":  len(header_matches),
        "total":           len(all_m),
        "results": [{
            "rule_id":     m.rule_id,
            "category":    m.category,
            "owasp_ref":   m.owasp_ref,
            "title":       m.title,
            "severity":    m.severity,
            "evidence":    m.evidence,
            "cwe":         m.cwe,
            "remediation": m.remediation,
        } for m in all_m],
    })

@app.route("/api/owasp/payloads")
@auth
def owasp_payloads():
    """Retorna payloads do OWASP Testing Guide."""
    return jsonify({
        "attack_types": list(TESTING_PAYLOADS.keys()),
        "payloads":     TESTING_PAYLOADS,
        "total":        sum(len(v) for v in TESTING_PAYLOADS.values()),
    })

@app.route("/api/feeds/stats")
@auth
def feeds_stats():
    """Status dos threat feeds."""
    if not FEEDS_AVAILABLE:
        return jsonify({"available": False})
    s = feed_stats()
    s["available"] = True
    s["abuseipdb_key_set"] = bool(os.environ.get("IDS_ABUSEIPDB_KEY"))
    return jsonify(s)

@app.route("/api/geo")
@auth
def geo_ips():
    """Retorna geolocalização dos IPs externos ativos."""
    try:
        from geo_ip import lookup
    except ImportError:
        return jsonify({"error": "geo_ip module not found"}), 500

    seen = {}
    # Fetch live connections directly
    live_conns = []
    try:
        r = subprocess.run(["netstat","-n","-o"],capture_output=True,text=True,timeout=8)
        for linha in r.stdout.strip().split("\n"):
            if "ESTABLISHED" not in linha: continue
            p = linha.split()
            if len(p) < 5: continue
            end = p[2]
            if ":" not in end: continue
            idx = end.rfind(":")
            ip2 = end[:idx].strip("[]")
            try: porta2 = int(end[idx+1:])
            except: continue
            proc2 = get_pid_name_cached(p[4]) or f"pid:{p[4]}"
            live_conns.append({"ip": ip2, "port": porta2, "process": proc2})
    except Exception:
        pass

    for conn in live_conns:
        ip = conn["ip"]
        if not ip or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            continue
        if ip not in seen:
            geo = lookup(ip)
            if not geo.get("private"):
                seen[ip] = {
                    "ip":      ip,
                    "country": geo["country"],
                    "city":    geo["city"],
                    "lat":     geo["lat"],
                    "lon":     geo["lon"],
                    "flag":    geo["flag"],
                    "org":     geo["org"],
                    "process": conn["process"],
                    "port":    conn["port"],
                    "hostname": resolve_ip(ip),
                }

    # Also include IPs from detections
    for det in ids.get_detections(limit=100):
        ip = det.get("source_ip","")
        if ip and not ip.startswith("127.") and not ip.startswith("192.168.") and ip not in seen:
            geo = lookup(ip)
            if not geo.get("private"):
                seen[ip] = {
                    "ip":      ip,
                    "country": geo["country"],
                    "city":    geo["city"],
                    "lat":     geo["lat"],
                    "lon":     geo["lon"],
                    "flag":    geo["flag"],
                    "org":     geo["org"],
                    "process": "detection",
                    "threat":  det.get("threat_name",""),
                    "severity": det.get("severity",""),
                    "port":    0,
                    "hostname": ip,
                }

    return jsonify({
        "points":    list(seen.values()),
        "total":     len(seen),
        "timestamp": datetime.now().isoformat() + "Z",
    })


@app.route("/")
@app.route("/dashboard")
def dashboard():
    p = pathlib.Path(__file__).parent/"dashboard.html"
    if not p.exists(): return "dashboard.html nao encontrado",404
    return p.read_text(encoding="utf-8"),200,{"Content-Type":"text/html;charset=utf-8"}

# ── Inicialização ─────────────────────────────────────────────────
def iniciar_monitoramento():
    threading.Thread(target=loop_monitor, kwargs={"intervalo":30},
                     daemon=True, name="ids-monitor").start()
    try:
        from packet_capture import PacketCapture, detectar_interface_ativa
        interface = detectar_interface_ativa()
        capture   = PacketCapture(callback=analisar, interface=interface)
        capture.iniciar()
        monitor_status["captura"] = f"ativa | interface={interface}"
        logger.info("Captura de pacotes iniciada | interface=%s", interface)
    except Exception as e:
        monitor_status["captura"] = f"indisponivel: {e}"
        logger.warning("Captura de pacotes indisponivel: %s", e)

iniciar_monitoramento()

if __name__=="__main__":
    host     = os.environ.get("IDS_HOST","127.0.0.1")
    port     = int(os.environ.get("IDS_PORT",5000))
    debug    = os.environ.get("IDS_DEBUG","false").lower()=="true"
    ssl_ctx  = get_ssl_context()
    print_startup_info()
    if ssl_ctx:
        app.run(host=host, port=HTTPS_PORT, debug=debug,
                use_reloader=False, ssl_context=ssl_ctx)
    else:
        app.run(host=host, port=port, debug=debug, use_reloader=False)
