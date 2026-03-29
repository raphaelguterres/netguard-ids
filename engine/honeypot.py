"""
NetGuard — Honeypot Inteligente
Abre portas falsas e captura fingerprint de atacantes.

Portas monitoradas:
  - 22   (SSH)
  - 23   (Telnet)
  - 445  (SMB)
  - 1433 (MSSQL)
  - 3306 (MySQL)
  - 3389 (RDP)
  - 5900 (VNC)
  - 8080 (HTTP alt)

Para cada conexão captura:
  - IP + porta de origem
  - Banner / payload enviado pelo atacante
  - Fingerprint TCP (TTL, janela TCP)
  - Timestamp preciso
  - Geolocalização aproximada
  - Tentativa de credencial (se SSH/Telnet)
"""

import socket
import threading
import logging
import time
import re
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Dict, Optional

logger = logging.getLogger("netguard.honeypot")

# ── Banners que o honeypot apresenta ─────────────────────────────
BANNERS = {
    22:   b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    23:   b"\xff\xfd\x18\xff\xfd \xff\xfd#\xff\xfd'\r\nLogin: ",
    445:  b"\x00\x00\x00\x54\xff\x53\x4d\x42",   # SMB negotiate
    1433: b"\x04\x01\x00\x25\x00\x00\x01\x00",   # MSSQL prelogin
    3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30",   # MySQL greeting
    3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00",   # RDP cookie
    5900: b"RFB 003.008\n",                        # VNC
    8080: b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"NetGuard\"\r\nContent-Length: 0\r\n\r\n",
}

SERVICE_NAMES = {
    22: "SSH", 23: "Telnet", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5900: "VNC", 8080: "HTTP",
}

# Default ports to open (can be overridden)
DEFAULT_PORTS = [22, 23, 445, 3306, 3389, 5900]

class HoneypotCapture:
    """Represents a single attacker interaction."""
    def __init__(self, ip: str, src_port: int, dst_port: int,
                 service: str, payload: bytes, banner_sent: bytes):
        self.id = f"HP_{int(time.time()*1000)}"
        self.ip = ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.service = service
        self.payload = payload
        self.banner_sent = banner_sent
        self.timestamp = datetime.now(timezone.utc).isoformat()

        # Analyze payload
        self.credentials = self._extract_credentials()
        self.user_agent = self._extract_user_agent()
        self.fingerprint = self._fingerprint()
        self.tags = self._classify()

    def _extract_credentials(self) -> Optional[Dict]:
        """Try to extract username/password from payload."""
        try:
            text = self.payload.decode("utf-8", errors="replace")
            # SSH username pattern
            if self.service == "SSH":
                m = re.search(r'user[name]*[:\s]+([^\s\x00-\x1f]+)', text, re.IGNORECASE)
                if m:
                    return {"username": m.group(1)[:64]}
            # HTTP Basic Auth
            if self.service == "HTTP":
                m = re.search(r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', text)
                if m:
                    import base64
                    try:
                        decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                        if ":" in decoded:
                            u, p = decoded.split(":", 1)
                            return {"username": u[:64], "password": p[:64]}
                    except Exception:
                        pass
            # Plain text user:pass patterns
            m = re.search(r'(?:user|login|username)[:\s]+([^\s\x00-\x1f]{1,32})', text, re.IGNORECASE)
            if m:
                return {"username": m.group(1)}
        except Exception:
            pass
        return None

    def _extract_user_agent(self) -> str:
        try:
            text = self.payload.decode("utf-8", errors="replace")
            m = re.search(r'User-Agent:\s*([^\r\n]+)', text, re.IGNORECASE)
            return m.group(1)[:200] if m else ""
        except Exception:
            return ""

    def _fingerprint(self) -> Dict:
        """Generate fingerprint of attacker from payload characteristics."""
        fp = {"payload_len": len(self.payload), "has_payload": len(self.payload) > 0}
        # Check for known scanner signatures
        try:
            text = self.payload.decode("utf-8", errors="replace").lower()
            if "masscan" in text:      fp["scanner"] = "Masscan"
            elif "nmap" in text:       fp["scanner"] = "Nmap"
            elif "zgrab" in text:      fp["scanner"] = "ZGrab"
            elif "shodan" in text:     fp["scanner"] = "Shodan"
            elif "censys" in text:     fp["scanner"] = "Censys"
            elif "python" in text:     fp["scanner"] = "Python script"
            elif "curl" in text:       fp["scanner"] = "curl"
            elif "wget" in text:       fp["scanner"] = "wget"
            # RDP specific
            if self.service == "RDP" and len(self.payload) > 0:
                fp["rdp_cookie"] = self.payload[:20].hex()
            # SSH specific
            if self.service == "SSH" and b"SSH-" in self.payload:
                m = re.search(rb'SSH-[\d.]+-([^\r\n]+)', self.payload)
                if m: fp["ssh_client"] = m.group(1).decode("utf-8", errors="replace")[:80]
        except Exception:
            pass
        return fp

    def _classify(self) -> List[str]:
        tags = []
        if self.credentials:
            tags.append("credential-theft")
        if self.fingerprint.get("scanner"):
            tags.append("port-scanner")
            tags.append(self.fingerprint["scanner"].lower().replace(" ", "-"))
        if self.service in ("RDP", "SSH"):
            tags.append("brute-force-attempt")
        if self.service == "SMB":
            tags.append("smb-probe")
        if len(self.payload) == 0:
            tags.append("syn-scan")
        return tags

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "ip": self.ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "service": self.service,
            "payload_hex": self.payload[:64].hex(),
            "payload_preview": self.payload[:64].decode("utf-8", errors="replace"),
            "credentials": self.credentials,
            "user_agent": self.user_agent,
            "fingerprint": self.fingerprint,
            "tags": self.tags,
            "timestamp": self.timestamp,
            "severity": "CRITICAL" if self.credentials else "HIGH",
        }


class PortListener(threading.Thread):
    """Listens on a single port and captures connections."""

    def __init__(self, port: int, captures: List, lock: threading.RLock,
                 stats: Dict, on_capture=None):
        super().__init__(daemon=True, name=f"honeypot-{port}")
        self.port = port
        self.service = SERVICE_NAMES.get(port, f"PORT{port}")
        self.captures = captures
        self.lock = lock
        self.stats = stats
        self.on_capture = on_capture
        self._running = False
        self._sock = None
        self.active = False

    def run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.port))
            self._sock.listen(5)
            self._sock.settimeout(1.0)
            self._running = True
            self.active = True
            logger.info("Honeypot | port=%d | service=%s | LISTENING", self.port, self.service)

            while self._running:
                try:
                    conn, addr = self._sock.accept()
                    threading.Thread(
                        target=self._handle,
                        args=(conn, addr),
                        daemon=True,
                    ).start()
                except socket.timeout:
                    continue
                except Exception:
                    break
        except OSError as e:
            logger.warning("Honeypot | port=%d | bind failed: %s", self.port, e)
            self.active = False

    def _handle(self, conn: socket.socket, addr):
        ip, src_port = addr
        try:
            conn.settimeout(3.0)
            # Send banner
            banner = BANNERS.get(self.port, b"")
            if banner:
                try: conn.sendall(banner)
                except Exception: pass
            # Receive attacker payload
            payload = b""
            try:
                payload = conn.recv(1024)
            except Exception:
                pass
            conn.close()

            cap = HoneypotCapture(
                ip=ip, src_port=src_port, dst_port=self.port,
                service=self.service, payload=payload, banner_sent=banner,
            )
            with self.lock:
                self.captures.append(cap.to_dict())
                self.captures[:] = self.captures[-1000:]
                self.stats["total_hits"] += 1
                self.stats["by_service"][self.service] = \
                    self.stats["by_service"].get(self.service, 0) + 1
                self.stats["by_ip"][ip] = self.stats["by_ip"].get(ip, 0) + 1

            severity = "CRITICAL" if cap.credentials else "HIGH"
            logger.warning(
                "HONEYPOT | %s | port=%d | src=%s:%d | tags=%s",
                severity, self.port, ip, src_port, cap.tags,
            )
            if self.on_capture:
                self.on_capture(cap.to_dict())

        except Exception as e:
            logger.debug("Honeypot handle error port=%d: %s", self.port, e)

    def stop(self):
        self._running = False
        self.active = False
        if self._sock:
            try: self._sock.close()
            except Exception: pass


class Honeypot:
    """
    Main honeypot manager. Opens multiple ports and aggregates captures.
    """

    def __init__(self, ports: List[int] = None, on_capture=None):
        self._ports = ports or DEFAULT_PORTS
        self._captures: List[dict] = []
        self._lock = threading.RLock()
        self._listeners: Dict[int, PortListener] = {}
        self._on_capture = on_capture
        self._stats = {
            "total_hits": 0,
            "by_service": {},
            "by_ip": {},
            "active_ports": [],
            "failed_ports": [],
        }

    def start(self, ports: List[int] = None):
        target_ports = ports or self._ports
        for port in target_ports:
            if port in self._listeners:
                continue
            listener = PortListener(
                port=port,
                captures=self._captures,
                lock=self._lock,
                stats=self._stats,
                on_capture=self._on_capture,
            )
            self._listeners[port] = listener
            listener.start()
            time.sleep(0.05)

        # Wait briefly to see which ports bound successfully
        time.sleep(0.5)
        with self._lock:
            self._stats["active_ports"] = [
                p for p, l in self._listeners.items() if l.active
            ]
            self._stats["failed_ports"] = [
                p for p, l in self._listeners.items() if not l.active
            ]

        logger.info(
            "Honeypot | active=%s | failed=%s",
            self._stats["active_ports"],
            self._stats["failed_ports"],
        )

    def stop(self):
        for listener in self._listeners.values():
            listener.stop()
        self._listeners.clear()

    def get_captures(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return list(reversed(self._captures[-limit:]))

    def stats(self) -> dict:
        with self._lock:
            top_ips = sorted(
                self._stats["by_ip"].items(),
                key=lambda x: x[1], reverse=True
            )[:10]
            return {
                "total_hits": self._stats["total_hits"],
                "by_service": dict(self._stats["by_service"]),
                "top_attackers": [{"ip": ip, "hits": n} for ip, n in top_ips],
                "active_ports": self._stats["active_ports"],
                "failed_ports": self._stats["failed_ports"],
            }

    def inject_demo(self) -> List[dict]:
        """Inject demo captures for testing."""
        import random
        scenarios = [
            ("45.33.32.156",  22,  22,  "SSH",    b"SSH-2.0-libssh_0.9.6\r\nuser: root\r\n"),
            ("185.220.101.45", 54321, 3389, "RDP", b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34Cookie: mstshash=admin"),
            ("198.199.10.1",  60001, 445, "SMB",   b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72"),
            ("23.129.64.190",  41234, 22, "SSH",   b"SSH-2.0-Masscan\r\n"),
            ("192.241.200.18", 55123, 3306, "MySQL", b"\x00\x00\x00\x00root\x00"),
        ]
        results = []
        for ip, sp, dp, svc, payload in scenarios:
            cap = HoneypotCapture(ip, sp, dp, svc, payload, BANNERS.get(dp, b""))
            d = cap.to_dict()
            with self._lock:
                self._captures.append(d)
                self._stats["total_hits"] += 1
                self._stats["by_service"][svc] = self._stats["by_service"].get(svc, 0) + 1
                self._stats["by_ip"][ip] = self._stats["by_ip"].get(ip, 0) + 1
            results.append(d)
        return results
