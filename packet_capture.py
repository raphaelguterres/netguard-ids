"""
NetGuard Packet Capture v1.0
Captura pacotes reais da interface Ethernet em tempo real.
Detecta: SYN flood, port scan, ARP spoofing, DNS poisoning,
         payloads suspeitos em HTTP, conexões para C2.
Integra diretamente com o IDSEngine.
"""

import threading
import time
import logging
from collections import defaultdict, deque
from datetime import datetime
from typing import Callable, Dict, List

logger = logging.getLogger("ids.capture")

# ── Interface de rede ─────────────────────────────────────────────
# Detectada automaticamente — Ethernet 192.168.15.2
INTERFACE = "Ethernet"

# ── Limiares de detecção ──────────────────────────────────────────
SYN_FLOOD_LIMITE    = 50    # SYNs do mesmo IP em 10s
PORT_SCAN_LIMITE    = 15    # portas diferentes em 10s
ARP_SPOOF_LIMITE    = 10    # respostas ARP do mesmo IP em 5s
DNS_QUERY_LIMITE    = 50    # queries DNS do mesmo IP em 10s

# Portas que nunca devem receber conexões de fora
PORTAS_CRITICAS = {22, 23, 3389, 445, 135, 139, 5985, 5986}

# ── Contadores por janela de tempo ────────────────────────────────

class JanelaTempo:
    """Contador deslizante thread-safe."""
    def __init__(self, janela_s: int):
        self.janela = janela_s
        self._data: Dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def adicionar(self, chave: str) -> int:
        agora = time.time()
        with self._lock:
            dq = self._data[chave]
            dq.append(agora)
            limite = agora - self.janela
            while dq and dq[0] < limite:
                dq.popleft()
            return len(dq)

    def contar(self, chave: str) -> int:
        agora = time.time()
        with self._lock:
            dq = self._data[chave]
            limite = agora - self.janela
            while dq and dq[0] < limite:
                dq.popleft()
            return len(dq)

    def resetar(self, chave: str):
        with self._lock:
            self._data.pop(chave, None)


# ── Engine de captura ─────────────────────────────────────────────

class PacketCapture:
    """
    Captura e analisa pacotes em tempo real.
    Chama callback(log, ip, field) quando detecta algo suspeito.
    """

    def __init__(self, callback: Callable, interface: str = INTERFACE):
        self.callback      = callback
        self.interface     = interface
        self.rodando       = False
        self._thread       = None
        # IP da interface local — pacotes originados aqui não geram alertas
        self._interface_ip      = self._get_local_ip()
        self._pacotes_capturados = 0
        self._alertas_gerados    = 0

    def _get_local_ip(self) -> str:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "192.168.15.2"  # fallback

        # Contadores
        self._syn_counter  = JanelaTempo(10)   # SYN flood
        self._port_counter = JanelaTempo(10)   # port scan
        self._arp_counter  = JanelaTempo(5)    # ARP spoof
        self._dns_counter  = JanelaTempo(10)   # DNS flood

        # Rastreia portas por IP (para detectar scan)
        self._portas_por_ip: Dict[str, set] = defaultdict(set)
        self._portas_lock   = threading.Lock()

        # ARP table legítima (IP -> MAC conhecido)
        self._arp_table: Dict[str, str] = {}
        self._arp_lock  = threading.Lock()

        # Alertas já enviados (evita spam)
        self._alertados: set = set()

        # Estatísticas
        self.stats = {
            "pacotes_capturados": 0,
            "alertas_gerados":    0,
            "iniciado_em":        None,
        }

    def stats(self) -> dict:
        """Retorna estatísticas da captura de pacotes."""
        return {
            "rodando":    self.rodando,
            "interface":  self.interface,
            "iniciado_em":        getattr(self,"_started_at",""),
            "pacotes_capturados": self._pacotes_capturados,
            "alertas_gerados":    self._alertas_gerados,
            "local_ip":   self._interface_ip,
            "syn_tracked":   len(self._conn_times._data) if hasattr(self._syn_counter, '_data') else 0,
            "port_tracked":  len(self._portas_por_ip),
        }

    def iniciar(self):
        if self.rodando:
            return
        self.rodando = True
        self._started_at = datetime.now().isoformat()
        self._thread = threading.Thread(
            target=self._capturar,
            daemon=True,
            name="netguard-capture"
        )
        self._thread.start()
        logger.info("Captura de pacotes iniciada | interface=%s", self.interface)

    def parar(self):
        self.rodando = False
        logger.info("Captura de pacotes encerrada | stats=%s", self.stats)

    def _capturar(self):
        try:
            from scapy.all import sniff, conf
            conf.verb = 0  # sem output do scapy

            sniff(
                iface=self.interface,
                prn=self._analisar_pacote,
                store=False,
                stop_filter=lambda _: not self.rodando,
            )
        except ImportError:
            logger.error("scapy não instalado — pip install scapy")
        except Exception as e:
            logger.error("Erro na captura: %s", e)

    def _analisar_pacote(self, pkt):
        """Analisa cada pacote capturado."""
        self._pacotes_capturados += 1

        try:
            from scapy.all import IP, TCP, UDP, ARP, DNS, Raw, ICMP

            # ── ARP Spoofing ──────────────────────────────────────
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
                self._checar_arp(pkt)

            if not pkt.haslayer(IP):
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Ignora loopback e broadcast
            if src_ip.startswith("127.") or src_ip == "0.0.0.0":
                return
            if dst_ip.endswith(".255") or dst_ip == "255.255.255.255":
                return

            # ── TCP ───────────────────────────────────────────────
            if pkt.haslayer(TCP):
                self._checar_tcp(pkt, src_ip, dst_ip)

            # ── UDP / DNS ─────────────────────────────────────────
            if pkt.haslayer(UDP):
                self._checar_udp(pkt, src_ip, dst_ip)

            # ── ICMP flood ────────────────────────────────────────
            if pkt.haslayer(ICMP):
                self._checar_icmp(pkt, src_ip)

            # ── Payload HTTP suspeito ─────────────────────────────
            if pkt.haslayer(Raw):
                self._checar_payload(pkt, src_ip)

        except Exception:
            pass  # nunca quebra a captura por erro de análise

    def _checar_arp(self, pkt):
        """Detecta ARP Spoofing — IP diferente com MAC diferente do conhecido."""
        from scapy.all import ARP
        ip_anunciado  = pkt[ARP].psrc
        mac_anunciado = pkt[ARP].hwsrc

        with self._arp_lock:
            mac_conhecido = self._arp_table.get(ip_anunciado)
            if mac_conhecido is None:
                # Primeira vez vendo esse IP — registra
                self._arp_table[ip_anunciado] = mac_anunciado
                return
            if mac_conhecido != mac_anunciado:
                # MAC mudou — possível ARP spoof
                chave = f"arp:{ip_anunciado}"
                if chave not in self._alertados:
                    self._alertados.add(chave)
                    self._alertar(
                        f"ARP SPOOFING DETECTED: IP={ip_anunciado} "
                        f"MAC_KNOWN={mac_conhecido} MAC_NEW={mac_anunciado}",
                        ip_anunciado, "firewall",
                        "CRITICO: possível ataque Man-in-the-Middle via ARP"
                    )

    def _checar_tcp(self, pkt, src_ip, dst_ip):
        from scapy.all import TCP
        flags     = pkt[TCP].flags
        dst_port  = pkt[TCP].dport
        src_port  = pkt[TCP].sport

        # ── SYN Flood ─────────────────────────────────────────────
        if flags == 0x02:  # SYN puro (sem ACK)
            count = self._syn_counter.adicionar(src_ip)
            if count == SYN_FLOOD_LIMITE:
                self._alertar(
                    f"SYN FLOOD DETECTED SRC={src_ip} DST={dst_ip} "
                    f"count={count} in 10s",
                    src_ip, "firewall",
                    f"SYN flood: {count} SYNs em 10s"
                )

        # ── Port Scan ─────────────────────────────────────────────
        if flags in (0x02, 0x00, 0x01):  # SYN, NULL, FIN scan
            # Ignora scan originado da própria máquina (enriquecimento de dispositivos)
            if src_ip == self._interface_ip or dst_ip.startswith("192.168."):
                return
            with self._portas_lock:
                self._portas_por_ip[src_ip].add(dst_port)
                n_portas = len(self._portas_por_ip[src_ip])

            self._port_counter.adicionar(f"{src_ip}:scan")
            if n_portas == PORT_SCAN_LIMITE:
                self._alertar(
                    f"PORT SCAN DETECTED SRC={src_ip} ports_scanned={n_portas}",
                    src_ip, "firewall",
                    f"Port scan: {n_portas} portas em 10s"
                )
                # Reseta para não repetir
                with self._portas_lock:
                    self._portas_por_ip[src_ip].clear()

        # ── Acesso a porta crítica de fora da rede ────────────────
        if dst_port in PORTAS_CRITICAS and not src_ip.startswith("192.168.15."):
            chave = f"crit:{src_ip}:{dst_port}"
            if chave not in self._alertados:
                self._alertados.add(chave)
                servicos = {
                    22:"SSH", 23:"Telnet", 3389:"RDP",
                    445:"SMB", 135:"RPC", 139:"NetBIOS",
                    5985:"WinRM", 5986:"WinRM-HTTPS"
                }
                srv = servicos.get(dst_port, str(dst_port))
                self._alertar(
                    f"EXTERNAL ACCESS TO {srv} SRC={src_ip} DST={dst_ip}:{dst_port}",
                    src_ip, "firewall",
                    f"Acesso externo à porta {srv} ({dst_port})"
                )

    def _checar_udp(self, pkt, src_ip, dst_ip):
        from scapy.all import UDP, DNS, DNSQR

        # ── DNS Tunneling / exfiltração via DNS ───────────────────
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
            count = self._dns_counter.adicionar(src_ip)
            if count == DNS_QUERY_LIMITE:
                self._alertar(
                    f"DNS FLOOD/TUNNELING SRC={src_ip} queries={count} in 10s",
                    src_ip, "firewall",
                    f"Possível DNS tunneling: {count} queries em 10s"
                )

            # Query para domínio suspeito (DGA — Domain Generation Algorithm)
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                partes = qname.split(".")

                # Whitelist de domínios legítimos com subdomínios longos
                DOMINIOS_LEGITIMOS = [
                    "datadoghq.com", "datadog.com",
                    "amazonaws.com", "cloudfront.net",
                    "azure.com", "azureedge.net", "microsoft.com",
                    "google.com", "googleapis.com", "gstatic.com",
                    "cloudflare.com", "cloudflare-dns.com",
                    "akamaiedge.net", "akamai.net", "akadns.net",
                    "fastly.net", "fastlylb.net",
                    "windows.com", "windowsupdate.com", "live.com",
                    "office.com", "office365.com", "sharepoint.com",
                    "apple.com", "icloud.com", "cdn-apple.com",
                    "facebook.com", "fbcdn.net", "instagram.com",
                    "whatsapp.com", "whatsapp.net",
                    "discord.com", "discordapp.com",
                    "spotify.com", "scdn.co",
                    "github.com", "githubusercontent.com",
                    "newrelic.com", "nr-data.net",
                    "sentry.io", "sentry-cdn.com",
                    "segment.com", "segment.io",
                    "intercom.io", "intercomcdn.com",
                    "hotjar.com", "hotjar.io",
                    "mixpanel.com", "amplitude.com",
                    "twilio.com", "sendgrid.net",
                    "zendesk.com", "zdassets.com",
                ]

                # Verifica se pertence a domínio legítimo
                legitimo = any(qname.endswith(d) for d in DOMINIOS_LEGITIMOS)

                # mDNS / Bonjour — domínio .local é sempre rede local
                if qname.endswith('.local'):
                    legitimo = True

                # UUIDs gerados automaticamente (ex: mDNS device discovery)
                import re as _re
                if _re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', partes[0] if partes else ''):
                    legitimo = True

                # Google Cast / Chromecast (_googlecast._tcp)
                if '_googlecast' in qname or '_tcp' in qname or '_udp' in qname:
                    legitimo = True

                # Protocolos de descoberta de rede (mDNS service types)
                if any(x in qname for x in ['_http','_https','_ssh','_smb','_ftp','_nfs','_afp','_airplay']):
                    legitimo = True

                # Domínios DGA: subdomínio longo e aleatório (>20 chars)
                if partes and len(partes[0]) > 20 and not legitimo:
                    chave = f"dga:{src_ip}:{qname[:30]}"
                    if chave not in self._alertados:
                        self._alertados.add(chave)
                        self._alertar(
                            f"POSSIBLE DGA/DNS TUNNELING SRC={src_ip} "
                            f"query={qname[:60]}",
                            src_ip, "firewall",
                            f"Domínio suspeito (possível DGA/C2): {qname[:60]}"
                        )

    def _checar_icmp(self, pkt, src_ip):
        from scapy.all import ICMP
        # ICMP flood simples
        count = self._syn_counter.adicionar(f"icmp:{src_ip}")
        if count == 100:
            self._alertar(
                f"ICMP FLOOD DETECTED SRC={src_ip} count={count} in 10s",
                src_ip, "firewall",
                f"ICMP flood: {count} pings em 10s"
            )

    def _checar_payload(self, pkt, src_ip):
        """Analisa payload TCP/UDP procurando padrões de ataque em texto."""
        from scapy.all import Raw
        import re

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            return

        if len(payload) < 10:
            return

        # Padrões suspeitos no payload
        padroes = [
            (r"union\s+select\s+null",          "SQL Injection no payload"),
            (r"<script[^>]*>.*?alert",           "XSS no payload"),
            (r"/etc/passwd|/etc/shadow",         "LFI — acesso a arquivo do sistema"),
            (r"bash\s+-i.*?/dev/tcp",            "Reverse shell no payload"),
            (r"cmd\.exe|powershell\.exe\s+-enc", "Execução de shell Windows"),
            (r"METERPRETER|meterpreter",         "Meterpreter detectado"),
        ]

        for padrao, descricao in padroes:
            if re.search(padrao, payload, re.IGNORECASE):
                chave = f"payload:{src_ip}:{padrao[:20]}"
                if chave not in self._alertados:
                    self._alertados.add(chave)
                    self._alertar(
                        f"MALICIOUS PAYLOAD SRC={src_ip} type={descricao} "
                        f"data={payload[:100]}",
                        src_ip, "url",
                        descricao
                    )
                break

    def _alertar(self, log: str, ip: str, field: str, origem: str = ""):
        """Envia alerta para o callback (IDSEngine)."""
        self._alertas_gerados += 1
        logger.warning("PACKET | %s | ip=%s | %s", origem, ip, log[:80])
        try:
            self.callback(log, ip, field)
        except Exception as e:
            logger.error("Erro no callback: %s", e)
        # Feed terminal ao vivo
        try:
            import app as _app
            _app.log_ao_vivo({
                "type": "packet",
                "msg":  origem or log[:60],
                "ip":   ip,
            })
        except Exception:
            pass


# ── Detecção automática de interface ─────────────────────────────

def detectar_interface_ativa() -> str:
    """
    Detecta a interface de rede principal — ignora VirtualBox,
    VMware e outros adaptadores virtuais.
    """
    VIRTUAL = ["virtualbox","vmware","vethernet","loopback",
               "pseudo","wan miniport","bluetooth"]
    try:
        from scapy.all import ifaces
        candidatas = []
        for iface in ifaces.values():
            ip   = getattr(iface, 'ip', '') or ''
            nome = (iface.name or '').lower()
            desc = (iface.description or '').lower()
            # Ignora virtuais
            if any(v in desc or v in nome for v in VIRTUAL):
                continue
            # Só IPs privados reais
            if ip and (ip.startswith("192.168.") or ip.startswith("10.")
                       or ip.startswith("172.")):
                candidatas.append((iface.name, ip, desc))

        if candidatas:
            # Prefere "Ethernet" ou "Wi-Fi" sobre outros
            for nome, ip, desc in candidatas:
                if "ethernet" in nome.lower() or "wi-fi" in nome.lower():
                    logger.info("Interface detectada: %s (%s)", nome, ip)
                    return nome
            # Fallback: primeira candidata
            nome, ip, _ = candidatas[0]
            logger.info("Interface detectada: %s (%s)", nome, ip)
            return nome
    except Exception as e:
        logger.warning("Erro ao detectar interface: %s", e)
    return INTERFACE  # fallback
