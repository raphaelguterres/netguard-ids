"""
NetGuard Threat Intelligence v1.0 — Local Edition
Sem dependência de API externa. Usa:
  1. Base de IPs maliciosos conhecidos (embutida)
  2. Análise de reputação por ASN/ranges conhecidos
  3. Detecção de Tor exit nodes (lista pública offline)
  4. Análise heurística de comportamento
"""

import re
import ipaddress
import logging
from typing import Dict, Optional

logger = logging.getLogger("ids.intel")

# ── Base local de ranges maliciosos conhecidos ───────────────────
# Ranges de ASNs e blocos frequentemente associados a ataques,
# botnets, scanners e infraestrutura de C2.
# Atualizado manualmente — pode ser expandido.

RANGES_MALICIOSOS = [
    # Shodan scanners conhecidos
    "66.240.192.0/24",   # Shodan
    "66.240.205.0/24",   # Shodan
    "66.240.219.0/24",   # Shodan
    "82.221.105.0/24",   # Shodan
    "198.20.69.0/24",    # Shodan
    "198.20.70.0/24",    # Shodan
    "198.20.99.0/24",    # Shodan

    # Censys scanners
    "162.142.125.0/24",  # Censys
    "167.94.138.0/24",   # Censys
    "167.94.145.0/24",   # Censys
    "167.94.146.0/24",   # Censys

    # GreyNoise / scanners conhecidos
    "45.83.64.0/21",

    # Ranges de botnets conhecidos (atualize conforme necessário)
    "185.220.100.0/22",  # Tor / infraestrutura anônima
    "185.220.101.0/24",
    "185.220.102.0/23",
]

# ── Padrões de IP suspeito por características ───────────────────

# ASNs conhecidos por hospedar infraestrutura maliciosa
# (mapeamento simplificado por range de IP)
HOSTING_SUSPEITO = [
    "167.94.",   # Censys
    "162.142.",  # Censys
    "66.240.",   # Shodan
    "198.20.",   # Shodan
    "82.221.",   # Shodan
    "185.220.",  # Tor / anon infra
    "193.32.1",  # scanner infra
    "89.248.",   # Botnet / scanner
    "92.118.",   # Botnet infra
]

# IPs individuais com histórico de ataque (adicione conforme detectar)
IPS_MALICIOSOS_CONHECIDOS = {
    "80.82.77.33":   "Shodan scanner",
    "80.82.77.139":  "Shodan scanner",
    "85.25.43.94":   "Scanner automático",
    "85.25.103.50":  "Scanner automático",
    "185.244.25.235":"Botnet node",
    "193.32.160.143":"Mass scanner",
}


# ── Classificação de IPs privados ────────────────────────────────

RANGES_PRIVADOS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in RANGES_PRIVADOS)
    except Exception:
        return False


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except Exception:
        return False


# ── Engine de reputação ──────────────────────────────────────────

class ThreatIntel:
    """
    Analisa reputação de IPs usando base local.
    Retorna score 0-100 (100 = certamente malicioso).
    """

    def __init__(self):
        # Compila ranges maliciosos para lookup rápido
        self._redes = []
        for r in RANGES_MALICIOSOS:
            try:
                self._redes.append(ipaddress.ip_network(r, strict=False))
            except Exception:
                pass

        # Cache de resultados (evita recalcular o mesmo IP)
        self._cache: Dict[str, Dict] = {}

    def analisar(self, ip: str) -> Dict:
        """
        Analisa um IP e retorna:
        {
          "ip": str,
          "score": int (0-100),
          "categoria": str,
          "motivos": [str],
          "is_private": bool,
        }
        """
        if ip in self._cache:
            return self._cache[ip]

        if not ip or ip == "unknown":
            return self._resultado(ip, 0, "desconhecido", [])

        # IP privado — confiável por padrão
        if is_private(ip) or is_loopback(ip):
            r = self._resultado(ip, 0, "privado", ["IP da rede local"])
            r["is_private"] = True
            self._cache[ip] = r
            return r

        score   = 0
        motivos = []

        # 1. IP individual conhecido
        if ip in IPS_MALICIOSOS_CONHECIDOS:
            score = 95
            motivos.append(f"IP malicioso conhecido: {IPS_MALICIOSOS_CONHECIDOS[ip]}")

        # 2. Range malicioso
        if score < 95:
            try:
                addr = ipaddress.ip_address(ip)
                for rede in self._redes:
                    if addr in rede:
                        score = max(score, 80)
                        motivos.append(f"Range malicioso: {rede}")
                        break
            except Exception:
                pass

        # 3. Prefixo de hosting suspeito
        if score < 80:
            for prefixo in HOSTING_SUSPEITO:
                if ip.startswith(prefixo):
                    score = max(score, 65)
                    motivos.append(f"Hosting suspeito: {prefixo}*")
                    break

        # 4. Heurística: IP termina em .1 ou .254 (gateways/routers)
        ultimo_octeto = int(ip.split(".")[-1]) if "." in ip else 0
        if ultimo_octeto in (1, 254):
            score = max(0, score - 10)  # menos suspeito

        # Categoria baseada no score
        if score >= 90:   cat = "malicioso"
        elif score >= 70: cat = "suspeito"
        elif score >= 40: cat = "monitorar"
        else:             cat = "limpo"

        if not motivos:
            motivos.append("Sem indicadores de ameaça conhecidos")

        result = self._resultado(ip, score, cat, motivos)
        self._cache[ip] = result
        return result

    def enriquecer_deteccao(self, detection: Dict) -> Dict:
        """Adiciona informações de reputação a uma detecção existente."""
        ip = detection.get("source_ip", "")
        if not ip:
            return detection
        intel = self.analisar(ip)
        detection["intel"] = intel
        # Se IP é malicioso conhecido, eleva confiança
        if intel["score"] >= 80 and detection.get("confidence", 1) < 0.99:
            detection["confidence"] = min(
                detection["confidence"] + 0.1, 0.99
            )
        return detection

    @staticmethod
    def _resultado(ip, score, categoria, motivos):
        return {
            "ip":         ip,
            "score":      score,
            "categoria":  categoria,
            "motivos":    motivos,
            "is_private": False,
        }

    def adicionar_ip_malicioso(self, ip: str, motivo: str):
        """Adiciona IP à base local em tempo de execução."""
        IPS_MALICIOSOS_CONHECIDOS[ip] = motivo
        self._cache.pop(ip, None)  # invalida cache
        logger.info("IP adicionado à base local: %s (%s)", ip, motivo)

    def stats(self) -> Dict:
        return {
            "ips_conhecidos":    len(IPS_MALICIOSOS_CONHECIDOS),
            "ranges_monitorados": len(self._redes),
            "cache_size":        len(self._cache),
        }


# Instância global reutilizável
intel = ThreatIntel()
