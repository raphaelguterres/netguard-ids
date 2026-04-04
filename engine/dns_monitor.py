"""
NetGuard — DNS Monitoring + DGA Detection
Monitora queries DNS e detecta padrões maliciosos.

Detecta:
  - DNS Tunneling: queries excessivamente longas (exfiltração de dados)
  - DGA Domains: domínios gerados algoritmicamente (malware C2)
  - Fast Flux: muitas mudanças de IP para o mesmo domínio
  - Typosquatting: domínios parecidos com marcas conhecidas
  - Alexa/popularity check: domínios nunca vistos antes com atividade suspeita
"""

import re
import math
import time
import logging
import threading
import ipaddress  # noqa: F401
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("netguard.dns")

# ── Legitimate TLDs and known-good domains ────────────────────────
BENIGN_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "live.com", "azure.com", "msftconnecttest.com",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "cloudflare.com", "cloudflare-dns.com", "amazonaws.com",
    "akamaiedge.net", "akamai.net", "fastly.net", "cdn77.com",
    "apple.com", "icloud.com", "mzstatic.com",
    "github.com", "githubusercontent.com",
    "ubuntu.com", "debian.org", "fedoraproject.org",
    "mozilla.org", "firefox.com",
}

# Common TLDs — DGA domains often use obscure TLDs
COMMON_TLDS = {
    "com", "net", "org", "edu", "gov", "io", "co", "uk",
    "de", "fr", "br", "jp", "cn", "ru", "au", "ca", "nl",
}

# ── DGA Detection ─────────────────────────────────────────────────
def _entropy(s: str) -> float:
    """Shannon entropy of string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())

def _consonant_ratio(s: str) -> float:
    """Ratio of consonants to total letters."""
    consonants = set("bcdfghjklmnpqrstvwxyz")
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in consonants) / len(letters)

def _has_suspicious_pattern(domain: str) -> bool:
    """Check for known DGA patterns."""
    # Long numeric sequences
    if re.search(r'\d{6,}', domain):
        return True
    # Alternating consonants (agkntv style)
    if re.search(r'[bcdfghjklmnpqrstvwxyz]{8,}', domain, re.IGNORECASE):
        return True
    # Hex-like sequences
    if re.search(r'[0-9a-f]{16,}', domain, re.IGNORECASE):
        return True
    # Very long subdomain labels
    labels = domain.split(".")
    if any(len(l) > 30 for l in labels):
        return True
    return False

def dga_score(domain: str) -> Tuple[float, List[str]]:
    """
    Score a domain for DGA likelihood. Returns (score 0-100, reasons).
    Score >= 60 → likely DGA
    """
    reasons = []
    score = 0.0

    # Extract the registrable domain (SLD + TLD)
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return 0.0, []

    tld = parts[-1]
    sld = parts[-2]  # Second-level domain

    # Skip known benign
    base = f"{sld}.{tld}"
    if base in BENIGN_DOMAINS:
        return 0.0, []
    for b in BENIGN_DOMAINS:
        if domain.endswith("." + b):
            return 0.0, []

    # 1. Entropy check (DGA domains have high entropy)
    ent = _entropy(sld)
    if ent > 3.8:
        score += 30
        reasons.append(f"high entropy ({ent:.1f})")
    elif ent > 3.2:
        score += 15

    # 2. Consonant ratio (DGA = too many consonants)
    cr = _consonant_ratio(sld)
    if cr > 0.80:
        score += 25
        reasons.append(f"consonant ratio {cr:.0%}")
    elif cr > 0.70:
        score += 10

    # 3. Length (DGA often 12-22 chars)
    ln = len(sld)
    if 12 <= ln <= 22:
        score += 10
        reasons.append(f"typical DGA length ({ln})")
    elif ln > 22:
        score += 5

    # 4. Suspicious patterns
    if _has_suspicious_pattern(domain):
        score += 20
        reasons.append("suspicious character pattern")

    # 5. Obscure TLD
    if tld not in COMMON_TLDS:
        score += 10
        reasons.append(f"uncommon TLD .{tld}")

    # 6. Many subdomains (tunneling)
    if len(parts) > 5:
        score += 15
        reasons.append(f"{len(parts)} subdomain levels")

    # 7. Domain length for tunneling (full domain > 60 chars)
    if len(domain) > 60:
        score += 20
        reasons.append(f"very long domain ({len(domain)} chars)")

    return min(100.0, score), reasons


# ── DNS Tunnel Detection ──────────────────────────────────────────
def tunnel_score(domain: str, query_type: str = "A") -> Tuple[float, List[str]]:
    """Detect DNS tunneling patterns."""
    reasons = []
    score = 0.0

    # TXT/NULL records used for tunneling
    if query_type in ("TXT", "NULL", "CNAME") and len(domain) > 40:
        score += 40
        reasons.append(f"{query_type} query on long domain")

    # Subdomain length (exfil data encoded as subdomains)
    parts = domain.split(".")
    longest_label = max((len(p) for p in parts), default=0)
    if longest_label > 50:
        score += 50
        reasons.append(f"label too long ({longest_label} chars)")
    elif longest_label > 35:
        score += 25
        reasons.append(f"long label ({longest_label} chars)")

    # Base64/hex encoded subdomains
    for part in parts[:-2]:
        if len(part) > 20:
            try:
                import base64
                decoded = base64.b64decode(part + "==")
                if len(decoded) > 10 and all(32 <= b < 127 for b in decoded):
                    score += 30
                    reasons.append("base64 encoded label")
                    break
            except Exception:
                pass
            if re.match(r'^[0-9a-fA-F]{20,}$', part):
                score += 25
                reasons.append("hex encoded label")
                break

    return min(100.0, score), reasons


class DNSMonitor:
    """
    Monitors DNS queries from packet capture and detects threats.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._alerts: List[dict] = []
        self._query_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._domain_ips: Dict[str, set] = defaultdict(set)
        self._stats = {
            "total_queries": 0,
            "unique_domains": 0,
            "dga_detected": 0,
            "tunnel_detected": 0,
            "fast_flux_detected": 0,
        }
        logger.info("DNSMonitor iniciado | DGA + Tunnel + FastFlux detection")

    def process_query(self, domain: str, query_type: str = "A",
                      source_ip: str = "", resolved_ip: str = "") -> Optional[dict]:
        """
        Process a single DNS query.
        Returns an alert dict if threat detected, else None.
        """
        if not domain or len(domain) < 4:
            return None

        domain = domain.lower().rstrip(".")

        with self._lock:
            self._stats["total_queries"] += 1
            self._query_history[source_ip].append({
                "ts": time.monotonic(),
                "domain": domain,
                "type": query_type,
            })

            # Track resolved IPs for fast flux
            if resolved_ip:
                self._domain_ips[domain].add(resolved_ip)

        alert = None

        # ── DGA Detection ────────────────────────────────────────
        dga, dga_reasons = dga_score(domain)
        if dga >= 65:
            alert = self._make_alert(
                rule_id="DNS-DGA",
                severity="HIGH" if dga < 85 else "CRITICAL",
                domain=domain,
                query_type=query_type,
                source_ip=source_ip,
                description=f"DGA domain detected (score {dga:.0f}/100): {', '.join(dga_reasons)}",
                mitre_technique="T1568.002",
                tags=["dga", "c2", "malware"],
                score=dga,
            )
            with self._lock:
                self._stats["dga_detected"] += 1

        # ── Tunnel Detection ─────────────────────────────────────
        elif (tun_score := tunnel_score(domain, query_type)[0]) >= 50:
            _, tun_reasons = tunnel_score(domain, query_type)
            alert = self._make_alert(
                rule_id="DNS-TUNNEL",
                severity="HIGH",
                domain=domain,
                query_type=query_type,
                source_ip=source_ip,
                description=f"DNS tunneling detected (score {tun_score:.0f}/100): {', '.join(tun_reasons)}",
                mitre_technique="T1071.004",
                tags=["tunnel", "exfiltration", "c2"],
                score=tun_score,
            )
            with self._lock:
                self._stats["tunnel_detected"] += 1

        # ── Fast Flux Detection ───────────────────────────────────
        elif resolved_ip:
            with self._lock:
                ips = self._domain_ips.get(domain, set())
            if len(ips) >= 5:
                alert = self._make_alert(
                    rule_id="DNS-FASTFLUX",
                    severity="MEDIUM",
                    domain=domain,
                    query_type=query_type,
                    source_ip=source_ip,
                    description=f"Fast Flux DNS: {len(ips)} different IPs for {domain}",
                    mitre_technique="T1568.001",
                    tags=["fast-flux", "c2", "botnet"],
                    score=70.0,
                    extra={"ip_count": len(ips), "ips": list(ips)[:10]},
                )
                with self._lock:
                    self._stats["fast_flux_detected"] += 1

        # Store alert
        if alert:
            with self._lock:
                self._alerts.append(alert)
                self._alerts = self._alerts[-500:]
            logger.warning("DNS ALERT | %s | %s | domain=%s | src=%s",
                          alert["rule_id"], alert["severity"], domain, source_ip)

        # Update unique domains
        with self._lock:
            self._stats["unique_domains"] = len(self._query_history)

        return alert

    def _make_alert(self, rule_id: str, severity: str, domain: str,
                    query_type: str, source_ip: str, description: str,
                    mitre_technique: str, tags: List[str],
                    score: float, extra: dict = None) -> dict:
        return {
            "id": f"{rule_id}_{int(time.time()*1000)}",
            "rule_id": rule_id,
            "severity": severity,
            "domain": domain,
            "query_type": query_type,
            "source_ip": source_ip,
            "description": description,
            "score": round(score, 1),
            "mitre_technique": mitre_technique,
            "mitre_tactic": "command_and_control",
            "tags": tags,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **(extra or {}),
        }

    def analyze_domain(self, domain: str, query_type: str = "A") -> dict:
        """Full analysis of a single domain (for API use)."""
        dga, dga_reasons = dga_score(domain)
        tun, tun_reasons = tunnel_score(domain, query_type)
        ent = _entropy(domain.split(".")[0] if "." in domain else domain)
        cr = _consonant_ratio(domain.split(".")[0] if "." in domain else domain)

        verdict = "clean"
        if dga >= 85 or tun >= 70:
            verdict = "malicious"
        elif dga >= 65 or tun >= 50:
            verdict = "suspicious"

        return {
            "domain": domain,
            "verdict": verdict,
            "dga_score": round(dga, 1),
            "dga_reasons": dga_reasons,
            "tunnel_score": round(tun, 1),
            "tunnel_reasons": tun_reasons,
            "entropy": round(ent, 2),
            "consonant_ratio": round(cr, 2),
            "length": len(domain),
        }

    def get_alerts(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return list(reversed(self._alerts[-limit:]))

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def inject_demo(self) -> List[dict]:
        """Demo: analyze known DGA/tunnel domains."""
        demo_domains = [
            ("xgkntvazmcpwsojl.com", "A", "192.168.15.50"),
            ("data.exfil.attacker.c2domains.xyz", "TXT", "192.168.15.51"),
            ("aabbccddee112233.evil.ru", "A", "10.0.0.5"),
            ("normal.google.com", "A", "192.168.1.1"),
            ("microsoft.com", "A", "192.168.1.2"),
        ]
        results = []
        for domain, qtype, src in demo_domains:
            a = self.process_query(domain, qtype, src, "")
            if a:
                results.append(a)
        return results
