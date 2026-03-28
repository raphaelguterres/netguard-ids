"""
NetGuard GeoIP — Base local sem API externa.
Lookup por prefixo de IP com fallback em múltiplas granularidades.
Cobre os principais ranges de IPs vistos em redes brasileiras.
"""

from typing import Dict, Optional

# ── Base de dados embutida ────────────────────────────────────────
# Ordenada do mais específico para o mais genérico
# Formato: prefixo → {country, city, lat, lon, flag, org}

GEO_DB: Dict[str, dict] = {
    # ── Cloudflare ────────────────────────────────────────────────
    "162.158.": {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "162.159.": {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "104.16.":  {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "104.17.":  {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "104.18.":  {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "104.19.":  {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "172.64.":  {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "172.65.":  {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "172.66.":  {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "188.114.": {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare"},
    "1.1.1.":   {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Cloudflare DNS"},
    # ── AWS ───────────────────────────────────────────────────────
    "52.":      {"country":"US","city":"N. Virginia","lat":38.13,"lon":-78.45,"flag":"🇺🇸","org":"Amazon AWS"},
    "54.":      {"country":"US","city":"N. Virginia","lat":38.13,"lon":-78.45,"flag":"🇺🇸","org":"Amazon AWS"},
    "3.":       {"country":"US","city":"Oregon","lat":45.52,"lon":-122.67,"flag":"🇺🇸","org":"Amazon AWS"},
    "18.":      {"country":"US","city":"N. Virginia","lat":38.13,"lon":-78.45,"flag":"🇺🇸","org":"Amazon AWS"},
    "44.":      {"country":"US","city":"N. Virginia","lat":38.13,"lon":-78.45,"flag":"🇺🇸","org":"Amazon AWS"},
    # ── Google / GCP ─────────────────────────────────────────────
    "34.":      {"country":"US","city":"Iowa","lat":41.59,"lon":-93.62,"flag":"🇺🇸","org":"Google Cloud"},
    "35.":      {"country":"US","city":"Iowa","lat":41.59,"lon":-93.62,"flag":"🇺🇸","org":"Google Cloud"},
    "142.250.": {"country":"US","city":"Mountain View","lat":37.38,"lon":-122.08,"flag":"🇺🇸","org":"Google"},
    "172.217.": {"country":"US","city":"Mountain View","lat":37.38,"lon":-122.08,"flag":"🇺🇸","org":"Google"},
    "172.253.": {"country":"US","city":"Mountain View","lat":37.38,"lon":-122.08,"flag":"🇺🇸","org":"Google"},
    "216.58.":  {"country":"US","city":"Mountain View","lat":37.38,"lon":-122.08,"flag":"🇺🇸","org":"Google"},
    "216.239.": {"country":"US","city":"Mountain View","lat":37.38,"lon":-122.08,"flag":"🇺🇸","org":"Google"},
    "74.125.":  {"country":"US","city":"Mountain View","lat":37.38,"lon":-122.08,"flag":"🇺🇸","org":"Google"},
    "8.8.":     {"country":"US","city":"Mountain View","lat":37.38,"lon":-122.08,"flag":"🇺🇸","org":"Google DNS"},
    # ── Microsoft / Azure ─────────────────────────────────────────
    "13.":      {"country":"US","city":"Virginia","lat":38.13,"lon":-78.45,"flag":"🇺🇸","org":"Microsoft Azure"},
    "20.":      {"country":"US","city":"Virginia","lat":38.13,"lon":-78.45,"flag":"🇺🇸","org":"Microsoft Azure"},
    "40.":      {"country":"US","city":"Virginia","lat":38.13,"lon":-78.45,"flag":"🇺🇸","org":"Microsoft"},
    "51.":      {"country":"IE","city":"Dublin","lat":53.33,"lon":-6.24,"flag":"🇮🇪","org":"Microsoft Azure EU"},
    "52.97.":   {"country":"US","city":"Virginia","lat":38.13,"lon":-78.45,"flag":"🇺🇸","org":"Microsoft O365"},
    "52.239.":  {"country":"US","city":"Virginia","lat":38.13,"lon":-78.45,"flag":"🇺🇸","org":"Microsoft"},
    "150.171.": {"country":"US","city":"Redmond","lat":47.67,"lon":-122.12,"flag":"🇺🇸","org":"Microsoft"},
    "204.79.":  {"country":"US","city":"Redmond","lat":47.67,"lon":-122.12,"flag":"🇺🇸","org":"Microsoft Bing"},
    # ── Meta / Facebook / WhatsApp ────────────────────────────────
    "157.240.": {"country":"US","city":"Menlo Park","lat":37.45,"lon":-122.17,"flag":"🇺🇸","org":"Meta/Facebook"},
    "31.13.":   {"country":"US","city":"Menlo Park","lat":37.45,"lon":-122.17,"flag":"🇺🇸","org":"Meta/Facebook"},
    "179.60.":  {"country":"US","city":"Menlo Park","lat":37.45,"lon":-122.17,"flag":"🇺🇸","org":"Meta/WhatsApp"},
    "129.134.": {"country":"US","city":"Menlo Park","lat":37.45,"lon":-122.17,"flag":"🇺🇸","org":"Meta"},
    # ── Discord ───────────────────────────────────────────────────
    "66.22.":   {"country":"US","city":"San Jose","lat":37.33,"lon":-121.88,"flag":"🇺🇸","org":"Discord"},
    "214.":     {"country":"US","city":"San Jose","lat":37.33,"lon":-121.88,"flag":"🇺🇸","org":"Discord"},
    # ── Anthropic ─────────────────────────────────────────────────
    "160.79.":  {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"Anthropic"},
    # ── Valve / Steam ─────────────────────────────────────────────
    "208.64.":  {"country":"US","city":"Bellevue","lat":47.61,"lon":-122.20,"flag":"🇺🇸","org":"Valve/Steam"},
    "155.133.": {"country":"US","city":"Seattle","lat":47.60,"lon":-122.33,"flag":"🇺🇸","org":"Valve/Steam"},
    "185.25.":  {"country":"SE","city":"Stockholm","lat":59.33,"lon":18.06,"flag":"🇸🇪","org":"Valve/Steam EU"},
    # ── Akamai / CDN ─────────────────────────────────────────────
    "23.":      {"country":"US","city":"Cambridge","lat":42.36,"lon":-71.05,"flag":"🇺🇸","org":"Akamai"},
    "151.101.": {"country":"US","city":"Los Angeles","lat":34.05,"lon":-118.24,"flag":"🇺🇸","org":"Fastly"},
    "199.232.": {"country":"US","city":"Los Angeles","lat":34.05,"lon":-118.24,"flag":"🇺🇸","org":"Fastly"},
    # ── Brasil ────────────────────────────────────────────────────
    "177.":     {"country":"BR","city":"São Paulo","lat":-23.54,"lon":-46.63,"flag":"🇧🇷","org":"Brasil ISP"},
    "179.":     {"country":"BR","city":"São Paulo","lat":-23.54,"lon":-46.63,"flag":"🇧🇷","org":"Brasil ISP"},
    "187.":     {"country":"BR","city":"Rio de Janeiro","lat":-22.90,"lon":-43.17,"flag":"🇧🇷","org":"Brasil ISP"},
    "189.":     {"country":"BR","city":"São Paulo","lat":-23.54,"lon":-46.63,"flag":"🇧🇷","org":"Vivo/Telefônica"},
    "191.":     {"country":"BR","city":"Brasília","lat":-15.77,"lon":-47.92,"flag":"🇧🇷","org":"Brasil ISP"},
    "200.":     {"country":"BR","city":"Brasília","lat":-15.77,"lon":-47.92,"flag":"🇧🇷","org":"Brasil ISP"},
    "201.":     {"country":"BR","city":"São Paulo","lat":-23.54,"lon":-46.63,"flag":"🇧🇷","org":"Claro Brasil"},
    "187.102.": {"country":"BR","city":"São Paulo","lat":-23.54,"lon":-46.63,"flag":"🇧🇷","org":"NET/Claro SP"},
    "186.":     {"country":"BR","city":"Curitiba","lat":-25.42,"lon":-49.26,"flag":"🇧🇷","org":"OI Brasil"},
    # ── China ─────────────────────────────────────────────────────
    "114.":     {"country":"CN","city":"Beijing","lat":39.90,"lon":116.40,"flag":"🇨🇳","org":"China Telecom"},
    "117.":     {"country":"CN","city":"Shanghai","lat":31.22,"lon":121.46,"flag":"🇨🇳","org":"China Unicom"},
    "118.":     {"country":"CN","city":"Guangzhou","lat":23.12,"lon":113.26,"flag":"🇨🇳","org":"China Mobile"},
    "119.":     {"country":"CN","city":"Hangzhou","lat":30.25,"lon":120.15,"flag":"🇨🇳","org":"China Unicom"},
    "120.":     {"country":"CN","city":"Hangzhou","lat":30.25,"lon":120.15,"flag":"🇨🇳","org":"Alibaba Cloud"},
    "121.":     {"country":"CN","city":"Beijing","lat":39.90,"lon":116.40,"flag":"🇨🇳","org":"China Telecom"},
    "123.":     {"country":"CN","city":"Beijing","lat":39.90,"lon":116.40,"flag":"🇨🇳","org":"China Telecom"},
    "124.":     {"country":"CN","city":"Beijing","lat":39.90,"lon":116.40,"flag":"🇨🇳","org":"China ISP"},
    # ── Rússia ────────────────────────────────────────────────────
    "185.220.": {"country":"RU","city":"Moscow","lat":55.75,"lon":37.61,"flag":"🇷🇺","org":"Tor Exit/Russia"},
    "91.108.":  {"country":"RU","city":"Moscow","lat":55.75,"lon":37.61,"flag":"🇷🇺","org":"Telegram"},
    "149.154.": {"country":"NL","city":"Amsterdam","lat":52.37,"lon":4.89,"flag":"🇳🇱","org":"Telegram"},
    "91.":      {"country":"RU","city":"Moscow","lat":55.75,"lon":37.61,"flag":"🇷🇺","org":"Russia ISP"},
    "95.":      {"country":"RU","city":"Moscow","lat":55.75,"lon":37.61,"flag":"🇷🇺","org":"Russia ISP"},
    # ── Europa ────────────────────────────────────────────────────
    "5.":       {"country":"NL","city":"Amsterdam","lat":52.37,"lon":4.89,"flag":"🇳🇱","org":"NL ISP"},
    "185.":     {"country":"NL","city":"Amsterdam","lat":52.37,"lon":4.89,"flag":"🇳🇱","org":"RIPE Europe"},
    "193.":     {"country":"DE","city":"Frankfurt","lat":50.11,"lon":8.68,"flag":"🇩🇪","org":"Germany ISP"},
    "194.":     {"country":"DE","city":"Frankfurt","lat":50.11,"lon":8.68,"flag":"🇩🇪","org":"DTAG Germany"},
    "195.":     {"country":"GB","city":"London","lat":51.50,"lon":-0.12,"flag":"🇬🇧","org":"UK ISP"},
    "46.":      {"country":"DE","city":"Frankfurt","lat":50.11,"lon":8.68,"flag":"🇩🇪","org":"Hetzner DE"},
    "78.":      {"country":"DE","city":"Frankfurt","lat":50.11,"lon":8.68,"flag":"🇩🇪","org":"Europe ISP"},
    "80.":      {"country":"DE","city":"Frankfurt","lat":50.11,"lon":8.68,"flag":"🇩🇪","org":"Europe ISP"},
    # ── Japão ─────────────────────────────────────────────────────
    "103.":     {"country":"JP","city":"Tokyo","lat":35.68,"lon":139.69,"flag":"🇯🇵","org":"Japan ISP"},
    "106.":     {"country":"IN","city":"Mumbai","lat":19.07,"lon":72.87,"flag":"🇮🇳","org":"India ISP"},
    # ── Scanners maliciosos ───────────────────────────────────────
    "66.240.":  {"country":"US","city":"San Diego","lat":32.71,"lon":-117.15,"flag":"🇺🇸","org":"⚠ Shodan Scanner"},
    "198.20.":  {"country":"US","city":"San Diego","lat":32.71,"lon":-117.15,"flag":"🇺🇸","org":"⚠ Shodan Scanner"},
    "82.221.":  {"country":"IS","city":"Reykjavik","lat":64.13,"lon":-21.82,"flag":"🇮🇸","org":"⚠ Shodan/Iceland"},
    "162.142.": {"country":"US","city":"Pittsburgh","lat":40.44,"lon":-79.99,"flag":"🇺🇸","org":"⚠ Censys Scanner"},
    "167.94.":  {"country":"US","city":"Pittsburgh","lat":40.44,"lon":-79.99,"flag":"🇺🇸","org":"⚠ Censys Scanner"},
    # ── SpaceX / Starlink ─────────────────────────────────────────
    "98.97.":   {"country":"US","city":"Hawthorne","lat":33.92,"lon":-118.32,"flag":"🇺🇸","org":"SpaceX Starlink"},
    # ── Discord CDN ───────────────────────────────────────────────
    "104.":     {"country":"US","city":"San Francisco","lat":37.77,"lon":-122.41,"flag":"🇺🇸","org":"CDN"},
    # ── Fallback ─────────────────────────────────────────────────
    "72.":      {"country":"US","city":"United States","lat":37.09,"lon":-95.71,"flag":"🇺🇸","org":"US ISP"},
    "4.":       {"country":"US","city":"United States","lat":37.09,"lon":-95.71,"flag":"🇺🇸","org":"Level3/Lumen"},
    "8.":       {"country":"US","city":"United States","lat":37.09,"lon":-95.71,"flag":"🇺🇸","org":"Level3"},
    "66.":      {"country":"US","city":"United States","lat":37.09,"lon":-95.71,"flag":"🇺🇸","org":"US ISP"},
    "67.":      {"country":"US","city":"United States","lat":37.09,"lon":-95.71,"flag":"🇺🇸","org":"US ISP"},
    "68.":      {"country":"US","city":"United States","lat":37.09,"lon":-95.71,"flag":"🇺🇸","org":"US ISP"},
    "104.":     {"country":"US","city":"United States","lat":37.09,"lon":-95.71,"flag":"🇺🇸","org":"US CDN"},
    "172.":     {"country":"US","city":"United States","lat":37.09,"lon":-95.71,"flag":"🇺🇸","org":"US ISP"},
}

# Sort by length descending for most-specific-first matching
_SORTED_PREFIXES = sorted(GEO_DB.keys(), key=len, reverse=True)

_PRIVATES = ["10.","172.16.","172.17.","172.18.","172.19.","172.20.",
             "172.21.","172.22.","172.23.","172.24.","172.25.","172.26.",
             "172.27.","172.28.","172.29.","172.30.","172.31.",
             "192.168.","127.","169.254.","0.0.0.0"]

_cache: dict = {}

def lookup(ip: str) -> dict:
    """
    Retorna informações geográficas para um IP.
    Usa lookup por prefixo, do mais específico ao menos específico.
    """
    if not ip or ip == "unknown":
        return _unknown()

    if ip in _cache:
        return _cache[ip]

    # IP privado
    if any(ip.startswith(p) for p in _privates_check()):
        r = {"country":"LAN","city":"Rede Local","lat":0,"lon":0,
             "flag":"🏠","org":"Rede Privada","private":True}
        _cache[ip] = r
        return r

    # Lookup por prefixo (mais específico primeiro)
    for prefix in _SORTED_PREFIXES:
        if ip.startswith(prefix):
            r = {**GEO_DB[prefix], "ip": ip, "private": False}
            _cache[ip] = r
            return r

    # Fallback genérico
    r = _unknown(ip)
    _cache[ip] = r
    return r

def _privates_check():
    return _PRIVATES

def _unknown(ip=""):
    return {"country":"??","city":"Unknown","lat":0,"lon":0,
            "flag":"🌐","org":"Unknown","ip":ip,"private":False}

def lookup_many(ips: list) -> list:
    """Lookup em lote."""
    return [{"ip": ip, **lookup(ip)} for ip in ips if ip]
