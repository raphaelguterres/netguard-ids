"""
NetGuard GeoIP — geolocalização de IP, sem chamada externa.

Estratégia em 2 camadas (a primeira que responder ganha):

    1) MaxMind GeoLite2 (.mmdb) via `maxminddb` — cobertura mundial real,
       resolução por cidade/país/ASN. Caminho via env IDS_GEOLITE2_DB
       (default: ./geolite2/GeoLite2-City.mmdb). ASN opcional via
       IDS_GEOLITE2_ASN_DB (default: ./geolite2/GeoLite2-ASN.mmdb).
       O carregamento é lazy: se a lib ou o arquivo não estiverem
       disponíveis, a camada simplesmente não responde — sem barulho.

    2) Prefix DB embutida (GEO_DB abaixo) — cobre cloud providers,
       scanners conhecidos e blocos de ISP brasileiros/asiáticos.
       É melhor que nada quando o mmdb não está presente, e ainda
       complementa o mmdb com a coluna `org` (algo que o GeoLite2-City
       sozinho não traz; ASN traz mas precisa de DB extra).

Por que duas camadas em vez de só GeoLite2:
    GeoLite2-City não conhece a rede que o IP pertence (org/ASN). A
    prefix DB tem uma coluna `org` curada — útil pra reconhecer "Cloudflare"
    ou "⚠ Censys Scanner" sem baixar o GeoLite2-ASN.mmdb. Quando o ASN
    db ESTÁ disponível, ele entra como fonte primária de `org`.

Interface pública (estável):
    lookup(ip)        -> dict com {country, city, lat, lon, flag, org, private, ip}
    lookup_many(ips)  -> [dict, ...]
"""

import os
import threading
from typing import Dict, Optional  # noqa: F401

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


# ── GeoLite2 (MaxMind .mmdb) — lazy, opcional ─────────────────────
# Os Reader objects do maxminddb são thread-safe pra leitura, mas a
# inicialização não é. Guardamos com um lock e usamos sentinels pra
# diferenciar "ainda não tentei" de "tentei e não tem".
_GEO_LOCK = threading.Lock()
_GEO_INIT_DONE = False
_GEO_CITY_READER = None   # type: Optional[object]
_GEO_ASN_READER = None    # type: Optional[object]


def _geolite2_path(env_var: str, default_rel: str) -> str:
    """Resolve caminho do .mmdb. Aceita absoluto ou relativo ao cwd do app."""
    p = os.environ.get(env_var, "").strip()
    if p:
        return p
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, default_rel)


def _geolite2_init() -> None:
    """
    Carrega os readers uma vez. Silencioso em falha — se faltar a lib
    ou o .mmdb, simplesmente seguimos sem GeoLite2 e caímos pro prefix DB.
    """
    global _GEO_INIT_DONE, _GEO_CITY_READER, _GEO_ASN_READER
    if _GEO_INIT_DONE:
        return
    with _GEO_LOCK:
        if _GEO_INIT_DONE:
            return
        try:
            import maxminddb  # type: ignore
        except Exception:
            _GEO_INIT_DONE = True
            return
        # Placeholder files (read README) ficam <1KB; mmdb real começa em
        # >5MB pro ASN e >50MB pro City. Esse threshold barato evita um
        # open() que ia explodir ruidosamente.
        _MIN_MMDB_SIZE = 65536  # 64KB — pega placeholders sem falso positivo

        city_path = _geolite2_path("IDS_GEOLITE2_DB", "geolite2/GeoLite2-City.mmdb")
        if os.path.isfile(city_path) and os.path.getsize(city_path) >= _MIN_MMDB_SIZE:
            try:
                _GEO_CITY_READER = maxminddb.open_database(city_path)  # type: ignore
            except Exception:
                _GEO_CITY_READER = None
        asn_path = _geolite2_path("IDS_GEOLITE2_ASN_DB", "geolite2/GeoLite2-ASN.mmdb")
        if os.path.isfile(asn_path) and os.path.getsize(asn_path) >= _MIN_MMDB_SIZE:
            try:
                _GEO_ASN_READER = maxminddb.open_database(asn_path)  # type: ignore
            except Exception:
                _GEO_ASN_READER = None
        _GEO_INIT_DONE = True


def geolite2_status() -> dict:
    """
    Diagnóstico para healthcheck/admin: indica se cada DB GeoLite2 está
    carregado. Não exige reload — só reporta o estado pós-init.
    """
    _geolite2_init()
    return {
        "city_loaded": _GEO_CITY_READER is not None,
        "asn_loaded":  _GEO_ASN_READER  is not None,
        "city_path":   _geolite2_path("IDS_GEOLITE2_DB",     "geolite2/GeoLite2-City.mmdb"),
        "asn_path":    _geolite2_path("IDS_GEOLITE2_ASN_DB", "geolite2/GeoLite2-ASN.mmdb"),
    }


def _flag_for_country(code: str) -> str:
    """
    Converte ISO-2 (BR, US, ...) em emoji da bandeira via Regional Indicator
    Symbols (U+1F1E6..U+1F1FF). Cai pro globo 🌐 se a entrada for inválida.
    """
    if not code or len(code) != 2 or not code.isalpha():
        return "🌐"
    base = 0x1F1E6
    a = ord(code[0].upper()) - ord("A")
    b = ord(code[1].upper()) - ord("A")
    if a < 0 or a > 25 or b < 0 or b > 25:
        return "🌐"
    return chr(base + a) + chr(base + b)


def _lookup_geolite2(ip: str) -> Optional[dict]:
    """
    Tenta GeoLite2-City + GeoLite2-ASN. Retorna None se não houver match
    ou se a camada estiver indisponível. Não usa cache (o caller já guarda).
    """
    _geolite2_init()
    if _GEO_CITY_READER is None and _GEO_ASN_READER is None:
        return None

    country_code = ""
    city_name = ""
    lat = 0.0
    lon = 0.0
    org = ""

    if _GEO_CITY_READER is not None:
        try:
            rec = _GEO_CITY_READER.get(ip)  # type: ignore[attr-defined]
        except Exception:
            rec = None
        if isinstance(rec, dict):
            # MaxMind aninha por idiomas; pegamos pt-BR > en > primeira chave.
            country_code = (
                ((rec.get("country") or {}).get("iso_code"))
                or ((rec.get("registered_country") or {}).get("iso_code"))
                or ""
            )
            city_names = (rec.get("city") or {}).get("names") or {}
            city_name = (
                city_names.get("pt-BR")
                or city_names.get("en")
                or (next(iter(city_names.values())) if city_names else "")
                or ""
            )
            loc = rec.get("location") or {}
            lat = float(loc.get("latitude")  or 0.0)
            lon = float(loc.get("longitude") or 0.0)

    if _GEO_ASN_READER is not None:
        try:
            rec = _GEO_ASN_READER.get(ip)  # type: ignore[attr-defined]
        except Exception:
            rec = None
        if isinstance(rec, dict):
            org = rec.get("autonomous_system_organization") or ""

    if not (country_code or city_name or org):
        # Reader carregado mas sem registro pra esse IP — devolve None
        # pra permitir cair no prefix DB.
        return None

    return {
        "country": country_code or "??",
        "city":    city_name or "Unknown",
        "lat":     lat,
        "lon":     lon,
        "flag":    _flag_for_country(country_code) if country_code else "🌐",
        "org":     org or "Unknown",
        "ip":      ip,
        "private": False,
        "source":  "geolite2",
    }


def lookup(ip: str) -> dict:
    """
    Retorna informações geográficas para um IP.

    Ordem de consulta:
        1. cache em memória
        2. GeoLite2-City/ASN (.mmdb), se disponíveis
        3. Prefix DB embutida (mais específico primeiro)
        4. Fallback "Unknown"
    """
    if not ip or ip == "unknown":
        return _unknown()

    if ip in _cache:
        return _cache[ip]

    # IP privado/loopback — atalho
    if any(ip.startswith(p) for p in _privates_check()):
        r = {"country":"LAN","city":"Rede Local","lat":0,"lon":0,
             "flag":"🏠","org":"Rede Privada","private":True,"ip":ip,
             "source":"private"}
        _cache[ip] = r
        return r

    # 1) GeoLite2 (mmdb) — autoritativo quando presente
    g = _lookup_geolite2(ip)
    if g is not None:
        # Se ASN db trouxe org genérica mas a prefix DB tem algo mais
        # informativo (ex: "⚠ Censys Scanner"), prefere o curado.
        for prefix in _SORTED_PREFIXES:
            if ip.startswith(prefix):
                curated_org = GEO_DB[prefix].get("org") or ""
                if curated_org and (
                    not g.get("org")
                    or g["org"] in ("Unknown", "")
                    or curated_org.startswith("⚠")
                ):
                    g["org"] = curated_org
                break
        _cache[ip] = g
        return g

    # 2) Prefix DB — mais específico primeiro
    for prefix in _SORTED_PREFIXES:
        if ip.startswith(prefix):
            r = {**GEO_DB[prefix], "ip": ip, "private": False, "source": "prefix"}
            _cache[ip] = r
            return r

    # 3) Fallback genérico
    r = _unknown(ip)
    _cache[ip] = r
    return r

def _privates_check():
    return _PRIVATES

def _unknown(ip=""):
    return {"country":"??","city":"Unknown","lat":0,"lon":0,
            "flag":"🌐","org":"Unknown","ip":ip,"private":False,
            "source":"unknown"}

def lookup_many(ips: list) -> list:
    """Lookup em lote."""
    return [{"ip": ip, **lookup(ip)} for ip in ips if ip]
