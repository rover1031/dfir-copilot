"""Conocimiento local para reconocer qué hay en un campo sin enviar sus valores a ningún sitio.

Patrones RE2 (los evalúa DuckDB), formatos de fecha candidatos (incluidos meses en español) y vocabulario técnico
"seguro" que sí puede mostrarse en el perfil porque no identifica a nadie.
"""
from __future__ import annotations

SEMANTIC_PATTERNS: dict[str, str] = {
    "ipv4": r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$",
    "ipv6": r"^(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$",
    "email": r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$",
    "url": r"^(?i:https?|ftp)://\S+$",
    "uri_path": r"^/\S*$",
    "http_request_line": r"^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/\d(?:\.\d)?$",
    "http_method": r"^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)$",
    "http_status": r"^[1-5]\d\d$",
    "user_agent": r"(?i)^(?:mozilla/|curl/|wget|python-|go-http|java/|okhttp|postmanruntime|scrapy|crawler|sqlmap|nikto)",
    "uuid": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    "md5": r"^[0-9a-fA-F]{32}$",
    "sha1": r"^[0-9a-fA-F]{40}$",
    "sha256": r"^[0-9a-fA-F]{64}$",
    "mac": r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$",
    "domain": r"^(?i:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})$",
    "windows_path": r"^(?:[A-Za-z]:\\|\\\\|\\Device\\)",
    "windows_sid": r"^S-1-\d+(?:-\d+)+$",
    "jwt": r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$",
}

# Credenciales dentro de un valor (p. ej. ?authtoken=… en una URL): se cuenta, nunca se muestra.
SECRET_IN_VALUE = r"(?i)(?:^|[?&;\s])[a-z_]*(?:token|api[_-]?key|passw(?:or)?d|pwd|secret|auth|contrase(?:ñ|n)a|clave)[a-z_]*="
SECRET_NAME_HINTS = ("token", "password", "passwd", "secret", "api_key", "apikey", "authorization", "cookie",
                     "contrasena", "clave", "credencial")

# Indicio de que un texto es una fecha (antes de probar formatos)
DATETIME_HINT = (r"(?i)(?:\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}|\d{1,2}:\d{2}|"
                 r"\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec|ene|abr|ago|dic|set)\b)")

# Meses en español cuya abreviatura difiere de la inglesa (el resto coinciden)
ES_MONTHS = {"ene": "Jan", "abr": "Apr", "ago": "Aug", "set": "Sep", "dic": "Dec"}

# Candidatos de fecha: (etiqueta, plantilla SQL sobre {v}). El orden desempata.
STRPTIME_FORMATS = [
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M",
    "%Y-%d-%m %H:%M:%S", "%Y-%d-%mT%H:%M:%S", "%Y-%d-%mT%H:%M",
    "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M",
    "%d-%m-%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y", "%m/%d/%Y", "%Y-%m-%d",
    "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S", "%d %b %Y %H:%M:%S",
]
# Pares mes/día que pueden confundirse entre sí
DAY_MONTH_PAIRS = [
    ("%Y-%m-%d %H:%M:%S", "%Y-%d-%m %H:%M:%S"), ("%Y-%m-%dT%H:%M:%S", "%Y-%d-%mT%H:%M:%S"),
    ("%Y-%m-%dT%H:%M", "%Y-%d-%mT%H:%M"), ("iso8601", "%Y-%d-%mT%H:%M"), ("iso8601", "%Y-%d-%m %H:%M:%S"),
    ("iso8601", "%Y-%d-%mT%H:%M:%S"), ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S"),
    ("%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M"), ("%d/%m/%Y", "%m/%d/%Y"),
]


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def es_to_en_months(expr: str) -> str:
    for es, en in ES_MONTHS.items():
        expr = f"regexp_replace({expr}, '(?i)\\b{es}\\b', '{en}', 'g')"
    return expr


def timestamp_candidates(v: str) -> list[tuple[str, str]]:
    """Expresiones SQL (una por formato) que devuelven TIMESTAMPTZ o NULL a partir del texto {v}."""
    out = [("iso8601", f"TRY_CAST({v} AS TIMESTAMPTZ)")]
    for fmt in STRPTIME_FORMATS:
        src = es_to_en_months(v) if "%b" in fmt else v
        expr = f"try_strptime({src}, {_lit(fmt)})"
        out.append((fmt, expr if "%z" in fmt else f"CAST({expr} AS TIMESTAMPTZ)"))
    num = f"TRY_CAST({v} AS DOUBLE)"
    out.append(("epoch_s", f"CASE WHEN {num} BETWEEN 1e9 AND 2.2e9 THEN to_timestamp({num}) END"))
    out.append(("epoch_ms", f"CASE WHEN {num} BETWEEN 1e12 AND 2.2e12 THEN to_timestamp({num} / 1000.0) END"))
    return out


# Vocabulario técnico cerrado: valores que no identifican a nadie y que sí ayudan a clasificar el log.
SAFE_VOCABULARY = {
    "get", "post", "put", "delete", "head", "options", "patch", "connect", "trace",
    "tcp", "udp", "icmp", "http", "https", "dns", "tls", "ssl", "ssh", "rdp", "smb", "ftp", "ldap", "kerberos", "ntlm",
    "allow", "allowed", "deny", "denied", "drop", "dropped", "block", "blocked", "accept", "accepted", "reject",
    "rejected", "permit", "permitted", "pass", "success", "succeeded", "failure", "failed", "fail", "error", "ok",
    "logon", "logoff", "login", "logout", "true", "false", "yes", "no", "none", "unknown",
    "debug", "info", "information", "notice", "warning", "warn", "critical", "fatal", "alert", "emergency",
    "permitir", "permitido", "denegar", "denegado", "bloquear", "bloqueado", "aceptado", "rechazado", "exito",
    "éxito", "fallo", "fallido", "correcto", "incorrecto", "si", "sí", "inicio", "cierre", "advertencia",
    "process_start", "process_end", "process_rollup2", "network_connect", "file_write", "file_create", "dns_request",
    "processrollup2", "networkconnectip4", "dnsrequest", "useridentity", "userlogon",
}
