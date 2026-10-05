"""Textos bilingües (es/en) del sistema.

Convención del proyecto: las CLAVES de los objetos JSON (Data Profile, ledger, herramientas) son un contrato estable y
van en inglés; el TEXTO dirigido a personas (avisos, explicaciones, informes) se traduce con `t()`. Así un pipeline
nunca se rompe por el idioma y cada analista lee en el suyo.
"""
from __future__ import annotations

import os
import string

SUPPORTED = ("es", "en")

_MESSAGES: dict[str, dict[str, str]] = {
    # --- privacidad ---------------------------------------------------------------------------------------------
    "privacy.strict": {
        "es": "Modo estricto: el perfil no contiene valores crudos del log; solo estadísticas, formas abstractas "
              "(letras→a, dígitos→9) y nombres de campos o parámetros.",
        "en": "Strict mode: the profile contains no raw log values; only statistics, abstract shapes "
              "(letters→a, digits→9) and field or parameter names.",
    },
    "privacy.enums": {
        "es": "Solo se listan valores de campos categóricos cuando todos pertenecen a un vocabulario técnico cerrado "
              "(métodos HTTP, códigos de estado, acciones como allow/deny).",
        "en": "Categorical values are listed only when all of them belong to a closed technical vocabulary "
              "(HTTP methods, status codes, actions such as allow/deny).",
    },
    # --- errores ---------------------------------------------------------------------------------------------------
    "err.unsupported_format": {
        "es": "Formato no soportado: '{ext}'. Formatos admitidos: CSV, TSV, JSON/NDJSON y Parquet (también .gz).",
        "en": "Unsupported format: '{ext}'. Supported: CSV, TSV, JSON/NDJSON and Parquet (also .gz).",
    },
    "err.unreadable": {
        "es": "No se pudo leer '{file}' como {fmt}: {error}",
        "en": "Could not read '{file}' as {fmt}: {error}",
    },
    "err.not_found": {"es": "No existe el archivo: {file}", "en": "File not found: {file}"},
    # --- avisos de calidad -----------------------------------------------------------------------------------------
    "warn.encoding_fallback": {
        "es": "El archivo no es UTF-8 válido; se leyó como {encoding} (típico de exportaciones de Excel en español).",
        "en": "The file is not valid UTF-8; it was read as {encoding} (typical of Spanish-locale Excel exports).",
    },
    "warn.schema_retry": {
        "es": "El esquema JSON varía a lo largo del archivo; se infirió leyendo el archivo completo.",
        "en": "The JSON schema varies across the file; it was inferred by reading the whole file.",
    },
    "warn.empty": {"es": "El archivo no contiene registros.", "en": "The file contains no records."},
    "warn.no_timestamp": {
        "es": "No se encontró ningún campo de fecha interpretable: la línea de tiempo no será posible sin ayuda.",
        "en": "No parseable date field was found: a timeline will not be possible without help.",
    },
    "warn.timestamp_ambiguous": {
        "es": "Fecha ambigua en '{field}': '{a}' y '{b}' interpretan los datos con resultados distintos. "
              "Confirma si el día va antes o después del mes.",
        "en": "Ambiguous date in '{field}': '{a}' and '{b}' both parse the data with different results. "
              "Confirm whether the day comes before or after the month.",
    },
    "warn.timestamp_rejected_alt": {
        "es": "En '{field}' se descartó '{fmt}': solo interpreta el {pct}% de los valores (indicio de orden día/mes "
              "distinto al esperado).",
        "en": "In '{field}', '{fmt}' was rejected: it only parses {pct}% of the values (hint of a day/month order "
              "different from expected).",
    },
    "warn.timestamp_partial": {
        "es": "Solo el {pct}% de '{field}' se interpreta con '{fmt}' en el archivo completo.",
        "en": "Only {pct}% of '{field}' parses with '{fmt}' across the whole file.",
    },
    "warn.timestamp_no_year": {
        "es": "'{field}' no incluye el año (formato tipo syslog): habrá que indicarlo al ingerir.",
        "en": "'{field}' has no year (syslog-like format): it must be supplied at ingestion.",
    },
    "warn.timezone_unknown": {
        "es": "'{field}' no indica zona horaria: se asumirá UTC hasta que se verifique.",
        "en": "'{field}' carries no time zone: UTC will be assumed until verified.",
    },
    "warn.secret_in_values": {
        "es": "'{field}' contiene credenciales o tokens dentro de sus valores (p. ej. parámetros: {keys}). "
              "Trátalos como expuestos.",
        "en": "'{field}' carries credentials or tokens inside its values (e.g. parameters: {keys}). "
              "Treat them as exposed.",
    },
    "warn.secret_field": {
        "es": "El nombre de '{field}' sugiere secretos (token, contraseña, clave).",
        "en": "The name of '{field}' suggests secrets (token, password, key).",
    },
    "warn.pii": {"es": "'{field}' contiene datos personales: {kinds}.", "en": "'{field}' contains personal data: {kinds}."},
    "warn.all_null": {"es": "'{field}' está vacío en todos los registros.", "en": "'{field}' is empty in every record."},
    "warn.high_nulls": {"es": "'{field}' está vacío en el {pct}% de los registros.",
                        "en": "'{field}' is empty in {pct}% of the records."},
    "warn.constant": {"es": "'{field}' tiene un único valor en todo el archivo.",
                      "en": "'{field}' holds a single value across the whole file."},
    "warn.fields_truncated": {
        "es": "Se perfilaron {kept} de {total} campos para respetar el límite de tamaño del perfil.",
        "en": "{kept} of {total} fields were profiled to respect the profile size limit.",
    },
    "warn.mapping_ambiguous": {
        "es": "Ambigüedad: '{canonical}' podría corresponder a {fields}.",
        "en": "Ambiguity: '{canonical}' could correspond to {fields}.",
    },
    "warn.request_line": {
        "es": "'{field}' contiene la línea completa de la petición HTTP (método, ruta y protocolo juntos): "
              "habrá que separarla al ingerir.",
        "en": "'{field}' holds the full HTTP request line (method, path and protocol together): "
              "it must be split at ingestion.",
    },
    "warn.constant.many": {"es": "{count} campos tienen un único valor en todo el archivo: {fields}.",
                           "en": "{count} fields hold a single value across the whole file: {fields}."},
    "warn.high_nulls.many": {
        "es": "{count} campos están vacíos en la mayoría de los registros (normal si cada tipo de evento trae campos "
              "distintos): {fields}.",
        "en": "{count} fields are empty in most records (normal when each event type carries different fields): "
              "{fields}.",
    },
    "warn.all_null.many": {"es": "{count} campos están vacíos en todos los registros: {fields}.",
                           "en": "{count} fields are empty in every record: {fields}."},
    "warn.pii.many": {"es": "{count} campos contienen datos personales: {fields}.",
                      "en": "{count} fields contain personal data: {fields}."},
    "warn.profile_trimmed": {
        "es": "El perfil se recortó para no superar {limit} KB: {omitted} campos sin mapear se listan solo por su "
              "nombre en 'unmapped_fields'.",
        "en": "The profile was trimmed to stay under {limit} KB: {omitted} unmapped fields are listed by name only "
              "in 'unmapped_fields'.",
    },
    # --- tipos de log ----------------------------------------------------------------------------------------------
    "log_type.web": {"es": "Acceso web / API", "en": "Web / API access"},
    "log_type.proxy": {"es": "Proxy web", "en": "Web proxy"},
    "log_type.firewall": {"es": "Firewall / flujo de red", "en": "Firewall / network flow"},
    "log_type.auth": {"es": "Autenticación / inicio de sesión", "en": "Authentication / logon"},
    "log_type.dns": {"es": "DNS", "en": "DNS"},
    "log_type.edr": {"es": "Telemetría de endpoint (EDR)", "en": "Endpoint telemetry (EDR)"},
    "log_type.unknown": {"es": "Desconocido", "en": "Unknown"},
}


def default_lang() -> str:
    lang = os.environ.get("DFIR_LANG", "es").strip().lower()[:2]
    return lang if lang in SUPPORTED else "es"


def resolve_lang(lang: str | None) -> str:
    value = (lang or default_lang()).strip().lower()[:2]
    if value not in SUPPORTED:
        raise ValueError(f"Idioma no soportado / unsupported language: {lang!r}. Usa {SUPPORTED}")
    return value


def t(key: str, lang: str | None = None, **kwargs) -> str:
    """Traduce `key` al idioma pedido y rellena sus marcadores."""
    entry = _MESSAGES.get(key)
    if entry is None:
        raise KeyError(f"mensaje sin definir: {key}")
    return entry[resolve_lang(lang)].format(**kwargs)


def placeholders(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name}


def catalog() -> dict[str, dict[str, str]]:
    return {k: dict(v) for k, v in _MESSAGES.items()}
