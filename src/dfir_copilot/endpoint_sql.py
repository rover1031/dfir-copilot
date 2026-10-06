"""Expresiones SQL compartidas para logs de endpoint. Las usan la seudonimización (para crear `<col>_base` y `<col>_flags` en la copia)
y los detectores (para calcularlas sobre los datos reales): una sola definición, así ambas copias dan exactamente lo mismo.

* `basename_sql`: el nombre del ejecutable sin ruta y en minúsculas (`\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe` -> `rundll32.exe`).
* `cmd_flags_sql`: señales técnicas de una línea de comandos, sin revelar su contenido (que puede llevar usuarios, equipos o secretos).
"""
from __future__ import annotations

CMD_FLAGS = (
    ("encoded", r"(?i)\s-(e|en|enc|enco|encodedcommand)\s+[a-z0-9+/=]{16,}"),
    ("download", r"(?i)(downloadstring|downloadfile|invoke-webrequest|\biwr\b|\bwget\b|\bcurl\b|urlcache|bitstransfer|/transfer)"),
    ("hidden", r"(?i)\s-w(indowstyle)?\s+hidden"),
    ("bypass", r"(?i)(executionpolicy\s+bypass|\s-ep\s+bypass|\s-nop(rofile)?\b)"),
    ("script_proxy", r"(?i)(mshta|regsvr32|rundll32)(\.exe)?\s.*(https?:|javascript:|scrobj|\.sct)"),
)


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


_BASENAME_RE = r"[^\\/]+$"  # lo que va después de la última barra (\ o /)


def basename_sql(expr: str) -> str:
    return f"NULLIF(lower(regexp_extract(CAST({expr} AS VARCHAR), {_lit(_BASENAME_RE)}, 0)), '')"


def cmd_flags_sql(expr: str) -> str:
    parts = ", ".join(f"CASE WHEN regexp_matches(CAST({expr} AS VARCHAR), {_lit(rx)}) THEN {_lit(name)} END" for name, rx in CMD_FLAGS)
    return f"NULLIF(concat_ws(',', {parts}), '')"
