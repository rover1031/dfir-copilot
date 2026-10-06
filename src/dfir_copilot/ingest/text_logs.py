"""Logs de texto por líneas -> CSV derivados que el resto del pipeline ya sabe analizar. Mismo enfoque que Excel: el archivo original
queda como evidencia con su hash y cada CSV derivado registra en la custodia de qué archivo y de qué formato sale.

Formatos reconocidos (se detectan solos mirando las primeras líneas):
* **Syslog de Palo Alto PAN-OS**, logs TRAFFIC y THREAT (con o sin cabecera syslog RFC 3164/5424 delante). Posiciones de campo según
  la documentación oficial de PAN-OS (iguales en 9.1, 10.x y 11.x para los campos que se usan): 1 Receive Time, 2 Serial Number,
  3 Type, 4 Subtype, 6 Generated Time, 7 Source Address, 8 Destination Address, 11 Rule Name, 12 Source User, 14 Application,
  16/17 zonas, 22 Session ID, 24/25 puertos, 29 Protocol, 30 Action; en TRAFFIC 32/33 Bytes Sent/Received y 52 Device Name; en THREAT
  31 URL/Filename, 32 Threat ID, 33 Category, 34 Severity. TRAFFIC y THREAT salen en CSV distintos (un caso cada uno). La URL y la
  categoría de THREAT se conservan en el CSV derivado, pero el análisis de proxy y DNS llega en la entrega C.
* **Logs de acceso Nginx/Apache** (formato "combined" y "common"): la hora lleva su desfase (`-0500`), así que la zona viene en el dato.

Las líneas que no encajan se cuentan y se informan; nunca se descartan en silencio.
"""
from __future__ import annotations

import csv
import io
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

TEXT_SUFFIXES = (".log", ".txt")
_PAN = re.compile(r"(?:^|[\s>])(\d*,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},[^,]*,(TRAFFIC|THREAT),.*)$")
_COMBINED = re.compile(r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: (\S+))?" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?')
_SNIFF = 50
_CHUNK_HINT = "se reconocen: syslog de Palo Alto PAN-OS (TRAFFIC y THREAT) y logs de acceso de Nginx/Apache"

PAN_TRAFFIC = ("Generated Time", "Source address", "Source Port", "Destination address", "Destination Port", "IP Protocol", "Action",
               "Bytes Sent", "Bytes Received", "Rule", "Source User", "Application", "Device Name", "Source Zone", "Destination Zone",
               "Session ID", "Subtype")
PAN_THREAT = ("Generated Time", "Source address", "Source Port", "Destination address", "Destination Port", "IP Protocol", "Action",
              "Rule", "Source User", "Application", "Device Name", "Source Zone", "Destination Zone", "Session ID", "Subtype",
              "URL o archivo", "Threat ID", "Categoria", "Severidad")
COMBINED = ("timestamp", "remote_addr", "remote_user", "method", "uri", "protocol", "status", "body_bytes_sent", "http_referer",
            "http_user_agent")


class TextLogError(ValueError):
    """Formato de texto no reconocido o sin ninguna línea válida."""


def _lines(path: Path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if line.strip():
                yield line


def detect(path: str | Path) -> str | None:
    """'panos' | 'combined' | None, mirando las primeras líneas con contenido."""
    pan = combined = 0
    for i, line in enumerate(_lines(Path(path))):
        if i >= _SNIFF:
            break
        pan += bool(_PAN.search(line))
        combined += bool(_COMBINED.match(line))
    if pan and pan >= combined:
        return "panos"
    return "combined" if combined else None


def _dash(v: str) -> str:
    return "" if v == "-" else v


def _panos(path: Path, target_for: Callable[[str], Path]) -> list[dict]:
    writers, files, counts, skipped = {}, {}, {"TRAFFIC": 0, "THREAT": 0}, 0
    try:
        for line in _lines(path):
            m = _PAN.search(line)
            f = next(csv.reader(io.StringIO(m.group(1)))) if m else []
            kind = f[3] if len(f) > 3 else None
            if kind not in counts or len(f) < (34 if kind == "TRAFFIC" else 35):
                skipped += 1
                continue
            if kind not in writers:
                files[kind] = target_for(kind.lower())
                fh = files[kind].open("w", newline="", encoding="utf-8")
                writers[kind] = (fh, csv.writer(fh))
                writers[kind][1].writerow(PAN_TRAFFIC if kind == "TRAFFIC" else PAN_THREAT)
            device = f[52] if len(f) > 52 and f[52] else f[2]
            common = [f[6], f[7], f[24], f[8], f[25], f[29], f[30]]
            if kind == "TRAFFIC":
                row = [*common, f[32], f[33], f[11], f[12], f[14], device, f[16], f[17], f[22], f[4]]
            else:
                row = [*common, f[11], f[12], f[14], device, f[16], f[17], f[22], f[4], f[31], f[32], f[33], f[34]]
            writers[kind][1].writerow(row)
            counts[kind] += 1
    finally:
        for fh, _ in writers.values():
            fh.close()
    if not files:
        raise TextLogError(f"Ninguna línea de PAN-OS TRAFFIC o THREAT válida ({skipped} descartada/s)")
    return [{"format": f"panos-{k.lower()}", "path": p, "rows": counts[k], "skipped": skipped} for k, p in files.items()]


def _combined(path: Path, target_for: Callable[[str], Path]) -> list[dict]:
    target, rows, skipped = target_for("acceso"), 0, 0
    with target.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COMBINED)
        for line in _lines(path):
            m = _COMBINED.match(line)
            try:
                ts = datetime.strptime(m.group(3), "%d/%b/%Y:%H:%M:%S %z").isoformat() if m else None
            except ValueError:
                ts = None
            if not ts:
                skipped += 1
                continue
            g = m.groups()
            w.writerow([ts, g[0], _dash(g[1]), g[3], g[4], g[5] or "", g[6], _dash(g[7]), _dash(g[8] or ""), _dash(g[9] or "")])
            rows += 1
    if not rows:
        target.unlink()
        raise TextLogError(f"Ninguna línea de log de acceso válida ({skipped} descartada/s)")
    return [{"format": "access-combined", "path": target, "rows": rows, "skipped": skipped}]


def text_to_csv(path: str | Path, target_for: Callable[[str], Path]) -> list[dict]:
    """Convierte un log de texto. `target_for(etiqueta)` da la ruta de cada CSV. Lanza TextLogError si no se reconoce."""
    path = Path(path)
    kind = detect(path)
    if kind == "panos":
        return _panos(path, target_for)
    if kind == "combined":
        return _combined(path, target_for)
    raise TextLogError(f"Formato de texto no reconocido ({_CHUNK_HINT})")
