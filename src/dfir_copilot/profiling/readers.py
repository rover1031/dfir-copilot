"""Lectura agnóstica de fuentes con DuckDB: CSV, TSV, JSON/NDJSON (también arreglos) y Parquet, comprimidos o no.

Nada se carga entero en RAM: DuckDB recorre los archivos en streaming. Este módulo solo decide CÓMO leer
(formato, codificación, dialecto) y valida que se puede leer completo.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import duckdb

from dfir_copilot.profiling.i18n import t

_FORMATS = {".csv": "csv", ".txt": "csv", ".log": "csv", ".tsv": "tsv", ".tab": "tsv",
            ".json": "json", ".jsonl": "json", ".ndjson": "json", ".parquet": "parquet", ".pq": "parquet"}
_COMPRESSIONS = {".gz": "gzip", ".gzip": "gzip", ".zst": "zstd"}
ENCODINGS = ("utf-8", "latin-1")  # latin-1 cubre las exportaciones de Excel en español (Windows-1252 es casi igual)


class SourceError(Exception):
    """El archivo no existe, no se puede leer o su formato no está soportado."""


@dataclass(frozen=True)
class SourceSpec:
    path: str
    format: str  # csv | tsv | json | parquet
    compression: str | None = None
    encoding: str | None = None
    delimiter: str | None = None
    has_header: bool | None = None
    json_full_schema: bool = False


def _lit(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def detect_format(path: str | Path, lang: str | None = None) -> tuple[str, str | None]:
    p = Path(path)
    suffixes = [s.lower() for s in p.suffixes]
    compression = _COMPRESSIONS.get(suffixes[-1]) if suffixes else None
    core = suffixes[-2] if compression and len(suffixes) >= 2 else (suffixes[-1] if suffixes else "")
    if core in _FORMATS:
        return _FORMATS[core], compression
    if not compression and p.exists():  # sin extensión conocida: mira los primeros bytes
        head = p.open("rb").read(4)
        if head == b"PAR1":
            return "parquet", None
        if head.lstrip()[:1] in (b"{", b"["):
            return "json", None
    raise SourceError(t("err.unsupported_format", lang, ext=core or p.name))


def relation_sql(spec: SourceSpec) -> str:
    """Función de tabla de DuckDB para leer la fuente. Los CSV se leen como texto: el perfilado decide los tipos."""
    path = _lit(spec.path)
    if spec.format == "parquet":
        return f"read_parquet({path})"
    if spec.format == "json":
        # map_inference_threshold=-1: objetos con muchas claves siguen siendo columnas (no un único MAP opaco)
        extra = ", sample_size=-1" if spec.json_full_schema else ""
        return f"read_json_auto({path}, format='auto', map_inference_threshold=-1{extra})"
    opts = ["all_varchar=true", f"encoding={_lit(spec.encoding or 'utf-8')}"]
    if spec.format == "tsv":
        opts.append("delim='\\t'")
    return f"read_csv({path}, {', '.join(opts)})"


def open_source(con: duckdb.DuckDBPyConnection, path: str | Path, lang: str | None = None,
                fmt: str | None = None) -> tuple[SourceSpec, int, list[tuple[str, dict]]]:
    """Decide cómo leer la fuente y la recorre entera una vez (conteo). Devuelve (spec, filas, avisos)."""
    p = Path(path)
    if not p.exists():
        raise SourceError(t("err.not_found", lang, file=p.name))
    detected, compression = detect_format(p, lang) if fmt is None else (fmt, None)
    base = SourceSpec(str(p.resolve()), detected, compression)
    notes: list[tuple[str, dict]] = []
    last_error: Exception | None = None

    if detected in ("csv", "tsv"):
        for encoding in ENCODINGS:
            spec = replace(base, encoding=encoding)
            try:
                rows = con.execute(f"SELECT count(*) FROM {relation_sql(spec)}").fetchone()[0]
                delim = ", delim='\\t'" if detected == "tsv" else ""
                sniff = con.execute(f"SELECT Delimiter, HasHeader FROM sniff_csv({_lit(spec.path)}, "
                                    f"encoding={_lit(encoding)}{delim})").fetchone()
                spec = replace(spec, delimiter=sniff[0], has_header=bool(sniff[1]))
                if encoding != "utf-8":
                    notes.append(("warn.encoding_fallback", {"encoding": encoding}))
                return spec, rows, notes
            except duckdb.Error as exc:
                last_error = exc
    elif detected == "json":
        for full in (False, True):
            spec = replace(base, json_full_schema=full)
            try:
                rows = con.execute(f"SELECT count(*) FROM {relation_sql(spec)}").fetchone()[0]
                if full:
                    notes.append(("warn.schema_retry", {}))
                return spec, rows, notes
            except duckdb.Error as exc:
                last_error = exc
    else:
        try:
            rows = con.execute(f"SELECT count(*) FROM {relation_sql(base)}").fetchone()[0]
            return base, rows, notes
        except duckdb.Error as exc:
            last_error = exc
    raise SourceError(t("err.unreadable", lang, file=p.name, fmt=detected,
                        error=str(last_error).splitlines()[0][:200])) from last_error
