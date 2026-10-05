"""Ingesta genérica: archivo (CSV, TSV, JSON/NDJSON, Parquet; también .gz) + mapping YAML -> Parquet canónico + manifiesto.

El mapping dice qué columna (o ruta anidada `a.b.c`) alimenta cada campo canónico, cómo interpretar la fecha, qué
columnas derivar con expresiones regulares y qué roles tienen (actor, recurso). La lectura es la misma que usa el
perfilador (`profiling.readers`), así que lo que se perfiló es lo que se ingiere.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import yaml

from dfir_copilot.i18n import t
from dfir_copilot.profiling.readers import SourceError, leaf_exprs, open_source, relation_sql
from dfir_copilot.profiling.semantics import es_to_en_months
from dfir_copilot.schema import CANONICAL_FIELDS

MAPPINGS_DIR = Path(__file__).parent / "mappings"
_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_TYPES = {"VARCHAR", "BIGINT", "INTEGER", "SMALLINT", "DOUBLE"}
_SCHEMA = {f.name: f.dtype for f in CANONICAL_FIELDS}
_SPECIAL_INPUTS = {"timestamp", "uri", "request_line"}  # entradas que no son campos canónicos directos
_ROLES = ("actor", "resource")  # qué columna es quién actúa y sobre qué (ver detectors/roles.py)
FORMATS = ("auto", "csv", "tsv", "json", "parquet")
TIMESTAMP_SPECIAL = ("iso8601", "epoch_s", "epoch_ms", "native")
_NESTED_KINDS = ("STRUCT", "MAP")


class OutputCollision(FileExistsError):
    """La carpeta de salida ya contiene el resultado de otro archivo de entrada."""


def _q(name: str) -> str:
    """Cita un identificador SQL."""
    return '"' + name.replace('"', '""') + '"'


def _lit(value: str) -> str:
    """Cita un literal de texto SQL."""
    return "'" + value.replace("'", "''") + "'"


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def _check_regex(name: str, regex: str) -> None:
    """Valida la regex con el propio motor (RE2) y exige un grupo de captura: sin él devolvería siempre vacío."""
    try:
        duckdb.connect().execute("SELECT regexp_extract('', ?, 1)", [regex])
    except duckdb.Error as exc:
        raise ValueError(f"'{name}': regex inválida: {str(exc).splitlines()[0]}") from exc
    try:
        groups = re.compile(regex).groups
    except re.error:  # sintaxis válida en RE2 pero no en Python: no se pueden contar los grupos
        return
    if groups < 1:
        raise ValueError(f"'{name}': la regex necesita un grupo de captura, p. ej. 'clave=([^&]+)'")


def _validate(m: dict) -> None:
    for key in ("source", "format", "fields", "timestamp"):
        if key not in m:
            raise ValueError(f"Mapping inválido: falta '{key}'")
    if m["format"] not in FORMATS:
        raise ValueError(f"Formato no soportado en el mapping: {m['format']!r} (válidos: {', '.join(FORMATS)})")
    fields = m["fields"]
    if "timestamp" not in fields:
        raise ValueError("fields debe incluir 'timestamp'")
    if "uri" not in fields and "endpoint" not in fields and "request_line" not in fields:
        raise ValueError("fields debe incluir 'uri' o 'endpoint' (o 'request_line', la petición HTTP completa)")
    for canon in fields:
        if canon not in _SCHEMA and canon not in _SPECIAL_INPUTS:
            raise ValueError(f"Campo desconocido en fields: {canon}")
    if "request_line" in fields:
        both = [c for c in ("uri", "http_method") if c in fields]
        if "uri" in fields and "http_method" in fields:
            raise ValueError("request_line ya aporta uri y http_method: quita " + " y ".join(both) + " de fields")
    ts = m["timestamp"]
    if not isinstance(ts, dict) or "format" not in ts:
        raise ValueError("timestamp requiere 'format' (strptime, o: " + ", ".join(TIMESTAMP_SPECIAL) + ")")
    roles = m.get("roles")
    if roles is not None:
        if not isinstance(roles, dict):
            raise ValueError(t("ingest.err.bad_roles", detail="debe ser un diccionario {actor: columna, resource: columna}"))
        outputs = set(_SCHEMA) | set(m.get("derived", {}))
        for role, col in roles.items():
            if role not in _ROLES:
                raise ValueError(t("ingest.err.bad_roles", detail=f"rol desconocido '{role}' (válidos: {_ROLES})"))
            if col not in outputs:
                raise ValueError(t("ingest.err.bad_roles", detail=f"'{role}: {col}' no es una columna del resultado"))
    for name, spec in m.get("derived", {}).items():
        if not _IDENT.match(name):
            raise ValueError(f"Nombre derivado inválido: {name}")
        if name not in _SCHEMA and not name.startswith("x_"):
            raise ValueError(f"'{name}' debe ser un campo canónico o empezar por x_")
        if "from" not in spec or "regex" not in spec:
            raise ValueError(f"'{name}' requiere 'from' y 'regex'")
        if spec.get("type", "VARCHAR").upper() not in _TYPES:
            raise ValueError(f"Tipo no permitido en '{name}': {spec['type']}")
        _check_regex(name, spec["regex"])


def load_mapping(source: str, path: str | Path | None = None) -> dict:
    """Carga un mapping por nombre (carpeta del paquete) o desde una ruta concreta (p. ej. la copia del caso)."""
    path = Path(path) if path else MAPPINGS_DIR / f"{source}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No existe el mapping: {path}")
    mapping = yaml.safe_load(path.read_text(encoding="utf-8"))
    _validate(mapping)
    mapping["_path"] = str(path)
    mapping["_sha256"] = sha256_file(path)
    return mapping


# --- construcción de la consulta ------------------------------------------------------------------------------
def _resolve(path: str, leaves: dict, what: str) -> tuple[str, str]:
    if path in leaves:
        return leaves[path]
    close = difflib.get_close_matches(path, list(leaves), n=3, cutoff=0.5)
    hint = f" ¿Quisiste decir: {', '.join(close)}?" if close else ""
    raise ValueError(f"'{what}' apunta a '{path}', que no existe en el origen.{hint}")


def _text(expr: str, dtype: str) -> str:
    """Expresión de texto: las estructuras y listas se serializan, el resto se convierte."""
    return f"CAST({expr} AS VARCHAR)"


def _cast(expr: str, source_type: str, dtype: str) -> str:
    nested = source_type.upper().startswith(_NESTED_KINDS) or source_type.endswith("]")
    inner = _text(expr, source_type) if nested else expr
    return f"TRY_CAST({inner} AS {dtype})"


def _timestamp_expr(expr: str, source_type: str, ts: dict) -> str:
    """TIMESTAMPTZ (UTC) a partir de la columna de fecha según `timestamp.format` del mapping."""
    fmt, tz = ts["format"], ts.get("timezone", "UTC")
    if fmt == "native":
        if source_type == "TIMESTAMP WITH TIME ZONE":
            return expr
        if source_type == "TIMESTAMP":
            return f"({expr} AT TIME ZONE {_lit(tz)})"
        raise ValueError(f"timestamp.format 'native' exige una columna de fecha tipada, no {source_type}")
    if fmt in ("epoch_s", "epoch_ms"):
        num = f"TRY_CAST({expr} AS DOUBLE)"
        lo, hi, div = ("1e9", "2.2e9", "") if fmt == "epoch_s" else ("1e12", "2.2e12", " / 1000.0")
        return f"CASE WHEN {num} BETWEEN {lo} AND {hi} THEN to_timestamp({num}{div}) END"
    v = _text(expr, source_type)
    if fmt == "iso8601":
        if ts.get("timezone_in_data"):
            return f"TRY_CAST({v} AS TIMESTAMPTZ)"
        return f"(TRY_CAST({v} AS TIMESTAMP) AT TIME ZONE {_lit(tz)})"
    src = es_to_en_months(v) if "%b" in fmt else v  # meses en español: ene, abr, ago, dic…
    parsed = f"try_strptime({src}, {_lit(fmt)})"
    return parsed if "%z" in fmt else f"({parsed} AT TIME ZONE {_lit(tz)})"


def _derived_expr(spec: dict, dtype: str, base: dict) -> str:
    if spec["from"] not in base:
        raise ValueError(f"'from: {spec['from']}' no existe entre las columnas base")
    return (
        f"TRY_CAST(NULLIF(regexp_extract({_q(spec['from'])}, {_lit(spec['regex'])}, 1), '') "
        f"AS {dtype})"
    )


def build_query(m: dict, rel: str, leaves: dict) -> str:
    """Consulta que normaliza la fuente `rel` al esquema canónico. `leaves`: ver `profiling.readers.leaf_exprs`."""
    fields, derived, ts = m["fields"], m.get("derived", {}), m["timestamp"]

    # Capa 1: columnas base (nombre -> expresión SQL sobre el alias `src`)
    ts_expr, ts_type = _resolve(fields["timestamp"], leaves, "timestamp")
    base: dict[str, str] = {
        "timestamp_raw": _text(ts_expr, ts_type),
        "timestamp_utc": _timestamp_expr(ts_expr, ts_type, ts),
    }
    uri_sql = None
    if "request_line" in fields:  # "GET /ruta?x=1 HTTP/1.1" -> método + ruta
        rl_expr, rl_type = _resolve(fields["request_line"], leaves, "request_line")
        rl = _text(rl_expr, rl_type)
        uri_sql = f"NULLIF(regexp_extract({rl}, '^[A-Z]+ (\\S+)', 1), '')"
        base["http_method"] = f"NULLIF(regexp_extract({rl}, '^([A-Z]+) ', 1), '')"
    elif "uri" in fields:
        u_expr, u_type = _resolve(fields["uri"], leaves, "uri")
        uri_sql = _text(u_expr, u_type)
    if uri_sql is not None:
        base["endpoint"] = f"split_part({uri_sql}, '?', 1)"
        base["query_string"] = f"CASE WHEN strpos({uri_sql}, '?') > 0 THEN substr({uri_sql}, strpos({uri_sql}, '?') + 1) END"
    for canon, col in fields.items():
        if canon in _SPECIAL_INPUTS:
            continue
        expr, typ = _resolve(col, leaves, canon)
        base[canon] = _cast(expr, typ, _SCHEMA[canon])
    # Columnas de origen que alimentan derivadas sin ser columnas base (p. ej. una ruta anidada o la línea de comandos)
    for n, spec in derived.items():
        if spec["from"] not in base:
            expr, typ = _resolve(spec["from"], leaves, f"{n}.from")
            base[spec["from"]] = _text(expr, typ)

    # Capa 2: salida final = canónicas (en orden) + timestamp_raw + derivadas x_
    items = []
    for fld in CANONICAL_FIELDS:
        n = fld.name
        if n == "source_row":
            expr = "source_row"
        elif n in derived:
            expr = _derived_expr(derived[n], fld.dtype, base)
        elif n in base:
            expr = _q(n)
        else:
            expr = f"CAST(NULL AS {fld.dtype})"
        items.append(f"{expr} AS {_q(n)}")
    items.append("timestamp_raw")
    for n, spec in derived.items():
        if n not in _SCHEMA:
            dtype = spec.get("type", "VARCHAR").upper()
            items.append(f"{_derived_expr(spec, dtype, base)} AS {_q(n)}")

    base_cols = ",\n        ".join(f"{expr} AS {_q(name)}" for name, expr in base.items())
    return f"""
    WITH src AS (
      SELECT CAST(row_number() OVER () AS BIGINT) AS source_row, *
      FROM {rel}
    ),
    base AS (
      SELECT source_row,
        {base_cols}
      FROM src
    )
    SELECT {', '.join(items)}
    FROM base
    ORDER BY timestamp_utc, source_row
    """


def _base_name(path: Path) -> str:
    """`export.ndjson.gz` -> `export` (el nombre del Parquet no arrastra la extensión del origen)."""
    name = path.name
    for _ in range(2):
        stem, dot, ext = name.rpartition(".")
        if dot and stem and ext.lower() in {"gz", "gzip", "zst", "csv", "tsv", "json", "jsonl", "ndjson", "log", "txt",
                                           "parquet", "pq", "tab"}:
            name = stem
    return name


def ingest_file(
    path: str | Path,
    source: str,
    out_dir: str | Path = "/workspace/data/processed",
    memory_limit: str = "2GB",
    mapping_path: str | Path | None = None,
    overwrite: bool = False,
) -> dict:
    """Normaliza un archivo (CSV, TSV, JSON/NDJSON, Parquet; también .gz) a Parquet canónico y escribe un manifiesto.

    Re-ingerir el MISMO archivo en la misma carpeta es idempotente; ingerir OTRO archivo con el mismo nombre en una
    carpeta que ya tiene resultado se rechaza (antes sobrescribía el Parquet del primero sin avisar).
    """
    in_path = Path(path).resolve()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    mapping = load_mapping(source, mapping_path)
    stem = _base_name(in_path)
    parquet_path = out_dir / f"{stem}.parquet"
    manifest_path = out_dir / f"{stem}.manifest.json"

    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    con.execute(f"SET memory_limit = {_lit(memory_limit)}")
    con.execute(f"SET temp_directory = {_lit(str(out_dir / '.duckdb_tmp'))}")
    con.execute("SET preserve_insertion_order = true")

    sha_in = sha256_file(in_path)
    if manifest_path.exists() and not overwrite:
        previous = json.loads(manifest_path.read_text(encoding="utf-8")).get("input", {}).get("sha256")
        if previous and previous != sha_in:
            raise OutputCollision(t("ingest.err.collision", out=out_dir, old=previous[:12], new=sha_in[:12]))

    fmt = None if mapping["format"] == "auto" else mapping["format"]
    spec, rows_in, _notes = open_source(con, in_path, fmt=fmt)
    while True:  # un JSON puede cambiar de tipo después de la muestra con que se infirió el esquema
        rel = relation_sql(spec, explicit=True)
        query = build_query(mapping, rel, leaf_exprs(con, rel))
        try:
            con.execute(f"COPY ({query}) TO {_lit(str(parquet_path))} (FORMAT PARQUET, COMPRESSION ZSTD)")
            break
        except duckdb.Error as exc:
            if spec.format != "json" or spec.json_full_schema or "Conversion Error" not in str(exc) \
                    and "JSON transform error" not in str(exc):
                raise
            spec = replace(spec, json_full_schema=True)

    # Reporte de calidad sobre el Parquet resultante
    pq = f"read_parquet({_lit(str(parquet_path))})"
    cols = [r[0] for r in con.execute(f"DESCRIBE SELECT * FROM {pq}").fetchall()]
    nulls_sql = ", ".join(f"count(*) FILTER (WHERE {_q(c)} IS NULL)" for c in cols)
    row = con.execute(
        f"SELECT count(*), CAST(min(timestamp_utc) AS VARCHAR), "
        f"CAST(max(timestamp_utc) AS VARCHAR), {nulls_sql} FROM {pq}"
    ).fetchone()
    rows_out, ts_min, ts_max, *null_list = row
    null_counts = dict(zip(cols, null_list, strict=True))
    con.close()

    tz_cfg = mapping["timestamp"]
    warnings = []
    if rows_in != rows_out:
        warnings.append(f"Filas de entrada ({rows_in}) distintas de salida ({rows_out})")
    if null_counts["timestamp_utc"]:
        warnings.append(f"{null_counts['timestamp_utc']} filas con timestamp no interpretable")
    if not tz_cfg.get("timezone_verified", False):
        warnings.append(f"Zona horaria NO verificada: se asumió {tz_cfg.get('timezone', 'UTC')}")
    for name in mapping.get("derived", {}):
        if rows_out and null_counts.get(name) == rows_out:
            warnings.append(t("ingest.warn.derived_empty", name=name))

    manifest = {
        "manifest_version": 1,
        "source": source,
        "ingested_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "duckdb_version": duckdb.__version__,
        "input": {
            "path": str(in_path),
            "bytes": in_path.stat().st_size,
            "sha256": sha_in,
            "rows": rows_in,
            "format": spec.format,
            "compression": spec.compression,
            "encoding": spec.encoding,
        },
        "output": {
            "path": str(parquet_path),
            "bytes": parquet_path.stat().st_size,
            "sha256": sha256_file(parquet_path),
            "rows": rows_out,
        },
        "mapping": {"path": mapping["_path"], "sha256": mapping["_sha256"]},
        "roles": mapping.get("roles"),  # qué columnas son actor y recurso para los detectores
        "timezone": {
            "assumed": tz_cfg.get("timezone", "UTC"),
            "verified": bool(tz_cfg.get("timezone_verified", False)),
        },
        "time_range_utc": [ts_min, ts_max],
        "null_counts": null_counts,
        "warnings": warnings,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def ingest_csv(csv_path: str | Path, *args, **kwargs) -> dict:
    """Nombre histórico de `ingest_file` (acepta cualquier formato soportado)."""
    return ingest_file(csv_path, *args, **kwargs)


__all__ = ["FORMATS", "MAPPINGS_DIR", "OutputCollision", "SourceError", "build_query", "ingest_csv", "ingest_file",
           "load_mapping", "sha256_file"]
