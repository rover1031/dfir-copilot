"""Ingesta genérica: CSV + mapping YAML -> Parquet canónico + manifiesto de custodia."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import yaml

from dfir_copilot.schema import CANONICAL_FIELDS

MAPPINGS_DIR = Path(__file__).parent / "mappings"
_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_TYPES = {"VARCHAR", "BIGINT", "INTEGER", "SMALLINT", "DOUBLE"}
_SCHEMA = {f.name: f.dtype for f in CANONICAL_FIELDS}
_SPECIAL_INPUTS = {"timestamp", "uri"}  # entradas que no son campos canónicos directos


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
    if m["format"] != "csv":
        raise ValueError("Este ingestor solo soporta format: csv")
    fields = m["fields"]
    if "timestamp" not in fields:
        raise ValueError("fields debe incluir 'timestamp'")
    if "uri" not in fields and "endpoint" not in fields:
        raise ValueError("fields debe incluir 'uri' o 'endpoint'")
    for canon in fields:
        if canon not in _SCHEMA and canon not in _SPECIAL_INPUTS:
            raise ValueError(f"Campo desconocido en fields: {canon}")
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


def load_mapping(source: str) -> dict:
    path = MAPPINGS_DIR / f"{source}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No existe el mapping: {path}")
    mapping = yaml.safe_load(path.read_text(encoding="utf-8"))
    _validate(mapping)
    mapping["_path"] = str(path)
    mapping["_sha256"] = sha256_file(path)
    return mapping


def _derived_expr(spec: dict, dtype: str, base: dict) -> str:
    if spec["from"] not in base:
        raise ValueError(f"'from: {spec['from']}' no existe entre las columnas base")
    return (
        f"TRY_CAST(NULLIF(regexp_extract({spec['from']}, {_lit(spec['regex'])}, 1), '') "
        f"AS {dtype})"
    )


def build_query(m: dict, csv_path: Path) -> str:
    fields, derived, ts = m["fields"], m.get("derived", {}), m["timestamp"]

    # Capa 1: columnas base (nombre -> expresión SQL sobre las columnas del origen)
    base: dict[str, str] = {
        "timestamp_raw": _q(fields["timestamp"]),
        "timestamp_utc": (
            f"(try_strptime({_q(fields['timestamp'])}, {_lit(ts['format'])}) "
            f"AT TIME ZONE {_lit(ts.get('timezone', 'UTC'))})"
        ),
    }
    if "uri" in fields:
        u = _q(fields["uri"])
        base["endpoint"] = f"split_part({u}, '?', 1)"
        base["query_string"] = (
            f"CASE WHEN strpos({u}, '?') > 0 THEN substr({u}, strpos({u}, '?') + 1) END"
        )
    for canon, col in fields.items():
        if canon in _SPECIAL_INPUTS:
            continue
        base[canon] = f"TRY_CAST({_q(col)} AS {_SCHEMA[canon]})"

    # Capa 2: salida final = canónicas (en orden) + timestamp_raw + derivadas x_
    items = []
    for fld in CANONICAL_FIELDS:
        n = fld.name
        if n == "source_row":
            expr = "source_row"
        elif n in derived:
            expr = _derived_expr(derived[n], fld.dtype, base)
        elif n in base:
            expr = n
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
      FROM read_csv({_lit(str(csv_path))}, header = true, all_varchar = true)
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


def ingest_csv(
    csv_path: str | Path,
    source: str,
    out_dir: str | Path = "/workspace/data/processed",
    memory_limit: str = "2GB",
) -> dict:
    """Normaliza un CSV a Parquet canónico y escribe un manifiesto de custodia."""
    csv_path = Path(csv_path).resolve()
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    mapping = load_mapping(source)
    parquet_path = out_dir / f"{csv_path.stem}.parquet"
    manifest_path = out_dir / f"{csv_path.stem}.manifest.json"

    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    con.execute(f"SET memory_limit = {_lit(memory_limit)}")
    con.execute(f"SET temp_directory = {_lit(str(out_dir / '.duckdb_tmp'))}")
    con.execute("SET preserve_insertion_order = true")

    sha_in = sha256_file(csv_path)
    rows_in = con.execute(
        f"SELECT count(*) FROM read_csv({_lit(str(csv_path))}, header = true, all_varchar = true)"
    ).fetchone()[0]

    query = build_query(mapping, csv_path)
    con.execute(
        f"COPY ({query}) TO {_lit(str(parquet_path))} (FORMAT PARQUET, COMPRESSION ZSTD)"
    )

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

    manifest = {
        "manifest_version": 1,
        "source": source,
        "ingested_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "duckdb_version": duckdb.__version__,
        "input": {
            "path": str(csv_path),
            "bytes": csv_path.stat().st_size,
            "sha256": sha_in,
            "rows": rows_in,
        },
        "output": {
            "path": str(parquet_path),
            "bytes": parquet_path.stat().st_size,
            "sha256": sha256_file(parquet_path),
            "rows": rows_out,
        },
        "mapping": {"path": mapping["_path"], "sha256": mapping["_sha256"]},
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
