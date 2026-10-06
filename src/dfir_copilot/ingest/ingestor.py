"""Ingesta genérica: archivo (CSV, TSV, JSON/NDJSON, Parquet; también .gz) + mapping YAML -> Parquet canónico + manifiesto.

El mapping dice qué columna (o ruta anidada `a.b.c`) alimenta cada campo canónico, cómo interpretar la fecha, qué
columnas derivar con expresiones regulares y qué roles tienen (actor, recurso). La lectura es la misma que usa el
perfilador (`profiling.readers`), así que lo que se perfiló es lo que se ingiere.
"""
from __future__ import annotations

import difflib
import functools
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
from dfir_copilot.schema import CANONICAL_FIELDS, ENDPOINT_FIELDS, NETWORK_FIELDS, SCHEMAS

MAPPINGS_DIR = Path(__file__).parent / "mappings"
_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")
_TYPES = {"VARCHAR", "BIGINT", "INTEGER", "SMALLINT", "DOUBLE"}
_SCHEMA = {f.name: f.dtype for f in (*CANONICAL_FIELDS, *NETWORK_FIELDS, *ENDPOINT_FIELDS)}
_SPECIAL_INPUTS = {"timestamp", "uri", "request_line"}  # entradas que no son campos canónicos directos
_ROLES = ("actor", "resource")  # qué columna es quién actúa y sobre qué (ver detectors/roles.py)
FORMATS = ("auto", "csv", "tsv", "json", "parquet")
TIMESTAMP_SPECIAL = ("iso8601", "epoch_s", "epoch_ms", "native")
_NESTED_KINDS = ("STRUCT", "MAP")
# Zona horaria (ver `check_timezone` y docs/zona_horaria.md)
TIMESTAMP_KEYS = ("format", "timezone", "timezone_verified", "timezone_in_data", "timezone_source", "timezone_note",
                  "timezone_fixed_offset")
TIMEZONE_SOURCES = ("in_data", "declared", "default")
_UTC_LIKE = {"UTC", "Etc/UTC", "Etc/UCT", "UCT", "GMT", "Etc/GMT", "Etc/GMT0", "Etc/GMT+0", "Etc/GMT-0", "GMT0", "Etc/Zulu",
             "Zulu", "Etc/Universal", "Universal", "Etc/Greenwich", "Greenwich"}
# Desfases fijos con aspecto de región: EST es -05:00 TODO el año (Nueva York es America/New_York); en Etc/GMT el signo va
# al revés (Etc/GMT+3 = UTC-03:00). Se rechazan salvo `timezone_fixed_offset: true`.
_FIXED_OFFSET = re.compile(r"^(?:Etc/GMT[+-]\d{1,2}|EST|MST|HST)$")
_ETC_SIGN = re.compile(r"^Etc/GMT([+-])(\d{1,2})$")
# Ventanas en las que una hora local puede repetirse o no existir: las transiciones reales son de 30 min, 1 h o 2 h.
_DST_STEPS = ("30 MINUTE", "1 HOUR", "2 HOUR")


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


@functools.cache
def _timezone_names() -> dict[str, str]:
    """Zonas que conoce ESTE DuckDB (la misma base que convierte): minúsculas -> escritura exacta."""
    con = duckdb.connect()
    try:
        return {r[0].lower(): r[0] for r in con.execute("SELECT name FROM pg_timezone_names()").fetchall()}
    finally:
        con.close()


def check_timezone(name, *, fixed_offset_ok: bool = False) -> str:
    """Valida un nombre de zona y lo devuelve. Falla pronto y con una sugerencia, no tras leer todo el archivo.

    Se exige la escritura exacta (DuckDB también acepta 'america/santiago' o 'UTC-3', pero dos mappings del mismo caso no
    deben escribir la misma zona de dos formas, y 'UTC-3' es un desfase fijo disfrazado).
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError(t("ingest.err.ts_type", name="timezone", expected="IANA name, e.g. America/Santiago"))
    names = _timezone_names()
    if name not in names.values():
        exact = names.get(name.strip().lower())
        options = [exact] if exact else difflib.get_close_matches(name, list(names.values()), n=3, cutoff=0.6)
        hint = t("ingest.err.tz_hint", options=", ".join(options)) if options else ""
        raise ValueError(t("ingest.err.tz_unknown", tz=name, hint=hint))
    if _FIXED_OFFSET.match(name) and not fixed_offset_ok:
        sign = _ETC_SIGN.match(name)
        detail = t("ingest.err.tz_sign", tz=name, offset=("-" if sign.group(1) == "+" else "+") + sign.group(2)) if sign else ""
        raise ValueError(t("ingest.err.tz_fixed", tz=name, sign=detail))
    return name


def carries_own_zone(ts: dict, source_type: str | None = None) -> bool:
    """¿El dato trae su propia zona? Entonces `timezone` no se aplica (epoch es UTC por definición)."""
    fmt = ts["format"]
    if fmt in ("epoch_s", "epoch_ms") or "%z" in fmt:
        return True
    if fmt == "iso8601":
        return bool(ts.get("timezone_in_data"))
    if fmt == "native":
        return source_type == "TIMESTAMP WITH TIME ZONE"
    return False


def timezone_source(ts: dict, source_type: str | None = None) -> str:
    """Procedencia de la zona: la declarada en el mapping o, si no se dice, la que se deduce de él."""
    if ts.get("timezone_source"):
        return ts["timezone_source"]
    if carries_own_zone(ts, source_type):
        return "in_data"
    if ts.get("timezone", "UTC") != "UTC" or ts.get("timezone_verified"):
        return "declared"
    return "default"


def local_timezone(tz: dict | None, *, from_manifest: bool = True) -> str | None:
    """Zona en la que tiene sentido hablar de "hora local" del archivo, o None.

    Solo cuando alguien la DECLARÓ y se aplicó: con la zona en el dato no se sabe cuál es la local del cliente (cada valor
    trae su desfase) y con UTC por defecto la hora local sería UTC disfrazada. Acepta el bloque `timezone` del manifiesto
    (`from_manifest=True`, también los anteriores a 5a) o el bloque `timestamp` de un mapping.
    """
    if not tz:
        return None
    if from_manifest:
        name, applied = tz.get("assumed", "UTC"), tz.get("applied", True)
        source = tz.get("source") or ("declared" if name != "UTC" else "default")
    else:
        name, applied, source = tz.get("timezone", "UTC"), not carries_own_zone(tz), timezone_source(tz)
    if not applied or source != "declared" or name in _UTC_LIKE:
        return None
    return name


def _validate_timestamp(ts: dict) -> None:
    unknown = sorted(set(ts) - set(TIMESTAMP_KEYS))
    if unknown:  # una errata como `timezone_verifed` se ignoraba en silencio y dejaba la zona sin verificar
        raise ValueError(t("ingest.err.ts_keys", keys=", ".join(unknown), valid=", ".join(TIMESTAMP_KEYS)))
    for key in ("timezone_verified", "timezone_in_data", "timezone_fixed_offset"):
        if key in ts and not isinstance(ts[key], bool):
            raise ValueError(t("ingest.err.ts_type", name=key, expected="true | false"))
    if "timezone_note" in ts and not isinstance(ts["timezone_note"], str):
        raise ValueError(t("ingest.err.ts_type", name="timezone_note", expected="string"))
    check_timezone(ts.get("timezone", "UTC"), fixed_offset_ok=bool(ts.get("timezone_fixed_offset")))
    source = ts.get("timezone_source")
    if source is None:
        return
    if source not in TIMEZONE_SOURCES:
        raise ValueError(t("ingest.err.ts_type", name="timezone_source", expected=" | ".join(TIMEZONE_SOURCES)))
    if source == "in_data" and ts["format"] != "native" and not carries_own_zone(ts):
        raise ValueError(t("ingest.err.tz_source", source=source, reason=t("ingest.err.tz_source_in_data", fmt=ts["format"])))
    if source == "declared" and carries_own_zone(ts):
        raise ValueError(t("ingest.err.tz_source", source=source, reason=t("ingest.err.tz_source_declared", fmt=ts["format"])))
    if source == "default" and (ts.get("timezone", "UTC") != "UTC" or ts.get("timezone_verified")):
        raise ValueError(t("ingest.err.tz_source", source=source, reason=t("ingest.err.tz_source_default")))


def _validate(m: dict) -> None:
    for key in ("source", "format", "fields", "timestamp"):
        if key not in m:
            raise ValueError(f"Mapping inválido: falta '{key}'")
    if m["format"] not in FORMATS:
        raise ValueError(f"Formato no soportado en el mapping: {m['format']!r} (válidos: {', '.join(FORMATS)})")
    fields = m["fields"]
    if "timestamp" not in fields:
        raise ValueError("fields debe incluir 'timestamp'")
    kind = m.get("schema", "web")
    if kind not in SCHEMAS:
        raise ValueError(f"schema desconocido: {kind!r} (válidos: {', '.join(SCHEMAS)})")
    if kind == "network":
        for need in ("src_ip", "dst_ip"):
            if need not in fields:
                raise ValueError(f"Un mapping de red (schema: network) necesita '{need}' en fields")
    elif kind == "endpoint":
        if "host" not in fields or not ({"process_name", "event_type"} & set(fields)):
            raise ValueError("Un mapping de endpoint (schema: endpoint) necesita 'host' y 'process_name' o 'event_type' en fields")
    elif "uri" not in fields and "endpoint" not in fields and "request_line" not in fields:
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
    _validate_timestamp(ts)
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


def _naive_expr(raw: str, ts: dict) -> str | None:
    """Hora local SIN zona tal como venía en el archivo, a partir de `timestamp_raw` (None si no aplica)."""
    fmt = ts["format"]
    if fmt in ("iso8601", "native"):
        return f"TRY_CAST({raw} AS TIMESTAMP)"
    if fmt in ("epoch_s", "epoch_ms") or "%z" in fmt:
        return None
    src = es_to_en_months(raw) if "%b" in fmt else raw
    return f"try_strptime({src}, {_lit(fmt)})"


def _dst_counts(con, pq: str, ts: dict) -> tuple[int, int]:
    """Filas cuya hora local no existe (el reloj se adelantó) o se repite (se atrasó) en la zona aplicada.

    DuckDB las resuelve sin avisar: una hora repetida se lee como su segunda ocurrencia y una inexistente se desplaza. Aquí
    se cuentan comparando la hora local original con la que resulta de convertir de vuelta. Un prefiltro limita las
    comprobaciones caras a las filas cercanas a un cambio de horario (4,5 M de filas: unos 7 s; con UTC no se ejecuta).
    """
    naive = _naive_expr("timestamp_raw", ts)
    tz = _lit(ts["timezone"])
    near_others = " OR ".join(f"timezone({tz}, u {op} INTERVAL {step}) = n" for step in _DST_STEPS for op in "-+")
    row = con.execute(f"""
        WITH t AS (SELECT timestamp_utc AS u, {naive} AS n FROM {pq} WHERE timestamp_utc IS NOT NULL),
        near AS (SELECT u, n, timezone({tz}, u) AS l FROM t
                 WHERE n IS NOT NULL AND (timezone({tz}, u) <> n
                       OR timezone({tz}, u + INTERVAL 2 HOUR) - timezone({tz}, u - INTERVAL 2 HOUR) <> INTERVAL 4 HOUR))
        SELECT count(*) FILTER (WHERE l <> n), count(*) FILTER (WHERE l = n AND ({near_others})) FROM near
    """).fetchone()
    return int(row[0]), int(row[1])


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
    for fld in (*NETWORK_FIELDS, *ENDPOINT_FIELDS):  # solo las que el mapping aporta: un log web no gana columnas
        if fld.name in base:
            items.append(f"{_q(fld.name)} AS {_q(fld.name)}")
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
        leaves = leaf_exprs(con, rel)
        ts_type = leaves.get(mapping["fields"]["timestamp"], (None, None))[1]
        query = build_query(mapping, rel, leaves)
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
    tz_cfg = mapping["timestamp"]
    tz_name = tz_cfg.get("timezone", "UTC")
    applied = not carries_own_zone(tz_cfg, ts_type)
    dst = None
    if applied and tz_name not in _UTC_LIKE and not _FIXED_OFFSET.match(tz_name) and _naive_expr("x", tz_cfg):
        dst = _dst_counts(con, pq, tz_cfg)
    con.close()

    tz_source = timezone_source(tz_cfg, ts_type)
    verified = bool(tz_cfg.get("timezone_verified", False)) or tz_source == "in_data"
    warnings = []
    if rows_in != rows_out:
        warnings.append(f"Filas de entrada ({rows_in}) distintas de salida ({rows_out})")
    if null_counts["timestamp_utc"]:
        warnings.append(f"{null_counts['timestamp_utc']} filas con timestamp no interpretable")
    if not verified:
        warnings.append(t("ingest.warn.tz_unverified", tz=tz_name))
    if not applied and tz_name != "UTC":
        warnings.append(t("ingest.warn.tz_ignored", tz=tz_name, fmt=tz_cfg["format"]))
    if dst and dst[0]:
        warnings.append(t("ingest.warn.dst_nonexistent", rows=f"{dst[0]:,}", tz=tz_name))
    if dst and dst[1]:
        warnings.append(t("ingest.warn.dst_ambiguous", rows=f"{dst[1]:,}", tz=tz_name))
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
        **({"log_schema": mapping["schema"]} if mapping.get("schema", "web") != "web" else {}),  # tipo de log (solo si no es web)
        "timezone": {
            "assumed": tz_name,
            "verified": verified,
            "source": tz_source,  # in_data | declared | default
            "note": tz_cfg.get("timezone_note"),  # quién la declaró o confirmó, y cuándo
            "applied": applied,  # False si el dato trae su propia zona y la declarada no se usó
            "dst_nonexistent_rows": dst[0] if dst else None,  # None: no se comprobó (UTC, desfase fijo o zona en el dato)
            "dst_ambiguous_rows": dst[1] if dst else None,
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


__all__ = ["FORMATS", "MAPPINGS_DIR", "TIMESTAMP_KEYS", "TIMEZONE_SOURCES", "OutputCollision", "SourceError", "build_query",
           "carries_own_zone", "check_timezone", "ingest_csv", "ingest_file", "load_mapping", "local_timezone", "sha256_file",
           "timezone_source"]
