"""El modelo propone, el código dispone: validación de lo que el LLM devuelve en la fase de interpretación.

Dos piezas:

* `SqlSandbox`: comprueba una consulta propuesta contra un *gemelo vacío* del dataset (mismas columnas y tipos, cero
  filas). Reutiliza `QueryEngine`, así que aplica exactamente las mismas reglas que la investigación real (una sola
  sentencia, solo SELECT, sin acceso a archivos ni red, con timeout) sin duplicarlas. Como la tabla está vacía, la
  comprobación es instantánea y no toca ningún dato.
* `review_interpretation`: conserva lo válido y anota lo descartado, con un código estable y el motivo. Nada se
  descarta en silencio y nada se reintenta solo.

Límite conocido: sobre una tabla vacía se detectan errores de sintaxis, de columnas y de tipos de enlace, pero no los de
ejecución que dependen de los valores (una conversión que falla con datos reales, una división por cero).
"""
from __future__ import annotations

import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import duckdb

from dfir_copilot.engine.query_engine import QueryEngine, QueryRejected, QueryTimeout
from dfir_copilot.interpret.schemas import MAX_QUERIES, MAX_QUESTIONS, ProfileInterpretation
from dfir_copilot.profiling.data_profile import DataProfile
from dfir_copilot.schema import CANONICAL_FIELDS, CANONICAL_NAMES

# Tipos admitidos para columnas derivadas: el nombre del tipo termina dentro de un CAST, así que va en lista cerrada.
ALLOWED_DTYPES = frozenset({
    "VARCHAR", "BIGINT", "INTEGER", "SMALLINT", "DOUBLE", "BOOLEAN", "DATE", "TIMESTAMP", "TIMESTAMPTZ",
})
_COLUMN_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_LOGS_RE = re.compile(r"\blogs\b", re.IGNORECASE)
_PRIORITY = {"high": 0, "medium": 1, "low": 2}


def columns_from_profile(profile: DataProfile, derived: Mapping[str, str] | None = None) -> dict[str, str]:
    """Columnas que el dataset ingerido tendrá, con su tipo DuckDB: las canónicas que el perfil mapea, más
    `source_row` y `timestamp_utc` si hay marca de tiempo, más las derivadas (`x_...`) que se pasen.

    Se restringe a lo mapeado a propósito: una consulta sobre una columna que el log no aporta debe fallar aquí y no
    devolver un vacío silencioso en la investigación.
    """
    dtypes = {f.name: f.dtype for f in CANONICAL_FIELDS}
    wanted = {"source_row"}
    if profile.timestamp is not None:
        wanted.add("timestamp_utc")
    wanted |= {m.canonical for m in profile.mapping if m.canonical in dtypes}
    columns = {f.name: f.dtype for f in CANONICAL_FIELDS if f.name in wanted}
    for name, dtype in (derived or {}).items():
        if not _COLUMN_RE.match(name):
            raise ValueError(f"Nombre de columna derivada inválido: {name!r}")
        if name in CANONICAL_NAMES:
            raise ValueError(f"La columna derivada {name!r} choca con una columna canónica")
        if dtype.upper() not in ALLOWED_DTYPES:
            raise ValueError(f"Tipo no admitido para {name!r}: {dtype!r} (admitidos: {sorted(ALLOWED_DTYPES)})")
        columns[name] = dtype.upper()
    return columns


@dataclass(frozen=True)
class SqlCheck:
    ok: bool
    code: Literal["policy_rejected", "sql_error", "timeout", "no_logs_reference"] | None = None
    detail: str | None = None


def _short(exc: Exception, limit: int = 300) -> str:
    first = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
    return first[:limit]


class SqlSandbox:
    """Gemelo vacío del dataset para probar consultas. Úsalo como gestor de contexto: borra su carpeta temporal."""

    def __init__(self, columns: Mapping[str, str], *, timeout_s: float = 5.0):
        if not columns:
            raise ValueError("Se necesita al menos una columna")
        self.columns = dict(columns)
        self._tmp = tempfile.TemporaryDirectory(prefix="dfir_sandbox_")
        try:
            path = Path(self._tmp.name) / "empty.parquet"
            select = ", ".join(f'CAST(NULL AS {dtype}) AS "{name}"' for name, dtype in self.columns.items())
            con = duckdb.connect(":memory:")
            try:
                con.execute(f"COPY (SELECT {select} WHERE false) TO '{path}' (FORMAT parquet)")
            finally:
                con.close()
            self._engine = QueryEngine(path, verify=False, max_rows=1, timeout_s=timeout_s, memory_limit="256MB")
        except Exception:
            self._tmp.cleanup()
            raise

    def check(self, sql: str) -> SqlCheck:
        if not _LOGS_RE.search(sql):
            return SqlCheck(False, "no_logs_reference", "La consulta no lee la vista `logs`")
        try:
            self._engine.query(sql, max_rows=1)
        except QueryRejected as exc:
            return SqlCheck(False, "policy_rejected", _short(exc))
        except QueryTimeout as exc:
            return SqlCheck(False, "timeout", _short(exc))
        except duckdb.Error as exc:
            return SqlCheck(False, "sql_error", _short(exc))
        return SqlCheck(True)

    def close(self) -> None:
        self._tmp.cleanup()

    def __enter__(self) -> SqlSandbox:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


@dataclass(frozen=True)
class Discard:
    """Algo que el modelo propuso y no se aceptó. `kind` dice de qué sección; `ref` lo identifica; `code` es estable."""

    kind: Literal["query", "mapping", "evidence", "question"]
    ref: str
    code: str
    detail: str


@dataclass(frozen=True)
class ReviewedInterpretation:
    interpretation: ProfileInterpretation  # solo lo aceptado
    discarded: tuple[Discard, ...]


def _review_mapping(item, profile: DataProfile, fields: set[str]) -> tuple[str, str] | None:
    """Devuelve (código, detalle) si la opinión sobre el mapeo no se sostiene contra el perfil; None si es válida."""
    if item.canonical not in CANONICAL_NAMES:
        return "unknown_canonical", f"{item.canonical!r} no es un campo canónico"
    if item.field not in fields:
        return "unknown_field", f"{item.field!r} no está en el perfil"
    pairs = {(m.canonical, m.field) for m in profile.mapping}
    mapped = {m.canonical for m in profile.mapping}
    if item.action in ("confirm", "reject") and (item.canonical, item.field) not in pairs:
        return "not_in_profile_mapping", f"El perfil no mapea {item.canonical!r} a {item.field!r}"
    if item.action == "change" and item.canonical not in mapped:
        return "not_mapped_yet", f"{item.canonical!r} no tiene mapeo que cambiar (usa 'add')"
    if item.action == "add" and item.canonical in mapped:
        return "already_mapped", f"{item.canonical!r} ya está mapeado (usa 'change')"
    return None


def review_interpretation(
    raw: ProfileInterpretation,
    profile: DataProfile,
    columns: Mapping[str, str],
    *,
    max_queries: int = MAX_QUERIES,
    max_questions: int = MAX_QUESTIONS,
    sandbox: SqlSandbox | None = None,
) -> ReviewedInterpretation:
    """Contrasta la propuesta del modelo con el perfil y con el esquema. No modifica `raw`."""
    fields = {f.path for f in profile.fields}
    discarded: list[Discard] = []

    # --- clasificación: las referencias a campos inexistentes se quitan, la clasificación se conserva
    evidence = []
    for path in raw.classification.evidence_fields:
        if path in fields:
            evidence.append(path)
        else:
            discarded.append(Discard("evidence", path, "unknown_field", f"{path!r} no está en el perfil"))
    classification = raw.classification.model_copy(update={"evidence_fields": evidence})

    # --- mapeo
    mapping = []
    for item in raw.mapping_review:
        problem = _review_mapping(item, profile, fields)
        if problem:
            discarded.append(Discard("mapping", f"{item.action}:{item.canonical}", *problem))
        else:
            mapping.append(item)

    # --- consultas: en orden, hasta el tope de válidas; el resto se anota sin comprobar
    own = sandbox is None
    sbx = sandbox or SqlSandbox(columns)
    try:
        queries, seen = [], set()
        for q in raw.proposed_queries:
            if q.id in seen:
                discarded.append(Discard("query", q.id, "duplicate_id", "Identificador repetido"))
                continue
            seen.add(q.id)
            if len(queries) >= max_queries:
                discarded.append(Discard("query", q.id, "over_limit", f"Más de {max_queries} consultas válidas"))
                continue
            check = sbx.check(q.sql)
            if check.ok:
                queries.append(q)
            else:
                discarded.append(Discard("query", q.id, check.code or "invalid", check.detail or ""))
    finally:
        if own:
            sbx.close()
    queries.sort(key=lambda q: _PRIORITY[q.priority])  # estable: dentro de una prioridad se respeta el orden del modelo

    # --- preguntas al analista
    questions = raw.analyst_questions[:max_questions]
    for extra in raw.analyst_questions[max_questions:]:
        discarded.append(Discard("question", extra.question[:60], "over_limit", f"Más de {max_questions} preguntas"))

    reviewed = ProfileInterpretation(
        classification=classification, mapping_review=mapping, proposed_queries=queries, analyst_questions=questions,
    )
    return ReviewedInterpretation(reviewed, tuple(discarded))
