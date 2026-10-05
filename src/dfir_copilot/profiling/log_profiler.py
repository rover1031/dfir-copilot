"""Fase local del análisis: perfila un archivo de logs con DuckDB y produce el Data Profile.

Flujo (todo en local; ningún valor crudo sale de aquí):
  1. readers.open_source  -> formato, codificación, dialecto; recorre el archivo una vez (conteo).
  2. esquema              -> columnas y estructuras anidadas (JSON) aplanadas en rutas "a.b.c".
  3. pasada completa      -> nulos, cardinalidad aproximada, longitudes, rangos temporales.
  4. muestra reproducible -> tipos semánticos, formas abstractas, claves de parámetros, candidatos de fecha.
  5. mapeo bilingüe       -> propuesta canónica (nombre + contenido) y pistas del tipo de log.
  6. verificación         -> el formato de fecha elegido se valida contra el archivo COMPLETO.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from dfir_copilot.profiling.data_profile import (
    DataProfile,
    Dataset,
    FieldProfile,
    LogTypeHint,
    MappingEntry,
    Privacy,
    Ratio,
    Source,
    TimestampCandidate,
    Warning_,
)
from dfir_copilot.profiling.i18n import resolve_lang, t
from dfir_copilot.profiling.readers import open_source, relation_sql, restricted_connection
from dfir_copilot.profiling.schema_mapper import FieldInfo, SchemaMapper, normalize_name
from dfir_copilot.profiling.semantics import (
    DATETIME_HINT,
    DAY_MONTH_PAIRS,
    SAFE_VOCABULARY,
    SECRET_IN_VALUE,
    SECRET_NAME_HINTS,
    SEMANTIC_PATTERNS,
    timestamp_candidates,
)

_NUMERIC = ("TINYINT", "SMALLINT", "INTEGER", "BIGINT", "HUGEINT", "UTINYINT", "USMALLINT", "UINTEGER", "UBIGINT",
            "FLOAT", "DOUBLE", "REAL", "DECIMAL")
_PII = {"ipv4": "ip_address", "ipv6": "ip_address", "email": "email", "jwt": "token", "windows_sid": "account_sid",
        "mac": "mac_address"}
_SAFE_PARAM = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,40}$")
_TZ_SUFFIX = r"(?:Z|[+-]\d{2}:?\d{2})$"
_GROUPABLE = ("warn.constant", "warn.high_nulls", "warn.all_null", "warn.pii")
MIN_ROWS_FOR_CONSTANT = 50  # con menos registros, "un único valor" no dice nada


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _pct(part, whole) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


def _kind(type_str: str) -> str:
    t_ = type_str.upper()
    if t_.endswith("[]") or t_.startswith("LIST"):
        return "list"
    if t_.startswith("MAP") or t_.startswith("STRUCT"):
        return "other"
    if t_.startswith(("TIMESTAMP", "DATE", "TIME")):
        return "time"
    if t_.startswith(_NUMERIC):
        return "numeric"
    if t_ == "BOOLEAN":
        return "bool"
    if t_ in ("VARCHAR", "JSON", "UUID"):
        return "varchar"
    return "other"


@dataclass(frozen=True)
class _Leaf:
    path: str
    expr: str
    type: str
    kind: str


class LogProfiler:
    """Perfilador local multi-formato. Uso: `LogProfiler("archivo.json", lang="en").profile()`."""

    def __init__(self, path: str | Path, *, lang: str | None = None, sample_rows: int = 10_000,
                 max_fields: int = 150, max_depth: int = 6, memory_limit: str = "2GB", compute_hash: bool = True,
                 max_profile_bytes: int = 24_000, mapper: SchemaMapper | None = None):
        self.path = Path(path)
        self.lang = resolve_lang(lang)
        self.sample_rows, self.max_fields, self.max_depth = int(sample_rows), int(max_fields), int(max_depth)
        self.memory_limit, self.compute_hash = memory_limit, compute_hash
        self.max_profile_bytes = int(max_profile_bytes)
        self.mapper = mapper or SchemaMapper()
        self._warnings: list[Warning_] = []

    # --- utilidades ---------------------------------------------------------------------------------------------
    def _warn(self, code: str, field: str | None = None, **kwargs) -> None:
        self._warnings.append(Warning_(code=code, field=field, message=t(code, self.lang, field=field, **kwargs)))

    def _connect(self) -> duckdb.DuckDBPyConnection:
        # Defensa en profundidad: esta conexión solo puede leer el archivo perfilado.
        return restricted_connection(self.path, self.memory_limit)

    def _sha256(self) -> str | None:
        if not self.compute_hash:
            return None
        h = hashlib.sha256()
        with open(self.path, "rb") as fh:
            while block := fh.read(1 << 20):
                h.update(block)
        return h.hexdigest()

    def _leaves(self, con, rel: str) -> list[_Leaf]:
        r = con.sql(f"SELECT * FROM {rel} AS src LIMIT 0")
        out: list[_Leaf] = []

        def walk(path: tuple, dtype, depth: int):
            if dtype.id == "struct" and depth < self.max_depth:
                for name, child in dtype.children:
                    walk(path + (name,), child, depth + 1)
            else:
                expr = "src." + ".".join(_q(p) for p in path)
                out.append(_Leaf(".".join(path), expr, str(dtype), _kind(str(dtype))))

        for name, dtype in zip(r.columns, r.types, strict=True):
            walk((name,), dtype, 0)
        return out

    # --- pasada completa: estadísticas exactas o aproximadas sobre TODO el archivo --------------------------------
    def _full_pass(self, con, rel: str, leaves: list[_Leaf]) -> dict:
        parts = []
        for i, lf in enumerate(leaves):
            parts.append(f"count({lf.expr}) AS nn_{i}")
            if lf.kind in ("varchar", "numeric", "time", "bool"):
                parts.append(f"approx_count_distinct({lf.expr}) AS d_{i}")
            if lf.kind == "varchar":
                parts += [f"min(length(CAST({lf.expr} AS VARCHAR))) AS lmin_{i}",
                          f"max(length(CAST({lf.expr} AS VARCHAR))) AS lmax_{i}",
                          f"avg(length(CAST({lf.expr} AS VARCHAR))) AS lavg_{i}"]
            if lf.kind == "time":
                parts += [f"CAST(min({lf.expr}) AS VARCHAR) AS tmin_{i}", f"CAST(max({lf.expr}) AS VARCHAR) AS tmax_{i}"]
        if not parts:
            return {}
        cur = con.execute(f"SELECT {', '.join(parts)} FROM {rel} AS src")
        return dict(zip([d[0] for d in cur.description], cur.fetchone(), strict=True))

    # --- muestra: qué hay DENTRO de cada campo (sin sacar valores) ---------------------------------------------------
    def _analyze_sample(self, con, i: int) -> dict:
        col = f'"f{i}"'
        base = f"(SELECT {col} AS v FROM __sample WHERE {col} IS NOT NULL)"
        parts = ["count(*) AS n", "count(TRY_CAST(v AS DOUBLE)) AS num",
                 f"count(*) FILTER (WHERE regexp_matches(v, {_lit(SECRET_IN_VALUE)})) AS secret",
                 f"count(*) FILTER (WHERE regexp_matches(v, {_lit(DATETIME_HINT)})) AS dt",
                 f"count(*) FILTER (WHERE regexp_matches(v, {_lit(_TZ_SUFFIX)})) AS tz",
                 "count(*) FILTER (WHERE strpos(v, '?') > 0 OR strpos(v, '&') > 0) AS qs"]
        parts += [f"count(*) FILTER (WHERE regexp_matches(v, {_lit(rx)})) AS s_{name}"
                  for name, rx in SEMANTIC_PATTERNS.items()]
        cur = con.execute(f"SELECT {', '.join(parts)} FROM {base}")
        row = dict(zip([d[0] for d in cur.description], cur.fetchone(), strict=True))
        n = row["n"]
        info = {"n": n, "numeric_pct": _pct(row["num"], n), "secret_pct": _pct(row["secret"], n),
                "dt_pct": _pct(row["dt"], n), "tz_pct": _pct(row["tz"], n), "qs_pct": _pct(row["qs"], n),
                "semantics": {name: _pct(row[f"s_{name}"], n) for name in SEMANTIC_PATTERNS if row[f"s_{name}"]}}
        shapes = con.execute(
            f"SELECT shape, count(*) AS c FROM (SELECT left(regexp_replace(regexp_replace(left(v, 300), "
            f"'\\p{{L}}+', 'a', 'g'), '\\p{{N}}+', '9', 'g'), 80) AS shape FROM {base}) "
            f"GROUP BY 1 ORDER BY c DESC, shape LIMIT 3").fetchall()
        info["shapes"] = [Ratio(name=s, pct=_pct(c, n)) for s, c in shapes]
        info["param_keys"] = []
        if info["qs_pct"] >= 10:
            keys = con.execute(
                f"SELECT k, count(*) AS c FROM (SELECT unnest(regexp_extract_all(v, '[?&;]([^=&#;\\s]{{1,40}})=', 1)) "
                f"AS k FROM {base}) GROUP BY 1 ORDER BY c DESC, k LIMIT 20").fetchall()
            info["param_keys"] = [k for k, _ in keys if _SAFE_PARAM.match(k)]
        return info

    def _timestamp_scores(self, con, i: int) -> list[tuple[str, float]]:
        cands = timestamp_candidates("v")
        parts = ", ".join(f"count({expr}) AS c{j}" for j, (_, expr) in enumerate(cands))
        cur = con.execute(f'SELECT count(*) AS n, {parts} FROM (SELECT "f{i}" AS v FROM __sample WHERE "f{i}" IS NOT NULL)')
        row = cur.fetchone()
        n = row[0]
        scores = [(label, _pct(row[j + 1], n)) for j, (label, _) in enumerate(cands)]
        order = {label: j for j, (label, _) in enumerate(cands)}
        return sorted([s for s in scores if s[1] > 0], key=lambda s: (-s[1], order[s[0]]))

    def _enum(self, con, i: int, distinct: int | None, semantics: dict) -> list[str] | None:
        if not distinct or distinct > 30:
            return None
        values = [v for (v,) in con.execute(
            f'SELECT DISTINCT "f{i}" FROM __sample WHERE "f{i}" IS NOT NULL ORDER BY 1 LIMIT 31').fetchall()]
        if not values or len(values) > 30:
            return None
        safe = all(str(v).strip().lower() in SAFE_VOCABULARY for v in values)
        statuses = semantics.get("http_status", 0) >= 99 and all(re.fullmatch(r"[1-5]\d\d", str(v)) for v in values)
        return sorted(str(v) for v in values) if (safe or statuses) else None

    # --- verificación del formato de fecha sobre el archivo completo -----------------------------------------------
    def _verify_timestamp(self, con, rel: str, leaf: _Leaf, label: str) -> tuple[float, str | None, str | None]:
        if label.startswith("native:"):
            return 100.0, None, None
        expr = dict(timestamp_candidates(f"CAST({leaf.expr} AS VARCHAR)"))[label]
        nn, ok, lo, hi = con.execute(
            f"SELECT count({leaf.expr}), count({expr}), CAST(min({expr}) AS VARCHAR), CAST(max({expr}) AS VARCHAR) "
            f"FROM {rel} AS src").fetchone()
        return _pct(ok, nn), lo, hi

    def _differs(self, con, i: int, a: str, b: str) -> bool:
        exprs = dict(timestamp_candidates("v"))
        return con.execute(
            f'SELECT count(*) FROM (SELECT "f{i}" AS v FROM __sample) '
            f"WHERE {exprs[a]} IS NOT NULL AND {exprs[b]} IS NOT NULL AND {exprs[a]} <> {exprs[b]}").fetchone()[0] > 0

    # --- orquestación ------------------------------------------------------------------------------------------
    def profile(self) -> DataProfile:
        self._warnings = []
        con = self._connect()
        spec, rows, notes = open_source(con, self.path, self.lang)
        for code, kwargs in notes:
            self._warn(code, **kwargs)
        # El tipo de un campo JSON se infiere con una muestra; si más adelante cambia, el error aparece al LEER
        # los valores (no al contar). Entonces se reinfiere el esquema leyendo el archivo completo.
        while True:
            rel = relation_sql(spec)
            all_leaves = self._leaves(con, rel)
            leaves = all_leaves[: self.max_fields]
            try:
                full = self._full_pass(con, rel, leaves) if rows else {}
                break
            except duckdb.Error:
                if spec.format != "json" or spec.json_full_schema:
                    raise
                spec = replace(spec, json_full_schema=True)
                self._warn("warn.schema_retry")
        if len(all_leaves) > len(leaves):
            self._warn("warn.fields_truncated", kept=len(leaves), total=len(all_leaves))
        nested = any("." in lf.path for lf in all_leaves)

        scalar = [(i, lf) for i, lf in enumerate(leaves) if lf.kind in ("varchar", "numeric", "time", "bool")]
        sample_rows = 0
        analysis, ts_scores = {}, {}
        if rows and scalar:
            cols = ", ".join(f'CAST({lf.expr} AS VARCHAR) AS "f{i}"' for i, lf in scalar)
            con.execute(f"CREATE TEMP TABLE __sample AS SELECT {cols} FROM {rel} AS src "
                        f"USING SAMPLE reservoir({self.sample_rows} ROWS) REPEATABLE (42)")
            sample_rows = con.execute("SELECT count(*) FROM __sample").fetchone()[0]
            for i, lf in scalar:
                analysis[i] = self._analyze_sample(con, i)
                if lf.kind == "time":
                    ts_scores[i] = [(f"native:{lf.type}", 100.0)]
                elif lf.kind in ("varchar", "numeric") and (
                        analysis[i]["dt_pct"] >= 50 or analysis[i]["numeric_pct"] >= 90):
                    ts_scores[i] = self._timestamp_scores(con, i)
        elif not rows:
            self._warn("warn.empty")

        # --- mapeo bilingüe con evidencia de contenido ---
        infos = [FieldInfo(lf.path, lf.kind, analysis.get(i, {}).get("semantics", {}),
                           (ts_scores.get(i) or [("", 0.0)])[0][1]) for i, lf in enumerate(leaves)]
        proposal = self.mapper.propose(infos)
        for amb in proposal.ambiguous:
            self._warn("warn.mapping_ambiguous", canonical=amb["canonical"],
                       fields=", ".join(c["field"] for c in amb["candidates"]))
        mapped = {m.field: m for m in proposal.matches.values()}

        # --- campos ---
        fields: list[FieldProfile] = []
        for i, lf in enumerate(leaves):
            nn = full.get(f"nn_{i}", 0) or 0
            null_pct = round(100.0 - _pct(nn, rows), 1) if rows else 100.0
            distinct = full.get(f"d_{i}")
            a = analysis.get(i, {})
            sem = a.get("semantics", {})
            ts = ts_scores.get(i) or []
            m = mapped.get(lf.path)
            pii = sorted({_PII[s] for s, p in sem.items() if s in _PII and p >= 30}
                         | ({"username"} if m and m.canonical == "user_id" else set())
                         | ({"phone"} if re.search(r"phone|telefono|celular|movil", normalize_name(lf.path)) else set()))
            fp = FieldProfile(
                path=lf.path, type=lf.type, null_pct=null_pct, distinct_approx=distinct,
                length=({"min": full.get(f"lmin_{i}"), "max": full.get(f"lmax_{i}"),
                         "avg": round(full[f"lavg_{i}"], 1) if full.get(f"lavg_{i}") is not None else None}
                        if lf.kind == "varchar" and nn else None),
                numeric_pct=a.get("numeric_pct") if a else None,
                semantics=[Ratio(name=s, pct=p) for s, p in sorted(sem.items(), key=lambda x: (-x[1], x[0])) if p >= 10][:4],
                shapes=a.get("shapes", []), url_param_keys=a.get("param_keys", []),
                enum_values=self._enum(con, i, distinct, sem) if a else None, pii=pii,
                secret_in_values_pct=a.get("secret_pct", 0.0),
                timestamp_format=ts[0][0] if ts and ts[0][1] >= 50 else None,
                timestamp_pct=ts[0][1] if ts and ts[0][1] >= 50 else None,
                mapped_to=m.canonical if m else None, mapping_score=m.score if m else None)
            fields.append(fp)
            # avisos por campo
            if rows and nn == 0:
                self._warn("warn.all_null", lf.path)
            elif rows and null_pct >= 90:
                self._warn("warn.high_nulls", lf.path, pct=null_pct)
            elif distinct == 1 and rows >= MIN_ROWS_FOR_CONSTANT:
                self._warn("warn.constant", lf.path)
            if fp.secret_in_values_pct > 0:
                secret_keys = [k for k in fp.url_param_keys if re.search(
                    r"token|key|pass|pwd|secret|auth|clave|contrase", k, re.I)] or ["?"]
                self._warn("warn.secret_in_values", lf.path, keys=", ".join(secret_keys))
            if any(h in normalize_name(lf.path) for h in SECRET_NAME_HINTS):
                self._warn("warn.secret_field", lf.path)
            if pii:
                self._warn("warn.pii", lf.path, kinds=", ".join(pii))
            if sem.get("http_request_line", 0) >= 50:
                self._warn("warn.request_line", lf.path)

        # --- fecha principal: verificada contra el archivo completo ---
        timestamp = None
        primary_i = None
        if "timestamp" in proposal.matches:
            primary_i = next(i for i, lf in enumerate(leaves) if lf.path == proposal.matches["timestamp"].field)
        else:
            best = sorted(((ts_scores[i][0][1], i) for i in ts_scores if ts_scores[i]), reverse=True)
            if best and best[0][0] >= 90:
                primary_i = best[0][1]
        if primary_i is not None and ts_scores.get(primary_i):
            lf, scores = leaves[primary_i], ts_scores[primary_i]
            label, pct_sample = scores[0]
            pct_full, lo, hi = self._verify_timestamp(con, rel, lf, label)
            if label.startswith("native:"):
                lo, hi = full.get(f"tmin_{primary_i}"), full.get(f"tmax_{primary_i}")
            tz_in_data = (True if label in ("epoch_s", "epoch_ms") or "%z" in label or "WITH TIME ZONE" in lf.type
                          else (analysis[primary_i]["tz_pct"] >= 90 if label == "iso8601" else
                                (None if label.startswith("native:") else False)))
            timestamp = TimestampCandidate(field=lf.path, format=label, parse_pct_sample=pct_sample,
                                           parse_pct_full=pct_full, min_utc=lo, max_utc=hi,
                                           timezone_in_data=tz_in_data,
                                           alternatives=[Ratio(name=l_, pct=p) for l_, p in scores[1:4]])
            if pct_full is not None and pct_full < 99:
                self._warn("warn.timestamp_partial", lf.path, pct=pct_full, fmt=label)
            if label == "%b %d %H:%M:%S":
                self._warn("warn.timestamp_no_year", lf.path)
            if tz_in_data is False:
                self._warn("warn.timezone_unknown", lf.path)
            pct_by_label = dict(scores)
            rejected: dict[float, list[str]] = {}  # varias lecturas equivalentes (iso8601 y %Y-%m-%d…) = un solo aviso
            for a_, b_ in DAY_MONTH_PAIRS:
                if label not in (a_, b_):
                    continue
                other = b_ if label == a_ else a_
                p_other = pct_by_label.get(other, 0.0)
                if p_other >= 95 and pct_sample >= 95 and self._differs(con, primary_i, label, other):
                    self._warn("warn.timestamp_ambiguous", lf.path, a=label, b=other)
                elif 0 < p_other < 95:
                    rejected.setdefault(p_other, []).append(other)
            for pct, labels in rejected.items():
                self._warn("warn.timestamp_rejected_alt", lf.path, fmt=" / ".join(dict.fromkeys(labels)), pct=pct)
        elif rows:
            self._warn("warn.no_timestamp")
        con.close()

        hints = [LogTypeHint(type=h["type"], label=t(f"log_type.{h['type']}", self.lang), score=h["score"],
                             evidence=h["evidence"]) for h in self.mapper.log_type_hints(proposal)]
        if not hints:
            hints = [LogTypeHint(type="unknown", label=t("log_type.unknown", self.lang), score=0.0, evidence=[])]
        self._group_warnings()
        profile = DataProfile(
            lang=self.lang, generated_at_utc=datetime.now(UTC).isoformat(timespec="seconds"),
            privacy=Privacy(notes=[t("privacy.strict", self.lang), t("privacy.enums", self.lang)]),
            source=Source(file_name=self.path.name, sha256=self._sha256(), size_bytes=self.path.stat().st_size,
                          format=spec.format, compression=spec.compression, encoding=spec.encoding,
                          delimiter=spec.delimiter, has_header=spec.has_header),
            dataset=Dataset(row_count=rows, field_count=len(all_leaves), profiled_fields=len(leaves),
                            sample_rows=sample_rows, nested=nested),
            fields=fields, timestamp=timestamp,
            mapping=[MappingEntry(canonical=m.canonical, field=m.field, score=m.score, method=m.method,
                                  evidence=list(m.evidence)) for m in proposal.matches.values()],
            ambiguous=proposal.ambiguous, unmapped_fields=proposal.unmapped,
            log_type_hints=hints, warnings=self._warnings)
        return self._fit_budget(profile)

    # --- avisos agrupados: uno por tipo cuando afectan a muchos campos ----------------------------------------------
    def _group_warnings(self, threshold: int = 4) -> None:
        grouped: list[Warning_] = []
        for code in _GROUPABLE:
            same = [w for w in self._warnings if w.code == code]
            if len(same) >= threshold:
                names = [w.field for w in same]
                listed = ", ".join(names[:8]) + (f" (+{len(names) - 8})" if len(names) > 8 else "")
                grouped.append(Warning_(code=code, message=t(f"{code}.many", self.lang, count=len(names),
                                                             fields=listed)))
        codes = {w.code for w in grouped}
        self._warnings = [w for w in self._warnings if w.code not in codes] + grouped

    # --- presupuesto de tamaño: el perfil debe seguir siendo "pocos KB" -----------------------------------------
    def _fit_budget(self, profile: DataProfile) -> DataProfile:
        def size() -> int:
            return len(profile.to_llm_json().encode("utf-8"))

        profile.dataset.fields_in_payload = len(profile.fields)
        if size() <= self.max_profile_bytes:
            return profile
        unmapped = [f for f in profile.fields if f.mapped_to is None]
        for f in unmapped:  # 1) menos detalle en lo que no está mapeado
            f.shapes, f.length, f.url_param_keys = f.shapes[:1], None, f.url_param_keys[:5]
            f.semantics = [r for r in f.semantics if r.pct >= 50]
        if size() > self.max_profile_bytes:
            for f in unmapped:  # 2) sin formas
                f.shapes = []
        omitted = 0
        if size() > self.max_profile_bytes:
            # 3) fuera los campos sin mapear menos informativos (los nombres siguen en unmapped_fields)
            def value(f: FieldProfile) -> tuple:
                informative = bool(f.pii or f.secret_in_values_pct or f.timestamp_format or f.semantics)
                return (informative, -f.null_pct, f.distinct_approx or 0, f.path)

            budget_msg = 400  # sitio para el aviso de recorte
            for f in sorted(unmapped, key=value):
                if size() + budget_msg <= self.max_profile_bytes:
                    break
                profile.fields.remove(f)
                omitted += 1
        if size() > self.max_profile_bytes:  # 4) último recurso: formas fuera en todo el perfil
            for f in profile.fields:
                f.shapes = []
        profile.dataset.fields_in_payload = len(profile.fields)
        if omitted:
            profile.warnings.append(Warning_(code="warn.profile_trimmed", message=t(
                "warn.profile_trimmed", self.lang, limit=self.max_profile_bytes // 1000, omitted=omitted)))
        return profile
