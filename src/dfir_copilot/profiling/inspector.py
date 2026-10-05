"""Inspector: convierte un archivo (y su Data Profile) en un BORRADOR de mapping que el analista revisa y aprueba.

Todo es local. Para proponer columnas derivadas de la URL (p. ej. el usuario que va dentro de `authtoken=ATUSER-ID-<x>`)
hace falta mirar los valores, que el Data Profile no lleva por diseño: por eso el Inspector los analiza aquí, con DuckDB,
y al analista solo le muestra ejemplos ENMASCARADOS y estadísticas. Al LLM no llega nada de esto.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from dfir_copilot.i18n import resolve_lang, t
from dfir_copilot.profiling.data_profile import DataProfile
from dfir_copilot.profiling.log_profiler import LogProfiler
from dfir_copilot.profiling.readers import leaf_exprs, open_source, relation_sql, restricted_connection
from dfir_copilot.profiling.schema_mapper import SchemaMapper, normalize_name

# Campos canónicos que el esquema actual sabe ingerir (ver schema.py); el resto se informa pero no se ingiere.
INGESTIBLE = ("timestamp", "src_ip", "user_id", "session_id", "http_method", "host", "uri", "status_code",
              "user_agent", "referer", "bytes_out")
_SEPARATORS = ("-ID-", "_ID_", ":", "|")  # prefijo+SEP+identificador: ATUSER-ID-ana, user:ana…
_SECRET_KEY = re.compile(r"token|key|pass|pwd|secret|auth|clave|contrase|credential", re.I)
_VALUE_RX = r"[^&#;\s]"
MAX_KEYS = 12
COMPOSITE_MIN_SHARE = 0.8  # fracción de valores con forma prefijo+id para tratar un parámetro como compuesto
MIN_HIT_PCT = 5.0
RESOURCE_MIN_DISTINCT = 20
EXACT_DISTINCT_BELOW = 1000  # por debajo, los distintos se cuentan exactos sobre el archivo completo


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def mask(value: str, keep: int = 2, stars: int = 8) -> str:
    """'ana.gomez' -> 'an********': deja ver la forma del valor sin revelarlo."""
    value = str(value)
    return value[:keep] + "*" * min(max(len(value) - keep, 0), stars)


@dataclass(frozen=True)
class Decision:
    code: str  # estable, en inglés
    level: str  # "required" (bloquea) | "review" (conviene mirarla)
    message: str
    field: str | None = None


@dataclass(frozen=True)
class DerivedProposal:
    name: str
    regex: str
    type: str
    role: str  # identity | credential_type | resource | dimension | other | canonical
    reason: str
    key: str  # parámetro de la URL del que sale
    hit_pct: float
    distinct: int
    examples: tuple = ()  # SIEMPRE enmascarados


@dataclass
class MappingDraft:
    mapping: dict
    decisions: list = field(default_factory=list)
    derived: list = field(default_factory=list)
    unsupported_fields: list = field(default_factory=list)
    status: str = "ready"  # ready | needs_review | unsupported
    lang: str = "es"
    log_type: str = "unknown"
    profile: DataProfile | None = None

    # --- salida ---------------------------------------------------------------------------------------------------
    def to_yaml(self) -> str:
        return _dump_yaml(self)

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_yaml(), encoding="utf-8")
        return path

    def render(self) -> str:
        lang = self.lang
        lines = [f"{t('inspector.status.' + self.status, lang)}", "", t("inspector.render.mapping", lang)]
        for canon, col in self.mapping["fields"].items():
            lines.append(f"  {canon:14} <- {col}")
        ts = self.mapping["timestamp"]
        origin = f", {ts['timezone_source']}" if ts.get("timezone_source") else ""
        lines.append(f"  {'timestamp.fmt':14} :  {ts['format']}  (tz {ts.get('timezone')}{origin}, "
                     f"verified={ts.get('timezone_verified')})")
        lines += ["", t("inspector.render.derived", lang)]
        if not self.derived:
            lines.append("  " + t("inspector.render.none", lang))
        for d in self.derived:
            lines.append(f"  {d.name:22} {d.type:8} {t('inspector.yaml.hits', lang, hit=d.hit_pct, distinct=d.distinct)}"
                         f"  [{d.reason}]  {t('inspector.yaml.examples', lang)}: {', '.join(d.examples) or '-'}")
        if "roles" in self.mapping:
            lines += ["", f"roles: {self.mapping['roles']}"]
        lines += ["", t("inspector.render.decisions", lang)]
        if not self.decisions:
            lines.append("  " + t("inspector.render.none", lang))
        for dec in self.decisions:
            lines.append(f"  [{t('inspector.render.level.' + dec.level, lang)}] {dec.message}")
        return "\n".join(lines)


# --- YAML a mano: comentarios útiles y garantía de que `yaml.safe_load(texto) == draft.mapping` --------------
def _y(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, int | float):
        return str(value)
    return _lit(str(value))


def _dump_yaml(d: MappingDraft) -> str:
    m, lang = d.mapping, d.lang
    out = [f"# {t('inspector.yaml.header', lang)}", f"source: {_y(m['source'])}", f"description: {_y(m['description'])}",
           f"format: {m['format']}", ""]
    if "inspector" in m:
        out += ["inspector:", *(f"  {k}: {_y(v)}" for k, v in m["inspector"].items()), ""]
    out.append("fields:")
    out += [f"  {canon}: {_y(col)}" for canon, col in m["fields"].items()]
    ts = m["timestamp"]
    out += ["", "timestamp:", f"  format: {_y(ts['format'])}", f"  timezone: {_y(ts['timezone'])}"]
    for key in ("timezone_source", "timezone_note", "timezone_fixed_offset", "timezone_in_data"):
        if key in ts:
            out.append(f"  {key}: {_y(ts[key])}")
    note = "" if ts["timezone_verified"] else f"   # {t('inspector.yaml.tz_unverified', lang)}"
    out.append(f"  timezone_verified: {_y(ts['timezone_verified'])}{note}")
    if m.get("derived"):
        out += ["", "derived:"]
        by_name = {p.name: p for p in d.derived}
        for name, spec in m["derived"].items():
            p = by_name.get(name)
            if p:
                out.append(f"  # {p.reason} · {t('inspector.yaml.hits', lang, hit=p.hit_pct, distinct=p.distinct)}"
                           f" · {t('inspector.yaml.examples', lang)}: {', '.join(p.examples) or '-'}")
            out += [f"  {name}:", f"    from: {_y(spec['from'])}", f"    regex: {_y(spec['regex'])}"]
            if "type" in spec:
                out.append(f"    type: {spec['type']}")
    if "roles" in m:
        out += ["", f"# {t('inspector.yaml.roles', lang)}", "roles:", *(f"  {k}: {_y(v)}" for k, v in m["roles"].items())]
    if d.decisions:
        out += ["", f"# --- {t('inspector.yaml.pending', lang)} ---"]
        out += [f"# [{dec.level}] {dec.message}" for dec in d.decisions]
    return "\n".join(out) + "\n"


# --- análisis local de los valores de la URL ----------------------------------------------------------------------
def _key_extract(key: str) -> str:
    return f"regexp_extract(v, {_lit('[?&;]' + re.escape(key) + '=(' + _VALUE_RX + '*)')}, 1)"


def _stats(con, regex: str) -> tuple[float, int, list]:
    """(% de filas con valor, distintos, ejemplos enmascarados) al aplicar la regex FINAL sobre la muestra."""
    total = con.execute("SELECT count(*) FROM __u WHERE v IS NOT NULL").fetchone()[0] or 1
    rx = _lit(regex)
    hits, distinct = con.execute(
        f"SELECT count(*) FILTER (WHERE x <> ''), count(DISTINCT x) FILTER (WHERE x <> '') "
        f"FROM (SELECT regexp_extract(v, {rx}, 1) AS x FROM __u WHERE v IS NOT NULL)").fetchone()
    top = con.execute(
        f"SELECT x FROM (SELECT regexp_extract(v, {rx}, 1) AS x FROM __u WHERE v IS NOT NULL) WHERE x <> '' "
        f"GROUP BY x ORDER BY count(*) DESC, x LIMIT 3").fetchall()
    return round(100.0 * hits / total, 1), int(distinct or 0), [mask(r[0]) for r in top]


def _analyze_key(con, key: str) -> dict:
    """Qué forma tienen los valores de un parámetro: numérico, compuesto (prefijo+id) o texto."""
    val = _key_extract(key)
    sep_cols = ", ".join(
        f"count(*) FILTER (WHERE regexp_matches(val, {_lit('^[A-Za-z][A-Za-z0-9]{1,19}' + re.escape(s) + '.+$')})) AS s{i}"
        for i, s in enumerate(_SEPARATORS))
    row = con.execute(
        f"SELECT count(*) FILTER (WHERE val <> ''), count(DISTINCT val) FILTER (WHERE val <> ''), "
        f"count(*) FILTER (WHERE regexp_matches(val, '^[0-9]{{1,18}}$')), {sep_cols} "
        f"FROM (SELECT {val} AS val FROM __u WHERE v IS NOT NULL)").fetchone()
    n, distinct, numeric, *seps = row
    info = {"n": n or 0, "distinct": distinct or 0, "numeric": numeric or 0, "sep": None, "prefixes": []}
    for i, s in enumerate(_SEPARATORS):
        if n and seps[i] / n >= COMPOSITE_MIN_SHARE:
            rx = '^([A-Za-z][A-Za-z0-9]{1,19})' + re.escape(s) + '.+$'
            # Los prefijos se descubren en TODO el archivo: uno raro (el 0,1 % de las filas) puede no estar en la muestra
            # y la regex lo dejaría fuera sin avisar.
            prefixes = [r[0] for r in con.execute(
                f"SELECT DISTINCT regexp_extract(val, {_lit(rx)}, 1) FROM (SELECT {val} AS val FROM __full) "
                f"WHERE regexp_matches(val, {_lit(rx)}) ORDER BY 1 LIMIT 11").fetchall() if r[0]]
            if 1 <= len(prefixes) <= 10:
                info["sep"], info["prefixes"] = s, prefixes
                break
    return info


def _derive(con, keys: list[str], taken: set, mapper: SchemaMapper, lang: str):
    proposals: list[DerivedProposal] = []
    decisions: list[Decision] = []

    def free(name: str) -> str:
        base, k = name[:40], 2
        while base in taken:
            base = f"{name[:36]}_{k}"
            k += 1
        taken.add(base)
        return base

    for key in keys[:MAX_KEYS]:
        a = _analyze_key(con, key)
        total = con.execute("SELECT count(*) FROM __u WHERE v IS NOT NULL").fetchone()[0] or 1
        if a["n"] == 0 or 100.0 * a["n"] / total < MIN_HIT_PCT:
            continue
        k_re = re.escape(key)
        slug = normalize_name(key) or "param"
        if slug[0].isdigit():
            slug = "p_" + slug
        if a["sep"]:  # prefijo + separador + identificador
            sep = re.escape(a["sep"])
            tmpl = '[A-Za-z][A-Za-z0-9]{1,19}'
            type_rx = f"{k_re}=({tmpl}){sep}"
            id_rx = f"{k_re}=(?:{'|'.join(re.escape(p) for p in sorted(a['prefixes']))}){sep}({_VALUE_RX}+)"
            hit, dist, ex = _stats(con, type_rx)
            proposals.append(DerivedProposal(free(f"x_{slug}_type"), type_rx, "VARCHAR", "credential_type",
                                             t("derived.reason.credential_type", lang), key, hit, dist, tuple(ex)))
            hit, dist, ex = _stats(con, id_rx)
            if 2 <= dist < max(int(hit / 100.0 * total), 3):  # compartido por varias peticiones: es una identidad
                name = free("user_id" if "user_id" not in taken else f"x_{slug}_id")
                proposals.append(DerivedProposal(name, id_rx, "VARCHAR", "identity",
                                                 t("derived.reason.identity", lang), key, hit, dist, tuple(ex)))
                decisions.append(Decision("derived_identity", "review", t("decision.derived_identity", lang, name=name, param=key)))
            if _SECRET_KEY.search(key):
                decisions.append(Decision("credential_in_url", "review", t("decision.credential_in_url", lang, param=key)))
            continue
        rx = f"{k_re}=({_VALUE_RX}+)"
        hit, dist, ex = _stats(con, rx)
        canonical = next((c for c in ("user_id", "session_id") if slug in mapper.canon[c]["strong"] and c not in taken), None)
        if canonical:
            taken.add(canonical)
            proposals.append(DerivedProposal(canonical, rx, "VARCHAR", "canonical",
                                             t("derived.reason.canonical", lang), key, hit, dist, tuple(ex)))
        elif a["numeric"] / a["n"] >= 0.99 and dist >= 2:
            role = "resource" if dist >= RESOURCE_MIN_DISTINCT else "dimension"
            proposals.append(DerivedProposal(free(f"x_{slug}"), rx, "BIGINT", role,
                                             t(f"derived.reason.{role}", lang), key, hit, dist, tuple(ex)))
        elif dist <= 30:
            proposals.append(DerivedProposal(free(f"x_{slug}"), rx, "VARCHAR", "dimension",
                                             t("derived.reason.dimension", lang), key, hit, dist, tuple(ex)))
        elif hit >= 50:
            proposals.append(DerivedProposal(free(f"x_{slug}"), rx, "VARCHAR", "other",
                                             t("derived.reason.other", lang), key, hit, dist, tuple(ex)))
        if _SECRET_KEY.search(key) and proposals and proposals[-1].key == key:
            decisions.append(Decision("credential_in_url", "review", t("decision.credential_in_url", lang, param=key)))
    return proposals, decisions


def _full_stats(con, proposals: list, lang: str) -> tuple[list, list]:
    """Mide cada derivada sobre el archivo COMPLETO (una pasada): % de filas con valor, distintos y filas que traen el
    parámetro pero de las que la regex no extrae nada. La muestra decide qué proponer; el archivo completo, qué tan bien."""
    if not proposals:
        return proposals, []
    parts = ["count(v)"]
    for p in proposals:
        parts += [f"count(*) FILTER (WHERE strpos(v, {_lit(p.key + '=')}) > 0)",
                  f"count(*) FILTER (WHERE regexp_extract(v, {_lit(p.regex)}, 1) <> '')",
                  # exacto si la muestra ve pocos valores (memoria acotada); aproximado si hay muchos
                  f"{'count(DISTINCT ' if p.distinct < EXACT_DISTINCT_BELOW else 'approx_count_distinct('}"
                  f"NULLIF(regexp_extract(v, {_lit(p.regex)}, 1), ''))"]
    total, *vals = con.execute(f"SELECT {', '.join(parts)} FROM __full").fetchone()
    total = total or 1
    refined, decisions = [], []
    for i, p in enumerate(proposals):
        present, hits, distinct = vals[3 * i: 3 * i + 3]
        refined.append(replace(p, hit_pct=round(100.0 * hits / total, 1), distinct=int(distinct or 0)))
        if present > hits:
            gap = present - hits
            decisions.append(Decision("derived_coverage_gap", "review", t(
                "decision.derived_gap", lang, name=p.name, rows=f"{gap:,}", pct=round(100.0 * gap / present, 2), param=p.key)))
    return refined, decisions


# --- orquestación --------------------------------------------------------------------------------------------------
def inspect_source(path: str | Path, *, lang: str | None = None, profile: DataProfile | None = None,
                   source_name: str | None = None, sample_rows: int = 20_000,
                   mapper: SchemaMapper | None = None, timezone: str | None = None,
                   timezone_note: str | None = None, timezone_fixed_offset: bool = False) -> MappingDraft:
    """Genera un borrador de mapping para `path`. No ingiere nada ni modifica el archivo.

    `timezone`: zona en que está la hora del archivo si el dato no la trae (nombre IANA, p. ej. 'America/Santiago'). Queda
    como declarada por el analista y SIN verificar; `timezone_note` registra quién la dio y cuándo. Se valida antes de
    perfilar, así una errata falla al instante y no tras leer el archivo.
    """
    from dfir_copilot.ingest.ingestor import (  # import tardío: el ingestor importa este paquete
        _validate,
        check_timezone,
    )

    if timezone is not None:
        check_timezone(timezone, fixed_offset_ok=timezone_fixed_offset)
    elif timezone_note is not None or timezone_fixed_offset:
        raise ValueError("timezone_note y timezone_fixed_offset solo tienen sentido junto con timezone")
    lang = resolve_lang(lang)
    path = Path(path)
    mapper = mapper or SchemaMapper()
    profile = profile or LogProfiler(path, lang=lang, mapper=mapper).profile()
    decisions: list[Decision] = []
    by_path = {f.path: f for f in profile.fields}

    # 1) campos canónicos que el esquema sabe ingerir
    fields: dict[str, str] = {}
    unsupported = []
    chosen = {m.canonical: m for m in profile.mapping}
    for m in profile.mapping:
        (fields.__setitem__(m.canonical, m.field) if m.canonical in INGESTIBLE else unsupported.append(m.canonical))
    uri_field = by_path.get(fields.get("uri", ""))
    if uri_field and any(r.name == "http_request_line" and r.pct >= 50 for r in uri_field.semantics):
        fields["request_line"] = fields.pop("uri")  # "GET /ruta HTTP/1.1": se separa método y ruta al ingerir
        fields.pop("http_method", None)
    for amb in profile.ambiguous:
        if amb["canonical"] in fields and amb["canonical"] in INGESTIBLE:
            decisions.append(Decision("mapping_ambiguous", "review", t(
                "decision.mapping_ambiguous", lang, canonical=amb["canonical"],
                fields=", ".join(c["field"] for c in amb["candidates"]), chosen=chosen[amb["canonical"]].field)))
    if unsupported:
        decisions.append(Decision("unsupported_fields", "review", t(
            "decision.unsupported_fields", lang, fields=", ".join(f"{chosen[c].field} ({c})" for c in unsupported))))
    if profile.source.has_header is False:
        decisions.append(Decision("header_missing", "required", t("decision.header_missing", lang)))

    # 2) fecha
    tsc = profile.timestamp
    if tsc is None or "timestamp" not in fields:
        fields.pop("timestamp", None)
        decisions.append(Decision("missing_timestamp", "required", t("decision.missing_timestamp", lang)))
        ts = {"format": "iso8601", "timezone": "UTC", "timezone_verified": False}
    else:
        fields["timestamp"] = tsc.field
        fmt = "native" if tsc.format.startswith("native:") else tsc.format
        in_data = bool(tsc.timezone_in_data)
        ts = {"format": fmt, "timezone": "UTC", "timezone_verified": in_data}
        if fmt == "iso8601":
            ts["timezone_in_data"] = in_data
        if in_data:  # la zona viaja en cada valor: nada que declarar ni verificar
            if timezone is not None:
                decisions.append(Decision("timezone_ignored", "review", t(
                    "decision.timezone_ignored", lang, tz=timezone, field=tsc.field), tsc.field))
        elif timezone is not None:
            ts.update({"timezone": timezone, "timezone_source": "declared"})
            if timezone_note:
                ts["timezone_note"] = timezone_note
            if timezone_fixed_offset:
                ts["timezone_fixed_offset"] = True
            decisions.append(Decision("timezone_declared", "review", t(
                "decision.timezone_declared", lang, field=tsc.field, tz=timezone), tsc.field))
        else:
            decisions.append(Decision("timezone_unverified", "review", t(
                "decision.timezone_unverified", lang, field=tsc.field, tz="UTC"), tsc.field))
        for w in profile.warnings:
            if w.code == "warn.timestamp_ambiguous":
                decisions.append(Decision("date_order_ambiguous", "required", w.message, w.field))
            elif w.code in ("warn.timestamp_partial", "warn.timestamp_no_year"):
                decisions.append(Decision(w.code.removeprefix("warn."), "review", w.message, w.field))

    # 3) columnas derivadas de la URL (análisis local de valores)
    derived: list[DerivedProposal] = []
    url_field = fields.get("uri") or fields.get("request_line")
    if url_field is None:
        decisions.append(Decision("missing_uri", "required", t("decision.missing_uri", lang)))
    log_type = profile.log_type_hints[0].type if profile.log_type_hints else "unknown"
    if url_field is not None and by_path.get(url_field) and by_path[url_field].url_param_keys:
        con = restricted_connection(path, "2GB")
        try:
            spec, _, _ = open_source(con, path)
            rel = relation_sql(spec, explicit=True)
            expr = leaf_exprs(con, rel)[url_field][0]
            con.execute(f"CREATE TEMP TABLE __u AS SELECT CAST({expr} AS VARCHAR) AS v FROM {rel} AS src "
                        f"USING SAMPLE reservoir({int(sample_rows)} ROWS) REPEATABLE (42)")
            con.execute(f"CREATE TEMP VIEW __full AS SELECT CAST({expr} AS VARCHAR) AS v FROM {rel} AS src")
            derived, extra = _derive(con, by_path[url_field].url_param_keys, set(fields), mapper, lang)
            derived, gaps = _full_stats(con, derived, lang)
            decisions += extra + gaps
        finally:
            con.close()

    # 4) roles propuestos
    roles: dict[str, str] = {}
    names = {p.name for p in derived}
    if "user_id" in fields or "user_id" in names:
        roles["actor"] = "user_id"
    elif "src_ip" in fields:
        roles["actor"] = "src_ip"
    resources = [p for p in derived if p.role == "resource"]
    if resources:
        roles["resource"] = max(resources, key=lambda p: (p.distinct, p.name)).name

    mapping: dict = {
        "source": source_name or re.sub(r"[^a-z0-9_]+", "_", path.name.split(".")[0].lower()).strip("_") or "fuente",
        "description": t("inspector.description", lang, file=profile.source.file_name,
                         type=profile.log_type_hints[0].label if profile.log_type_hints else "?"),
        "format": profile.source.format,
        "inspector": {"file_sha256": profile.source.sha256} if profile.source.sha256 else {},
        "fields": fields, "timestamp": ts,
    }
    if not mapping["inspector"]:
        del mapping["inspector"]
    if derived:
        mapping["derived"] = {p.name: {"from": "query_string", "regex": p.regex,
                                       **({"type": p.type} if p.type != "VARCHAR" else {})} for p in derived}
    if roles:
        mapping["roles"] = roles

    # 5) ¿se puede ingerir?
    if "timestamp" not in fields or url_field is None:
        if log_type not in ("web", "proxy"):
            decisions.insert(0, Decision("unsupported_log_type", "required", t(
                "decision.unsupported_log_type", lang, type=profile.log_type_hints[0].label)))
        status = "unsupported"
    else:
        try:
            _validate(mapping)
            status = "needs_review" if any(d.level == "required" for d in decisions) else "ready"
        except ValueError as exc:
            decisions.append(Decision("invalid_draft", "required", t("decision.invalid_draft", lang, error=str(exc))))
            status = "needs_review"
    return MappingDraft(mapping, decisions, derived, [chosen[c].field for c in unsupported], status, lang, log_type, profile)
