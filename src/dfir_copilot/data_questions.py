"""Preguntas rápidas sobre los datos, SIN modelo: el código entiende preguntas frecuentes y responde con la cifra exacta, al instante y
sin gastar tokens. Lo que no entiende lo dice y sugiere preguntárselo al agente.

Es genérico para cualquier tipo de log: las entidades y relaciones salen del perfil (`data_profile`), que a su vez depende solo de las
columnas presentes. Las respuestas que necesitan el dataset (rankings con más de 10, primera aparición de un valor) consultan la copia con
alias y muestran la consulta usada. La pregunta llega ya traducida a alias (la interfaz la pasa por el mismo guardián que las preguntas al
agente), así que una IP real escrita por el analista se busca por su alias.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from dfir_copilot.data_profile import ENTITIES, column_for

EXAMPLES = ("¿Cuántas columnas hay?", "¿Cuántas IPs distintas hay?", "¿Cuántos usuarios hay?", "Top 10 de dst_port",
            "¿Qué campos están vacíos?", "¿Cuál es el rango de fechas?", "¿Quién habla con quién?", "¿Cuándo apareció IP-0001?")
_VALUE = re.compile(r"\b([A-Z]{1,6}-[0-9]{2,}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})\b|[\"'«]([^\"'»]+)[\"'»]")


@dataclass
class Answer:
    matched: bool
    text: str
    headers: tuple = ()
    rows: list = field(default_factory=list)
    sql: str | None = None


def _norm(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"\s+", " ", re.sub(r"[¿?¡!,.;:()]", " ", text)).strip()


def _has(q: str, *words: str) -> bool:
    return any(re.search(rf"\b{re.escape(w)}", q) for w in words)


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _column(q: str, profile: dict) -> str | None:
    """La columna a la que se refiere la pregunta: por su nombre exacto, o por los sinónimos de las entidades (el más largo primero)."""
    names = {c["name"] for c in profile["columns"]}
    for name in sorted(names, key=len, reverse=True):
        if re.search(rf"\b{re.escape(name.lower())}\b", q):
            return name
    candidates = sorted(((syn, col) for col, _, syns in ENTITIES for syn in syns), key=lambda x: -len(x[0]))
    for syn, col in candidates:
        if re.search(rf"\b{re.escape(syn)}", q) and (col in names or f"{col}_base" in names):
            return col
    return None


def _col_profile(profile: dict, column: str, present: set[str]) -> dict | None:
    """El perfil de la columna que se cuenta para esa entidad: la derivada (`<col>_base`) si existe, si no la propia."""
    by = {c["name"]: c for c in profile["columns"]}
    return by.get(column_for(column, present)) or by.get(column)


def _entity(profile: dict, column: str) -> dict | None:
    return next((e for e in profile.get("entities", []) if e["column"] == column), None)


def answer(question: str, profile: dict, engine=None, top_max: int = 50) -> Answer:
    """Responde `question` (ya en alias) con el perfil y, si hace falta, con consultas sobre `engine` (la copia con alias)."""
    raw = question or ""
    q = _norm(raw)
    if not q:
        return Answer(False, "Escribe una pregunta.")
    present = {c["name"] for c in profile["columns"]}
    col = _column(q, profile)
    count_words = ("cuant", "how many", "numero de", "cantidad", "total de", "count")

    if _has(q, "columna", "campo", "column", "field") and _has(q, *count_words) and not col:
        names = [c["name"] for c in profile["columns"]]
        return Answer(True, f"El dataset tiene {len(names)} columnas.", ("columna", "tipo", "% con valor", "distintos"),
                      [[c["name"], c["type"], c["filled_pct"], c["distinct"]] for c in profile["columns"]])
    if _has(q, "relacion", "quien habla", "pares", "pairs", "relationship", "con quien"):
        rels = profile.get("relations") or []
        if not rels:
            return Answer(True, "Este log no trae dos columnas relacionables (por ejemplo origen y destino, o equipo y proceso).")
        rows = [[f"{r['from']} → {r['to']}", a, b, n] for r in rels for a, b, n in r["top"][:5]]
        return Answer(True, "Pares más frecuentes entre columnas relacionadas: "
                      + "; ".join(f"{r['from']}→{r['to']}: {r['pairs']:,} pares distintos" for r in rels) + ".",
                      ("relación", "de", "a", "eventos"), rows)
    if _has(q, "cuando aparecio", "cuando se vio", "primera vez", "ultima vez", "first seen", "last seen", "cuando aparece"):
        m = _VALUE.search(raw)
        value = (m.group(1) or m.group(2)).strip() if m else None
        if not value or engine is None:
            return Answer(False, "Indica el valor entre comillas o como alias/IP, por ejemplo: ¿cuándo apareció IP-0001?")
        cols = [column_for(c, present) for c, _, _ in ENTITIES if column_for(c, present) in present]
        lit = "'" + value.replace("'", "''") + "'"
        sql = " UNION ALL ".join(
            f"SELECT '{c}' AS columna, count(*) AS eventos, CAST(min(timestamp_utc) AS VARCHAR) AS primera, "
            f"CAST(max(timestamp_utc) AS VARCHAR) AS ultima FROM logs WHERE CAST({_q(c)} AS VARCHAR) = {lit}" for c in cols)
        rows = [list(r) for r in engine.query(sql).rows if r[1]]
        if not rows:
            return Answer(True, f"{value} no aparece en ninguna columna de entidad.", sql=sql)
        return Answer(True, f"{value} aparece en {len(rows)} columna(s).", ("columna", "eventos", "primera vez (UTC)", "última vez (UTC)"),
                      rows, sql)
    if _has(q, "top", "mas frecuente", "mas comun", "ranking", "principales", "most common", "mas activ") and col:
        n = min(int(m.group(1)), top_max) if (m := re.search(r"\b(\d{1,3})\b", q)) else 10
        target = column_for(col, present)
        sql = (f"SELECT CAST({_q(target)} AS VARCHAR) AS valor, count(*) AS eventos FROM logs WHERE {_q(target)} IS NOT NULL "
               f"GROUP BY 1 ORDER BY eventos DESC, valor LIMIT {n}")
        if engine is None:
            top = (_col_profile(profile, col, present) or {}).get("top", [])[:n]
            return Answer(True, f"Los {len(top)} valores más frecuentes de {target}:", ("valor", "eventos"), top)
        return Answer(True, f"Los {n} valores más frecuentes de {target}:", ("valor", "eventos"), [list(r) for r in engine.query(sql).rows], sql)
    if _has(q, "ip") and _has(q, *count_words) and col not in ("src_ip", "dst_ip"):
        ents = [e for e in profile.get("entities", []) if e["column"] in ("ip", "src_ip", "dst_ip")]
        if ents:
            return Answer(True, " · ".join(f"{e['label']}: {e['distinct']:,}" for e in ents) + ".", ("entidad", "distintas"),
                          [[e["label"], e["distinct"]] for e in ents])
    if col and _has(q, *count_words, "distint", "valores", "diferentes"):
        e = _entity(profile, col)
        c = _col_profile(profile, col, present)
        label, distinct = (e["label"], e["distinct"]) if e else (col, c["distinct"] if c else 0)
        top = (c or {}).get("top", [])[:5]
        return Answer(True, f"{label}: {distinct:,} distintos" + (f" (en {c['filled']:,} filas con valor)." if c else "."),
                      ("valor más frecuente", "eventos"), top)
    if _has(q, "fila", "registro", "evento", "linea", "rows", "records", "events") and _has(q, *count_words):
        return Answer(True, f"El dataset tiene {profile['rows']:,} filas.")
    if _has(q, "rango", "fecha", "periodo", "desde cuando", "hasta cuando", "date range", "time range"):
        t = profile.get("time")
        if not t:
            return Answer(True, "Este log no trae una hora legible.")
        return Answer(True, f"De {t['from_utc']} a {t['to_utc']} (UTC), {len(t['per_day'])} día(s) con eventos.")
    if _has(q, "vacia", "vacio", "sin datos", "empty"):
        empty = profile["quality"]["empty_columns"]
        return Answer(True, f"{len(empty)} columna(s) vacía(s): {', '.join(empty)}." if empty else "Ninguna columna está vacía.")
    if _has(q, "duplicad", "duplicate"):
        return Answer(True, f"{profile['quality']['duplicate_rows']:,} fila(s) duplicada(s) exactas.")
    if _has(q, "hueco", "gap", "sin eventos", "silencio"):
        t = profile.get("time")
        if not t:
            return Answer(True, "Este log no trae una hora legible.")
        return Answer(True, f"Hueco típico entre eventos: {t['median_gap_s']} s. Los más largos:", ("desde (UTC)", "hasta (UTC)", "segundos"),
                      t["largest_gaps"])
    if _has(q, "hora", "hour") and t_ok(profile):
        hours = profile["time"]["per_hour"]
        peak = max(range(24), key=lambda h: (hours[h], -h))
        return Answer(True, f"La hora con más eventos ({profile['time']['zone']}) es las {peak}:00 con {hours[peak]:,}.")
    if _has(q, "formato", "format", "tipo de dato", "parece") and col:
        c = _col_profile(profile, col, present)
        if c and c.get("formats"):
            return Answer(True, f"Formato de los valores de {c['name']} (longitud {c['length']['min']}–{c['length']['max']}):",
                          ("formato", "%"), c["formats"])
    return Answer(False, "No sé responder eso sin el modelo. Prueba con una de las preguntas de ejemplo, o pásasela al agente en la "
                         "pestaña Preguntar (gasta tokens).")


def t_ok(profile: dict) -> bool:
    return bool(profile.get("time"))


__all__ = ["EXAMPLES", "Answer", "answer"]
