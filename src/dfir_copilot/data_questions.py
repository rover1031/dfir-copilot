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
            "¿Qué campos están vacíos?", "¿Cuál es el rango de fechas?", "¿Quién habla con quién?", "¿Cuándo apareció IP-0001?",
            "Top 20 de IPs que más peticiones hicieron al endpoint /invoices/search", "¿Cuál es el top de países detrás de dichas IPs?")
_VALUE = re.compile(r"\b([A-Z]{1,6}-[0-9]{2,}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})\b|[\"'«]([^\"'»]+)[\"'»]")


@dataclass
class Answer:
    matched: bool
    text: str
    headers: tuple = ()
    rows: list = field(default_factory=list)
    sql: str | None = None
    context: dict = field(default_factory=dict)  # filtro y ranking de esta respuesta: la siguiente pregunta puede decir «dichas IPs»


def _norm(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii").lower()
    return re.sub(r"\s+", " ", re.sub(r"[¿?¡!,.;:()]", " ", text)).strip()


def _has(q: str, *words: str) -> bool:
    return any(re.search(rf"\b{re.escape(w)}", q) for w in words)


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _column(q: str, profile: dict, exclude: set[str] = frozenset()) -> str | None:
    """La columna a la que se refiere la pregunta: por su nombre exacto, por su nombre corto si es derivada, o por los sinónimos de las
    entidades (el más largo primero). `exclude`: las que la pregunta usa como filtro («al endpoint /x» no pide rankear endpoint)."""
    names = {c["name"] for c in profile["columns"]} - set(exclude)
    for name in sorted(names, key=len, reverse=True):
        if re.search(rf"\b{re.escape(name.lower())}\b", q):
            return name
    for name in sorted(names, key=len, reverse=True):  # columnas derivadas por su nombre corto: x_invoice_id -> invoice_id, invoice
        base = name.removeprefix("x_")
        for token in (base, base.removesuffix("_id")):
            if name.startswith("x_") and len(token) >= 4 and re.search(rf"\b{re.escape(token.lower())}", q):
                return name
    candidates = sorted(((syn, col) for col, _, syns in ENTITIES for syn in syns), key=lambda x: -len(x[0]))
    for syn, col in candidates:
        if re.search(rf"\b{re.escape(syn)}", q) and (col in names or f"{col}_base" in names):
            return col
    if re.search(r"\bips?\b", q):  # «IPs» a secas: las de origen (quien hace las peticiones), o las de destino si no hay
        return "src_ip" if "src_ip" in names else ("dst_ip" if "dst_ip" in names else None)
    return None


def _filters(raw: str, q: str, present: set[str]) -> dict:
    """Filtros escritos en la pregunta: una ruta (`al endpoint /invoices/search`) y `columna = valor`."""
    out = {}
    m = re.search(r"(?<![\w/])(/[A-Za-z0-9_\-./{}]+)", raw)
    if m and "endpoint" in present:
        out["endpoint"] = m.group(1).rstrip(".")
    for col, val in re.findall(r"\b([a-z_][a-z0-9_]*)\s*=\s*([^\s,?¿]+)", raw):
        if col in present:
            out[col] = val
    return out


def _where(filters: dict) -> str:
    if not filters:
        return ""
    return " AND " + " AND ".join(f"CAST({_q(c)} AS VARCHAR) = '{str(v).replace(chr(39), chr(39) * 2)}'" for c, v in filters.items())


def _fdesc(filters: dict) -> str:
    return (" (filtro: " + ", ".join(f"{c} = {v}" for c, v in filters.items()) + ")") if filters else ""


def _col_profile(profile: dict, column: str, present: set[str]) -> dict | None:
    """El perfil de la columna que se cuenta para esa entidad: la derivada (`<col>_base`) si existe, si no la propia."""
    by = {c["name"]: c for c in profile["columns"]}
    return by.get(column_for(column, present)) or by.get(column)


def _entity(profile: dict, column: str) -> dict | None:
    return next((e for e in profile.get("entities", []) if e["column"] == column), None)


def answer(question: str, profile: dict, engine=None, top_max: int = 50, real_engine=None, geo=None,
           context: dict | None = None) -> Answer:
    """Responde `question` (ya en alias) con el perfil y, si hace falta, con consultas sobre `engine` (la copia con alias).

    `real_engine` y `geo` solo se usan para los países (hace falta la IP real para geolocalizar; sale solo el agregado por país).
    `context`: el de la respuesta anterior, para entender «dichas IPs», «esas IPs»..."""
    raw = question or ""
    q = _norm(raw)
    if not q:
        return Answer(False, "Escribe una pregunta.")
    present = {c["name"] for c in profile["columns"]}
    count_words = ("cuant", "how many", "numero de", "cantidad", "total de", "count")
    filters = _filters(raw, q, present)
    # la ruta y los «columna = valor» son filtros: se quitan del texto antes de decidir qué columna se pide (si no, «/invoices/search»
    # haría pensar que se pregunta por invoice_id)
    q_cols = re.sub(r"\b[a-z_][a-z0-9_]*\s*=\s*\S+", " ", re.sub(r"(?<![\w/])/[a-z0-9_\-./{}]+", " ", q))
    col = _column(q_cols, profile, exclude=set(filters))
    previous = context if _has(q, "dichas", "dichos", "esas", "esos", "estas", "estos", "those", "these") and context else None
    if previous and not filters:
        filters = dict(previous.get("filter") or {})

    if _has(q, "pais", "paises", "country", "countries", "geolocal"):
        return _countries(q, filters, previous, present, real_engine, geo)

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
    if col and _has(q, "top", "mas frecuente", "mas comun", "ranking", "principales", "most common", "mas activ", "mas afectad",
                    "mas atacad", "mas consultad", "que mas", "cuales son los", "cual es el"):
        n = min(int(m.group(1)), top_max) if (m := re.search(r"\btop\s*(\d{1,3})\b|\b(\d{1,3})\s+(?:ips|valores|primer)", q)) and \
            (m.group(1) or m.group(2)) else (1 if _has(q, "cual es el", "mas afectad") and not _has(q, "top") else 10)
        if m and (m.group(1) or m.group(2)):
            n = min(int(m.group(1) or m.group(2)), top_max)
        target = column_for(col, present)
        sql = (f"SELECT CAST({_q(target)} AS VARCHAR) AS valor, count(*) AS eventos FROM logs WHERE {_q(target)} IS NOT NULL{_where(filters)} "
               f"GROUP BY 1 ORDER BY eventos DESC, valor LIMIT {n}")
        note = " El log identifica a cada actor por su authtoken: se muestran esas identidades." if (
            target == "user_id" and _has(q, "token", "authtoken")) else ""
        ctx = {"filter": filters, "column": target, "top": n}
        head = (f"El valor más frecuente de {target} (por número de eventos)" if n == 1
                else f"Los {n} valores más frecuentes de {target}")
        if engine is None:
            top = (_col_profile(profile, col, present) or {}).get("top", [])[:n]
            return Answer(True, f"{head}:{note}", ("valor", "eventos"), top, context=ctx)
        return Answer(True, f"{head}{_fdesc(filters)}:{note}", ("valor", "eventos"), [list(r) for r in engine.query(sql).rows], sql, context=ctx)
    generic_ip = re.search(r"\bips?\b", q_cols) and not _has(q, "origen", "destino", "source", "destination")
    if _has(q, "ip") and _has(q, *count_words) and (col not in ("src_ip", "dst_ip") or generic_ip) and not filters:
        ents = [e for e in profile.get("entities", []) if e["column"] in ("ip", "src_ip", "dst_ip")]
        if ents:
            return Answer(True, " · ".join(f"{e['label']}: {e['distinct']:,}" for e in ents) + ".", ("entidad", "distintas"),
                          [[e["label"], e["distinct"]] for e in ents])
    if col and _has(q, *count_words, "distint", "valores", "diferentes"):
        e = _entity(profile, col)
        c = _col_profile(profile, col, present)
        label, distinct = (e["label"], e["distinct"]) if e else (col, c["distinct"] if c else 0)
        top = (c or {}).get("top", [])[:5]
        sql = None
        if filters and engine is not None:
            target = column_for(col, present)
            sql = f"SELECT count(DISTINCT {_q(target)}) FROM logs WHERE {_q(target)} IS NOT NULL{_where(filters)}"
            distinct = int(engine.query(sql).rows[0][0])
        note = (" El log no dice a quién pertenece cada uno: esa cifra es el máximo de dueños posibles (usuarios afectados), "
                "no un recuento de usuarios." if _has(q, "afectad") and col != "user_id" else "")
        return Answer(True, f"{label}: {distinct:,} distintos{_fdesc(filters)}" + (f" (en {c['filled']:,} filas con valor)." if c and not
                      filters else ".") + note, ("valor más frecuente", "eventos"), top, sql)
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


def _countries(q: str, filters: dict, previous: dict | None, present: set[str], real_engine, geo) -> Answer:
    """Top de países de las IPs (de origen salvo que diga «destino»), con el filtro y, si dice «dichas», solo las del ranking anterior.
    Geolocalizar necesita la IP real: se hace en local sobre los datos reales y solo sale el agregado por país."""
    from dfir_copilot.geoip import ATTRIBUTION

    col = "dst_ip" if _has(q, "destino", "destination") else "src_ip"
    if previous and previous.get("column") in ("src_ip", "dst_ip"):
        col = previous["column"]
    if col not in present:
        return Answer(True, "Este log no trae IPs que geolocalizar.")
    if geo is None:
        return Answer(True, "Para responder países hace falta una base GeoIP local (no viene incluida por tamaño y licencia). Descarga "
                      "gratis «IP to Country Lite» de DB-IP (CSV o MMDB) en https://db-ip.com/db/download/ip-to-country-lite y déjala "
                      "en la carpeta geoip/ de la raíz de datos (o indica la ruta con DFIR_GEOIP_DB).")
    if real_engine is None:
        return Answer(False, "Geolocalizar necesita los datos reales (en local); esta consulta no los tiene.")
    limit = f" LIMIT {int(previous['top'])}" if previous and previous.get("column") == col and previous.get("top") else ""
    sql = (f"SELECT CAST({_q(col)} AS VARCHAR) AS ip, count(*) AS eventos FROM logs WHERE {_q(col)} IS NOT NULL{_where(filters)} "
           f"GROUP BY 1 ORDER BY eventos DESC, ip{limit}")
    by: dict[str, list[int]] = {}
    for ip, n in real_engine.query(sql, max_rows=100000).rows:
        country = geo.country(ip) or "desconocido"
        agg = by.setdefault(country, [0, 0])
        agg[0] += n
        agg[1] += 1
    rows = sorted(([c, e, i] for c, (e, i) in by.items()), key=lambda r: (-r[1], r[0]))
    scope = f"de las {previous['top']} IPs del ranking anterior" if limit else f"de {col}"
    return Answer(True, f"Países {scope}{_fdesc(filters)}. {ATTRIBUTION}", ("país", "eventos", "IPs"), rows[:20], sql.replace(" AS ip", " AS ip"))


def t_ok(profile: dict) -> bool:
    return bool(profile.get("time"))


__all__ = ["EXAMPLES", "Answer", "answer"]
