"""Perfil de datos: el desglose de "ingeniero de datos" que se hace antes de investigar. 100 % local (DuckDB sobre el dataset completo).

Qué calcula:
* **Por campo**: tipo, celdas con valor y vacías, valores distintos, los más frecuentes con su conteo; mínimo, máximo, media y percentiles
  si es numérico. Una columna con un valor distinto por fila se marca como identificador único (no tiene sentido listar "los más frecuentes").
* **IPs**: para cada columna IP de la copia seudonimizada, cuántas hay de cada alcance (privada, pública, ...) y cuántas distintas.
* **Tiempo**: eventos por día y por hora (en la zona local si se declaró; si no, UTC) y los **huecos** más largos entre eventos
  consecutivos frente al hueco típico: en forense, un hueco puede ser una caída del recolector o un borrado.
* **Calidad**: filas duplicadas, horas que no se pudieron leer, columnas vacías.
* **Entidades** (versión 2): cuántas IPs de origen y de destino, usuarios, equipos, procesos, puertos, reglas, rutas... las que traiga el log.
* **Relaciones**: los pares más frecuentes (origen -> destino, equipo -> proceso, usuario -> IP...) entre las columnas presentes.
* **Primera y última aparición** de las entidades principales, con sus eventos y días activos.
* **Formato de los valores** de cada campo de texto: qué parte parecen IPs, correos, hashes, URLs, rutas, números o alias.

Todo es GENÉRICO: las listas de abajo son datos, no código por tipo de log. Un log web, de firewall, de endpoint o de un tipo futuro usa
las que le apliquen según las columnas que traiga; un tipo nuevo solo tiene que añadir nombres aquí.

Se calcula sobre la COPIA SEUDONIMIZADA: el resultado lleva alias, se puede mostrar al modelo y se guarda en el caso con su hash en el
ledger. La interfaz traduce los alias a valores reales solo en pantalla, con el interruptor de siempre.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

PROFILE_VERSION = 2
# (columna canónica, etiqueta, sinónimos para las preguntas rápidas). El orden es el de presentación.
ENTITIES = (
    ("src_ip", "IPs de origen", ("ip de origen", "ips de origen", "ip origen", "ips origen", "source ip", "source ips", "origen")),
    ("dst_ip", "IPs de destino", ("ip de destino", "ips de destino", "ip destino", "ips destino", "destination ip", "destino")),
    ("user_id", "usuarios", ("usuarios", "usuario", "users", "user", "cuentas", "cuenta", "authtokens", "authtoken", "tokens", "token")),
    ("host", "equipos / hosts", ("equipos", "equipo", "hosts", "host", "maquinas", "maquina", "dispositivos", "dispositivo")),
    ("process_name", "procesos", ("procesos", "proceso", "processes", "process", "ejecutables", "ejecutable", "binarios")),
    ("parent_process", "procesos padre", ("procesos padre", "proceso padre", "padres", "parent")),
    ("dst_port", "puertos de destino", ("puertos", "puerto", "ports", "port")),
    ("protocol", "protocolos", ("protocolos", "protocolo", "protocols", "protocol")),
    ("action", "acciones", ("acciones", "accion", "actions", "action")),
    ("rule_name", "reglas", ("reglas", "regla", "rules", "rule", "politicas")),
    ("application", "aplicaciones", ("aplicaciones", "aplicacion", "applications", "apps")),
    ("endpoint", "rutas (URL)", ("rutas", "ruta", "urls", "url", "endpoints")),
    ("http_method", "métodos HTTP", ("metodos", "metodo", "methods")),
    ("status_code", "códigos de respuesta", ("codigos", "codigo", "status")),
    ("user_agent", "user-agents", ("user agents", "user-agents", "user agent", "navegadores")),
    ("session_id", "sesiones", ("sesiones", "sesion", "sessions")),
    ("file_hash", "hashes", ("hashes", "hash", "sha256")),
    ("event_type", "tipos de evento", ("tipos de evento", "tipo de evento", "event types")),
)
# Pares que interesan si el log trae ambas columnas (como mucho MAX_RELATIONS, en este orden).
RELATIONS = (("src_ip", "dst_ip"), ("src_ip", "dst_port"), ("host", "process_name"), ("process_name", "dst_ip"), ("user_id", "src_ip"),
             ("rule_name", "action"), ("src_ip", "endpoint"), ("user_id", "host"), ("host", "dst_ip"), ("user_id", "endpoint"))
MAX_RELATIONS = 6
FIRST_LAST = ("src_ip", "dst_ip", "user_id", "host", "process_name")
_FORMATS = (  # (clase, expresión regular): la primera que encaja
    ("alias", r"^[A-Z]{1,6}-[0-9]{2,}$"), ("ipv4", r"^([0-9]{1,3}\.){3}[0-9]{1,3}$"),
    ("ipv6", r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"), ("email", r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$"),
    ("url", r"^(https?://|www\.)"), ("hash", r"^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$"),
    ("ruta", r"^([A-Za-z]:\\|\\|/)"), ("número", r"^-?[0-9]+(\.[0-9]+)?$"),
)
_NUMERIC = ("TINYINT", "SMALLINT", "INTEGER", "BIGINT", "HUGEINT", "UTINYINT", "USMALLINT", "UINTEGER", "UBIGINT", "FLOAT", "DOUBLE", "DECIMAL")
_SKIP = {"source_row"}


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _num(v):
    if v is None:
        return None
    f = float(v)
    return int(f) if f.is_integer() else round(f, 3)


def column_for(name: str, present: set[str]) -> str:
    """Columna a contar para una entidad: el nombre del ejecutable (`<col>_base`) si la copia lo trae, si no la propia columna."""
    return f"{name}_base" if f"{name}_base" in present else name


def _lit(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


def _extended(engine, columns: list[dict], present: set[str], total: int) -> dict:
    filled = {c["name"]: c["filled"] for c in columns}
    has = lambda c: c in present and filled.get(c, 0) > 0  # noqa: E731
    entities = []
    for name, label, _ in ENTITIES:
        col = column_for(name, present)
        if has(col):
            entities.append({"column": name, "counted": col, "label": label,
                             "distinct": int(engine.query(f"SELECT count(DISTINCT {_q(col)}) FROM logs").rows[0][0])})
    if has("src_ip") and has("dst_ip"):
        both = engine.query("SELECT count(DISTINCT v) FROM (SELECT src_ip AS v FROM logs UNION ALL SELECT dst_ip FROM logs) WHERE v IS NOT NULL")
        entities.insert(0, {"column": "ip", "counted": "src_ip+dst_ip", "label": "IPs en total (origen o destino)",
                            "distinct": int(both.rows[0][0])})
    relations = []
    for a, b in RELATIONS:
        ca, cb = column_for(a, present), column_for(b, present)
        if len(relations) >= MAX_RELATIONS or not (has(ca) and has(cb)):
            continue
        n = engine.query(f"SELECT count(*) FROM (SELECT DISTINCT {_q(ca)}, {_q(cb)} FROM logs WHERE {_q(ca)} IS NOT NULL AND {_q(cb)} IS NOT NULL)").rows[0][0]
        top = engine.query(f"SELECT CAST({_q(ca)} AS VARCHAR), CAST({_q(cb)} AS VARCHAR), count(*) AS n FROM logs WHERE {_q(ca)} IS NOT NULL "
                           f"AND {_q(cb)} IS NOT NULL GROUP BY 1, 2 ORDER BY n DESC, 1, 2 LIMIT 10").rows
        relations.append({"from": a, "to": b, "pairs": int(n), "top": [[x, y, int(k)] for x, y, k in top]})
    first_last = []
    if "timestamp_utc" in present:
        for name in FIRST_LAST:
            col = column_for(name, present)
            if has(col):
                rows = engine.query(
                    f"SELECT CAST({_q(col)} AS VARCHAR) AS v, count(*) AS n, CAST(min(timestamp_utc) AS VARCHAR), CAST(max(timestamp_utc) AS VARCHAR), "
                    f"count(DISTINCT CAST(timestamp_utc AS DATE)) FROM logs WHERE {_q(col)} IS NOT NULL GROUP BY 1 ORDER BY n DESC, v LIMIT 10").rows
                first_last.append({"column": name, "top": [[v, int(n), a, b, int(d)] for v, n, a, b, d in rows]})
    for c in columns:
        if c["filled"] and c["type"].startswith("VARCHAR"):
            cls = " ".join(f"WHEN regexp_matches(v, {_lit(rx)}) THEN {_lit(name)}" for name, rx in _FORMATS)
            rows = engine.query(f"SELECT CASE {cls} ELSE 'texto' END AS f, count(*) AS n FROM (SELECT CAST({_q(c['name'])} AS VARCHAR) AS v "
                                f"FROM logs WHERE {_q(c['name'])} IS NOT NULL) GROUP BY 1 ORDER BY n DESC, f").rows
            c["formats"] = [[f, round(100 * n / c["filled"], 1)] for f, n in rows]
            mn, avg, mx = engine.query(f"SELECT min(length(CAST({_q(c['name'])} AS VARCHAR))), avg(length(CAST({_q(c['name'])} AS VARCHAR))), "
                                       f"max(length(CAST({_q(c['name'])} AS VARCHAR))) FROM logs").rows[0]
            c["length"] = {"min": _num(mn), "avg": _num(avg), "max": _num(mx)}
    return {"entities": entities, "relations": relations, "first_last": first_last}


def build_profile(engine, top_n: int = 10) -> dict:
    """Perfil del dataset que sirve `engine` (vista `logs`). Determinista: mismo dataset, mismo perfil."""
    cols = [(r[0], str(r[1]).upper()) for r in engine.query("DESCRIBE logs").rows if r[0] not in _SKIP]
    names = [c for c, _ in cols]
    parts = ["count(*)"] + [f"count({_q(c)}), count(DISTINCT {_q(c)})" for c in names]
    row = engine.query(f"SELECT {', '.join(parts)} FROM logs").rows[0]
    total = int(row[0])
    columns = []
    for i, (name, dtype) in enumerate(cols):
        filled, distinct = int(row[1 + 2 * i]), int(row[2 + 2 * i])
        c = {"name": name, "type": dtype, "filled": filled, "empty": total - filled,
             "filled_pct": round(100 * filled / total, 1) if total else 0.0, "distinct": distinct}
        if filled and distinct == filled and filled > top_n:
            c["unique_per_row"] = True
        elif filled and "TIMESTAMP" not in dtype:
            c["top"] = [[str(v), int(n)] for v, n in engine.query(
                f"SELECT CAST({_q(name)} AS VARCHAR) AS v, count(*) AS n FROM logs WHERE {_q(name)} IS NOT NULL "
                f"GROUP BY 1 ORDER BY n DESC, v LIMIT {int(top_n)}").rows]
        if filled and dtype.split("(")[0] in _NUMERIC:
            mn, mx, avg, p50, p95 = engine.query(
                f"SELECT min({_q(name)}), max({_q(name)}), avg({_q(name)}), quantile_cont({_q(name)}, 0.5), "
                f"quantile_cont({_q(name)}, 0.95) FROM logs").rows[0]
            c["stats"] = {"min": _num(mn), "max": _num(mx), "avg": _num(avg), "p50": _num(p50), "p95": _num(p95)}
        columns.append(c)

    present = set(names)
    ips = []
    for name in names:
        if f"{name}_scope" in present:
            ips.append({"column": name, "scopes": [[str(s), int(n), int(d)] for s, n, d in engine.query(
                f"SELECT coalesce({_q(name + '_scope')}, 'sin dato') AS s, count(*) AS n, count(DISTINCT {_q(name)}) AS d FROM logs "
                f"GROUP BY 1 ORDER BY n DESC, s").rows]})

    time = None
    if "timestamp_utc" in present:
        tcol, zone = ("timestamp_local", "local") if "timestamp_local" in present else ("timestamp_utc", "UTC")
        rng = engine.query("SELECT CAST(min(timestamp_utc) AS VARCHAR), CAST(max(timestamp_utc) AS VARCHAR), "
                           "count(*) FILTER (WHERE timestamp_utc IS NULL) FROM logs").rows[0]
        per_day = [[str(d), int(n)] for d, n in engine.query(
            f"SELECT CAST(CAST({tcol} AS DATE) AS VARCHAR) AS d, count(*) AS n FROM logs WHERE {tcol} IS NOT NULL GROUP BY 1 ORDER BY 1",
            max_rows=1000).rows]
        per_hour = {int(h): int(n) for h, n in engine.query(
            f"SELECT hour({tcol}) AS h, count(*) AS n FROM logs WHERE {tcol} IS NOT NULL GROUP BY 1 ORDER BY 1").rows}
        gaps_sql = ("WITH t AS (SELECT timestamp_utc AS ts, lag(timestamp_utc) OVER (ORDER BY timestamp_utc, source_row) AS p FROM logs "
                    "WHERE timestamp_utc IS NOT NULL), g AS (SELECT p, ts, (epoch_ms(ts) - epoch_ms(p)) / 1000.0 AS s FROM t WHERE p IS NOT NULL)")
        median_gap = engine.query(f"{gaps_sql} SELECT median(s) FROM g").rows[0][0]
        gaps = [[str(a), str(b), _num(s)] for a, b, s in engine.query(
            f"{gaps_sql} SELECT CAST(p AS VARCHAR), CAST(ts AS VARCHAR), s FROM g ORDER BY s DESC, ts LIMIT 5").rows]
        time = {"from_utc": rng[0], "to_utc": rng[1], "unreadable": int(rng[2]), "zone": zone, "per_day": per_day,
                "per_hour": [per_hour.get(h, 0) for h in range(24)], "median_gap_s": _num(median_gap), "largest_gaps": gaps}

    data_cols = [c for c in names if c != "timestamp_raw"]
    dup = engine.query(f"SELECT coalesce(sum(c - 1), 0) FROM (SELECT count(*) AS c FROM logs GROUP BY {', '.join(map(_q, data_cols))})"
                       ).rows[0][0] if data_cols else 0
    quality = {"duplicate_rows": int(dup), "empty_columns": [c["name"] for c in columns if c["filled"] == 0],
               "unreadable_times": time["unreadable"] if time else None}
    return {"profile_version": PROFILE_VERSION, "rows": total, "columns": columns, "ips": ips, "time": time, "quality": quality,
            **_extended(engine, columns, present, total)}


def digest(profile: dict, limit: int = 1800) -> str:
    """Resumen corto del perfil para el agente (en alias, como el perfil)."""
    out = [f"PERFIL DE DATOS (calculado por código sobre la copia): {profile['rows']:,} filas, {len(profile['columns'])} columnas."]
    t = profile.get("time")
    if t:
        busiest = sorted(t["per_day"], key=lambda x: (-x[1], x[0]))[:3]
        out.append(f"Rango UTC {t['from_utc']} → {t['to_utc']}. Días con más eventos ({t['zone']}): "
                   + ", ".join(f"{d} ({n:,})" for d, n in busiest) + ".")
        if t["largest_gaps"]:
            a, b, s = t["largest_gaps"][0]
            out.append(f"Hueco más largo sin eventos: {s:,} s ({a} → {b}); hueco típico {t['median_gap_s']} s.")
    if profile.get("entities"):
        out.append("Entidades: " + ", ".join(f"{e['label']} {e['distinct']:,}" for e in profile["entities"]) + ".")
    for rel in profile.get("relations", [])[:3]:
        out.append(f"{rel['from']}→{rel['to']} ({rel['pairs']:,} pares): " + ", ".join(f"{a}→{b}={n:,}" for a, b, n in rel["top"][:3]) + ".")
    for ip in profile["ips"]:
        out.append(f"{ip['column']}: " + ", ".join(f"{s} {n:,} eventos/{d:,} distintas" for s, n, d in ip["scopes"]) + ".")
    for c in profile["columns"]:
        if c.get("top") and 1 < c["distinct"] <= 50:
            out.append(f"{c['name']} ({c['distinct']} valores): " + ", ".join(f"{v}={n:,}" for v, n in c["top"][:5]) + ".")
    q = profile["quality"]
    if q["duplicate_rows"] or q["empty_columns"]:
        out.append(f"Calidad: {q['duplicate_rows']:,} filas duplicadas; columnas vacías: {', '.join(q['empty_columns']) or 'ninguna'}.")
    text = " ".join(out)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def save_profile(profile: dict, path: str | Path) -> str:
    """Guarda el perfil como JSON canónico y devuelve su SHA-256 (para registrarlo en el ledger)."""
    data = json.dumps(profile, ensure_ascii=False, sort_keys=True, indent=1)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(data + "\n", encoding="utf-8")
    return hashlib.sha256((data + "\n").encode("utf-8")).hexdigest()


__all__ = ["ENTITIES", "PROFILE_VERSION", "RELATIONS", "build_profile", "column_for", "digest", "save_profile"]
