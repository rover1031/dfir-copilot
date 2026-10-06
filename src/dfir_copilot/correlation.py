"""Correlación entre fuentes de un mismo análisis (entrega D2). Local, por código, sin modelo.

Qué hace con los casos ingeridos de un análisis:
1. **Entidades compartidas** (cualquier par de casos): IPs que aparecen en más de una fuente, con sus eventos en cada una.
2. **Firewall × endpoint** (si hay un caso de red y otro de endpoint con conexiones):
   * une cada conexión del endpoint con la del firewall de la misma IP de origen, IP de destino y puerto, la más cercana en el tiempo;
   * **estima el desfase de relojes** (mediana de las diferencias de esos pares) y acepta como coincidencia la que, corregido el desfase,
     cae dentro de una tolerancia (2 s por defecto). Un desfase mayor que `max_skew_s` no se busca: se dice que no hay pares;
   * agrupa en **flujos**: equipo · proceso → destino:puerto, con cuántas conexiones vio el endpoint, cuántas casan con el firewall y qué
     acción les dio el firewall;
   * **atribuye los hallazgos del firewall** (que solo conocen la IP) al equipo y al proceso del endpoint: «la baliza de la IP X la abre
     rundll32.exe en el equipo Y». La IP -> equipo sale del propio endpoint, con su ventana de tiempo (las IPs dinámicas cambian de equipo).

Se calcula sobre los datos REALES (es local) y el resultado se guarda en `<análisis>/correlacion.json` con su hash en el ledger de cada caso
implicado. La interfaz lo muestra en alias por defecto. Límite conocido: con NAT entre el equipo y el firewall, la IP de origen del firewall
no es la del equipo y no habrá pares (se informa).
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import duckdb

from dfir_copilot.endpoint_sql import basename_sql

MIN_CONSISTENT = 0.5  # fracción mínima de pares origen-destino-puerto que deben coincidir en el desfase estimado para darlo por bueno
_NETWORK_FINDINGS = ("beaconing", "volume_outlier", "risky_outbound", "service_fanout", "blocked_then_allowed", "policy_contradiction")


def _lit(v: str) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def _cases(project) -> list[dict]:
    out = []
    for f in project.files():
        if not f.supported or not (project.cases_dir / f.case_id / "case.json").exists():
            continue
        ws = project.workspace(f.case_id)
        if not ws.meta.get("dataset"):
            continue
        man = ws.engine().manifest
        out.append({"case_id": f.case_id, "file": f.name, "ws": ws, "schema": man.get("log_schema", "web"),
                    "parquet": man["output"]["path"]})
    return out


def _columns(con, parquet: str) -> set[str]:
    return {r[0] for r in con.execute(f"DESCRIBE SELECT * FROM read_parquet({_lit(parquet)})").fetchall()}


def _shared_ips(con, cases: list[dict]) -> dict:
    parts = []
    for c in cases:
        cols = _columns(con, c["parquet"]) & {"src_ip", "dst_ip"}
        for col in sorted(cols):
            parts.append(f"SELECT {_lit(c['case_id'])} AS caso, {col} AS ip FROM read_parquet({_lit(c['parquet'])}) WHERE {col} IS NOT NULL")
    if len({p.split("'")[1] for p in parts}) < 2:
        return {"total": 0, "top": []}
    con.execute(f"CREATE OR REPLACE TEMP TABLE ips AS {' UNION ALL '.join(parts)}")
    total = con.execute("SELECT count(*) FROM (SELECT ip FROM ips GROUP BY ip HAVING count(DISTINCT caso) > 1)").fetchone()[0]
    rows = con.execute("SELECT ip, count(DISTINCT caso) AS fuentes, count(*) AS eventos, list_sort(list(DISTINCT caso)) FROM ips GROUP BY ip "
                       "HAVING count(DISTINCT caso) > 1 ORDER BY eventos DESC, ip LIMIT 20").fetchall()
    return {"total": int(total), "top": [[ip, int(f), int(n), list(cs)] for ip, f, n, cs in rows]}


def _ports(m: dict) -> list[int]:
    """Puertos concretos del hallazgo: `puertos` si es una lista (en otros detectores es un conteo) o `puerto`."""
    p = m.get("puertos")
    if isinstance(p, list):
        return [int(x) for x in p if x is not None]
    return [int(m["puerto"])] if isinstance(m.get("puerto"), int) else []


def _findings(ws) -> list[dict]:
    """Hallazgos del caso con sus valores reales (el ledger los guarda en alias)."""
    _, ps = ws.pseudonymized()
    out = []
    for e in ws.ledger(ws.engine()).entries("finding"):
        d = e["data"]
        out.append({"detector": d["detector"], "severity": d["severity"], "entity": {k: ps.reveal_any(str(v)) for k, v in d["entity"].items()},
                    "related": {k: [ps.reveal_any(str(x)) for x in xs] for k, xs in (d.get("related") or {}).items()},
                    "destino": ps.reveal_any(str(d.get("metrics", {}).get("destino"))) if d.get("metrics", {}).get("destino") else None,
                    "puertos": _ports(d.get("metrics", {}))})
    return out


def _hour_hint(con, max_skew_s: float, sample: int = 3000) -> dict | None:
    """Si las fuentes no casan, ¿casan desplazando el firewall un número entero de horas? Eso suele ser una zona horaria mal declarada en
    una de las dos (p. ej. un firewall sin zona interpretado como hora local frente a un EDR en UTC). Prueba de -14 h a +14 h sobre una muestra."""
    best = None
    for h in range(-14, 15):
        if h == 0:
            continue
        n = con.execute(f"""SELECT count(DISTINCT e.rid) FROM (SELECT * FROM ed WHERE rid <= {int(sample)}) e JOIN fw
            ON e.src_ip = fw.src_ip AND e.dst_ip = fw.dst_ip AND e.dst_port IS NOT DISTINCT FROM fw.dst_port
            AND fw.ts + to_hours({h}) BETWEEN e.ts - to_seconds({float(max_skew_s)!r}) AND e.ts + to_seconds({float(max_skew_s)!r})""").fetchone()[0]
        if best is None or n > best[1]:
            best = (h, n)
    total = con.execute(f"SELECT count(*) FROM ed WHERE rid <= {int(sample)}").fetchone()[0]
    if best and total and best[1] >= 0.5 * total:
        return {"hours": best[0], "fraction": round(best[1] / total, 3)}
    return None


def _no_pairs(con, base: dict, max_skew_s: float) -> dict:
    hint = _hour_hint(con, max_skew_s)
    if hint:
        base["hour_offset_hint"] = hint
        base["reason"] += (f" Casan si se desplaza el firewall {hint['hours']:+d} h ({hint['fraction']:.0%} de una muestra): probablemente la "
                           f"zona horaria de una de las fuentes está mal declarada; revisa la del firewall y la del endpoint.")
    return base


def _fw_edr(con, fw: dict, edr: dict, tol_s: float, max_skew_s: float) -> dict:
    con.execute(f"""CREATE OR REPLACE TEMP VIEW fw AS SELECT timestamp_utc AS ts, src_ip, dst_ip, dst_port, action
                    FROM read_parquet({_lit(fw['parquet'])}) WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL AND timestamp_utc IS NOT NULL""")
    con.execute(f"""CREATE OR REPLACE TEMP TABLE ed AS SELECT row_number() OVER () AS rid, timestamp_utc AS ts, src_ip, dst_ip, dst_port, host,
                    {basename_sql('process_name')} AS proc FROM read_parquet({_lit(edr['parquet'])})
                    WHERE dst_ip IS NOT NULL AND src_ip IS NOT NULL AND timestamp_utc IS NOT NULL""")
    # par más cercano de cada conexión del endpoint, dentro de ±max_skew_s (join por rango: eficiente en DuckDB)
    con.execute(f"""CREATE OR REPLACE TEMP TABLE near AS
        SELECT ed.rid, ed.host, ed.proc, ed.src_ip, ed.dst_ip, ed.dst_port, fw.action,
               (epoch_ms(ed.ts) - epoch_ms(fw.ts)) / 1000.0 AS diff
        FROM ed JOIN fw ON ed.src_ip = fw.src_ip AND ed.dst_ip = fw.dst_ip AND ed.dst_port IS NOT DISTINCT FROM fw.dst_port
             AND fw.ts BETWEEN ed.ts - to_seconds({float(max_skew_s)!r}) AND ed.ts + to_seconds({float(max_skew_s)!r})
        QUALIFY row_number() OVER (PARTITION BY ed.rid ORDER BY abs(epoch_ms(ed.ts) - epoch_ms(fw.ts)), fw.ts) = 1""")
    edr_events = con.execute("SELECT count(*) FROM ed").fetchone()[0]
    paired = con.execute("SELECT count(*), median(diff) FROM near").fetchone()
    if not paired[0]:
        return _no_pairs(con, {"status": "sin_pares", "edr_events": int(edr_events),
                               "reason": f"Ninguna conexión del endpoint tiene par en el firewall dentro de ±{max_skew_s:g} s "
                                         f"(¿NAT, otra red o relojes muy desfasados?)."}, max_skew_s)
    # El desfase se estima POR PAR origen-destino-puerto (cada par vota una vez), no por conexión: con tráfico periódico (una baliza cada
    # 600 s) y un desfase mayor que la ventana, cada conexión cae siempre a la misma distancia de la SIGUIENTE baliza y daría un desfase falso
    # pero «consistente». Por pares, la baliza es un solo voto y el resto del tráfico, aleatorio, no coincide.
    skew, keys = con.execute("SELECT median(km), count(*) FROM (SELECT median(diff) AS km FROM near GROUP BY src_ip, dst_ip, dst_port)").fetchone()
    skew = float(skew)
    consistent = con.execute(f"SELECT count(*) FROM (SELECT median(diff) AS km FROM near GROUP BY src_ip, dst_ip, dst_port) "
                             f"WHERE abs(km - {skew!r}) <= {float(tol_s)!r}").fetchone()[0]
    matched = con.execute(f"SELECT count(*) FROM near WHERE abs(diff - {skew!r}) <= {float(tol_s)!r}").fetchone()[0]
    if consistent < MIN_CONSISTENT * keys:
        return _no_pairs(con, {"status": "sin_pares", "edr_events": int(edr_events), "paired": int(paired[0]), "matched": int(matched),
                "reason": f"Solo {consistent:,} de {keys:,} pares origen-destino-puerto coinciden en un mismo desfase (se necesita al menos el "
                          f"{MIN_CONSISTENT:.0%}): las fuentes no parecen del mismo periodo o red, o el desfase supera ±{max_skew_s:g} s "
                          f"(¿NAT, otra red o relojes muy desfasados?)."}, max_skew_s)
    flows = con.execute(f"""SELECT ed.host, ed.proc, ed.dst_ip, ed.dst_port, count(*) AS conexiones,
            count(near.rid) FILTER (WHERE abs(near.diff - {skew!r}) <= {float(tol_s)!r}) AS casan,
            list_sort(list(DISTINCT near.action) FILTER (WHERE near.action IS NOT NULL)) AS acciones,
            CAST(min(ed.ts) AS VARCHAR), CAST(max(ed.ts) AS VARCHAR)
        FROM ed LEFT JOIN near USING (rid) GROUP BY 1, 2, 3, 4 ORDER BY conexiones DESC, ed.host, ed.proc, ed.dst_ip, ed.dst_port LIMIT 25""").fetchall()
    ip_host = con.execute("""SELECT src_ip, host, count(*), CAST(min(ts) AS VARCHAR), CAST(max(ts) AS VARCHAR) FROM ed GROUP BY 1, 2
                             ORDER BY src_ip, min(ts), host""").fetchall()
    hosts_of = {}
    for ip, host, *_ in ip_host:
        hosts_of.setdefault(ip, []).append(host)
    attributions = []
    for f in _findings(fw["ws"]):
        ip = f["entity"].get("src_ip")
        if f["detector"] not in _NETWORK_FINDINGS or not ip or ip not in hosts_of:
            continue
        dsts = [d for d in ([f["destino"]] if f["destino"] else []) + f["related"].get("dst_ip", []) if d]
        cond = f" AND dst_ip IN ({', '.join(_lit(d) for d in dsts)})" if dsts else ""
        if f["puertos"]:  # p. ej. administración hacia Internet: solo los procesos de esos puertos
            cond += f" AND dst_port IN ({', '.join(str(x) for x in f['puertos'])})"
        procs = con.execute(f"SELECT host, proc, count(*) AS n FROM ed WHERE src_ip = {_lit(ip)}{cond} GROUP BY 1, 2 "
                            f"ORDER BY n DESC, host, proc LIMIT 3").fetchall()
        attributions.append({"detector": f["detector"], "severity": f["severity"], "src_ip": ip, "destinos": dsts[:3],
                             "hosts": hosts_of[ip], "procesos": [[h, p, int(n)] for h, p, n in procs]})
    edr_hosts = {f["entity"].get("host") for f in _findings(edr["ws"]) if f["entity"].get("host")}
    for a in attributions:
        a["tambien_en_endpoint"] = sorted(set(a["hosts"]) & edr_hosts)
    return {"status": "ok", "firewall": fw["case_id"], "endpoint": edr["case_id"], "edr_events": int(edr_events), "paired": int(paired[0]),
            "matched": int(matched), "skew_s": round(skew, 3), "tolerance_s": tol_s,
            "flows": [[h, p, d, port, int(n), int(m), list(a or []), f, la] for h, p, d, port, n, m, a, f, la in flows],
            "ip_host": [[ip, h, int(n), a, b] for ip, h, n, a, b in ip_host][:50], "attributions": attributions}


def correlate_project(project, tol_s: float = 2.0, max_skew_s: float = 120.0) -> dict:
    """Correlaciona los casos del análisis y guarda el resultado. Devuelve el resultado (también si no aplica, con el motivo)."""
    cases = _cases(project)
    result = {"version": 1, "computed_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
              "cases": [{"case_id": c["case_id"], "file": c["file"], "schema": c["schema"]} for c in cases]}
    if len(cases) < 2:
        result.update(status="no_aplica", reason="Hacen falta al menos dos archivos analizados en el mismo análisis.")
        return result
    con = duckdb.connect()
    try:
        con.execute("SET TimeZone = 'UTC'")
        result["shared_ips"] = _shared_ips(con, cases)
        fws = [c for c in cases if c["schema"] == "network"]
        edrs = [c for c in cases if c["schema"] == "endpoint" and "dst_ip" in _columns(con, c["parquet"])]
        result["pairs"] = [_fw_edr(con, fw, edr, tol_s, max_skew_s) for fw in fws for edr in edrs]
    finally:
        con.close()
    result["status"] = "ok"
    data = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=1) + "\n"
    (project.dir / "correlacion.json").write_text(data, encoding="utf-8")
    sha = hashlib.sha256(data.encode("utf-8")).hexdigest()
    for c in cases:
        c["ws"].ledger(c["ws"].engine()).append("correlation", {"file": "correlacion.json", "sha256": sha,
                                                                "cases": [x["case_id"] for x in cases]})
    return result


def load(project) -> dict | None:
    path = project.dir / "correlacion.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def digest_for(result: dict | None, ps) -> str | None:
    """Resumen de la correlación para el agente de UN caso, sin valores reales: las IPs pasan por el diccionario de ese caso, los equipos
    se numeran (EQUIPO-1...) y los procesos van por su nombre de ejecutable (vocabulario técnico)."""
    pairs = [x for x in (result or {}).get("pairs", []) if x.get("status") == "ok"]
    if not pairs:
        return None
    hosts: dict[str, str] = {}

    def host(h):
        return hosts.setdefault(h, f"EQUIPO-{len(hosts) + 1}")

    def ip(v):
        try:
            return ps.alias_text(str(v)).text if ps else "IP"
        except Exception:  # noqa: BLE001 - un valor dudoso no se envía
            return "IP"

    out = []
    for pr in pairs:
        out.append(f"CORRELACIÓN FIREWALL×ENDPOINT (calculada por código): {pr['matched']:,} de {pr['edr_events']:,} conexiones del endpoint "
                   f"casan con el firewall; desfase de relojes estimado {pr['skew_s']} s.")
        for a in pr["attributions"][:8]:
            procs = ", ".join(f"{host(h)}·{proc} ({n:,})" for h, proc, n in a["procesos"][:2])
            out.append(f"- {a['detector']} ({a['severity']}) en {ip(a['src_ip'])} -> {procs}"
                       + (" · también señalado por el endpoint" if a["tambien_en_endpoint"] else "") + ".")
    return "\n".join(out)[:2500]


__all__ = ["correlate_project", "digest_for", "load"]
