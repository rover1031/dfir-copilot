"""Vista del incidente: un análisis con varias fuentes visto como un todo, SIN perder de dónde sale cada cosa.

* `sources`: cada archivo analizado como fuente, con su tipo (firewall, endpoint, web...), un color fijo por tipo y el hash de su archivo.
* `findings`: los hallazgos de todas las fuentes juntos, ordenados por severidad, cada uno con su fuente.
* `timeline`: la línea de tiempo del incidente en UTC: entrada de cada archivo en la custodia, inicio y fin de la actividad de cada
  hallazgo, primeras conexiones atribuidas por la correlación, hipótesis y decisiones, y notas del analista. Las horas de una fuente
  de endpoint se muestran corregidas con el desfase de relojes que estimó la correlación, y se marca que están corregidas.
* `tokens` / `over_budget`: el consumo del incidente completo frente a su tope (`max_tokens_incident`).

Todo lo que se devuelve va en ALIAS (cada fuente con su diccionario); la interfaz lo traduce a valores reales solo con el interruptor.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

KIND = {"network": ("Firewall", "network"), "endpoint": ("Endpoint", "endpoint"), "web": ("Web", "web")}
_SEV = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _lit(v) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def sources(project) -> list[dict]:
    custody = {e["file"]: e for e in project.custody() if e["action"] in ("added", "derived")} if project.mode == "evidence" else {}
    out = []
    for f in project.files():
        if not f.supported or not (project.cases_dir / f.case_id / "case.json").exists():
            continue
        ws = project.workspace(f.case_id)
        if not ws.meta.get("dataset"):
            continue
        man = ws.engine().manifest
        schema = man.get("log_schema", "web")
        label, css = KIND.get(schema, (schema, "other"))
        sha = (custody.get(f.name) or {}).get("sha256") or man.get("input", {}).get("sha256")
        out.append({"case_id": f.case_id, "file": f.name, "schema": schema, "label": label, "css": css, "sha": sha,
                    "rows": man.get("output", {}).get("rows"), "ws": ws})
    return out


def findings(srcs: list[dict]) -> list[dict]:
    rows = []
    for s in srcs:
        for e in s["ws"].ledger(s["ws"].engine()).entries("finding"):
            d = e["data"]
            rows.append({"source": s, "severity": d["severity"], "detector": d["detector"], "title": d.get("title"),
                         "entity": ", ".join(f"{k}={v}" for k, v in d["entity"].items()), "summary": d["summary"],
                         "finding_id": d["finding_id"], "entity_raw": d["entity"],
                         "dst": [x for x in ([d.get("metrics", {}).get("destino")] + list((d.get("related") or {}).get("dst_ip", []))) if x]})
    return sorted(rows, key=lambda r: (_SEV.get(r["severity"], 9), r["source"]["label"], r["detector"], r["finding_id"]))


def _skew_by_case(project) -> dict[str, float]:
    path = project.dir / "correlacion.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {pr["endpoint"]: pr["skew_s"] for pr in data.get("pairs", []) if pr.get("status") == "ok"}


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace(" ", "T").replace("+00", "+00:00") if str(ts).endswith("+00") else str(ts).replace(" ", "T"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def timeline(project, srcs: list[dict], limit: int = 400) -> list[dict]:
    """Eventos ordenados por hora UTC (corregida en las fuentes de endpoint correlacionadas). Cada evento lleva su fuente."""
    skew = _skew_by_case(project)
    by_file = {s["file"]: s for s in srcs}
    events = []

    def add(ts, source, kind, text, severity=None, corrected=False):
        dt = _parse(ts) if isinstance(ts, str) else ts
        if dt is None:
            return
        events.append({"dt": dt, "ts": dt.strftime("%Y-%m-%d %H:%M:%S"), "source": source, "kind": kind, "text": text,
                       "severity": severity, "corrected": corrected})

    if project.mode == "evidence":
        for e in project.custody():
            if e["action"] == "added":
                add(e["at_utc"], by_file.get(e["file"]), "custodia", f"Entra en la evidencia: {e['file']} (SHA-256 {e['sha256'][:12]}…)")
    for s in srcs:
        pseudo, _ = s["ws"].pseudonymized()
        cols = {r[0] for r in pseudo.query("DESCRIBE logs").rows}
        delta = timedelta(seconds=skew.get(s["case_id"], 0.0))
        corrected = s["case_id"] in skew
        for f in findings([s]):
            conds = [f"CAST({_q(k)} AS VARCHAR) = {_lit(v)}" for k, v in f["entity_raw"].items() if k in cols]
            if f["dst"] and "dst_ip" in cols:  # la actividad SEÑALADA (p. ej. la baliza), no toda la actividad de esa IP
                conds.append(f"CAST(dst_ip AS VARCHAR) IN ({', '.join(_lit(x) for x in f['dst'][:5])})")
            target = f" → {', '.join(f['dst'][:2])}" if f["dst"] else ""
            if not conds or "timestamp_utc" not in cols:
                continue
            a, b, n = pseudo.query(f"SELECT min(timestamp_utc), max(timestamp_utc), count(*) FROM logs WHERE {' AND '.join(conds)}").rows[0]
            da, db = _parse(str(a)), _parse(str(b))  # el motor entrega las horas como texto
            if not n or da is None:
                continue
            add(da - delta, s, "hallazgo", f"Empieza lo que señala {f['detector']}: {f['entity']}{target}", f["severity"], corrected)
            if db and db != da:
                add(db - delta, s, "hallazgo", f"Último evento de {f['detector']}: {f['entity']}{target} ({n:,} eventos)", f["severity"], corrected)
        ledger = s["ws"].ledger(s["ws"].engine())
        for e in ledger.entries("hypothesis"):
            add(e["ts_utc"], s, "hipótesis", f"Hipótesis propuesta {e['data']['hypothesis_id']}: {e['data']['statement']}")
        for e in ledger.entries("hypothesis_update"):
            d = e["data"]
            if d.get("decision") in ("approved", "rejected"):
                add(e["ts_utc"], s, "decisión", f"{d['hypothesis_id']} {'aprobada' if d['decision'] == 'approved' else 'rechazada'} "
                                                f"({d.get('from')} → {d.get('to')})" + (f": {d['note']}" if d.get("note") else ""))
        for e in ledger.entries("note"):
            add(e["ts_utc"], s, "nota", f"Nota del analista: {e['data'].get('text', '')}")
    corr = project.dir / "correlacion.json"
    if corr.exists():
        data = json.loads(corr.read_text(encoding="utf-8"))
        for pr in data.get("pairs", []):
            if pr.get("status") != "ok":
                continue
            edr = next((s for s in srcs if s["case_id"] == pr["endpoint"]), None)
            if edr is None:
                continue
            _, ps = edr["ws"].pseudonymized()  # correlacion.json guarda valores reales: aquí se pasan a los alias de la fuente de endpoint

            def alias(value, ps=ps):
                try:
                    return ps.alias_text(str(value)).text
                except Exception:  # noqa: BLE001 - un valor dudoso no se muestra
                    return "•••"

            delta = timedelta(seconds=pr["skew_s"])
            for a in pr["attributions"][:10]:
                flow = next((f for f in pr["flows"] if a["procesos"] and f[0] == a["procesos"][0][0] and f[1] == a["procesos"][0][1]), None)
                if flow and _parse(flow[7]):
                    add(_parse(flow[7]) - delta, {"label": "Correlación", "css": "corr", "file": "firewall × endpoint", "case_id": edr["case_id"]},
                        "correlación", f"Primera conexión de {flow[1]} en {alias(flow[0])} → {alias(flow[2])}:{flow[3]} "
                        f"({a['detector']} del firewall)", a["severity"], True)
    events.sort(key=lambda e: (e["dt"], e["kind"], e["text"]))
    return events[:limit]


def tokens(project) -> dict:
    """Tokens del incidente: la interpretación y los turnos del agente de todas sus fuentes (del disco, sin abrir DuckDB)."""
    total, per = 0, []
    for f in project.files():
        case_dir = project.cases_dir / f.case_id
        n = 0
        path = case_dir / "p1" / "interpretacion.json"
        if path.exists():
            try:
                u = json.loads(path.read_text(encoding="utf-8")).get("usage") or {}
                n += int(u.get("input_tokens", 0) or 0) + int(u.get("output_tokens", 0) or 0) or int(u.get("total_tokens", 0) or 0)
            except (OSError, ValueError, TypeError):
                pass
        for ledger in (case_dir / "ledger").glob("*.jsonl") if (case_dir / "ledger").is_dir() else ():
            for line in ledger.read_text(encoding="utf-8").splitlines():
                if '"agent_turn"' in line:
                    d = json.loads(line).get("data", {})
                    n += int(d.get("tokens_delta") if d.get("tokens_delta") is not None else (d.get("tokens") or 0))
        if n:
            per.append({"file": f.name, "case_id": f.case_id, "tokens": n})
        total += n
    val = project.dir / "valoracion.json"  # la valoración del incidente también gasta
    if val.exists():
        u = (json.loads(val.read_text(encoding="utf-8")).get("usage") or {})
        n = int(u.get("input_tokens", 0) or 0) + int(u.get("output_tokens", 0) or 0)
        if n:
            per.append({"file": "valoración del incidente", "case_id": None, "tokens": n})
            total += n
    cap = project.settings.max_tokens_incident
    return {"total": total, "cap": cap, "per_source": per, "pct": round(100 * total / cap, 1) if cap else None}


def over_budget(project) -> bool:
    t = tokens(project)
    return bool(t["cap"]) and t["total"] >= t["cap"]


__all__ = ["KIND", "findings", "over_budget", "sources", "timeline", "tokens"]
