"""Informe del INCIDENTE (todas las fuentes): se genera solo al pulsar «Exportar», con todo lo que hay en ese momento.

Secciones: valoración del modelo (si se pidió) · fuentes y custodia · hallazgos por fuente · correlación · línea de tiempo · hipótesis y
decisiones · conclusiones de las conversaciones · consumo · limitaciones. Cada dato lleva su fuente.

Variantes: «compartible» (alias; se comprueba por código que no lleva ningún valor real conocido de ninguna fuente, y si lo llevara NO se
escribe) e «interno» (valores reales, para el expediente). La exportación queda en el ledger de cada fuente con el SHA-256 del informe.
"""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from dfir_copilot import incident
from dfir_copilot.assessment import VERDICTS, real_hits
from dfir_copilot.assessment import load as load_assessment
from dfir_copilot.correlation import load as load_correlation

VARIANTS = ("compartible", "interno")


class IncidentReportLeak(RuntimeError):
    """El informe compartible llevaría valores reales: no se escribe."""


def _cell(text, limit=400) -> str:
    return str(text if text is not None else "—").replace("|", "\\|").replace("\n", " ")[:limit]


def build(project, variant: str = "compartible") -> str:
    from dfir_copilot.agent.hypotheses import HypothesisBook

    if variant not in VARIANTS:
        raise ValueError(f"Variante desconocida: {variant!r}")
    srcs = incident.sources(project)
    pss = [s["ws"].pseudonymized()[1] for s in srcs]
    out = [f"# Informe del incidente · {project.name}" + (f" ({project.ticket})" if project.ticket else ""), "",
           f"_Generado el {datetime.now(UTC).isoformat(timespec='seconds')} · variante {variant} · {len(srcs)} fuente(s) de evidencia._", ""]
    a = load_assessment(project)
    out += ["## 1. Valoración", ""]
    if not a:
        out += ["Todavía no se pidió la valoración del modelo para este incidente.", ""]
    elif not a.get("ok"):
        out += [f"La última valoración no se pudo usar: {_cell(a.get('error'))}.", ""]
    else:
        v = a["assessment"]
        out += [f"**Veredicto:** {VERDICTS[v['verdict']]} · **confianza:** {v['confidence']}" + (f" · **tipo:** {_cell(v['attack_type'])}" if v.get("attack_type") else ""),
                "", v["summary"], ""]
        if v.get("mitre"):
            out += ["**ATT&CK:** " + ", ".join(v["mitre"]), ""]
        for title, side in (("Evidencia a favor", "evidence_for"), ("Evidencia en contra", "evidence_against")):
            if v.get(side):
                out += [f"**{title}:**", "", *(f"- `{e['ref']}` ({e['source']}): {_cell(e['explanation'], 600)}" for e in v[side]), ""]
        for title, key in (("Qué falta comprobar", "gaps"), ("Siguientes pasos", "next_steps")):
            if v.get(key):
                out += [f"**{title}:**", "", *(f"- {_cell(x, 400)}" for x in v[key]), ""]
        out += [f"_Valoración del modelo {a.get('model') or ''} el {a['computed_at_utc']}. Las citas se verificaron por código "
                f"({a.get('discarded_refs', 0)} descartada/s por no existir)._" + (" " + " ".join(a["code_notes"]) if a.get("code_notes") else ""), ""]
    out += ["## 2. Fuentes de evidencia y custodia", "", "| Fuente | Archivo | Filas | SHA-256 |", "|---|---|---|---|"]
    out += [f"| {s['label']} | {_cell(s['file'])} | {s['rows']:,} | `{s['sha']}` |" for s in srcs]
    out += ["", "## 3. Hallazgos (por fuente, de más a menos grave)", "", "| Severidad | Fuente | Detector | Entidad | Resumen |", "|---|---|---|---|---|"]
    out += [f"| {f['severity']} | {f['source']['label']} | {f['detector']} | `{_cell(f['entity'], 120)}` | {_cell(f['summary'])} |"
            for f in incident.findings(srcs)]
    corr = load_correlation(project)
    out += ["", "## 4. Correlación entre fuentes", ""]
    pairs = [p for p in (corr or {}).get("pairs", [])]
    if not pairs:
        out += ["No hay un par firewall + endpoint correlacionado en este incidente.", ""]
    for pr in pairs:
        if pr.get("status") != "ok":
            out += [f"No se pudo correlacionar: {_cell(pr.get('reason'), 600)}", ""]
            continue
        edr_ps = next((s["ws"].pseudonymized()[1] for s in srcs if s["case_id"] == pr["endpoint"]), pss[0])

        def al(v, ps=edr_ps):
            try:
                return ps.alias_text(str(v)).text
            except Exception:  # noqa: BLE001
                return "•••"

        out += [f"{pr['matched']:,} de {pr['edr_events']:,} conexiones del endpoint casan con el firewall; desfase de relojes estimado "
                f"{pr['skew_s']} s (tolerancia ±{pr['tolerance_s']} s).", "", "| Hallazgo del firewall | IP | Equipo · proceso | También en endpoint |",
                "|---|---|---|---|"]
        out += [f"| {x['detector']} ({x['severity']}) | `{al(x['src_ip'])}` | " + "; ".join(f"`{al(h)}` · {p} ({n:,})" for h, p, n in x["procesos"][:2])
                + f" | {'sí' if x['tambien_en_endpoint'] else 'no'} |" for x in pr["attributions"]]
        out += [""]
    out += ["## 5. Línea de tiempo (UTC; ⏱ = hora corregida por el desfase)", ""]
    out += [f"- {e['ts']}{' ⏱' if e['corrected'] else ''} · {(e['source'] or {}).get('label', '—')} · {e['kind']}: {_cell(e['text'], 300)}"
            for e in incident.timeline(project, srcs, limit=80)]
    out += ["", "## 6. Hipótesis y decisiones del analista", ""]
    for s in srcs:
        ledger = s["ws"].ledger(s["ws"].engine())
        hyps = HypothesisBook(ledger).all()
        for h in hyps:
            out.append(f"- **{s['label']}** `{h['hypothesis_id']}` — {h['status']}: {_cell(h['statement'], 400)}")
        for e in ledger.entries("hypothesis_update"):
            d = e["data"]
            if d.get("decision") in ("approved", "rejected"):
                out.append(f"  - {e['ts_utc']} {d['hypothesis_id']} {'aprobada' if d['decision'] == 'approved' else 'rechazada'}"
                           + (f": {_cell(d['note'], 300)}" if d.get("note") else ""))
    out += ["", "## 7. Conclusiones de las conversaciones con el agente", ""]
    for s in srcs:
        answers = [e for e in s["ws"].ledger(s["ws"].engine()).entries("agent_turn") if e["data"].get("answer")][-3:]
        out += [f"- **{s['label']}** ({e['ts_utc']}): {_cell(e['data']['answer'], 900)}" for e in answers]
    t = incident.tokens(project)
    out += ["", "## 8. Consumo de modelo", "", f"{t['total']:,} tokens en el incidente" + (f" (tope {t['cap']:,})" if t["cap"] else "") + "."]
    out += [f"- {_cell(x['file'])}: {x['tokens']:,}" for x in t["per_source"]]
    out += ["", "## 9. Limitaciones", "",
            "- Los hallazgos los calcula el código; la valoración es del modelo, que solo vio información en alias y cuyas citas se verificaron.",
            "- Cada fuente conserva su zona horaria declarada; si no está verificada, las horas pueden desplazarse (la correlación lo detecta "
            "cuando las fuentes casan desplazando horas enteras).",
            "- La correlación necesita que el firewall vea la IP real del equipo (sin NAT)." if pairs else "- Sin correlación entre fuentes.", ""]
    text = "\n".join(out)
    if variant == "interno":
        for ps in pss:
            text = ps.reveal_any(text)
        return text
    for s, ps in zip(srcs, pss, strict=True):
        if real_hits(ps, text):
            raise IncidentReportLeak(f"El informe compartible llevaría valores reales de {s['file']}: no se escribe")
    return text


def export(project, variant: str = "compartible") -> dict:
    from dfir_copilot.reporting import reports_root

    text = build(project, variant)
    folder = reports_root() / project.id
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"informe_incidente.es.{variant}.md"
    path.write_text(text, encoding="utf-8")
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    for s in incident.sources(project):
        s["ws"].ledger(s["ws"].engine()).append("report_export", {"scope": "incident", "variant": variant, "lang": "es",
                                                                  "sha256": sha, "file": path.name})
    return {"path": path, "sha256": sha, "variant": variant}


__all__ = ["VARIANTS", "IncidentReportLeak", "build", "export"]
