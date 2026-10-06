"""Valoración del incidente por el modelo (entrega E2): ¿hay un incidente?, ¿de qué tipo?, ¿con qué confianza?, ¿qué lo sostiene y qué
lo contradice?, ¿qué falta comprobar?

El modelo NO ve filas ni valores reales: recibe lo que el código ya sabe del incidente, todo en alias (con diccionario compartido, la
misma IP tiene el mismo alias en todas las fuentes):
fuentes, hallazgos (con su id f-...), correlación (C1, C2...), perfiles de datos, hipótesis (h-...) con las decisiones del analista,
notas y las conclusiones de las conversaciones con el agente.

Salvaguardas, por código:
* Antes de enviar: si el contexto llevara algún valor real conocido de cualquier fuente, NO se envía (`ContextLeak`).
* Al recibir: cada evidencia debe citar un identificador que exista en el contexto; las que no, se descartan y se cuentan.
* Un veredicto «confirmado» o «probable» sin ninguna evidencia citable que sobreviva se rebaja a «no concluyente», y se dice.
* Se guarda en `<análisis>/valoracion.json` con su SHA-256 en el ledger de cada fuente, y su consumo cuenta para el tope del incidente.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from dfir_copilot import incident

VERDICTS = {"incidente_confirmado": "Incidente confirmado", "incidente_probable": "Incidente probable",
            "no_concluyente": "No concluyente", "falso_positivo": "Falso positivo"}

SYSTEM = (
    "Eres un analista DFIR sénior. Recibes el estado de UN incidente ya analizado por código: sus fuentes de evidencia, los hallazgos de "
    "cada una, la correlación entre fuentes, los perfiles de datos, las hipótesis con las decisiones del analista, sus notas y las "
    "conclusiones de las conversaciones con el agente. Todos los valores van en alias (IP-0001, H-0002...): úsalos tal cual.\n"
    "Tu tarea: valorar si hay un incidente de seguridad, de qué tipo, con qué confianza y qué técnicas ATT&CK lo describen.\n"
    "Reglas: 1) Como evidencia solo puedes citar identificadores que aparecen en el contexto entre corchetes ([f-...], [h-...], [C1]...). "
    "2) Da también la evidencia EN CONTRA y lo que falta comprobar: una valoración sin contraargumentos no es útil. 3) Si la evidencia no "
    "basta, el veredicto es no_concluyente. 4) No inventes valores, hechos ni técnicas sin respaldo en el contexto. 5) Distingue lo que "
    "dice cada fuente (firewall, endpoint, web) de lo que sale de la correlación. Responde SOLO con el JSON del esquema."
)


class Evidence(BaseModel):
    ref: str = Field(min_length=2, max_length=40)
    explanation: str = Field(min_length=5, max_length=600)


class Assessment(BaseModel):
    verdict: Literal["incidente_confirmado", "incidente_probable", "no_concluyente", "falso_positivo"]
    confidence: Literal["alta", "media", "baja"]
    summary: str = Field(min_length=20, max_length=2000)
    attack_type: str | None = Field(default=None, max_length=200)
    mitre: list[str] = Field(default_factory=list, max_length=15)
    evidence_for: list[Evidence] = Field(default_factory=list, max_length=20)
    evidence_against: list[Evidence] = Field(default_factory=list, max_length=20)
    gaps: list[str] = Field(default_factory=list, max_length=10)
    next_steps: list[str] = Field(default_factory=list, max_length=10)


def schema() -> dict:
    return Assessment.model_json_schema()


class ContextLeak(RuntimeError):
    """El contexto para el modelo llevaría valores reales: no se envía."""


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _ps(src):
    return src["ws"].pseudonymized()[1]


def build_context(project, max_chars: int = 30000) -> tuple[str, dict[str, str]]:
    """(texto en alias para el modelo, {ref: etiqueta de su fuente}) — las referencias que el modelo puede citar."""
    from dfir_copilot.agent.hypotheses import HypothesisBook
    from dfir_copilot.data_profile import digest

    srcs = incident.sources(project)
    refs: dict[str, str] = {}
    # la descripción del análisis NO se envía: la escribe el analista y puede llevar valores reales
    out = [f"INCIDENTE: {project.name}" + (f" ({project.ticket})" if project.ticket else ""), "", "FUENTES:"]
    for s in srcs:
        out.append(f"- {s['label']}: {s['file']} · {s['rows']:,} filas · esquema {s['schema']}")
    out += ["", "HALLAZGOS (calculados por código; [id] fuente · severidad · detector: resumen):"]
    for f in incident.findings(srcs)[:60]:
        refs[f["finding_id"]] = f["source"]["label"]
        out.append(f"- [{f['finding_id']}] {f['source']['label']} · {f['severity']} · {f['detector']}: {f['summary']}")
    corr_path = project.dir / "correlacion.json"
    if corr_path.exists():
        data = json.loads(corr_path.read_text(encoding="utf-8"))
        fw_src = {s["case_id"]: s for s in srcs}
        n = 0
        for pr in data.get("pairs", []):
            if pr.get("status") != "ok" or pr["firewall"] not in fw_src:
                out += ["", f"CORRELACIÓN: no se pudo ({pr.get('reason', 'sin pares')})"]
                continue
            ps = _ps(fw_src[pr["endpoint"]] if pr["endpoint"] in fw_src else fw_src[pr["firewall"]])

            def a(v, ps=ps):
                try:
                    return ps.alias_text(str(v)).text
                except Exception:  # noqa: BLE001
                    return "•••"

            out += ["", f"CORRELACIÓN FIREWALL×ENDPOINT (por código): {pr['matched']:,} de {pr['edr_events']:,} conexiones del endpoint "
                        f"casan con el firewall; desfase de relojes {pr['skew_s']} s. Atribuciones [Cn]:"]
            for x in pr["attributions"][:15]:
                n += 1
                refs[f"C{n}"] = "Correlación"
                procs = "; ".join(f"{a(h)}·{p} ({k:,} conexiones)" for h, p, k in x["procesos"][:2])
                both = " · el endpoint también señala ese equipo" if x["tambien_en_endpoint"] else ""
                out.append(f"- [C{n}] {x['detector']} ({x['severity']}) del firewall en {a(x['src_ip'])} → {procs}{both}")
    for s in srcs:
        prof = s["ws"].dir / "p1" / "perfil_datos.json"
        if prof.exists():
            out += ["", f"PERFIL DE DATOS · {s['label']}: " + digest(json.loads(prof.read_text(encoding="utf-8")), limit=900)]
        ledger = s["ws"].ledger(s["ws"].engine())
        hyps = HypothesisBook(ledger).all()
        if hyps:
            out += ["", f"HIPÓTESIS · {s['label']} ([id] estado: enunciado):"]
            for h in hyps[:10]:
                refs[h["hypothesis_id"]] = s["label"]
                out.append(f"- [{h['hypothesis_id']}] {h['status']}: {h['statement']}")
            for e in ledger.entries("hypothesis_update"):
                d = e["data"]
                if d.get("decision") in ("approved", "rejected") and d.get("note"):
                    out.append(f"  · decisión del analista sobre {d['hypothesis_id']}: {d['decision']} — {d['note']}")
        notes = [e["data"].get("text", "") for e in ledger.entries("note")][-5:]
        if notes:
            out += ["", f"NOTAS DEL ANALISTA · {s['label']}:", *(f"- {t}" for t in notes)]
        answers = [e["data"].get("answer") for e in ledger.entries("agent_turn") if e["data"].get("answer")][-4:]
        if answers:
            out += ["", f"CONCLUSIONES DE LAS CONVERSACIONES · {s['label']} (respuestas del agente, de la más antigua a la más reciente):"]
            out += ["- " + _flat(t)[:700] for t in answers]
    text = "\n".join(out)[:max_chars]
    for s in srcs:  # salvaguarda: ningún valor real conocido de ninguna fuente sale hacia el modelo
        if real_hits(_ps(s), text):
            raise ContextLeak(f"El contexto llevaría valores reales de {s['file']}: no se envía")
    return text, refs


_BARE_EXE = re.compile(r"^[A-Za-z0-9_.-]+\.(exe|dll|bat|cmd|ps1|com|scr|sys|msi)$", re.I)
_PROC_COLUMNS = ("process_name", "parent_process", "command_line", "file_path")


def real_hits(ps, text: str) -> list[dict]:
    """Valores reales en `text`, salvo un caso: en columnas de proceso, ruta o línea de comandos, un valor que es SOLO un nombre de
    ejecutable (`explorer.exe`, sin ruta ni argumentos) es vocabulario técnico, el mismo que la copia conserva en `<col>_base`."""
    return [h for h in ps.find_real(text)
            if not (h["column"] in _PROC_COLUMNS and _BARE_EXE.match(ps.reveal_any(h["alias"]) or ""))]


def assess(project, llm, model_name: str | None = None) -> dict:
    """Pide la valoración, la valida y la guarda. Devuelve el resultado (también si falla, con `ok: False` y el motivo)."""
    if incident.over_budget(project):
        return {"ok": False, "error": "Se alcanzó el tope de tokens del incidente."}
    context, refs = build_context(project)
    reply = llm.invoke(SYSTEM, context, schema())
    result = {"ok": False, "computed_at_utc": datetime.now(UTC).isoformat(timespec="seconds"), "usage": reply.usage, "model": model_name,
              "context_sha256": hashlib.sha256(context.encode("utf-8")).hexdigest(), "context_chars": len(context)}
    if reply.data is None:
        result["error"] = f"respuesta del modelo no utilizable: {reply.parse_error or 'vacía'}"
    else:
        try:
            a = Assessment.model_validate(reply.data)
        except ValidationError as exc:
            result["error"] = f"la respuesta no cumple el esquema: {exc.errors()[0].get('msg')}"
        else:
            data = a.model_dump()
            discarded = 0
            for side in ("evidence_for", "evidence_against"):
                kept = []
                for ev in data[side]:
                    ref = ev["ref"].strip("[] ")
                    if ref in refs:
                        kept.append({**ev, "ref": ref, "source": refs[ref]})
                    else:
                        discarded += 1
                data[side] = kept
            data["mitre"] = [m for m in data["mitre"] if re.fullmatch(r"T\d{4}(\.\d{3})?", m.strip())]
            notes = []
            if data["verdict"] in ("incidente_confirmado", "incidente_probable") and not data["evidence_for"]:
                notes.append(f"Rebajado por código de «{VERDICTS[data['verdict']]}» a «No concluyente»: ninguna evidencia citada existe en el contexto.")
                data["verdict"] = "no_concluyente"
            result.update(ok=True, assessment=data, discarded_refs=discarded, code_notes=notes)
    payload = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=1) + "\n"
    (project.dir / "valoracion.json").write_text(payload, encoding="utf-8")
    sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    for s in incident.sources(project):
        s["ws"].ledger(s["ws"].engine()).append("incident_assessment", {
            "file": "valoracion.json", "sha256": sha, "ok": result["ok"],
            "verdict": result.get("assessment", {}).get("verdict"), "confidence": result.get("assessment", {}).get("confidence")})
    return result


def load(project) -> dict | None:
    path = project.dir / "valoracion.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


__all__ = ["VERDICTS", "Assessment", "ContextLeak", "assess", "build_context", "load", "real_hits", "schema"]
