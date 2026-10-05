"""Presentación y registro del resultado de la interpretación (P1-a): texto para el analista y diccionario para guardar."""
from __future__ import annotations

from dataclasses import asdict

from dfir_copilot.interpret.interpret import InterpretationResult

_L = {
    "es": {
        "classification": "Clasificación", "confidence": "confianza", "evidence": "evidencia", "rationale": "razón",
        "mapping": "Revisión del mapeo", "queries": "Consultas aceptadas", "hypothesis": "Hipótesis",
        "if_true": "Si es cierta", "refuted": "Se refuta si", "discarded": "Descartado por el validador",
        "questions": "Preguntas para el analista", "usage": "Consumo", "input": "entrada", "output": "salida",
        "total": "total", "time": "tiempo", "tokens": "tokens", "unusable": "La respuesta del modelo no se pudo usar",
        "none": "(ninguna)", "prompt": "versión del prompt", "why": "por qué importa",
    },
    "en": {
        "classification": "Classification", "confidence": "confidence", "evidence": "evidence", "rationale": "rationale",
        "mapping": "Mapping review", "queries": "Accepted queries", "hypothesis": "Hypothesis",
        "if_true": "If true", "refuted": "Refuted if", "discarded": "Discarded by the validator",
        "questions": "Questions for the analyst", "usage": "Usage", "input": "input", "output": "output",
        "total": "total", "time": "time", "tokens": "tokens", "unusable": "The model's response could not be used",
        "none": "(none)", "prompt": "prompt version", "why": "why it matters",
    },
}


def _usage_line(result: InterpretationResult, w: dict) -> str:
    u = result.usage or {}
    parts = [f"{w[k]} {u[key]:,}" for k, key in (("input", "input_tokens"), ("output", "output_tokens"), ("total", "total_tokens"))
             if isinstance(u.get(key), int)]
    tokens = f"{w['tokens']}: " + " | ".join(parts) if parts else f"{w['tokens']}: n/d"
    return f"{w['usage']}: {tokens} | {w['time']}: {result.elapsed_ms / 1000:.1f} s | {w['prompt']}: {result.prompt_version}"


def render_interpretation(result: InterpretationResult, lang: str = "es") -> str:
    w = _L[lang if lang in _L else "es"]
    if not result.ok:
        return f"{w['unusable']}: {result.error} - {result.error_detail}\n{_usage_line(result, w)}"
    r = result.reviewed.interpretation
    c = r.classification
    out = [f"{w['classification']}: {c.log_type} ({w['confidence']} {c.confidence:.2f})",
           f"  {w['evidence']}: {', '.join(c.evidence_fields) or w['none']}", f"  {w['rationale']}: {c.rationale}", ""]
    out.append(f"{w['mapping']} ({len(r.mapping_review)})")
    out += [f"  [{m.action}] {m.canonical} <- {m.field}: {m.reason}" for m in r.mapping_review] or [f"  {w['none']}"]
    out += ["", f"{w['queries']} ({len(r.proposed_queries)})"]
    for i, q in enumerate(r.proposed_queries, 1):
        out += [f"  {i}. [{q.priority}] {q.id}", f"     {w['hypothesis']}: {q.hypothesis}", f"     {w['if_true']}: {q.expected_if_true}",
                f"     {w['refuted']}: {q.refuted_if}", f"     SQL: {' '.join(q.sql.split())}"]
    if not r.proposed_queries:
        out.append(f"  {w['none']}")
    out += ["", f"{w['discarded']} ({len(result.reviewed.discarded)})"]
    out += [f"  - {d.kind} {d.ref}: {d.code} - {d.detail}" for d in result.reviewed.discarded] or [f"  {w['none']}"]
    out += ["", f"{w['questions']} ({len(r.analyst_questions)})"]
    for i, q in enumerate(r.analyst_questions, 1):
        out += [f"  {i}. {q.question}", f"     {w['why']}: {q.why_it_matters}"]
    if not r.analyst_questions:
        out.append(f"  {w['none']}")
    return "\n".join(out + ["", _usage_line(result, w)])


def result_to_dict(result: InterpretationResult) -> dict:
    """Todo lo que merece guardarse de una llamada, listo para JSON. No incluye el perfil enviado ni datos de los logs."""
    return {
        "prompt_version": result.prompt_version, "ok": result.ok, "error": result.error, "error_detail": result.error_detail,
        "usage": result.usage, "elapsed_ms": result.elapsed_ms, "columns": result.columns,
        "interpretation": result.reviewed.interpretation.model_dump() if result.ok else None,
        "discarded": [asdict(d) for d in result.reviewed.discarded] if result.ok else [],
    }
