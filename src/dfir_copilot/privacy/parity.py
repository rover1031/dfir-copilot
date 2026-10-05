"""Paridad de detectores: ¿la copia seudonimizada da las MISMAS conclusiones que los datos reales? (P1-b.2b).

Los detectores que ve el modelo corren sobre la copia (así sus hallazgos salen en alias por construcción, sin traducir texto).
Esa decisión es válida solo si la copia no cambia lo que detectan: los alias son biyectivos y el desplazamiento conserva
diferencias, pero `scrub`/`mask_*` pueden fundir valores distintos en uno (dos User-Agent que solo difieren en un token).
Esta comprobación lo mide sobre los datos reales del analista, en local:

* identifica cada hallazgo por detector + entidad traducida a alias (`Pseudonymizer.alias`), así se puede cruzar;
* compara severidad y métricas numéricas;
* lo que difiere en texto (p. ej. la lista de User-Agent) se informa SOLO por nombre de métrica, nunca por valor: el resultado
  contiene alias y cifras, nada que haya que proteger.
"""
from __future__ import annotations

import math
from numbers import Number

from dfir_copilot.detectors import run_detectors
from dfir_copilot.detectors.roles import resolve_roles


def _identity(finding, ps, translate: bool) -> tuple:
    """Clave comparable de un hallazgo, en el espacio de alias. `translate=True` para los de los datos reales (hay que
    llevarlos a alias); los de la copia ya vienen en alias y no se tocan."""
    def al(col, value):
        return str(ps.alias(col, value)) if translate else str(value)

    cols = {c: v for c, v in finding.entity.items() if c in ps.treatments}
    if cols:
        return tuple(sorted((c, al(c, v)) for c, v in cols.items()))
    # entidad sintética (p. ej. un grupo "C1"): su identidad son los miembros
    return tuple(sorted((c, tuple(sorted(al(c, v) for v in vals))) for c, vals in finding.related.items()
                        if c in ps.treatments))


def _run(engine, roles, names):
    mark = len(engine.history)
    try:
        return {r.name: r for r in run_detectors(engine, names=names, roles=roles)}
    finally:
        del engine.history[mark:]  # es una verificación, no análisis: no ensucia el historial que va al ledger


def _same_number(a, b) -> bool:
    return math.isclose(float(a), float(b), rel_tol=1e-9, abs_tol=1e-9)


def detector_parity(real_engine, pseudo_engine, ps, names: list[str] | None = None) -> dict:
    """Ejecuta los detectores sobre ambas copias y compara. Solo local; el resultado no lleva valores reales.

    `equivalent` exige mismos detectores aplicables, mismas entidades (en alias), misma severidad y mismas métricas
    numéricas. Las diferencias de texto no la rompen: se listan en `text_differences` para que el analista las valore.
    """
    roles = resolve_roles(real_engine)
    real, pseudo = _run(real_engine, roles, names), _run(pseudo_engine, roles, names)
    report, ok = {}, True
    for name in sorted(real):
        a, b = real[name], pseudo[name]
        fa = {_identity(f, ps, True): f for f in a.findings}
        fb = {_identity(f, ps, False): f for f in b.findings}
        matched = sorted(set(fa) & set(fb))
        only_real, only_pseudo = sorted(set(fa) - set(fb)), sorted(set(fb) - set(fa))
        numeric, text = [], []
        for key in matched:
            x, y = fa[key], fb[key]
            if x.severity != y.severity:
                numeric.append({"entity": key, "metric": "severity", "real": x.severity, "pseudo": y.severity})
            for metric in sorted(set(x.metrics) | set(y.metrics)):
                u, v = x.metrics.get(metric), y.metrics.get(metric)
                if isinstance(u, Number) and isinstance(v, Number) and not isinstance(u, bool) and not isinstance(v, bool):
                    if not _same_number(u, v):
                        numeric.append({"entity": key, "metric": metric, "real": u, "pseudo": v})
                elif u != v:
                    text.append({"entity": key, "metric": metric})  # solo el nombre: el valor puede ser sensible
        status_ok = a.status == b.status
        entry_ok = status_ok and not only_real and not only_pseudo and not numeric
        ok = ok and entry_ok
        report[name] = {"status": {"real": a.status, "pseudo": b.status}, "findings": {"real": len(fa), "pseudo": len(fb)},
                        "matched": len(matched), "only_real": [list(k) for k in only_real],
                        "only_pseudo": [list(k) for k in only_pseudo], "numeric_differences": numeric,
                        "text_differences": text, "equivalent": entry_ok}
    return {"equivalent": ok, "detectors": report}
