"""Correlación determinista: combina señales de dimensiones distintas sobre la misma entidad."""
from __future__ import annotations

from dataclasses import dataclass

from dfir_copilot.detectors.base import SEVERITIES


@dataclass(frozen=True)
class CaseCandidate:
    entity: str
    signals: int  # nº de detectores distintos que señalan a la entidad
    detectors: tuple
    severity: str
    findings: tuple


def correlate(runs, key: str = "user_id", min_severity: str = "medium") -> list[CaseCandidate]:
    """Agrupa los hallazgos por entidad (la del hallazgo o las asociadas en `related`).

    Una sola señal conserva su severidad; dos o más detectores sobre la misma entidad elevan el
    caso a `high`. Los hallazgos por debajo de `min_severity` son contexto, no señal.
    """
    floor = SEVERITIES.index(min_severity)
    by_entity: dict[str, dict[str, list]] = {}
    for run in runs:
        for f in run.findings:
            if SEVERITIES.index(f.severity) < floor:
                continue
            names = {f.entity.get(key), *f.related.get(key, ())} - {None}
            for name in names:
                by_entity.setdefault(name, {}).setdefault(f.detector, []).append(f)
    cases = []
    for name, per_detector in by_entity.items():
        findings = tuple(x for group in per_detector.values() for x in group)
        top = max(SEVERITIES.index(x.severity) for x in findings)
        severity = "high" if len(per_detector) >= 2 else SEVERITIES[top]
        cases.append(CaseCandidate(name, len(per_detector), tuple(sorted(per_detector)), severity, findings))
    return sorted(cases, key=lambda c: (-c.signals, -SEVERITIES.index(c.severity), c.entity))
