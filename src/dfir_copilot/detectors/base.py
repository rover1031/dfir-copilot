"""Contrato común de los detectores: reciben un QueryEngine y devuelven hallazgos con evidencia."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace

from dfir_copilot.engine.query_engine import QueryEngine

SEVERITIES = ("info", "low", "medium", "high")


class NotApplicable(Exception):
    """El detector no puede ejecutarse sobre este dataset (faltan columnas o datos)."""


@dataclass(frozen=True)
class Finding:
    detector: str
    title: str
    severity: str
    entity: dict
    summary: str
    metrics: dict
    evidence: tuple = ()  # entradas de engine.history; las completa run_detectors
    mitre: tuple = ()
    related: dict = field(default_factory=dict)  # {columna: [valores]} de entidades asociadas

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity debe ser una de {SEVERITIES}")


@dataclass(frozen=True)
class DetectorRun:
    name: str
    status: str  # "ok" | "not_applicable" | "error"
    reason: str
    findings: tuple
    queries: tuple


class Detector(ABC):
    name: str = ""
    description: str = ""

    @abstractmethod
    def run(self, engine: QueryEngine) -> list[Finding]:
        """Devuelve hallazgos; lanza NotApplicable si el dataset no sirve para este detector."""


def ensure_columns(engine: QueryEngine, columns: list[str]) -> None:
    """Comprueba que las columnas existan en la vista y tengan datos."""
    described = {row[0] for row in engine.query("DESCRIBE logs").rows}
    missing = [c for c in columns if c not in described]
    if missing:
        raise NotApplicable(f"faltan columnas: {missing}")
    counts = ", ".join('count("{0}") AS "{0}"'.format(c.replace('"', '""')) for c in columns)
    res = engine.query(f"SELECT {counts} FROM logs")
    empty = [c for c, n in zip(res.columns, res.rows[0], strict=True) if n == 0]
    if empty:
        raise NotApplicable(f"columnas sin datos en este dataset: {empty}")


_REGISTRY: dict[str, type[Detector]] = {}


def register(cls: type[Detector]) -> type[Detector]:
    if not cls.name:
        raise ValueError("El detector necesita un `name`")
    _REGISTRY[cls.name] = cls
    return cls


def available() -> dict[str, str]:
    return {name: cls.description for name, cls in _REGISTRY.items()}


def run_detectors(
    engine: QueryEngine, names: list[str] | None = None, params: dict | None = None, roles=None
) -> list[DetectorRun]:
    """Ejecuta detectores aislados entre sí y adjunta a cada hallazgo las consultas que lo respaldan.

    `roles` (ver `detectors.roles`) fija qué columnas son actor y recurso; los `params` explícitos tienen prioridad.
    Sin `roles` se conservan los valores por defecto de cada detector (`user_id`, `x_invoice_id`).
    """
    from dfir_copilot.detectors.roles import detector_params

    params = params or {}
    if roles is not None:
        role_params = detector_params(roles)
        params = {name: {**role_params.get(name, {}), **params.get(name, {})}
                  for name in {*role_params, *params}}
    runs = []
    for name, cls in _REGISTRY.items():
        if names and name not in names:
            continue
        start = len(engine.history)
        try:
            findings = cls(**params.get(name, {})).run(engine)
            status, reason = "ok", ""
        except NotApplicable as exc:
            findings, status, reason = [], "not_applicable", str(exc)
        except Exception as exc:  # un detector roto no debe detener a los demás
            findings, status, reason = [], "error", f"{type(exc).__name__}: {exc}"
        queries = tuple(q for q in engine.history[start:] if q["status"] == "ok")
        findings = tuple(replace(f, evidence=queries) for f in findings)
        runs.append(DetectorRun(name, status, reason, findings, queries))
    return runs
