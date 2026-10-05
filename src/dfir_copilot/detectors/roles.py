"""Roles de análisis: qué columna es el ACTOR (quién actúa) y cuál el RECURSO (sobre qué actúa).

Los detectores no deben depender de nombres de columna concretos (`user_id`, `x_invoice_id`): el mapping declara los
roles y, si no los declara, se infieren de los datos. El resultado queda en el ledger, porque cambia lo que significa
cada hallazgo (un mismo detector sobre otro actor responde otra pregunta).

Prioridad: override manual > roles del mapping (manifiesto) > inferencia.
"""
from __future__ import annotations

from dataclasses import dataclass

from dfir_copilot.i18n import t

ROLE_NAMES = ("actor", "resource")
_FALLBACK_ACTOR = "src_ip"
_FALLBACK_RESOURCE = "endpoint"

# Parámetros de cada detector que dependen de un rol
_DETECTOR_ROLE_PARAMS = {
    "resource_breadth": {"actor_col": "actor", "resource_col": "resource"},
    "automation_clients": {"actor_col": "actor"},
    "actor_ip_cluster": {"actor_col": "actor"},
    "activity_ramp": {"actor_col": "actor"},
}


class RoleError(ValueError):
    """Un rol apunta a una columna que no existe o no tiene datos."""


@dataclass(frozen=True)
class Roles:
    actor: str
    resource: str
    sources: dict  # {"actor": "override"|"mapping"|"inferred", "resource": ...}
    notes: tuple = ()  # explicación para personas, en el idioma pedido

    def as_record(self) -> dict:
        """Lo que se guarda en el ledger: sin textos, para que cambiar de idioma no cree entradas nuevas."""
        return {"actor": self.actor, "resource": self.resource, "sources": dict(self.sources)}


def detector_params(roles: Roles) -> dict[str, dict]:
    """Parámetros por detector derivados de los roles."""
    values = {"actor": roles.actor, "resource": roles.resource}
    return {name: {param: values[role] for param, role in spec.items()} for name, spec in _DETECTOR_ROLE_PARAMS.items()}


def _columns_with_data(engine) -> tuple[dict, dict]:
    """(columnas con datos -> tipo, distintos por columna derivada). Son consultas de metadatos: no quedan en el
    historial del motor, igual que el replay, para no presentarlas como análisis."""
    mark = len(engine.history)
    try:
        described = {r[0]: r[1] for r in engine.query("DESCRIBE logs").rows}
        counts = ", ".join(f'count("{c}") AS "n_{c}"' for c in described)
        row = engine.query(f"SELECT {counts} FROM logs").rows[0]
        with_data = {c: described[c] for c, n in zip(described, row, strict=True) if n}
        derived = [c for c in with_data if c.startswith("x_")]
        distinct = {}
        if derived:
            exprs = ", ".join(f'count(DISTINCT "{c}") AS "d_{c}"' for c in derived)
            distinct = dict(zip(derived, engine.query(f"SELECT {exprs} FROM logs").rows[0], strict=True))
        return with_data, distinct
    finally:
        del engine.history[mark:]


def resolve_roles(engine, overrides: dict | None = None, lang: str | None = None) -> Roles:
    """Decide actor y recurso para este dataset y explica por qué."""
    with_data, distinct = _columns_with_data(engine)
    declared = (getattr(engine, "manifest", None) or {}).get("roles") or {}
    overrides = overrides or {}
    chosen: dict[str, str] = {}
    sources: dict[str, str] = {}
    notes: list[str] = []

    for role in ROLE_NAMES:
        col, source = overrides.get(role), "override"
        if col is None:
            col, source = declared.get(role), "mapping"
        if col is None:
            continue
        if col not in with_data:
            all_columns = {r[0] for r in engine.query("DESCRIBE logs").rows}
            del engine.history[-1:]
            key = "roles.err.no_data" if col in all_columns else "roles.err.unknown_column"
            raise RoleError(t(key, lang, role=role, col=col))
        chosen[role], sources[role] = col, source
        notes.append(t("roles.note.override" if source == "override" else f"roles.note.{role}_from_mapping",
                       lang, role=role, col=col))

    if "actor" not in chosen:
        sources["actor"] = "inferred"
        if "user_id" in with_data:
            chosen["actor"] = "user_id"
            notes.append(t("roles.note.actor_user", lang, col="user_id"))
        else:
            chosen["actor"] = _FALLBACK_ACTOR
            notes.append(t("roles.note.actor_ip", lang))
    if "resource" not in chosen:
        sources["resource"] = "inferred"
        candidates = sorted(((n, c) for c, n in distinct.items() if n >= 2), key=lambda x: (-x[0], x[1]))
        if candidates:
            chosen["resource"] = candidates[0][1]
            notes.append(t("roles.note.resource_inferred", lang, col=chosen["resource"]))
        else:
            chosen["resource"] = _FALLBACK_RESOURCE
            notes.append(t("roles.note.resource_endpoint", lang))
    return Roles(chosen["actor"], chosen["resource"], sources, tuple(notes))
