"""Ejecuta, sobre los datos reales y en local, las consultas que el validador aceptó (P1-a).

El validador solo ve una tabla vacía: no puede saber si una conversión fallará con valores reales o si la consulta devuelve
algo. Esto cierra ese hueco y deja medido cuántas consultas aceptadas fallan con datos reales (una métrica de calidad del
prompt). Los resultados con valores reales se quedan en tu máquina: no vuelven al modelo.

Es exploración, no evidencia: pasa por un `QueryEngine` suelto, sin ledger. La ejecución registrada llega con el agente (P1-b).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

import duckdb

from dfir_copilot.engine.query_engine import QueryRejected, QueryTimeout
from dfir_copilot.interpret.interpret import InterpretationResult

Status = Literal["ok", "empty", "error", "timeout", "rejected"]


@dataclass(frozen=True)
class QueryRun:
    id: str
    priority: str
    status: Status
    row_count: int = 0
    truncated: bool = False
    elapsed_ms: int = 0
    error: str | None = None
    columns: tuple = ()
    rows: list = field(default_factory=list)  # valores reales: solo para mostrar en local


def run_accepted_queries(engine, result: InterpretationResult, *, max_rows: int = 20) -> list[QueryRun]:
    if not result.ok:
        raise ValueError("No hay interpretación utilizable que ejecutar")
    runs = []
    for q in result.reviewed.interpretation.proposed_queries:
        try:
            r = engine.query(q.sql, max_rows=max_rows)
        except QueryTimeout as exc:
            runs.append(QueryRun(q.id, q.priority, "timeout", error=str(exc)[:300]))
        except QueryRejected as exc:
            runs.append(QueryRun(q.id, q.priority, "rejected", error=str(exc)[:300]))
        except duckdb.Error as exc:
            runs.append(QueryRun(q.id, q.priority, "error", error=(str(exc).strip().splitlines() or [""])[0][:300]))
        else:
            runs.append(QueryRun(q.id, q.priority, "ok" if r.row_count else "empty", r.row_count, r.truncated, r.elapsed_ms,
                                 columns=r.columns, rows=r.rows))
    return runs


def summarize_runs(runs: list[QueryRun]) -> dict:
    """Conteos por estado. `accepted_but_failed` = pasaron el validador y fallaron con datos reales."""
    counts = Counter(r.status for r in runs)
    return {"accepted": len(runs), "by_status": dict(counts),
            "accepted_but_failed": sum(counts[s] for s in ("error", "timeout", "rejected"))}
