"""Herramientas del agente: solo lectura, acotadas, sanitizadas y auditadas en el ledger."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from dfir_copilot.detectors import available, correlate, run_detectors
from dfir_copilot.detectors.roles import resolve_roles
from dfir_copilot.engine.profiler import LogProfiler
from dfir_copilot.evidence.ledger import candidate_id, finding_id, query_id
from dfir_copilot.tools.sanitize import clean_text, render, sanitize

Bucket = Literal["hour", "day", "week", "month"]


@dataclass(frozen=True)
class ToolLimits:
    max_rows: int = 50          # filas que ve el LLM por consulta
    max_cell_chars: int = 120   # caracteres por celda de texto
    max_chars: int = 8000       # tamaño total del resultado
    timeline_points: int = 60   # puntos de una serie temporal


@dataclass(frozen=True)
class ToolOutput:
    ok: bool
    data: dict
    text: str  # lo único que debe llegar al LLM
    warnings: tuple = field(default_factory=tuple)


class NoArgs(BaseModel):
    pass


class QueryArgs(BaseModel):
    sql: str = Field(min_length=1, max_length=4000, description="Una sentencia SELECT sobre la vista `logs`.")


class ProfileArgs(BaseModel):
    kind: Literal["overview", "top", "status_by", "activity", "timeline"]
    dimension: str | None = Field(None, description="Columna de `logs` (obligatoria salvo en overview/timeline).")
    n: int = Field(10, ge=1, le=50)
    bucket: Bucket = "day"
    filters: dict[str, str | int] | None = Field(None, description="Filtros de igualdad {columna: valor}.")


class DetectArgs(BaseModel):
    names: list[str] | None = Field(None, description="Detectores a ejecutar; vacío = todos.")


class TimelineArgs(BaseModel):
    dimension: str = Field(description="Columna que identifica la entidad (p. ej. user_id, src_ip).")
    value: str = Field(max_length=200, description="Valor de la entidad.")
    bucket: Bucket = "day"


class Toolkit:
    def __init__(self, engine, ledger=None, limits: ToolLimits = ToolLimits()):
        self.engine, self.ledger, self.limits = engine, ledger, limits
        self.profiler = LogProfiler(engine)
        self._roles = None  # se resuelven la primera vez que hacen falta (no cambian durante el hilo)
        self._tools = {
            "describe_dataset": (NoArgs, self._describe,
                                 "Esquema, volumen, rango temporal, columnas sin datos, zona horaria y detectores disponibles."),
            "run_query": (QueryArgs, self._run_query,
                          "Consulta SQL de solo lectura (una sentencia SELECT) sobre la vista `logs`."),
            "profile": (ProfileArgs, self._profile,
                        "Perfiles listos: overview, top, status_by, activity, timeline."),
            "run_detectors": (DetectArgs, self._detect,
                              "Ejecuta los detectores y correlaciona sus señales por identidad."),
            "build_timeline": (TimelineArgs, self._timeline,
                               "Línea de tiempo de una entidad (usuario, IP...): volumen por periodo, primer y último periodo, pico."),
        }

    @property
    def roles(self):
        if self._roles is None:
            self._roles = resolve_roles(self.engine)
        return self._roles

    def specs(self) -> list[dict]:
        return [{"name": n, "description": d, "schema": m.model_json_schema()} for n, (m, _, d) in self._tools.items()]

    # --- punto de entrada único ---------------------------------------------------------
    def call(self, name: str, args: dict | None = None) -> ToolOutput:
        start = len(self.engine.history)
        if name not in self._tools:
            return self._fail(name, args, start, f"herramienta desconocida: {name}. Disponibles: {sorted(self._tools)}")
        model, fn, _ = self._tools[name]
        try:
            parsed = model(**(args or {}))
        except (ValidationError, TypeError) as exc:
            return self._fail(name, args, start, f"argumentos inválidos: {exc}")
        try:
            data = fn(parsed)
        except Exception as exc:  # noqa: BLE001 - el agente debe recibir el error, no romper el bucle
            return self._fail(name, args, start, f"{type(exc).__name__}: {exc}")
        return self._finish(name, args, start, data)

    # --- implementaciones ----------------------------------------------------------------
    def _shape(self, res) -> dict:
        return {"columns": list(res.columns), "rows": [list(r) for r in res.rows[: self.limits.max_rows]],
                "row_count": min(res.row_count, self.limits.max_rows),
                "truncated": res.truncated or res.row_count > self.limits.max_rows,
                "elapsed_ms": res.elapsed_ms}

    def _describe(self, _args) -> dict:
        m = self.engine.manifest or {}
        rows = m.get("output", {}).get("rows")
        empty = [c for c, n in m.get("null_counts", {}).items() if rows and n == rows]
        ov = self.profiler.overview()
        return {
            "dataset_sha256": self.engine.dataset_sha256,
            "columns": dict(self.profiler.columns),
            "columns_without_data": empty,
            "overview": dict(zip(ov.columns, ov.rows[0], strict=True)),
            "timezone": m.get("timezone", {}),
            "roles": self.roles.as_record(),
            "detectors": available(),
        }

    def _run_query(self, args: QueryArgs) -> dict:
        res = self.engine.query(args.sql, max_rows=self.limits.max_rows)
        out = self._shape(res)
        out["query_id"] = query_id(self.engine.history[-1])
        return out

    def _profile(self, args: ProfileArgs) -> dict:
        p = self.profiler
        if args.kind == "overview":
            res = p.overview()
        elif args.kind == "timeline":
            res = p.timeline(args.bucket, args.filters)
        elif args.dimension is None:
            raise ValueError(f"`dimension` es obligatoria para kind={args.kind}")
        elif args.kind == "top":
            res = p.top(args.dimension, args.n, args.filters)
        elif args.kind == "status_by":
            res = p.status_by(args.dimension, args.n, args.filters)
        else:
            res = p.activity(args.dimension, args.n)
        return self._shape(res)

    def _detect(self, args: DetectArgs) -> dict:
        known = available()
        unknown = [n for n in (args.names or []) if n not in known]
        if unknown:
            raise ValueError(f"detectores desconocidos: {unknown}. Disponibles: {sorted(known)}")
        roles = self.roles
        runs = run_detectors(self.engine, names=args.names or None, roles=roles)
        cases = correlate(runs, key=roles.actor)
        if self.ledger:
            self.ledger.record_roles(roles)
            self.ledger.record_runs(runs)
            self.ledger.record_cases(cases)
        ds = self.engine.dataset_sha256
        cap = 10
        findings = []
        for r in runs:
            for f in r.findings:
                related = {}
                for k, v in f.related.items():
                    related[k] = list(v)[:cap]
                    related[f"{k}_total"] = len(v)
                findings.append({"finding_id": finding_id(f, ds), "detector": f.detector, "severity": f.severity,
                                 "summary": f.summary, "entity": f.entity, "metrics": f.metrics, "related": related})
        return {
            "detectors": [{"name": r.name, "status": r.status, "reason": r.reason, "findings": len(r.findings)}
                          for r in runs],
            "findings": findings,
            "candidates": [{"candidate_id": candidate_id(c, ds), "entity": c.entity, "signals": c.signals,
                            "severity": c.severity,
                            "detectors": list(c.detectors)} for c in cases],
        }

    def _timeline(self, args: TimelineArgs) -> dict:
        res = self.profiler.timeline(args.bucket, {args.dimension: args.value})
        rows = res.rows
        if not rows:
            return {"dimension": args.dimension, "value": args.value, "total": 0, "message": "sin eventos"}
        peak = max(rows, key=lambda r: r[1])
        limit = self.limits.timeline_points
        points = rows
        if len(rows) > limit:  # conserva los periodos más intensos, en orden cronológico
            keep = sorted(sorted(rows, key=lambda r: -r[1])[:limit], key=lambda r: r[0])
            points = keep
        return {
            "dimension": args.dimension, "value": args.value, "bucket": args.bucket,
            "total": sum(r[1] for r in rows), "active_periods": len(rows),
            "first_period": rows[0][0], "last_period": rows[-1][0],
            "peak": {"period": peak[0], "requests": peak[1]},
            "series": [[p, n] for p, n in points],
            "series_truncated": len(rows) > limit or res.truncated,
        }

    # --- salida segura y auditoría -----------------------------------------------------------
    def _finish(self, name, args, start, data) -> ToolOutput:
        clean, warnings = sanitize(data, self.limits.max_cell_chars)
        qids = [query_id(q) for q in self.engine.history[start:] if q["status"] == "ok"][-5:]
        payload = {"tool": name, "ok": True, "data": clean, "warnings": warnings[:10], "query_ids": qids}
        if len(warnings) > 10:
            payload["warnings"].append(f"... y {len(warnings) - 10} más")
        text = render(payload)
        while len(text) > self.limits.max_chars:
            d = payload["data"]
            key = max((k for k, v in d.items() if isinstance(v, list) and len(v) > 1),
                      key=lambda k: len(d[k]), default=None)
            if key is None:
                payload["data"] = {"error": "resultado demasiado grande; acota la consulta"}
                text = render(payload)
                break
            d[key] = d[key][: max(1, len(d[key]) // 2)]
            d["truncated_by_budget"] = True
            text = render(payload)
        self._audit(name, args, True, start, warnings)
        return ToolOutput(True, payload["data"], text, tuple(warnings))

    def _fail(self, name, args, start, message) -> ToolOutput:
        payload = {"tool": name, "ok": False, "error": clean_text(message, 400)}
        self._audit(name, args, False, start, [])
        return ToolOutput(False, {"error": payload["error"]}, render(payload), ())

    def _audit(self, name, args, ok, start, warnings) -> None:
        if not self.ledger:
            return
        queries = self.engine.history[start:]
        self.ledger.record_queries(queries)
        self.ledger.append("tool_call", {"tool": name, "args": args or {}, "ok": ok,
                                         "query_ids": [query_id(q) for q in queries],
                                         "injection_warnings": list(warnings)})
