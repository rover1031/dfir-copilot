"""Análisis automático de un archivo de un proyecto, por etapas e idempotente.

El análisis lo hace el CÓDIGO; el modelo solo enriquece (acuerdo del proyecto). Por eso las etapas son:

| Etapa       | Qué hace                                                                          | Modelo |
|-------------|-----------------------------------------------------------------------------------|--------|
| `draft`     | perfila el archivo en local y propone el mapping (Inspector)                      | no     |
| `interpret` | P1-a: el modelo recibe SOLO el perfil (metadatos) y propone clasificación y SQL   | sí     |
| `ingest`    | normaliza a Parquet en el caso; el caso queda atado por hash                      | no     |
| `copy`      | copia seudonimizada (política `priv-1`)                                           | no     |
| `detectors` | detectores sobre la copia, correlación y registro en el ledger                    | no     |
| `explore`   | ejecuta en local las consultas que el modelo propuso en `interpret`               | no     |
| `triage`    | el agente (LangGraph) hace un triaje inicial; sus hipótesis quedan PENDIENTES de   | sí     |
|             | tu aprobación y con su criterio de refutación                                     |        |

Las etapas del modelo son opcionales (`use_llm`) y se saltan solas si no hay clave configurada: el análisis local no depende de ellas.
Cada etapa guarda su estado en `<proyecto>/status/<caso>.json`; al reintentar se reanuda donde se quedó.
"""
from __future__ import annotations

import json
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from dfir_copilot.projects import Project, SourceFile
from dfir_copilot.tools.sanitize import clean_text

STEPS = ("draft", "interpret", "ingest", "copy", "profile", "detectors", "explore", "triage")
STEP_STATUS = ("pending", "running", "done", "skipped", "needs_attention", "unsupported", "failed")

TRIAGE_QUESTION = {
    "es": ("Haz un triaje inicial de este dataset. Usa los detectores, formula como máximo dos hipótesis falsables con su criterio de "
           "refutación, pruébalas e intenta refutarlas antes de pedir su confirmación, y resume qué quedó sin comprobar."),
    "en": ("Run an initial triage of this dataset. Use the detectors, formulate at most two falsifiable hypotheses with their refutation "
           "criterion, test them and try to refute them before asking for confirmation, and summarize what remains unchecked."),
}


@dataclass(frozen=True)
class Deps:
    """Cómo conseguir el modelo. En pruebas se sustituyen por modelos simulados; sin clave configurada devuelven/lanzan y la etapa se salta."""

    agent_llm: Callable[[], object] | None = None          # () -> modelo de chat de LangChain
    structured_llm: Callable[[], object] | None = None     # () -> StructuredLLM (P1-a)


def default_deps() -> Deps:
    from dfir_copilot.agent.llm import LLMConfig, make_llm
    from dfir_copilot.interpret import LangChainStructured

    def structured():
        return LangChainStructured(make_llm(replace(LLMConfig.from_env(), timeout_s=180)))

    return Deps(agent_llm=make_llm, structured_llm=structured)


def llm_status() -> tuple[bool, str]:
    """¿Hay un modelo configurado? (clave y proveedor). Sin llamar a la API."""
    from dfir_copilot.agent.llm import LLMConfig, LLMConfigError, make_llm

    try:
        make_llm(LLMConfig.from_env())
        return True, "modelo configurado"
    except LLMConfigError as exc:
        return False, str(exc)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_status(source: SourceFile) -> dict:
    return {"case_id": source.case_id, "file": source.name, "state": "pending", "started_at": None, "finished_at": None,
            "steps": {s: {"status": "pending", "message": "", "started_at": None, "finished_at": None} for s in STEPS}}


def _overall(steps: dict) -> str:
    values = [v["status"] for v in steps.values()]
    if "unsupported" in values:  # formato que todavía no sabemos ingerir: no es un fallo, y no hay nada que reintentar
        return "unsupported"
    if "failed" in values:
        return "failed"
    if "running" in values or "pending" in values:
        return "running"
    return "needs_attention" if "needs_attention" in values else "done"


class _Stop(Exception):
    """Detiene el análisis de un archivo con un estado final (p. ej. formato no soportado)."""

    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class Pipeline:
    def __init__(self, project: Project, source: SourceFile, deps: Deps | None = None,
                 on_update: Callable[[dict], None] | None = None):
        self.project, self.source, self.deps = project, source, deps or Deps()
        self.settings = project.settings
        self.on_update = on_update
        self.ws = project.workspace(source.case_id, create=True)
        self.p1 = self.ws.dir / "p1"
        self.state = project.status(source.case_id) or new_status(source)
        # un estado guardado por una versión anterior no conoce las etapas nuevas: se añaden como pendientes, en su orden
        blank = new_status(source)["steps"]
        self.state["steps"] = {st: self.state["steps"].get(st, blank[st]) for st in STEPS}
        self._draft = None
        self._interpretation = None

    # --- estado ------------------------------------------------------------------------------------------------
    def _save(self) -> None:
        self.state["state"] = _overall(self.state["steps"])
        self.project.save_status(self.source.case_id, self.state)
        if self.on_update:
            self.on_update(self.state)

    def _set(self, step: str, status: str, message: str = "") -> None:
        s = self.state["steps"][step]
        if status == "running":
            s["started_at"] = _now()
        else:
            s["finished_at"] = _now()
        s["status"], s["message"] = status, clean_text(message, 400)
        self._save()

    # --- ejecución -----------------------------------------------------------------------------------------------
    def run(self) -> dict:
        self.state["started_at"], self.state["finished_at"] = _now(), None
        for step in STEPS:
            prev = self.state["steps"][step]["status"]
            if prev in ("done", "needs_attention"):
                continue  # ya hecho en una ejecución anterior (con su aviso, si lo tuvo)
            # Un "skipped" se reintenta SIEMPRE: puede ser porque no había modelo (quizá ahora sí) o porque una etapa anterior se detuvo
            # (formato que antes no se soportaba). Las etapas son idempotentes, así que reintentar lo ya resuelto no cuesta nada.
            self._set(step, "running")
            try:
                status, message = getattr(self, f"_step_{step}")()
            except _Stop as stop:
                self._set(step, stop.status, stop.message)
                self._skip_rest(step, f"detenido en '{step}'")
                break
            except Exception as exc:  # noqa: BLE001 - se registra y se detiene; se puede reintentar
                self._set(step, "failed", f"{type(exc).__name__}: {exc}")
                self._skip_rest(step, f"no se ejecutó: falló '{step}'", status="pending")
                break
            self._set(step, status, message)
        self.state["finished_at"] = _now()
        self._save()
        return self.state

    def _skip_rest(self, after: str, message: str, status: str = "skipped") -> None:
        later = STEPS[STEPS.index(after) + 1:]
        for s in later:
            if self.state["steps"][s]["status"] in ("pending", "running"):
                self.state["steps"][s].update(status=status, message=message)
        self._save()

    # --- etapas -------------------------------------------------------------------------------------------------------
    def _inspect(self):
        from dfir_copilot.profiling import inspect_source

        s = self.settings
        note = f"Declarada al crear el proyecto '{self.project.id}'" + (f" por {s.analyst}" if s.analyst else "")
        return inspect_source(self.source.path, lang=s.language, timezone=s.timezone, timezone_note=note if s.timezone else None)

    def _step_draft(self):
        if not self.source.supported:
            raise _Stop("unsupported", f"formato de archivo no soportado: {self.source.name} (se admiten csv, tsv, json, ndjson y parquet)")
        if self.ws.meta.get("dataset"):
            return "done", "el caso ya está ingerido"
        self._draft = self._inspect()
        self.p1.mkdir(parents=True, exist_ok=True)
        self._draft.save(self.p1 / "mapping_borrador.yaml")
        if self._draft.status == "unsupported":
            why = next((d.message for d in self._draft.decisions if d.code == "unsupported_log_type"), "tipo de log sin esquema todavía")
            raise _Stop("unsupported", f"formato de log no soportado todavía: {why}")
        if self._draft.status == "needs_review":
            codes = ", ".join(d.code for d in self._draft.decisions if d.level == "required")
            return "needs_attention", f"mapping aceptado automáticamente; decisiones por revisar: {codes}"
        return "done", f"mapping propuesto ({self._draft.log_type})"

    def _step_interpret(self):
        if not self.settings.use_llm:
            return "skipped", "el proyecto no usa el modelo"
        if not self.deps.structured_llm:
            return "skipped", "no hay modelo configurado"
        if over_incident_budget(self.project):
            return "skipped", "tope de tokens del incidente alcanzado"
        if self._draft is None:  # reanudación: la etapa draft ya estaba hecha; el borrador se reconstruye del archivo (local, sin modelo)
            self._draft = self._inspect()
        from dfir_copilot.agent.llm import LLMConfigError
        from dfir_copilot.interpret import interpret_profile, result_to_dict

        try:
            llm = self.deps.structured_llm()
        except LLMConfigError as exc:
            return "skipped", f"modelo no configurado: {exc}"
        result = interpret_profile(llm, self._draft.profile, derived=self._draft.derived,
                                   lang=self.settings.language, timestamp=self._draft.mapping.get("timestamp"))
        self._interpretation = result
        (self.p1 / "interpretacion.json").write_text(json.dumps(result_to_dict(result), ensure_ascii=False, indent=2) + "\n",
                                                     encoding="utf-8")
        if not result.ok:
            return "needs_attention", f"respuesta del modelo no utilizable ({result.error})"
        return "done", "interpretación guardada (el modelo solo vio metadatos del perfil)"

    def _step_ingest(self):
        if self.ws.meta.get("dataset"):
            return "done", "ya ingerido"
        self.ws.add_raw(self.source.path, link=True)
        manifest = self.ws.ingest(self.source.path, self.p1 / "mapping_borrador.yaml")
        warnings = manifest.get("warnings") or []
        msg = f"{manifest['output']['rows']:,} filas"
        if warnings:
            msg += f" · {len(warnings)} aviso(s): {warnings[0]}"
        return ("needs_attention" if warnings else "done"), msg

    def _step_copy(self):
        _, ps = self.ws.pseudonymized()
        return "done", f"copia seudonimizada lista ({len(ps.treatments)} columnas tratadas)"

    def _step_detectors(self):
        from dfir_copilot.tools import Toolkit

        pseudo, _ = self.ws.pseudonymized()
        ledger = self.ws.ledger(self.ws.engine())
        if ledger.entries("detector_run"):
            return "done", "los detectores ya se ejecutaron"
        out = Toolkit(pseudo, ledger).call("run_detectors")
        if not out.ok:
            raise RuntimeError(out.data.get("error", "los detectores fallaron"))
        n = len(out.data["findings"])
        return "done", f"{n} hallazgo(s) · {len(out.data['candidates'])} caso(s) candidato(s)"

    def _step_explore(self):
        if self._interpretation is None or not self._interpretation.ok:
            return "skipped", "sin consultas propuestas por el modelo"
        from dfir_copilot.interpret import run_accepted_queries, summarize_runs

        runs = run_accepted_queries(self.ws.engine(), self._interpretation, max_rows=20)
        (self.p1 / "consultas.json").write_text(json.dumps([
            {"id": r.id, "priority": r.priority, "status": r.status, "row_count": r.row_count, "columns": list(r.columns),
             "rows": [list(x) for x in r.rows[:20]], "error": r.error} for r in runs], ensure_ascii=False, default=str, indent=1) + "\n",
            encoding="utf-8")
        summary = summarize_runs(runs)
        return "done", f"{summary['accepted']} consulta(s) ejecutadas en local · {summary['accepted_but_failed']} fallida(s)"

    def _step_profile(self):
        """El desglose de ingeniero de datos (local, sobre la copia con alias): ver `data_profile`."""
        from dfir_copilot.data_profile import build_profile, save_profile

        path = self.p1 / "perfil_datos.json"
        ledger = self.ws.ledger(self.ws.engine())
        if path.exists() and ledger.entries("data_profile"):
            return "done", "perfil ya calculado"
        pseudo, _ = self.ws.pseudonymized()
        prof = build_profile(pseudo)
        sha = save_profile(prof, path)
        ledger.append("data_profile", {"file": "p1/perfil_datos.json", "sha256": sha, "rows": prof["rows"],
                                       "columns": len(prof["columns"]), "copy": pseudo.copy_id})
        q = prof["quality"]
        return "done", (f"{prof['rows']:,} filas · {len(prof['columns'])} columnas · {q['duplicate_rows']:,} duplicada(s)"
                        + (f" · {len(q['empty_columns'])} columna(s) vacía(s)" if q["empty_columns"] else ""))

    def _triage_question(self) -> tuple[str, tuple]:
        """La pregunta del triaje más el resumen del perfil (en alias). Las cifras del resumen las calculó el código: se marcan como
        literales para que el guardián de privacidad no las confunda con identificadores."""
        question = TRIAGE_QUESTION[self.settings.language]
        path = self.p1 / "perfil_datos.json"
        if not path.exists():
            return question, ()
        import re

        from dfir_copilot.data_profile import digest

        text = digest(json.loads(path.read_text(encoding="utf-8")))
        return f"{question}\n\n{text}", tuple(sorted(set(re.findall(r"\d[\d.,:+-]*\d|\d", text))))

    def _step_triage(self):
        if not self.settings.use_llm:
            return "skipped", "el proyecto no usa el modelo"
        if not self.deps.agent_llm:
            return "skipped", "no hay modelo configurado"
        if over_incident_budget(self.project):
            return "skipped", "tope de tokens del incidente alcanzado"
        from dfir_copilot.agent.graph import build_agent
        from dfir_copilot.agent.llm import LLMConfigError

        pseudo, ps = self.ws.pseudonymized()
        ledger = self.ws.ledger(self.ws.engine())
        if ledger.entries("agent_turn"):
            return "done", "ya hay un triaje en este caso"
        try:
            llm = self.deps.agent_llm()
        except LLMConfigError as exc:
            return "skipped", f"modelo no configurado: {exc}"
        s = self.settings
        agent = build_agent(pseudo, ledger, llm, analyst=s.analyst, max_steps=14, max_tokens=s.max_tokens,
                            max_tokens_case=s.max_tokens_case, pseudonymizer=ps, checkpointer=self.ws.checkpointer())
        question, literal = self._triage_question()
        r = agent.ask(question, literal=literal)
        if r.status == "needs_approval":
            return "needs_attention", f"{len(r.approvals)} hipótesis pendiente(s) de tu aprobación · {r.tokens:,} tokens"
        return "done", f"triaje completado · {r.tokens:,} tokens" + (f" · cortado por {r.cut_by}" if r.cut_by else "")


def run_pipeline(project: Project, source: SourceFile, deps: Deps | None = None,
                 on_update: Callable[[dict], None] | None = None) -> dict:
    """Ejecuta (o reanuda) el análisis de un archivo y devuelve su estado."""
    return Pipeline(project, source, deps, on_update).run()


def over_incident_budget(project: Project) -> bool:
    from dfir_copilot.incident import over_budget

    return over_budget(project)


def correlate_after(project: Project) -> None:
    """Correlación entre fuentes al terminar un archivo: solo si el análisis tiene 2+ casos ingeridos. Un fallo aquí no tumba el análisis
    del archivo: se deja escrito en `correlacion_error.txt` del análisis."""
    from dfir_copilot.correlation import correlate_project

    ingested = sum(1 for f in project.files() if f.supported and (project.cases_dir / f.case_id / "case.json").exists()
                   and json.loads((project.cases_dir / f.case_id / "case.json").read_text(encoding="utf-8")).get("dataset"))
    if ingested < 2:
        return
    try:
        correlate_project(project)
        (project.dir / "correlacion_error.txt").unlink(missing_ok=True)
    except Exception as exc:  # noqa: BLE001
        (project.dir / "correlacion_error.txt").write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")


class PipelineRunner:
    """Lanza análisis en segundo plano (un hilo por archivo, uno a la vez por defecto). `sync=True` los ejecuta en el acto (pruebas)."""

    def __init__(self, workers: int = 1, sync: bool = False):
        self.sync = sync
        self._pool = None if sync else ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dfir-pipeline")
        self._running: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def running(self, project_id: str, case_id: str) -> bool:
        return (project_id, case_id) in self._running

    def submit(self, project: Project, source: SourceFile, deps: Deps | None = None) -> bool:
        key = (project.id, source.case_id)
        with self._lock:
            if key in self._running:
                return False
            self._running.add(key)
            # marca de arranque inmediata: la interfaz ya ve "en curso" antes de que el hilo empiece
            state = project.status(source.case_id) or new_status(source)
            state["state"] = "running"
            project.save_status(source.case_id, state)

        def job():
            try:
                run_pipeline(project, source, deps)
                correlate_after(project)
            finally:
                with self._lock:
                    self._running.discard(key)

        if self.sync:
            job()
        else:
            self._pool.submit(job)
        return True


__all__ = ["STEPS", "STEP_STATUS", "TRIAGE_QUESTION", "Deps", "Pipeline", "PipelineRunner", "default_deps", "llm_status",
           "new_status", "run_pipeline"]
