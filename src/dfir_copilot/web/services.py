"""Servicios de la interfaz: resolver casos, agentes en caché y trabajos en segundo plano para lo que llama al modelo."""
from __future__ import annotations

import os
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from dfir_copilot.agent.graph import build_agent
from dfir_copilot.agent.llm import LLMConfigError
from dfir_copilot.cases import DEFAULT_ROOT, CaseError, CaseWorkspace
from dfir_copilot.pipeline import Deps, PipelineRunner, default_deps, llm_status
from dfir_copilot.projects import Project, ProjectError, ProjectSettings


class NotFound(Exception):
    """Proyecto o caso inexistente (la vista lo convierte en 404)."""


class Busy(Exception):
    """Ya hay una operación con el modelo en curso en este caso."""


class NoModel:
    """Sustituye al modelo cuando no hay clave: el agente sigue sirviendo hipótesis, notas y aprobaciones pendientes; preguntar da un error claro."""

    model = "sin-modelo"

    def bind_tools(self, tools, **kwargs):
        return self

    def invoke(self, *args, **kwargs):
        raise LLMConfigError("No hay un modelo configurado: define la clave de API en el .env y reinicia la interfaz")


@dataclass
class CaseCtx:
    ws: CaseWorkspace
    project: Project | None
    settings: ProjectSettings
    base: str  # URL base de las vistas de este caso


@dataclass
class Bundle:
    ws: CaseWorkspace
    real: object
    pseudo: object
    ps: object
    ledger: object
    agent: object
    model_ok: bool
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass
class Job:
    id: str
    kind: str
    state: str = "running"  # running | done | error
    result: dict | None = None
    error: str | None = None


class Services:
    def __init__(self, sync: bool = False, deps: Deps | None = None, cases_root: str | Path | None = None):
        self.sync = sync
        self._deps = deps
        self.cases_root = Path(cases_root or os.environ.get("DFIR_CASES_ROOT", DEFAULT_ROOT))
        self.runner = PipelineRunner(workers=int(os.environ.get("DFIR_WEB_WORKERS", "1")), sync=sync)
        self._bundles: dict[str, Bundle] = {}
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()

    # --- modelo ---------------------------------------------------------------------------------------------------
    @property
    def deps(self) -> Deps:
        if self._deps is None:
            self._deps = default_deps()
        return self._deps

    def model_status(self) -> tuple[bool, str]:
        if self._deps is not None:
            return (True, "modelo configurado") if self._deps.agent_llm else (False, "sin modelo")
        return llm_status()

    # --- casos ----------------------------------------------------------------------------------------------------
    def case(self, project_id: str | None, case_id: str) -> CaseCtx:
        try:
            if project_id:
                project = Project.open(project_id)
                project.file(case_id)  # el caso debe corresponder a un archivo del proyecto
                ws = project.workspace(case_id)
                return CaseCtx(ws, project, project.settings, f"/proyectos/{project_id}/casos/{case_id}/")
            ws = CaseWorkspace.open(case_id, root=self.cases_root)
            return CaseCtx(ws, None, ProjectSettings(language=ws.lang if ws.lang in ("es", "en") else "es",
                                                     analyst=ws.meta.get("analyst")), f"/casos/{case_id}/")
        except (ProjectError, CaseError) as exc:
            raise NotFound(str(exc)) from exc

    def legacy_cases(self) -> list[dict]:
        return CaseWorkspace.list_cases(self.cases_root)

    # --- agente por caso -------------------------------------------------------------------------------------------
    def bundle(self, ctx: CaseCtx) -> Bundle:
        key = str(ctx.ws.dir)
        with self._lock:
            cached = self._bundles.get(key)
            if cached and (cached.model_ok or not self.model_status()[0]):
                return cached
            ws, s = ctx.ws, ctx.settings
            if not ws.meta.get("dataset"):
                raise NotFound("El caso aún no tiene datos ingeridos")
            real = ws.engine(timeout_s=120)
            pseudo, ps = ws.pseudonymized(timeout_s=120)
            ledger = ws.ledger(real)
            try:
                llm, ok = (self.deps.agent_llm() if self.deps.agent_llm else NoModel()), bool(self.deps.agent_llm)
            except LLMConfigError:
                llm, ok = NoModel(), False
            agent = build_agent(pseudo, ledger, llm, analyst=s.analyst, max_steps=14, max_tokens=s.max_tokens,
                                max_tokens_case=s.max_tokens_case, pseudonymizer=ps, checkpointer=ws.checkpointer())
            refresh_profile_digest(agent, ws)
            self._bundles[key] = Bundle(ws, real, pseudo, ps, ledger, agent, ok)
            return self._bundles[key]

    # --- trabajos en segundo plano ----------------------------------------------------------------------------------
    def submit(self, bundle: Bundle, kind: str, fn) -> Job:
        if not bundle.lock.acquire(blocking=False):
            raise Busy("Ya hay una operación con el modelo en curso en este caso")
        job = Job(uuid.uuid4().hex[:12], kind)
        with self._lock:
            self._jobs[job.id] = job
            for old in list(self._jobs)[:-60]:
                self._jobs.pop(old, None)

        def run():
            try:
                job.result = fn()
                job.state = "done"
            except Exception as exc:  # noqa: BLE001 - el error se muestra en la interfaz, no tumba el servidor
                job.error, job.state = f"{type(exc).__name__}: {exc}", "error"
            finally:
                bundle.lock.release()

        if self.sync:
            run()
        else:
            threading.Thread(target=run, daemon=True, name=f"dfir-job-{job.id}").start()
        return job

    def job(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise NotFound("Trabajo desconocido (¿se reinició el servidor?)")
        return job

    def forget(self, prefix) -> int:
        """Suelta los agentes en caché de los casos bajo `prefix` (p. ej. un análisis que se mueve a la papelera)."""
        prefix = str(prefix).rstrip("/")
        with self._lock:
            keys = [k for k in self._bundles if k == prefix or k.startswith(prefix + "/")]
            for k in keys:
                self._bundles.pop(k, None)
        return len(keys)


_services: Services | None = None


def get_services() -> Services:
    global _services
    if _services is None:
        _services = Services(sync=os.environ.get("DFIR_WEB_SYNC") == "1")
    return _services


def reset_services(**kwargs) -> Services:
    """Para pruebas: un `Services` nuevo (síncrono, con modelos simulados, raíz de casos de prueba)."""
    global _services
    _services = Services(**kwargs)
    return _services


def refresh_profile_digest(agent, ws) -> None:
    """El agente de la interfaz recibe en cada pregunta el resumen del perfil de datos: una pregunta de datos se resuelve en uno o dos pasos
    en vez de diez. Va en el mensaje de la pregunta (no en el prompt de sistema), así no invalida conversaciones guardadas."""
    import json

    from dfir_copilot.data_profile import digest

    path = ws.dir / "p1" / "perfil_datos.json"
    text = digest(json.loads(path.read_text(encoding="utf-8"))) if path.exists() else None
    corr = ws.dir.parent.parent / "correlacion.json"  # <análisis>/cases/<caso> -> <análisis>/correlacion.json
    if corr.exists():
        from dfir_copilot.correlation import digest_for

        try:
            _, ps = ws.pseudonymized()
            extra = digest_for(json.loads(corr.read_text(encoding="utf-8")), ps)
        except Exception:  # noqa: BLE001 - la correlación es un extra: si falla, el agente sigue con el perfil
            extra = None
        text = "\n\n".join(x for x in (text, extra) if x) or None
    agent.profile_digest = text
