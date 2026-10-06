"""Vistas: server-rendered con HTMX para los fragmentos. Todo lo sensible se queda en esta máquina; los alias se muestran como los ve el modelo
y un interruptor (`?reveal=1`) los traduce a valores reales SOLO en pantalla."""
from __future__ import annotations

import json
import re
from collections import Counter

from django.conf import settings as django_settings
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from dfir_copilot.privacy import AmbiguousText
from dfir_copilot.projects import Project, ProjectError, ProjectSettings, browse, data_root, inbox_root
from dfir_copilot.reporting import ReportError, export_report, reports_root
from dfir_copilot.timezone_status import BASES, TimezoneError, confirm_timezone, timezone_state
from dfir_copilot.web.services import Busy, NotFound, get_services

TABS = ("resumen", "datos", "hipotesis", "preguntar", "notas", "informe", "integridad")
_FILENAME = re.compile(r"^informe\.(es|en)\.(interno|compartible)\.md$")
_SEV = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _reveal(request) -> bool:
    return (request.POST.get("reveal") or request.GET.get("reveal")) == "1"


def _msg(request, text: str, level: str = "error", status: int = 200):
    return render(request, "web/_message.html", {"text": text, "level": level}, status=status)


def _ctx(pid, cid):
    try:
        return get_services().case(pid, cid)
    except NotFound as exc:
        raise Http404(str(exc)) from exc


def _bundle(ctx):
    try:
        return get_services().bundle(ctx)
    except NotFound as exc:
        raise Http404(str(exc)) from exc


def _result(r) -> dict:
    return {"status": r.status, "answer": r.answer, "sent": r.sent, "substitutions": list(r.substitutions), "tokens": r.tokens,
            "steps": r.steps, "cut_by": r.cut_by, "approvals": len(r.approvals)}


def _literals(request) -> tuple:
    return tuple(x.strip() for x in (request.POST.get("literal") or "").split(",") if x.strip())


# --- inicio y proyectos ---------------------------------------------------------------------------------------------

def _home_context(extra: dict | None = None) -> dict:
    sv = get_services()
    projects = []
    for p in Project.list():
        states = Counter((p.status(f.case_id) or {}).get("state", "pending") for f in p.files() if f.supported)
        projects.append({"id": p.id, "name": p.name, "ticket": p.ticket, "files": len(p.files()), "states": dict(states)})
    ok, msg = sv.model_status()
    return {"projects": projects, "legacy": sv.legacy_cases(), "llm_ok": ok, "llm_msg": msg, "data_root": data_root(),
            "form": {"language": "es", "max_tokens": 210000, "use_llm": True}, **(extra or {})}


@require_GET
def home(request):
    return render(request, "web/home.html", _home_context())


@require_POST
def project_create(request):
    p = request.POST
    form = {"name": p.get("name", ""), "source_dir": p.get("source_dir", ""), "language": p.get("language", "es"),
            "timezone": p.get("timezone", ""), "analyst": p.get("analyst", ""), "use_llm": p.get("use_llm") == "on",
            "max_tokens": p.get("max_tokens") or 210000}
    try:
        if not form["source_dir"].strip():
            raise ProjectError("Escribe la carpeta del servidor, o usa «Nuevo análisis» para subir o elegir archivos")
        settings = ProjectSettings(language=form["language"], timezone=form["timezone"].strip() or None,
                                   analyst=form["analyst"].strip() or None, use_llm=form["use_llm"], max_tokens=int(form["max_tokens"]))
        project = Project.create(form["name"], form["source_dir"], settings)
    except (ProjectError, ValueError) as exc:
        return render(request, "web/home.html", _home_context({"error": str(exc), "form": form}), status=400)
    sv = get_services()
    for f in project.files():
        if f.supported:
            sv.runner.submit(project, f, sv.deps)
    return redirect(f"/proyectos/{project.id}/")


def _open_project(pid: str) -> Project:
    try:
        return Project.open(pid)
    except ProjectError as exc:
        raise Http404(str(exc)) from exc


def _ingested(project: Project, case_id: str) -> bool:
    """¿El caso tiene un dataset ingerido? Un archivo no soportado o que falló antes de ingerir no tiene nada que abrir."""
    try:
        return bool(json.loads((project.cases_dir / case_id / "case.json").read_text(encoding="utf-8")).get("dataset"))
    except (OSError, ValueError):
        return False


def _case_tokens(project: Project, case_id: str) -> dict | None:
    """Tokens gastados por el caso: la interpretación del perfil más todos los turnos del agente (del ledger, sin abrir DuckDB)."""
    case_dir = project.cases_dir / case_id
    interp, agent = 0, 0
    path = case_dir / "p1" / "interpretacion.json"
    if path.exists():
        try:
            u = json.loads(path.read_text(encoding="utf-8")).get("usage") or {}
            interp = int(u.get("input_tokens", 0) or 0) + int(u.get("output_tokens", 0) or 0) or int(u.get("total_tokens", 0) or 0)
        except (OSError, ValueError, TypeError):
            interp = 0
    for ledger in (case_dir / "ledger").glob("*.jsonl") if (case_dir / "ledger").is_dir() else ():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if '"agent_turn"' in line:
                d = json.loads(line).get("data", {})
                agent += int(d.get("tokens_delta") if d.get("tokens_delta") is not None else (d.get("tokens") or 0))
    total = interp + agent
    return {"interpret": f"{interp:,}", "agent": f"{agent:,}", "total": f"{total:,}"} if total else None


def _project_rows(project: Project) -> tuple[list[dict], bool]:
    sv = get_services()
    rows, running = [], False
    for f in project.files():
        st = project.status(f.case_id)
        is_running = sv.runner.running(project.id, f.case_id)
        running = running or is_running
        # estado "running" en disco sin hilo vivo: el servidor se reinició a mitad de un análisis
        interrupted = bool(st and st.get("state") == "running" and not is_running)
        rows.append({"file": f, "status": st, "running": is_running, "interrupted": interrupted, "tokens": _case_tokens(project, f.case_id),
                     "has_case": _ingested(project, f.case_id),
                     "steps": list((st or {}).get("steps", {}).items())})
    return rows, running


def _correlation_view(project: Project, reveal: bool) -> dict | None:
    """La correlación lista para mostrar: en alias (el diccionario de cada caso traduce lo que conoce) salvo con el interruptor."""
    from dfir_copilot.correlation import load

    corr = load(project)
    if not corr or reveal or corr.get("status") != "ok":
        return corr
    pss = []
    for c in corr.get("cases", []):
        try:
            pss.append(project.workspace(c["case_id"]).pseudonymized()[1])
        except Exception:  # noqa: BLE001 - un caso que ya no abre: sus valores se muestran ocultos
            continue

    def a(value):
        for ps in pss:
            try:
                out = ps.alias_text(str(value)).text
            except Exception:  # noqa: BLE001
                continue
            if out != str(value):
                return out
        return "•••"

    for pr in corr.get("pairs", []):
        for f in pr.get("flows", []):
            f[0], f[2] = a(f[0]), a(f[2])
        for x in pr.get("attributions", []):
            x["src_ip"], x["hosts"] = a(x["src_ip"]), [a(h) for h in x["hosts"]]
            x["procesos"] = [[a(h), p, n] for h, p, n in x["procesos"]]
            x["tambien_en_endpoint"] = [a(h) for h in x["tambien_en_endpoint"]]
    corr.get("shared_ips", {})["top"] = [[a(ip), *rest] for ip, *rest in corr.get("shared_ips", {}).get("top", [])]
    return corr


@require_GET
def project_page(request, pid):
    project = _open_project(pid)
    rows, running = _project_rows(project)
    ok, msg = get_services().model_status()
    reveal = _reveal(request)
    error = project.dir / "correlacion_error.txt"
    from dfir_copilot import incident

    return render(request, "web/project.html", {"project": project, "rows": rows, "running": running, "settings": project.settings,
                                                 "tokens": incident.tokens(project),
                                                 "llm_ok": ok, "llm_msg": msg, "reveal": reveal, "corr": _correlation_view(project, reveal),
                                                 "corr_error": error.read_text(encoding="utf-8") if error.exists() else None,
                                                 "n_ingested": sum(1 for r in rows if r["has_case"])})


@require_POST
def project_correlate(request, pid):
    from dfir_copilot.correlation import correlate_project

    project = _open_project(pid)
    correlate_project(project)
    return redirect(f"/proyectos/{project.id}/")


@require_GET
def project_status(request, pid):
    project = _open_project(pid)
    rows, running = _project_rows(project)
    return render(request, "web/_project_files.html", {"project": project, "rows": rows, "running": running})


@require_POST
def project_run(request, pid, cid):
    project = _open_project(pid)
    sv = get_services()
    for f in project.files():
        if f.supported and cid in ("todos", f.case_id):
            sv.runner.submit(project, f, sv.deps)
    rows, running = _project_rows(project)
    return render(request, "web/_project_files.html", {"project": project, "rows": rows, "running": running})


# --- caso ------------------------------------------------------------------------------------------------------------

@require_GET
def case_page(request, pid, cid):
    ctx = _ctx(pid, cid)
    return render(request, "web/case.html", {"ctx": ctx, "base": ctx.base, "pid": pid, "case_id": cid, "reveal": _reveal(request),
                                             "tabs": TABS, "model_ok": get_services().model_status()[0]})


def _shower(b, reveal: bool):
    """Función que deja el texto como lo ve el modelo (alias) o, con el interruptor, traducido a valores reales (solo en pantalla)."""
    def show(text):
        return b.ps.reveal_any(text) if reveal else text

    return show


def _find_sort(d: dict):
    return (_SEV.get(d["severity"], 9), d["finding_id"])


def _tab_resumen(ctx, b, reveal):
    v = _shower(b, reveal)
    ds = b.ledger.entries("case_opened")[0]["data"]["dataset"]
    man = b.real.manifest or {}
    findings = [{**d, "summary": v(d["summary"]), "entity": v(", ".join(f"{k}={x}" for k, x in d["entity"].items()))}
                for d in sorted((e["data"] for e in b.ledger.entries("finding")), key=_find_sort)]
    cands = [{**d, "entity": v(d["entity"])} for d in (e["data"] for e in b.ledger.entries("case_candidate"))]
    p1 = ctx.ws.dir / "p1"
    interp, explored = None, None
    if (p1 / "interpretacion.json").exists():
        interp = json.loads((p1 / "interpretacion.json").read_text(encoding="utf-8"))
    if (p1 / "consultas.json").exists():
        explored = json.loads((p1 / "consultas.json").read_text(encoding="utf-8"))
    return {"ds": ds, "tz": man.get("timezone", {}), "tzs": timezone_state(b.ledger, man), "tz_bases": BASES,
            "analyst": ctx.settings.analyst or "", "roles": man.get("roles") or {}, "findings": findings[:40],
            "n_findings": len(findings), "cands": cands[:10], "interp": interp, "explored": explored,
            "pipeline": ctx.project.status(ctx.ws.case_id) if ctx.project else None}


def _approval(r, v):
    return {**r, "hipotesis": v(r["hipotesis"]), "justificacion": v(r["justificacion"]),
            "criterio_de_refutacion": v(r["criterio_de_refutacion"]),
            "evidencia": [{**e, "detalle": v(e["detalle"])} for e in r["evidencia"]],
            "intentos_de_refutacion": [{**a, "detalle": v(a["detalle"]), "habria_refutado_si": v(a["habria_refutado_si"]),
                                        "observado": v(a["observado"])} for a in r["intentos_de_refutacion"]]}


def _tab_hipotesis(ctx, b, reveal):
    v = _shower(b, reveal)
    items = [{"id": h["hypothesis_id"], "status": h["status"], "statement": v(h["statement"]),
              "falsifier": v(h["falsifier"]) if h.get("falsifier") else None, "attempts": len(h.get("refutation_checks") or []),
              "evidence": h["evidence_refs"], "superseded_by": h.get("superseded_by"),
              "closed": h["status"] in ("confirmada", "refutada", "retirada")} for h in b.agent.book.all()]
    return {"items": items, "pending": [_approval(r, v) for r in b.agent.pending()], "model_ok": b.model_ok}


def _tab_datos(ctx, b, reveal):
    """El perfil de datos (en alias; con el interruptor, valores reales solo en pantalla)."""
    path = ctx.ws.dir / "p1" / "perfil_datos.json"
    if not path.exists():
        return {"profile": None}
    prof = json.loads(path.read_text(encoding="utf-8"))
    v = _shower(b, reveal)
    for c in prof["columns"]:
        c["top"] = [[v(x), n] for x, n in c.get("top", [])]
    for r in prof.get("relations", []):
        r["top"] = [[v(a), v(c), n] for a, c, n in r["top"]]
    for f in prof.get("first_last", []):
        f["top"] = [[v(x), *rest] for x, *rest in f["top"]]
    t = prof.get("time")
    if t:
        top_day = max((n for _, n in t["per_day"]), default=0) or 1
        t["days"] = [{"d": d, "n": n, "pct": round(100 * n / top_day, 1)} for d, n in t["per_day"]]
        top_hour = max(t["per_hour"]) or 1
        t["hours"] = [{"h": h, "n": n, "pct": round(100 * n / top_hour, 1)} for h, n in enumerate(t["per_hour"])]
    from dfir_copilot.data_profile import PROFILE_VERSION
    from dfir_copilot.data_questions import EXAMPLES

    return {"profile": prof, "qa_examples": EXAMPLES, "outdated": prof.get("profile_version", 1) < PROFILE_VERSION}


def _incident_over(project) -> bool:
    from dfir_copilot.incident import over_budget

    return over_budget(project)


def _auto_running(ctx) -> bool:
    """¿El análisis automático (con su triaje) sigue corriendo para este caso? Mientras tanto no se pregunta ni se decide: serían
    dos agentes sobre la misma conversación."""
    return bool(ctx.project and get_services().runner.running(ctx.project.id, ctx.ws.case_id))


def _last_error(b) -> str | None:
    errors = [e["data"].get("error") for e in b.ledger.entries("agent_turn") if e["data"].get("status") == "error"]
    return errors[-1] if errors else None


def _tab_preguntar(ctx, b, reveal):
    v = _shower(b, reveal)
    turns = [{"ts": e["ts_utc"], "question": v(e["data"].get("question") or ""), "answer": v(e["data"].get("answer") or ""),
              "tokens": e["data"].get("tokens_delta", e["data"].get("tokens")), "cut_by": e["data"].get("cut_by"),
              "status": e["data"]["status"]} for e in b.ledger.entries("agent_turn")][-12:]
    return {"phase": b.agent.phase(), "last_error": _last_error(b), "auto_running": _auto_running(ctx), "turns": turns, "budget": b.agent.budget(), "model_ok": b.model_ok, "pending": len(b.agent.pending())}


def _tab_notas(ctx, b, reveal):
    v = _shower(b, reveal)
    notes = [{"ts": e["ts_utc"], "text": v(e["data"]["text"]), "status": e["data"].get("status"), "analyst": e["data"].get("analyst"),
              "shown": str(e["data"].get("copy") or "").startswith("pseudonymized:")} for e in b.ledger.entries("note")]
    return {"notes": notes[::-1]}


def _tab_informe(ctx, b, reveal):
    exports = [{**e["data"], "ts": e["ts_utc"]} for e in b.ledger.entries("report_export")][::-1]  # el más reciente primero
    seen = set()
    for e in exports:
        key = (e["lang"], e["variant"])
        e["current"] = key not in seen  # el archivo se sobrescribe: solo el último de cada idioma y variante está en disco
        seen.add(key)
        e["exists"] = e["current"] and (reports_root() / ctx.ws.case_id / e["file"]).exists()
    return {"exports": exports[:12], "lang": ctx.settings.language}


def _tab_integridad(ctx, b, reveal):
    report = ctx.ws.verify()
    s = b.ledger.summary()
    return {"checks": [{"ok": c.ok, "text": line} for c, line in zip(report.checks, report.render(ctx.settings.language).splitlines(), strict=False)],
            "ok": report.ok, "summary": s, "copies": b.ledger.copies(), "budget": b.agent.budget()}


_TAB_BUILDERS = {"resumen": _tab_resumen, "datos": _tab_datos, "hipotesis": _tab_hipotesis, "preguntar": _tab_preguntar, "notas": _tab_notas,
                 "informe": _tab_informe, "integridad": _tab_integridad}


@require_GET
def tab_view(request, pid, cid, tab):
    if tab not in TABS:
        raise Http404("Pestaña desconocida")
    ctx = _ctx(pid, cid)
    if not ctx.ws.meta.get("dataset"):
        return _msg(request, "El análisis de este archivo todavía no ha ingerido los datos. Vuelve al proyecto para ver su avance.", "info")
    return _render_tab(request, ctx, tab)


def _render_tab(request, ctx, tab, flash: tuple | None = None):
    b = _bundle(ctx)
    reveal = _reveal(request)
    data = _TAB_BUILDERS[tab](ctx, b, reveal)
    return render(request, f"web/_tab_{tab}.html", {"base": ctx.base, "reveal": reveal, "case_id": ctx.ws.case_id, "flash": flash,
                                                      "model_ok": b.model_ok, **data})


# --- acciones con el modelo (trabajos en segundo plano) ---------------------------------------------------------------

def _job_response(request, ctx, job):
    return render(request, "web/_job.html", {"job": job, "base": ctx.base, "reveal": _reveal(request),
                                              **_job_view(ctx, job, _reveal(request))})


def _job_view(ctx, job, reveal):
    result = dict(job.result or {})
    if job.state == "done" and reveal:
        b = _bundle(ctx)
        for key in ("answer", "sent"):
            if result.get(key):
                result[key] = b.ps.reveal_any(result[key])
    return {"result": result}


_RUNNING_MSG = ("El análisis automático de este caso sigue en curso (el triaje con el modelo). Espera a que termine: la página del "
                "proyecto muestra el avance.")
_CRASHED_MSG = ("La conversación quedó a medias por un error anterior. Pulsa «Reiniciar conversación» en la pestaña Preguntar: no se "
                "pierden hipótesis, notas ni el ledger.")


@require_POST
def ask(request, pid, cid):
    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    question = (request.POST.get("question") or "").strip()
    if not question:
        return _msg(request, "Escribe una pregunta.", status=400)
    if _auto_running(ctx):
        return _msg(request, _RUNNING_MSG, status=409)
    if ctx.project and _incident_over(ctx.project):
        return _msg(request, "Se alcanzó el tope de tokens del incidente (todas sus fuentes). Súbelo en los ajustes del análisis o sigue "
                             "con las preguntas rápidas sin modelo de la pestaña Datos.", status=409)
    phase = b.agent.phase()
    if phase == "crashed":
        return _msg(request, _CRASHED_MSG, status=409)
    if phase == "awaiting_approval":
        return _msg(request, "Hay propuestas del agente esperando tu decisión: apruébalas o recházalas en la pestaña Hipótesis.", status=409)
    if not b.model_ok:
        return _msg(request, "No hay un modelo configurado: define la clave de API en el .env y reinicia la interfaz.", status=409)
    literal = _literals(request)
    try:
        b.agent.preview(question, literal)  # antes de nada: si es ambiguo no se lanza nada
    except AmbiguousText as exc:
        return _msg(request, str(exc), status=422)
    try:
        job = get_services().submit(b, "ask", lambda: _result(b.agent.ask(question, literal=literal)))
    except Busy as exc:
        return _msg(request, str(exc), status=409)
    return _job_response(request, ctx, job)


@require_POST
def decide(request, pid, cid):
    """Una decisión y una nota por propuesta pendiente. Sin «continuar», se registran al instante sin llamar al modelo."""
    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    if _auto_running(ctx):
        return _msg(request, _RUNNING_MSG, status=409)
    pending = b.agent.pending()
    if not pending:
        return _render_tab(request, ctx, "hipotesis", ("error", "No hay ninguna propuesta pendiente."))
    decisions = []
    for r in pending:
        hid = r["hypothesis_id"]
        decision, note = request.POST.get(f"decision_{hid}"), (request.POST.get(f"note_{hid}") or "").strip()
        if decision not in ("approve", "reject"):
            return _render_tab(request, ctx, "hipotesis", ("error", f"Falta tu decisión sobre {hid}: aprueba o rechaza cada propuesta."))
        decisions.append({"hypothesis_id": hid, "decision": decision, "note": note})
    cont = request.POST.get("continue") == "on"
    if cont and not b.model_ok:
        return _render_tab(request, ctx, "hipotesis", ("error", "Que el agente siga necesita el modelo: configura la clave de API "
                                                                 "o registra las decisiones sin marcar «continuar»."))
    literal = _literals(request)
    try:
        for d in decisions:
            b.agent.preview(d["note"], literal)
    except AmbiguousText as exc:
        return _render_tab(request, ctx, "hipotesis", ("error", str(exc)))
    if cont:
        try:
            job = get_services().submit(b, "decide", lambda: _result(b.agent.resume(decisions, literal=literal, continue_agent=True)))
        except Busy as exc:
            return _msg(request, str(exc), status=409)
        return _job_response(request, ctx, job)
    if not b.lock.acquire(blocking=False):
        return _render_tab(request, ctx, "hipotesis", ("error", "Ya hay una operación con el modelo en curso en este caso."))
    try:
        result = b.agent.resume(decisions, literal=literal, continue_agent=False)
    except ValueError as exc:
        return _render_tab(request, ctx, "hipotesis", ("error", str(exc)))
    finally:
        b.lock.release()
    return _render_tab(request, ctx, "hipotesis", ("ok", result.answer))


@require_GET
def job_view(request, pid, cid, job_id):
    ctx = _ctx(pid, cid)
    try:
        job = get_services().job(job_id)
    except NotFound as exc:
        raise Http404(str(exc)) from exc
    return _job_response(request, ctx, job)


# --- acciones rápidas (sin modelo) ------------------------------------------------------------------------------------

@require_POST
def retire(request, pid, cid, hid):
    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    reason = (request.POST.get("reason") or "").strip()
    try:
        b.agent.retire(hid, reason, (request.POST.get("superseded_by") or "").strip() or None, _literals(request))
    except Exception as exc:  # noqa: BLE001 - HypothesisError, AmbiguousText...: se muestra tal cual al analista
        return _render_tab(request, ctx, "hipotesis", ("error", str(exc)))
    return _render_tab(request, ctx, "hipotesis", ("ok", f"Hipótesis {hid} retirada."))


@require_POST
def note(request, pid, cid):
    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    text = (request.POST.get("text") or "").strip()
    status = request.POST.get("status") or None
    try:
        res = b.agent.note(text, status=status, literal=_literals(request))
    except (AmbiguousText, ValueError) as exc:
        return _render_tab(request, ctx, "notas", ("error", str(exc)))
    sub = f" ({sum(s['count'] for s in res.substitutions)} valor(es) traducidos a alias)" if res.substitutions else ""
    return _render_tab(request, ctx, "notas", ("ok", f"Nota guardada{sub}. El agente la verá en cada pregunta."))


# --- informe ---------------------------------------------------------------------------------------------------------

@require_POST
def export(request, pid, cid):
    """El botón Exportar: genera el informe, lo guarda y lo registra en el ledger."""
    ctx = _ctx(pid, cid)
    _bundle(ctx)  # abre la copia y el ledger antes de generar
    p = request.POST
    try:
        out = export_report(ctx.ws, variant=p.get("variant", "compartible"), lang=p.get("lang", ctx.settings.language),
                            recommendations=p.get("recommendations", ""), run_replay=p.get("replay") == "on",
                            analyst=ctx.settings.analyst)
    except ReportError as exc:
        return _render_tab(request, ctx, "informe", ("error", str(exc)))
    r = out.report
    return render(request, "web/_export_result.html", {"base": ctx.base, "report": r, "file": out.path.name, "reveal": _reveal(request)})


@require_GET
def download(request, pid, cid, filename):
    ctx = _ctx(pid, cid)
    if not _FILENAME.match(filename):
        raise Http404("Archivo no válido")
    path = (reports_root() / ctx.ws.case_id / filename).resolve()
    if not path.is_file() or not path.is_relative_to(reports_root().resolve()):
        raise Http404("El informe no existe")
    return FileResponse(path.open("rb"), as_attachment=True, filename=f"{ctx.ws.case_id}.{filename}",
                        content_type="text/markdown; charset=utf-8")


def healthz(request):
    return HttpResponse("ok", content_type="text/plain")


# --- asistente "Nuevo análisis": datos -> archivos -> analizar ----------------------------------------------------------

COMMON_ZONES = ("America/Santiago", "America/Bogota", "America/Lima", "America/Guayaquil", "America/Panama", "America/Santo_Domingo",
                "America/Mexico_City", "America/Argentina/Buenos_Aires", "UTC")
_KIND_LABEL = {"log": "log", "excel": "Excel (por hojas)", "text": "texto (Palo Alto / Nginx)", "document": "documento",
               "other": "no admitido"}
_STATE_LABEL = {"running": "analizando…", "done": "listo", "needs_attention": "listo · revisar avisos", "failed": "falló",
                "unsupported": "no soportado", "pending": "en cola"}


@require_http_methods(["GET", "POST"])
def analysis_new(request):
    form = {"name": "", "ticket": "", "description": "", "analyst": "", "language": "es", "timezone": "", "use_llm": True,
            "max_tokens": 210000}
    if request.method == "POST":
        p = request.POST
        form = {"name": p.get("name", ""), "ticket": p.get("ticket", ""), "description": p.get("description", ""),
                "analyst": p.get("analyst", ""), "language": p.get("language", "es"), "timezone": p.get("timezone", ""),
                "use_llm": p.get("use_llm") == "on", "max_tokens": p.get("max_tokens") or 210000}
        try:
            cap = (request.POST.get("max_tokens_incident") or "").strip()
            settings = ProjectSettings(language=form["language"], timezone=form["timezone"].strip() or None,
                                       analyst=form["analyst"].strip() or None, use_llm=form["use_llm"], max_tokens=int(form["max_tokens"]),
                                       max_tokens_incident=int(cap) if cap else None)
            project = Project.create(form["name"], None, settings, ticket=form["ticket"], description=form["description"])
        except (ProjectError, ValueError) as exc:
            return render(request, "web/analysis_new.html", {"form": form, "error": str(exc), "zones": COMMON_ZONES}, status=400)
        return redirect(f"/proyectos/{project.id}/archivos/")
    return render(request, "web/analysis_new.html", {"form": form, "zones": COMMON_ZONES})


def _evidence_rows(project: Project) -> list[dict]:
    last = {}
    for e in project.custody():
        if e["action"] in ("added", "derived"):
            last[e["file"]] = e
    rows = []
    for f in project.files():
        e = last.get(f.name, {})
        if e.get("action") == "derived":
            origin = f"derivado de {e['derived_from']['file']}, hoja «{e.get('sheet')}» ({e.get('rows', 0):,} filas)"
        elif e.get("origin") == "upload":
            origin = f"subido desde tu equipo ({e.get('origin_name') or f.name})"
        elif e.get("origin") == "server":
            origin = f"del servidor: {e.get('origin_path')} ({'copiado' if e.get('mode') == 'copy' else 'enlazado'})"
        else:
            origin = "—"
        st = project.status(f.case_id) or {}
        state = st.get("state")
        rows.append({"file": f, "kind_label": _KIND_LABEL.get(f.kind, f.kind), "sha": e.get("sha256"), "origin": origin,
                     "by": e.get("analyst"), "at": e.get("at_utc"), "state": state, "state_label": _STATE_LABEL.get(state, "en cola")})
    return rows


def _evidence_list(request, project: Project, flash: tuple | None = None, status: int = 200):
    rows = _evidence_rows(project)
    running = any(get_services().runner.running(project.id, r["file"].case_id) for r in rows)
    return render(request, "web/_evidence_list.html", {"project": project, "rows": rows, "flash": flash, "running": running,
                                                         "n_logs": sum(1 for r in rows if r["file"].supported)}, status=status)


def _start_new(project: Project) -> None:
    """Análisis automático: cada log que entra y aún no tiene estado se pone a analizar (un archivo a la vez, en segundo plano)."""
    sv = get_services()
    for f in project.files():
        if f.supported and project.status(f.case_id) is None and not sv.runner.running(project.id, f.case_id):
            sv.runner.submit(project, f, sv.deps)


def _open_evidence_project(pid: str) -> Project:
    project = _open_project(pid)
    if project.mode != "evidence":
        raise Http404("Este análisis vincula una carpeta del servidor; no admite añadir archivos")
    return project


@require_GET
def evidence_page(request, pid):
    project = _open_project(pid)
    if project.mode != "evidence":
        return redirect(f"/proyectos/{project.id}/")
    rows = _evidence_rows(project)
    running = any(get_services().runner.running(project.id, r["file"].case_id) for r in rows)
    return render(request, "web/evidence.html", {"project": project, "rows": rows, "n_logs": sum(1 for r in rows if r["file"].supported),
                                                 "max_mb": django_settings.DFIR_MAX_UPLOAD_MB, "inbox": inbox_root(), "running": running})


@require_GET
def evidence_list(request, pid):
    return _evidence_list(request, _open_evidence_project(pid))


@require_POST
def evidence_upload(request, pid):
    project = _open_evidence_project(pid)
    files = request.FILES.getlist("files")
    if not files:
        return _evidence_list(request, project, ("error", "Elige al menos un archivo"), status=400)
    added, errors = [], []
    limit = django_settings.DFIR_MAX_UPLOAD_MB * (1 << 20)
    for f in files:
        try:
            recs = project.add_upload(f.name, f.chunks(), analyst=project.settings.analyst, max_bytes=limit)
            added += [r["file"] for r in recs if r["action"] in ("added", "derived")]
            errors += [f"{r['file']}: {r['error']}" for r in recs if r["action"] == "derivation_failed"]
        except ProjectError as exc:
            errors.append(f"{f.name}: {exc}")
    if added:
        _start_new(project)
    return _evidence_list(request, project, _flash(added, errors), status=200 if added or not errors else 400)


def _flash(added: list[str], errors: list[str]) -> tuple:
    parts = []
    if added:
        parts.append(f"Añadidos: {', '.join(added)}.")
    if errors:
        parts.append("No se pudo: " + "; ".join(errors))
    return ("error" if errors and not added else "ok" if not errors else "info", " ".join(parts))


@require_GET
def evidence_browse(request, pid):
    project = _open_evidence_project(pid)
    try:
        listing = browse(request.GET.get("ruta", ""), base=inbox_root())
    except ProjectError as exc:
        return _msg(request, str(exc), status=400)
    return render(request, "web/_server_browser.html", {"project": project, "b": listing})


@require_POST
def evidence_add(request, pid):
    project = _open_evidence_project(pid)
    paths = [p for p in request.POST.getlist("paths") if p.strip()]
    mode = request.POST.get("modo", "copy")
    if not paths:
        return _evidence_list(request, project, ("error", "Marca al menos un archivo"), status=400)
    added, errors = [], []
    for rel in paths:
        try:
            recs = project.add_from_server(inbox_root() / rel, mode=mode, analyst=project.settings.analyst, base=inbox_root())
            added += [r["file"] for r in recs if r["action"] in ("added", "derived")]
            errors += [f"{r['file']}: {r['error']}" for r in recs if r["action"] == "derivation_failed"]
        except ProjectError as exc:
            errors.append(f"{rel}: {exc}")
    if added:
        _start_new(project)
    return _evidence_list(request, project, _flash(added, errors), status=200 if added or not errors else 400)


@require_POST
def evidence_analyze(request, pid):
    project = _open_evidence_project(pid)
    sv = get_services()
    for f in project.files():
        if f.supported:
            sv.runner.submit(project, f, sv.deps)
    return redirect(f"/proyectos/{project.id}/")


# --- zona horaria del caso -----------------------------------------------------------------------------------------------

@require_POST
def timezone_confirm(request, pid, cid):
    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    p = request.POST
    try:
        data = confirm_timezone(b.ledger, b.real.manifest or {}, p.get("timezone", ""), p.get("basis", ""), p.get("analyst"), p.get("note"))
    except TimezoneError as exc:
        return _render_tab(request, ctx, "resumen", ("error", str(exc)))
    return _render_tab(request, ctx, "resumen", ("ok", f"Zona {data['timezone']} registrada como: {data['basis_text']}. "
                                                       "No cambia ningún dato; queda en el ledger y el informe lo dirá así."))


@require_POST
def reset_conversation(request, pid, cid):
    """Descarta la conversación con el agente (no toca hipótesis, notas ni el ledger) para poder volver a preguntar."""
    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    if _auto_running(ctx):
        return _render_tab(request, ctx, "preguntar", ("error", _RUNNING_MSG))
    b.agent.reset()
    return _render_tab(request, ctx, "preguntar", ("ok", "Conversación reiniciada. Las hipótesis, las notas y el ledger siguen intactos."))


@require_POST
def compute_profile(request, pid, cid):
    """Calcula el perfil de un caso que no lo tiene (p. ej. uno anterior a esta etapa). Local, sin modelo."""
    from dfir_copilot.data_profile import build_profile, save_profile
    from dfir_copilot.web.services import refresh_profile_digest

    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    path = ctx.ws.dir / "p1" / "perfil_datos.json"
    if not path.exists() or request.POST.get("force") == "1":  # force: recalcular un perfil de una versión anterior
        prof = build_profile(b.pseudo)
        sha = save_profile(prof, path)
        b.ledger.append("data_profile", {"file": "p1/perfil_datos.json", "sha256": sha, "rows": prof["rows"],
                                         "columns": len(prof["columns"]), "copy": b.pseudo.copy_id})
        refresh_profile_digest(b.agent, ctx.ws)
    return _render_tab(request, ctx, "datos", ("ok", "Perfil calculado sobre el dataset completo (local, sin modelo)."))


@require_POST
def data_question(request, pid, cid):
    """Preguntas rápidas sobre los datos, sin modelo. La pregunta pasa por el mismo guardián que las del agente (valores reales -> alias)
    y la respuesta se muestra en alias, o con valores reales si el interruptor está activo."""
    from dfir_copilot.data_questions import answer

    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    path = ctx.ws.dir / "p1" / "perfil_datos.json"
    if not path.exists():
        return _msg(request, "Calcula primero el perfil de datos.", status=409)
    from dfir_copilot.geoip import geo_db

    try:
        question = b.agent.preview((request.POST.get("question") or "").strip()).text
    except AmbiguousText as exc:
        return _msg(request, str(exc), status=422)
    try:
        context = json.loads(request.POST.get("context") or "null")
    except ValueError:
        context = None
    # los países necesitan la IP real: se geolocaliza en local y solo sale el agregado por país
    a = answer(question, json.loads(path.read_text(encoding="utf-8")), b.pseudo, real_engine=b.real, geo=geo_db(),
               context=context if isinstance(context, dict) else None)
    v = _shower(b, _reveal(request))
    a.text = v(a.text)
    a.rows = [[v(x) if isinstance(x, str) else x for x in row] for row in a.rows]
    return render(request, "web/_data_answer.html", {"a": a, "context": json.dumps(a.context or context or {})})


# --- vista del incidente: hallazgos de todas las fuentes y línea de tiempo, siempre con su procedencia ---------------------------

def _source_shower(src: dict, reveal: bool):
    if not reveal:
        return lambda x: x
    _, ps = src["ws"].pseudonymized()
    return ps.reveal_any


@require_GET
def incident_findings(request, pid):
    from dfir_copilot import incident

    project = _open_project(pid)
    reveal = _reveal(request)
    srcs = incident.sources(project)
    shows = {s["case_id"]: _source_shower(s, reveal) for s in srcs}
    rows = [{**f, "entity": shows[f["source"]["case_id"]](f["entity"]), "summary": shows[f["source"]["case_id"]](f["summary"])}
            for f in incident.findings(srcs)]
    return render(request, "web/_incident_findings.html", {"project": project, "rows": rows, "sources": srcs, "reveal": reveal})


@require_GET
def incident_timeline(request, pid):
    from dfir_copilot import incident

    project = _open_project(pid)
    reveal = _reveal(request)
    srcs = incident.sources(project)
    shows = {s["case_id"]: _source_shower(s, reveal) for s in srcs}
    events = incident.timeline(project, srcs)
    for e in events:
        cid = (e["source"] or {}).get("case_id")
        if cid in shows:
            e["text"] = shows[cid](e["text"])
    return render(request, "web/_incident_timeline.html", {"project": project, "events": events, "reveal": reveal})
