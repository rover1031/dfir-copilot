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
from dfir_copilot.projects import Project, ProjectError, ProjectSettings, browse, data_root
from dfir_copilot.reporting import ReportError, export_report, reports_root
from dfir_copilot.timezone_status import BASES, TimezoneError, confirm_timezone, timezone_state
from dfir_copilot.web.services import Busy, NotFound, get_services

TABS = ("resumen", "hipotesis", "preguntar", "notas", "informe", "integridad")
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


def _project_rows(project: Project) -> tuple[list[dict], bool]:
    sv = get_services()
    rows, running = [], False
    for f in project.files():
        st = project.status(f.case_id)
        is_running = sv.runner.running(project.id, f.case_id)
        running = running or is_running
        # estado "running" en disco sin hilo vivo: el servidor se reinició a mitad de un análisis
        interrupted = bool(st and st.get("state") == "running" and not is_running)
        rows.append({"file": f, "status": st, "running": is_running, "interrupted": interrupted,
                     "has_case": _ingested(project, f.case_id),
                     "steps": list((st or {}).get("steps", {}).items())})
    return rows, running


@require_GET
def project_page(request, pid):
    project = _open_project(pid)
    rows, running = _project_rows(project)
    ok, msg = get_services().model_status()
    return render(request, "web/project.html", {"project": project, "rows": rows, "running": running, "settings": project.settings,
                                                 "llm_ok": ok, "llm_msg": msg})


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


def _tab_preguntar(ctx, b, reveal):
    v = _shower(b, reveal)
    turns = [{"ts": e["ts_utc"], "question": v(e["data"].get("question") or ""), "answer": v(e["data"].get("answer") or ""),
              "tokens": e["data"].get("tokens_delta", e["data"].get("tokens")), "cut_by": e["data"].get("cut_by"),
              "status": e["data"]["status"]} for e in b.ledger.entries("agent_turn")][-12:]
    return {"turns": turns, "budget": b.agent.budget(), "model_ok": b.model_ok, "pending": len(b.agent.pending())}


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


_TAB_BUILDERS = {"resumen": _tab_resumen, "hipotesis": _tab_hipotesis, "preguntar": _tab_preguntar, "notas": _tab_notas,
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


@require_POST
def ask(request, pid, cid):
    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    question = (request.POST.get("question") or "").strip()
    if not question:
        return _msg(request, "Escribe una pregunta.", status=400)
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
    ctx = _ctx(pid, cid)
    b = _bundle(ctx)
    decision, note = request.POST.get("decision"), (request.POST.get("note") or "").strip()
    if decision not in ("approve", "reject"):
        return _msg(request, "Decisión no válida.", status=400)
    if not b.model_ok:
        return _msg(request, "Aprobar o rechazar reanuda al agente, que necesita el modelo: configura la clave de API.", status=409)
    if not b.agent.pending():
        return _msg(request, "No hay ninguna aprobación pendiente.", status=409)
    literal = _literals(request)
    try:
        b.agent.preview(note, literal)
    except AmbiguousText as exc:
        return _msg(request, str(exc), status=422)
    try:
        job = get_services().submit(b, "decide", lambda: _result(b.agent.resolve(decision, note, literal=literal)))
    except Busy as exc:
        return _msg(request, str(exc), status=409)
    return _job_response(request, ctx, job)


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
_KIND_LABEL = {"log": "log", "excel": "Excel (por hojas)", "document": "documento", "other": "no admitido"}


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
            settings = ProjectSettings(language=form["language"], timezone=form["timezone"].strip() or None,
                                       analyst=form["analyst"].strip() or None, use_llm=form["use_llm"], max_tokens=int(form["max_tokens"]))
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
        rows.append({"file": f, "kind_label": _KIND_LABEL.get(f.kind, f.kind), "sha": e.get("sha256"), "origin": origin,
                     "by": e.get("analyst"), "at": e.get("at_utc")})
    return rows


def _evidence_list(request, project: Project, flash: tuple | None = None, status: int = 200):
    rows = _evidence_rows(project)
    return render(request, "web/_evidence_list.html", {"project": project, "rows": rows, "flash": flash,
                                                         "n_logs": sum(1 for r in rows if r["file"].supported)}, status=status)


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
    return render(request, "web/evidence.html", {"project": project, "rows": rows, "n_logs": sum(1 for r in rows if r["file"].supported),
                                                 "max_mb": django_settings.DFIR_MAX_UPLOAD_MB, "data_root": data_root()})


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
        listing = browse(request.GET.get("ruta", ""))
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
            recs = project.add_from_server(data_root() / rel, mode=mode, analyst=project.settings.analyst)
            added += [r["file"] for r in recs if r["action"] in ("added", "derived")]
            errors += [f"{r['file']}: {r['error']}" for r in recs if r["action"] == "derivation_failed"]
        except ProjectError as exc:
            errors.append(f"{rel}: {exc}")
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
