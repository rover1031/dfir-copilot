"""Vistas de la papelera: eliminar análisis y casos sueltos de forma recuperable, restaurarlos y eliminarlos definitivamente.

Toda la lógica está en `dfir_copilot.trash`; aquí solo se comprueba la confirmación escrita, que no haya nada analizándose y se suelta la
caché de agentes del análisis antes de moverlo."""
from __future__ import annotations

from pathlib import Path

from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import path
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from dfir_copilot import trash as T
from dfir_copilot.projects import data_root, projects_root
from dfir_copilot.web.services import get_services
from dfir_copilot.web.views import _open_project

TRASH_DIR = "papelera"


def roots() -> T.Roots:
    from dfir_copilot.reporting.report import reports_root

    return T.Roots(trash=data_root() / TRASH_DIR, projects=projects_root(), cases=Path(get_services().cases_root), reports=reports_root())


def _busy(project) -> bool:
    sv = get_services()
    if any(sv.runner.running(project.id, f.case_id) for f in project.files()):
        return True
    prefix = str(project.dir)
    return any(k.startswith(prefix) and b.lock.locked() for k, b in list(getattr(sv, "_bundles", {}).items()))


def _forget(path_: Path) -> None:
    forget = getattr(get_services(), "forget", None)
    if forget:
        forget(path_)


def _analyst(project) -> str:
    try:
        return project.settings.analyst or ""
    except Exception:  # noqa: BLE001
        return ""


def _project_summary(project) -> dict:
    try:
        custody = project.verify_custody()
    except Exception:  # noqa: BLE001
        custody = None
    return {"kind": "análisis", "id": project.id, "name": project.name, "mode": project.mode, "files": len(project.files()),
            "bytes": T._size(Path(project.dir)), "custody": custody,
            "source_dir": str(project.source_dir) if project.mode == "folder" else None, "analyst": _analyst(project),
            "action": f"/proyectos/{project.id}/eliminar/"}


@require_http_methods(["GET", "POST"])
def project_delete(request, pid):
    project = _open_project(pid)
    ctx = _project_summary(project)
    if request.method == "POST":
        if (request.POST.get("confirmacion") or "").strip() != project.id:
            return render(request, "web/delete_confirm.html", {**ctx, "error": f"Escribe exactamente «{project.id}» para confirmar."}, status=400)
        by = (request.POST.get("analista") or "").strip() or ctx["analyst"] or None
        try:
            busy = _busy(project)
            if not busy:
                _forget(Path(project.dir))
            T.trash_project(project, roots(), by=by, running=busy)
        except T.TrashError as exc:
            return render(request, "web/delete_confirm.html", {**ctx, "error": str(exc)}, status=409)
        return redirect("/papelera/")
    return render(request, "web/delete_confirm.html", ctx)


@require_http_methods(["GET", "POST"])
def case_delete(request, cid):
    r = roots()
    try:
        T._check_id(cid, "caso")
    except T.TrashError as exc:
        raise Http404(str(exc)) from exc
    case_dir = r.cases / cid
    if not case_dir.is_dir():
        raise Http404(f"No existe el caso '{cid}'")
    ctx = {"kind": "caso", "id": cid, "name": cid, "mode": "caso", "files": sum(1 for p in case_dir.rglob("*") if p.is_file()),
           "bytes": T._size(case_dir), "custody": None, "source_dir": None, "analyst": "", "action": f"/casos/{cid}/eliminar/"}
    if request.method == "POST":
        if (request.POST.get("confirmacion") or "").strip() != cid:
            return render(request, "web/delete_confirm.html", {**ctx, "error": f"Escribe exactamente «{cid}» para confirmar."}, status=400)
        try:
            _forget(case_dir)
            T.trash_case(cid, r, by=(request.POST.get("analista") or "").strip() or None)
        except T.TrashError as exc:
            return render(request, "web/delete_confirm.html", {**ctx, "error": str(exc)}, status=409)
        return redirect("/papelera/")
    return render(request, "web/delete_confirm.html", ctx)


def _trash_page(request, flash: tuple | None = None, status: int = 200):
    r = roots()
    listing = T.items(r)
    return render(request, "web/trash.html", {"items": listing, "total": sum(i.get("bytes", 0) for i in listing), "flash": flash,
                                              "registry": T.verify_registry(r), "vaciar": T.VACIAR}, status=status)


@require_GET
def trash_page(request):
    return _trash_page(request)


@require_POST
def trash_restore(request, item):
    try:
        card = T.restore(item, roots(), by=(request.POST.get("analista") or "").strip() or None)
    except T.TrashError as exc:
        return _trash_page(request, ("error", str(exc)), 409)
    return _trash_page(request, ("ok", f"Restaurado «{card['name']}»."))


@require_POST
def trash_purge(request, item):
    try:
        card = T.purge(item, roots(), by=(request.POST.get("analista") or "").strip() or None,
                       confirmation=request.POST.get("confirmacion") or "")
    except T.TrashError as exc:
        return _trash_page(request, ("error", str(exc)), 409)
    return _trash_page(request, ("ok", f"Eliminado definitivamente «{card['id']}». Queda constancia en el registro de eliminaciones."))


@require_POST
def trash_empty(request):
    try:
        n = T.purge_all(roots(), by=(request.POST.get("analista") or "").strip() or None, confirmation=request.POST.get("confirmacion") or "")
    except T.TrashError as exc:
        return _trash_page(request, ("error", str(exc)), 409)
    return _trash_page(request, ("ok", f"Papelera vaciada: {n} elemento(s) eliminados definitivamente."))


urlpatterns = [
    path("proyectos/<str:pid>/eliminar/", project_delete, name="project_delete"),
    path("casos/<str:cid>/eliminar/", case_delete, name="case_delete"),
    path("papelera/", trash_page, name="trash"),
    path("papelera/vaciar/", trash_empty, name="trash_empty"),
    path("papelera/<str:item>/restaurar/", trash_restore, name="trash_restore"),
    path("papelera/<str:item>/eliminar/", trash_purge, name="trash_purge"),
]
