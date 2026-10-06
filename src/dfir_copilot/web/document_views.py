"""Vistas del análisis de documentos (PDF). Todo el trabajo lo hace `dfir_copilot.documents.service`; esto solo lo lanza y lo muestra.

* Al entrar un PDF al análisis se lanza solo, en la misma cola que los logs (`runner.submit_task`): un archivo a la vez.
* Los resultados viven junto al documento: `<proyecto>/documents/<caso>/` (no en `status/`, que recorren otras piezas del análisis).
* El documento es local: los CSV de IOCs se pueden descargar; el texto de las páginas y el estado interno, no.
* Verificar un hash leído por OCR contra una fuente de texto es rápido (no repite el OCR) y se hace en la misma petición."""
from __future__ import annotations

from django.http import FileResponse, Http404
from django.shortcuts import render
from django.urls import path
from django.views.decorators.http import require_GET, require_POST

from dfir_copilot.documents import iocs as I
from dfir_copilot.documents import service as D
from dfir_copilot.projects import ProjectError
from dfir_copilot.web.services import get_services
from dfir_copilot.web.views import _STATE_LABEL, _open_project

DOCS_DIR = "documents"
ROW_LIMIT = 200                       # filas máximas por tabla en pantalla; el CSV completo se descarga
MAX_REFERENCE_CHARS = 2_000_000
DOWNLOADS = {"iocs.csv": "text/csv", "candidatos_ocr.csv": "text/csv", "dudosos.csv": "text/csv",
             "resumen.json": "application/json", "manifest.json": "application/json"}
KIND_LABEL = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5", "ip": "IP", "url": "URL", "domain": "Dominio", "onion": ".onion",
              "email": "Correo", "cve": "CVE"}


def _geo():
    """Base GeoIP local si existe; sin ella no se calculan países (y el resumen lo dice)."""
    try:
        from dfir_copilot.geoip import geo_db

        return geo_db()
    except Exception:  # noqa: BLE001
        return None


def doc_dir(project, source):
    return project.dir / DOCS_DIR / source.case_id


def document_state(project, source) -> dict:
    """Estado del análisis de un documento, con la forma que `_evidence_rows` espera (`{"state": ...}`); `{}` si aún no se lanzó."""
    return D.read_state(doc_dir(project, source))


def _job(project, source) -> None:
    D.run_job(source.path, doc_dir(project, source), geo=_geo())


def start_documents(project) -> None:
    """Lanza el análisis de cada documento que aún no tiene estado. Lo llama `_start_new` al entrar archivos."""
    runner = get_services().runner
    for f in project.files():
        if f.kind != "document" or document_state(project, f) or runner.running(project.id, f.case_id):
            continue
        D.write_state(doc_dir(project, f), "running")             # marca inmediata: la interfaz ya lo ve "analizando…"
        runner.submit_task(project.id, f.case_id, lambda p=project, s=f: _job(p, s))


def _doc(pid: str, cid: str):
    project = _open_project(pid)
    try:
        source = project.file(cid)
    except ProjectError as exc:
        raise Http404(str(exc)) from exc
    if source.kind != "document":
        raise Http404("Este archivo no es un documento")
    return project, source


def _context(project, source, flash: tuple | None = None) -> dict:
    d = doc_dir(project, source)
    st = document_state(project, source)
    state = st.get("state")
    ctx = {"project": project, "source": source, "state": state or "pending", "state_label": _STATE_LABEL.get(state, "en cola"),
           "error": st.get("error"), "running": state == "running", "flash": flash, "ready": False,
           "base": f"/proyectos/{project.id}/documentos/{source.case_id}/"}
    if state in ("done", "needs_attention") and (d / "manifest.json").is_file():
        try:
            data = D.load(d)
        except D.DocumentError as exc:
            ctx["error"] = str(exc)
            return ctx
        ex, summary, manifest = data["extraction"], data["summary"], data["manifest"]
        blocklist = I.priority_rows(ex)
        stats = summary["estadisticas"]
        ctx.update(ready=True, manifest=manifest, summary=summary, stats=stats,
                   by_kind=[(KIND_LABEL.get(k, k), n) for k, n in stats["unicos_por_tipo"].items()],
                   blocklist=blocklist[:ROW_LIMIT], n_blocklist=len(blocklist), candidates=I.candidate_rows(ex)[:ROW_LIMIT],
                   doubtful=ex.doubtful[:ROW_LIMIT], n_doubtful=len(ex.doubtful), countries=summary["paises"],
                   reference=manifest.get("reference"), verification=summary.get("verificacion"))
    return ctx


def _render(request, project, source, flash: tuple | None = None, status: int = 200):
    template = "web/_document_body.html" if request.headers.get("HX-Request") else "web/document.html"
    return render(request, template, _context(project, source, flash), status=status)


@require_GET
def document_page(request, pid, cid):
    project, source = _doc(pid, cid)
    return _render(request, project, source)


@require_POST
def document_verify(request, pid, cid):
    project, source = _doc(pid, cid)
    d = doc_dir(project, source)
    text = (request.POST.get("referencia") or "").strip()
    if not text:
        return _render(request, project, source, ("error", "Pega el texto de referencia (p. ej. la tabla de IOCs de la página web del boletín)."), 400)
    if len(text) > MAX_REFERENCE_CHARS:
        return _render(request, project, source, ("error", "El texto de referencia es demasiado grande."), 400)
    if document_state(project, source).get("state") not in ("done", "needs_attention"):
        return _render(request, project, source, ("error", "El análisis del documento aún no terminó."), 400)
    try:
        report = D.verify_document(d, text, _geo())
    except D.DocumentError as exc:
        return _render(request, project, source, ("error", str(exc)), 400)
    msg = (f"Verificados {report['verificados']}; corregidos {len(report['corregidos'])} (el OCR difería de la fuente en pocos caracteres); "
           f"sin confirmar {report['sin_confirmar']}. {len(report['en_la_fuente_y_no_en_el_documento'])} hash(es) de la fuente no están "
           "en el documento.")
    return _render(request, project, source, ("ok", msg))


@require_POST
def document_reanalyze(request, pid, cid):
    project, source = _doc(pid, cid)
    runner = get_services().runner
    if runner.running(project.id, source.case_id):
        return _render(request, project, source, ("info", "El análisis de este documento ya está en curso."))
    D.write_state(doc_dir(project, source), "running")
    runner.submit_task(project.id, source.case_id, lambda: _job(project, source))
    return _render(request, project, source)


@require_GET
def document_download(request, pid, cid, filename):
    project, source = _doc(pid, cid)
    if filename not in DOWNLOADS:
        raise Http404("Archivo no disponible para descarga")
    path_ = doc_dir(project, source) / filename
    if not path_.is_file():
        raise Http404("Ese resultado aún no existe")
    stem = source.name.rsplit(".", 1)[0]
    return FileResponse(path_.open("rb"), as_attachment=True, filename=f"{stem}.{filename}", content_type=DOWNLOADS[filename])


urlpatterns = [
    path("proyectos/<str:pid>/documentos/<str:cid>/", document_page, name="document"),
    path("proyectos/<str:pid>/documentos/<str:cid>/verificar/", document_verify, name="document_verify"),
    path("proyectos/<str:pid>/documentos/<str:cid>/reanalizar/", document_reanalyze, name="document_reanalyze"),
    path("proyectos/<str:pid>/documentos/<str:cid>/descargar/<str:filename>/", document_download, name="document_download"),
]
