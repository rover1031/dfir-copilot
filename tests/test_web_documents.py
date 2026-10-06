"""PDF-a.4: la pantalla de análisis de documentos. Lo esencial: un PDF que entra se analiza solo y su pantalla muestra IOCs, avisos y
descargas; los hashes de OCR sin verificar se ven aparte y se verifican pegando una fuente (sin repetir el OCR); un PDF dañado queda como
fallido y se puede reintentar; solo se descargan los resultados permitidos; y un archivo que no es documento no tiene pantalla."""
import os
import shutil

import pytest

pytest.importorskip("django", reason="la interfaz web es opcional: pip install -e '.[web]'")
pymupdf = pytest.importorskip("pymupdf")

os.environ.setdefault("DFIR_WEB_SECRET", "secreto-de-pruebas")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dfir_copilot.web.settings")

import django  # noqa: E402

django.setup()
from django.test import Client  # noqa: E402
from test_document_service import _text_pdf  # noqa: E402
from test_pdf_reader import MD5, SHA1, _table_pdf  # noqa: E402

from dfir_copilot.documents import service as D  # noqa: E402
from dfir_copilot.projects import Project, ProjectSettings  # noqa: E402
from dfir_copilot.web import document_views as V  # noqa: E402
from dfir_copilot.web.services import reset_services  # noqa: E402

needs_tesseract = pytest.mark.skipif(shutil.which("tesseract") is None, reason="falta el binario tesseract")


@pytest.fixture
def project(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("DFIR_DATA_ROOT", str(data))
    monkeypatch.setenv("DFIR_PROJECTS_ROOT", str(data / "projects"))
    monkeypatch.setenv("DFIR_REPORTS_ROOT", str(tmp_path / "reports"))
    reset_services(sync=True)
    return Project.create("Boletin uno", None, ProjectSettings(language="es"))


def _add(project, name, data, analyze=True):
    project.add_upload(name, [data], analyst="eder")
    if analyze:
        V.start_documents(project)
    return next(f for f in project.files() if f.name == name)


def _url(project, source, tail=""):
    return f"/proyectos/{project.id}/documentos/{source.case_id}/{tail}"


def test_un_pdf_que_entra_se_analiza_solo_y_la_pantalla_lo_muestra(project, tmp_path):
    src = _add(project, "boletin.pdf", _text_pdf(tmp_path).read_bytes())
    assert D.read_state(V.doc_dir(project, src))["state"] == "done" and V.document_state(project, src)["state"] == "done"
    page = Client().get(_url(project, src))
    html = page.content.decode()
    assert page.status_code == 200 and "evil.example.ru" in html and "listo" in html and "Descargar iocs.csv" in html
    blocklist = html.split("IOCs para controles")[1].split("</table>")[0]                          # solo la tarjeta de la lista de bloqueo
    assert "8.8.8.8" in blocklist and "10.0.0.5" not in blocklist and "https://x.com/" not in blocklist
    assert "Hashes leídos por OCR, sin verificar" not in html                                       # nada sin verificar
    assert "Sin base GeoIP" in html or "País de las IP públicas" in html


def test_el_fragmento_htmx_no_trae_la_pagina_completa(project, tmp_path):
    src = _add(project, "boletin.pdf", _text_pdf(tmp_path).read_bytes())
    html = Client().get(_url(project, src), HTTP_HX_REQUEST="true").content.decode()
    assert '<div id="doc"' in html and "<html" not in html


def test_lanzar_dos_veces_no_repite_el_analisis(project, tmp_path, monkeypatch):
    _add(project, "boletin.pdf", _text_pdf(tmp_path).read_bytes())
    calls = []
    monkeypatch.setattr(V, "_job", lambda p, s: calls.append(s.name))
    V.start_documents(project)
    assert calls == []


def test_documento_sin_analizar_ofrece_analizarlo(project, tmp_path):
    src = _add(project, "boletin.pdf", _text_pdf(tmp_path).read_bytes(), analyze=False)
    html = Client().get(_url(project, src)).content.decode()
    assert "aún no se ha analizado" in html and "Analizar ahora" in html
    assert Client().post(_url(project, src, "reanalizar/")).status_code == 200
    assert "evil.example.ru" in Client().get(_url(project, src)).content.decode()


def test_pdf_danado_queda_fallido_y_se_puede_reintentar(project):
    src = _add(project, "roto.pdf", b"esto no es un pdf")
    assert V.document_state(project, src)["state"] == "failed"
    html = Client().get(_url(project, src)).content.decode()
    assert "Reintentar el análisis" in html and "falló" in html


def test_descargas_solo_las_permitidas(project, tmp_path):
    src = _add(project, "boletin.pdf", _text_pdf(tmp_path).read_bytes())
    ok = Client().get(_url(project, src, "descargar/iocs.csv/"))
    assert ok.status_code == 200 and "attachment" in ok["Content-Disposition"] and b"evil.example.ru" in b"".join(ok.streaming_content)
    for name in ("pages.jsonl", "extraction.json", "estado.json", "..%2F..%2Fmanifest.json", "noexiste.csv"):
        assert Client().get(_url(project, src, f"descargar/{name}/")).status_code == 404, name


def test_lo_que_no_es_documento_o_no_existe_da_404(project, tmp_path):
    csv_src = _add(project, "datos.csv", b"a,b\n1,2\n", analyze=False)
    assert Client().get(_url(project, csv_src)).status_code == 404
    assert Client().get(f"/proyectos/{project.id}/documentos/no-existe/").status_code == 404
    assert Client().get("/proyectos/no-existe/documentos/x/").status_code == 404
    assert Client().post(_url(project, csv_src, "verificar/"), {"referencia": "x"}).status_code == 404


def test_verificar_exige_texto_y_analisis_terminado(project, tmp_path):
    src = _add(project, "boletin.pdf", _text_pdf(tmp_path).read_bytes())
    r = Client().post(_url(project, src, "verificar/"), {"referencia": "   "})
    assert r.status_code == 400 and "Pega el texto de referencia" in r.content.decode()
    D.write_state(V.doc_dir(project, src), "running")
    r = Client().post(_url(project, src, "verificar/"), {"referencia": "algo"})
    assert r.status_code == 400 and "aún no terminó" in r.content.decode()


@needs_tesseract
def test_hashes_de_ocr_se_ven_aparte_y_se_verifican_pegando_la_fuente(project, tmp_path):
    src = _add(project, "boletin_raster.pdf", _table_pdf(tmp_path, [("MD5", MD5, (28, 4)), ("SHA-1", SHA1, (28, 12))]).read_bytes())
    assert V.document_state(project, src)["state"] == "needs_attention"
    html = Client().get(_url(project, src)).content.decode()
    assert "Hashes leídos por OCR, sin verificar (2)" in html and MD5 in html and "Verificar contra una fuente de texto" in html
    assert "revisar avisos" in html
    r = Client().post(_url(project, src, "verificar/"), {"referencia": f"fuente\n{MD5}\n{SHA1}\n"})
    html = r.content.decode()
    assert r.status_code == 200 and "Verificados 2" in html and "Hashes leídos por OCR, sin verificar" not in html
    assert "Fuente de referencia aplicada" in html and "IOCs para controles (2)" in html
    assert V.document_state(project, src)["state"] == "done"


# --- integración con las vistas reales de evidencia (solo existen en el proyecto, no en el arnés) --------------------------------------
W = pytest.importorskip("dfir_copilot.web.views")


@pytest.mark.skipif(not hasattr(W, "evidence_upload"), reason="requiere las vistas reales de evidencia")
def test_subir_un_pdf_desde_la_interfaz_lo_analiza_y_la_lista_enlaza_su_pantalla(project, tmp_path):
    from django.core.files.uploadedfile import SimpleUploadedFile

    pdf = SimpleUploadedFile("boletin.pdf", _text_pdf(tmp_path).read_bytes(), content_type="application/pdf")
    r = Client().post(f"/proyectos/{project.id}/archivos/subir/", {"files": pdf})
    html = r.content.decode()
    assert r.status_code == 200 and "ver análisis" in html and "listo" in html
    src = next(f for f in project.files() if f.name == "boletin.pdf")
    assert (V.doc_dir(project, src) / "manifest.json").is_file()
    assert "ver análisis" in Client().get(f"/proyectos/{project.id}/archivos/lista/").content.decode()
