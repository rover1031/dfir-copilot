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


# --- PDF-b.2: chat con el documento ---------------------------------------------------------------------------------------------
from test_document_chat import FakeChat, call, say  # noqa: E402


@pytest.fixture
def install_model(monkeypatch):
    def install(script, cls=FakeChat):
        llm = cls(script)
        monkeypatch.setattr(V, "_model", lambda: (llm, "ok"))
        monkeypatch.setattr(V, "_model_available", lambda: True)
        return llm
    return install


def _ready(project, tmp_path):
    return _add(project, "boletin.pdf", _text_pdf(tmp_path).read_bytes())


def _allow(project, src, value="1"):
    return Client().post(_url(project, src, "modelo/"), {"permitir": value})


GOOD = [call("buscar_en_documento", {"consulta": "backup services encryption"}),
        say("Deshabilitaron los backups: «Attackers disabled backup services before encryption» (p.1).")]


def test_por_defecto_nada_sale_hacia_el_modelo(project, tmp_path, install_model):
    src = _ready(project, tmp_path)
    llm = install_model(list(GOOD))
    html = Client().get(_url(project, src)).content.decode()
    assert "Permitir enviar pasajes al modelo para este documento" in html and 'name="question"' not in html
    r = Client().post(_url(project, src, "preguntar/"), {"question": "¿backups?"})
    assert r.status_code == 409 and "no tiene permitido" in r.content.decode()
    assert llm.seen == [] and C_read(project, src) == []


def C_read(project, src):
    from dfir_copilot.documents import chat as C

    return C.read_turns(V.doc_dir(project, src))


def test_permitir_preguntar_ver_lo_enviado_y_conservar_la_conversacion(project, tmp_path, install_model):
    src = _ready(project, tmp_path)
    llm = install_model(GOOD + [say("Segunda respuesta.")])
    assert 'name="question"' in _allow(project, src).content.decode()
    r = Client().post(_url(project, src, "preguntar/"), {"question": "¿Qué hicieron con los backups?"})
    html = r.content.decode()
    assert r.status_code == 200 and "Deshabilitaron los backups" in html and "✔ 1 cita(s) verificada(s)" in html
    assert "Salió hacia el modelo: buscar_en_documento (p.1)" in html and "⚠" not in html
    turns = C_read(project, src)
    assert len(turns) == 1 and turns[0]["verified"] == 1 and turns[0]["sent"][0]["pages"] == [1]
    Client().post(_url(project, src, "preguntar/"), {"question": "¿y qué más?"})
    assert any("¿Qué hicieron con los backups?" in getattr(m, "content", "") for m in llm.seen[-1])    # el historial se reenvía
    assert "Segunda respuesta" in Client().get(_url(project, src)).content.decode()


def test_una_cita_inventada_se_ve_marcada_y_con_aviso(project, tmp_path, install_model):
    src = _ready(project, tmp_path)
    install_model([call("ver_pagina", {"pagina": 1}), say("Usaron vssadmin «they deleted every shadow copy with vssadmin» (p.1).")])
    _allow(project, src)
    html = Client().post(_url(project, src, "preguntar/"), {"question": "¿shadow copies?"}).content.decode()
    assert "⚠ cita no verificada" in html and "NO existe en la página indicada" in html and "1 cita(s) NO verificada(s)" in html


def test_sin_modelo_configurado_lo_dice(project, tmp_path, monkeypatch):
    src = _ready(project, tmp_path)
    monkeypatch.setattr(V, "_model", lambda: (None, "No hay un modelo configurado: define la clave de API en el .env y reinicia la interfaz."))
    monkeypatch.setattr(V, "_model_available", lambda: False)
    _allow(project, src)
    r = Client().post(_url(project, src, "preguntar/"), {"question": "hola"})
    assert r.status_code == 409 and "No hay un modelo configurado" in r.content.decode() and C_read(project, src) == []


def test_un_error_del_modelo_no_tumba_nada_y_no_deja_la_pregunta_bloqueada(project, tmp_path, install_model):
    src = _ready(project, tmp_path)

    class Boom(FakeChat):
        def invoke(self, messages, *a, **k):
            raise RuntimeError("sin red")

    install_model([], cls=Boom)
    _allow(project, src)
    r = Client().post(_url(project, src, "preguntar/"), {"question": "hola"})
    assert r.status_code == 502 and "No se pudo responder: RuntimeError: sin red" in r.content.decode() and C_read(project, src) == []
    install_model(list(GOOD))
    assert Client().post(_url(project, src, "preguntar/"), {"question": "otra vez"}).status_code == 200    # el candado se liberó


def test_validaciones_de_la_pregunta_y_revocar_el_permiso(project, tmp_path, install_model):
    src = _ready(project, tmp_path)
    llm = install_model(list(GOOD))
    _allow(project, src)
    assert Client().post(_url(project, src, "preguntar/"), {"question": "  "}).status_code == 400
    assert Client().post(_url(project, src, "preguntar/"), {"question": "x" * (V.MAX_QUESTION_CHARS + 1)}).status_code == 400
    D.write_state(V.doc_dir(project, src), "running")
    assert Client().post(_url(project, src, "preguntar/"), {"question": "hola"}).status_code == 400
    D.write_state(V.doc_dir(project, src), "done")
    _allow(project, src, "0")
    assert Client().post(_url(project, src, "preguntar/"), {"question": "hola"}).status_code == 409
    assert llm.seen == [] and "Ya no se envía nada" in _allow(project, src, "0").content.decode()


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
