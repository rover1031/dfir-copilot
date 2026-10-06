"""Interfaz web (Django + HTMX). Lo esencial: crear un proyecto arranca el análisis solo; lo que escribe el analista se traduce a alias; los valores
reales solo salen con el interruptor; el informe se exporta y se descarga; una ruta fuera de la raíz de datos o una petición sin CSRF se rechazan."""
import os

import pytest

pytest.importorskip("django", reason="la interfaz web es opcional: pip install -e '.[web]'")  # sin Django, este archivo se salta

os.environ["DFIR_WEB_SECRET"] = "secreto-de-pruebas"
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dfir_copilot.web.settings")

import django  # noqa: E402

django.setup()
from conftest import ScriptedChat  # noqa: E402
from django.test import Client  # noqa: E402
from test_agent import FULL, HID, call, say  # noqa: E402
from test_privacy_agent import _case  # noqa: E402

from dfir_copilot.pipeline import Deps  # noqa: E402
from dfir_copilot.projects import Project  # noqa: E402
from dfir_copilot.synthetic import make_idor_dataset, write_csv  # noqa: E402
from dfir_copilot.web.services import reset_services  # noqa: E402

USAGE = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}


def after_approval():
    """Guion del agente tras una aprobación o una pregunta: responde y termina."""
    from langchain_core.messages import AIMessage

    return [AIMessage(content=f"Respuesta {i}", usage_metadata=USAGE) for i in range(6)]


def make_env(tmp_path, monkeypatch, first_script=None, model=True):
    """Entorno aislado: raíz de datos, de proyectos y de informes en `tmp_path`, y un modelo simulado.

    La primera llamada a `agent_llm` (el triaje del análisis automático) usa `first_script`; las siguientes (la interfaz) responden
    sin herramientas, porque el hilo ya está en marcha."""
    data = tmp_path / "data"
    inbox = data / "inbox" / "analisis1"
    inbox.mkdir(parents=True)
    rows, _ = make_idor_dataset()
    write_csv(inbox / "three_months.csv", rows)
    (inbox / "notas.txt").write_text("no es un log", encoding="utf-8")
    monkeypatch.setenv("DFIR_DATA_ROOT", str(data))
    monkeypatch.setenv("DFIR_PROJECTS_ROOT", str(data / "projects"))
    monkeypatch.setenv("DFIR_REPORTS_ROOT", str(tmp_path / "reports"))
    calls = []

    def factory():
        calls.append(1)
        return ScriptedChat(script=(first_script() if first_script and len(calls) == 1 else after_approval()))

    deps = Deps(agent_llm=factory if model else None, structured_llm=None)
    sv = reset_services(sync=True, deps=deps, cases_root=tmp_path / "cases")
    return sv, inbox


def create_project(client, inbox, **extra):
    data = {"name": "Análisis 1", "source_dir": str(inbox), "language": "es", "timezone": "America/Santiago", "analyst": "eder",
            "use_llm": "on", "max_tokens": "210000", **extra}
    return client.post("/proyectos/nuevo/", data, follow=True)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    sv, inbox = make_env(tmp_path, monkeypatch, first_script=FULL)          # el triaje deja una hipótesis pendiente de aprobación
    client = Client()
    resp = create_project(client, inbox)
    assert resp.status_code == 200
    return client, sv, inbox


@pytest.fixture()
def quiet(tmp_path, monkeypatch):
    """El triaje termina sin pendientes: se puede preguntar."""
    sv, inbox = make_env(tmp_path, monkeypatch, first_script=lambda: [call("describe_dataset"), say("Triaje: sin novedades.")])
    client = Client()
    create_project(client, inbox)
    return client, sv, inbox


CASE = "/proyectos/analisis-1/casos/analisis-1--three-months/"


# --- inicio y proyectos -------------------------------------------------------------------------------------------

def test_el_inicio_muestra_el_formulario_de_nuevo_proyecto(tmp_path, monkeypatch):
    make_env(tmp_path, monkeypatch)
    r = Client().get("/")
    assert r.status_code == 200 and "Nuevo proyecto" in r.content.decode() and "Carpeta con los archivos" in r.content.decode()


def test_crear_un_proyecto_lanza_el_analisis_y_muestra_el_avance(env):
    client, sv, _ = env
    page = client.get("/proyectos/analisis-1/").content.decode()
    assert "three_months.csv" in page and "formato no soportado" in page and "Abrir caso" in page
    assert page.count("Abrir caso") == 1                                  # solo el archivo ingerido: notas.txt no tiene nada que abrir
    for step in ("draft", "ingest", "copy", "detectors", "triage"):
        assert f">{step}<" in page
    st = Project.open("analisis-1").status("analisis-1--three-months")
    assert st["state"] == "needs_attention" and st["steps"]["triage"]["status"] == "needs_attention"
    assert "pendiente(s) de tu aprobación" in st["steps"]["triage"]["message"]


def test_una_carpeta_fuera_de_la_raiz_de_datos_se_rechaza(tmp_path, monkeypatch):
    make_env(tmp_path, monkeypatch)
    r = Client().post("/proyectos/nuevo/", {"name": "x", "source_dir": "/etc", "language": "es"})
    assert r.status_code == 400 and "dentro de" in r.content.decode()


def test_datos_invalidos_se_explican_sin_crear_nada(tmp_path, monkeypatch):
    _, inbox = make_env(tmp_path, monkeypatch)
    c = Client()
    r = c.post("/proyectos/nuevo/", {"name": "x", "source_dir": str(inbox), "timezone": "America/Santigo", "language": "es"})
    assert r.status_code == 400 and not Project.list()
    assert create_project(c, inbox).status_code == 200
    again = c.post("/proyectos/nuevo/", {"name": "Análisis 1", "source_dir": str(inbox), "language": "es"})
    assert again.status_code == 400 and "Ya existe" in again.content.decode()


def test_sin_token_csrf_un_post_se_rechaza(tmp_path, monkeypatch):
    _, inbox = make_env(tmp_path, monkeypatch)
    r = Client(enforce_csrf_checks=True).post("/proyectos/nuevo/", {"name": "x", "source_dir": str(inbox)})
    assert r.status_code == 403


def test_proyecto_o_caso_inexistente_es_404(env):
    client, _, _ = env
    assert client.get("/proyectos/no-existe/").status_code == 404
    assert client.get("/proyectos/analisis-1/casos/otro/").status_code == 404
    assert client.get("/casos/no-existe/").status_code == 404


def test_un_analisis_interrumpido_se_ve_como_tal(env):
    client, _, _ = env
    project = Project.open("analisis-1")
    st = project.status("analisis-1--three-months")
    st["state"] = "running"                                                         # el servidor se reinició a mitad
    project.save_status("analisis-1--three-months", st)
    assert "interrumpido" in client.get("/proyectos/analisis-1/").content.decode()


# --- el caso -----------------------------------------------------------------------------------------------------

def test_el_resumen_muestra_datos_y_hallazgos_de_los_detectores(env):
    client, _, _ = env
    page = client.get(CASE + "tab/resumen/").content.decode()
    assert "Hallazgos de los detectores" in page and "activity_ramp" in page and "sin verificar" in page


def test_los_valores_reales_solo_salen_con_el_interruptor(env):
    client, _, _ = env
    oculto = client.get(CASE + "tab/resumen/").content.decode()
    visible = client.get(CASE + "tab/resumen/?reveal=1").content.decode()
    assert "atacante0" not in oculto and "atacante0" in visible
    assert "Mostrar valores reales" in client.get(CASE).content.decode()
    assert "Ocultar valores reales" in client.get(CASE + "?reveal=1").content.decode()


def test_la_pestana_de_hipotesis_enseña_lo_que_hay_que_decidir(env):
    client, _, _ = env
    page = client.get(CASE + "tab/hipotesis/").content.decode()
    assert "Esperando tu decisión" in page and "Criterio de refutación" in page and "La habría refutado si" in page
    assert "count(DISTINCT user_id)" in page and "Aprobar" in page and "Rechazar" in page


def test_aprobar_y_continuar_reanuda_al_agente_y_traduce_la_nota(env):
    client, _, _ = env
    r = client.post(CASE + "decidir/", {f"decision_{HID}": "approve", f"note_{HID}": "Aprobada solo en lo observable; atacante00 usa 66.6.6.1",
                                        "continue": "on"})
    body = r.content.decode()
    assert r.status_code == 200 and "Respuesta del agente" in body and "atacante00" not in body       # el agente ve alias
    hyp = client.get(CASE + "tab/hipotesis/").content.decode()
    assert "confirmada" in hyp and "Esperando tu decisión" not in hyp


def test_rechazar_deja_la_hipotesis_en_prueba(env):
    client, _, _ = env
    client.post(CASE + "decidir/", {f"decision_{HID}": "reject", f"note_{HID}": "El intento no puede refutarla"})
    hyp = client.get(CASE + "tab/hipotesis/").content.decode()
    assert "en_prueba" in hyp and "confirmada" not in hyp


def test_registrar_sin_continuar_es_inmediato_y_no_llama_al_modelo(env):
    client, sv, _ = env
    r = client.post(CASE + "decidir/", {f"decision_{HID}": "approve", f"note_{HID}": "Revisado: el intento podía salir distinto"})
    body = r.content.decode()
    assert r.status_code == 200 and "sin reanudar al agente" in body and "Respuesta del agente" not in body   # sin trabajo en 2.º plano
    assert "confirmada" in body and "Esperando tu decisión" not in body
    assert "Respuesta" in client.post(CASE + "preguntar/", {"question": "¿Y ahora?"}).content.decode()       # se puede seguir preguntando


def test_una_decision_que_falta_se_explica_y_no_registra_nada(env):
    client, _, _ = env
    body = client.post(CASE + "decidir/", {f"decision_{HID}": "quizas", f"note_{HID}": "x"}).content.decode()
    assert "Falta tu decisión" in body and "Esperando tu decisión" in body                  # nada se registró: sigue pendiente


def test_decidir_sin_propuestas_pendientes_se_explica(quiet):
    client, _, _ = quiet
    assert "No hay ninguna propuesta pendiente" in client.post(CASE + "decidir/", {"x": "y"}).content.decode()


def test_preguntar_traduce_los_valores_reales_y_enseña_lo_enviado(quiet):
    client, _, _ = quiet
    r = client.post(CASE + "preguntar/", {"question": "¿Qué hizo atacante00 desde 66.6.6.1?"})
    body = r.content.decode()
    assert r.status_code == 200 and "Lo que recibió el modelo" in body and "atacante00" not in body and "66.6.6.1" not in body
    assert "U-00" in body and "IP-00" in body
    chat = client.get(CASE + "tab/preguntar/").content.decode()
    assert "atacante00" not in chat and "Conversación" in chat


def test_un_valor_ambiguo_se_bloquea_antes_de_enviar(quiet):
    client, _, _ = quiet
    r = client.post(CASE + "preguntar/", {"question": "¿Quién consultó la factura 118822123?"})
    assert r.status_code == 422 and "el modelo lo ve como 123" in r.content.decode()
    ok = client.post(CASE + "preguntar/", {"question": "Hay 118822123 filas", "literal": "118822123"})
    assert ok.status_code == 200 and "Respuesta del agente" in ok.content.decode()


def test_sin_modelo_preguntar_y_aprobar_se_explican(tmp_path, monkeypatch):
    sv, inbox = make_env(tmp_path, monkeypatch, model=False)
    client = Client()
    create_project(client, inbox)
    assert Project.open("analisis-1").status("analisis-1--three-months")["steps"]["triage"]["status"] == "skipped"
    r = client.post(CASE + "preguntar/", {"question": "hola"})
    assert r.status_code == 409 and "modelo" in r.content.decode()
    assert "No hay ninguna propuesta pendiente" in client.post(CASE + "decidir/", {"x": "y"}).content.decode()
    assert "disabled" in client.get(CASE + "tab/preguntar/").content.decode()          # el botón está deshabilitado
    assert client.get(CASE + "tab/resumen/").status_code == 200                          # y el resto sigue funcionando


def test_las_notas_se_traducen_se_guardan_y_las_ve_el_agente(quiet):
    client, _, _ = quiet
    r = client.post(CASE + "notas/", {"text": "Confirmado con IAM: atacante00 usa 66.6.6.1", "status": "confirmed"})
    page = r.content.decode()
    assert "Nota guardada" in page and "traducidos a alias" in page and "atacante00" not in page
    assert "confirmed" in page and "U-00" in page
    ledger_text = list(Project.open("analisis-1").cases_dir.glob("*/ledger/*.jsonl"))[0].read_text(encoding="utf-8")
    assert "atacante00" not in ledger_text


def test_retirar_una_hipotesis_desde_la_interfaz(env):
    client, _, _ = env
    hid = "h-615951a2"
    page = client.post(CASE + f"retirar/{hid}/", {"reason": "Duplicada de otra mejor formulada"}).content.decode()
    assert "retirada" in page and "Hipótesis h-615951a2 retirada" in page
    err = client.post(CASE + "retirar/h-nada/", {"reason": "x"}).content.decode()
    assert "desconocida" in err


# --- informe -----------------------------------------------------------------------------------------------------

def test_el_boton_exportar_genera_el_informe_y_se_puede_descargar(env, tmp_path):
    client, _, _ = env
    assert "Exportar informe" in client.get(CASE).content.decode()                       # el botón está en la cabecera del caso
    r = client.post(CASE + "informe/exportar/", {"variant": "compartible", "lang": "es", "replay": "on",
                                                 "recommendations": "Revisar con IAM la cuenta atacante00"})
    body = r.content.decode()
    assert r.status_code == 200 and "Informe generado" in body and "informe.es.compartible.md" in body and "SHA-256" in body
    dl = client.get(CASE + "informe/descargar/informe.es.compartible.md/")
    assert dl.status_code == 200 and "attachment" in dl["Content-Disposition"]
    text = b"".join(dl.streaming_content).decode()
    assert "# Informe forense" in text and "atacante00" not in text and "COMPARTIBLE" in text
    tab = client.get(CASE + "tab/informe/").content.decode()
    assert "informe.es.compartible.md" in tab and "SHA-256" in tab
    assert (tmp_path / "reports" / "analisis-1--three-months" / "informe.es.compartible.md").exists()


def test_la_variante_interna_y_el_ingles(env):
    client, _, _ = env
    client.post(CASE + "informe/exportar/", {"variant": "interno", "lang": "en"})
    text = b"".join(client.get(CASE + "informe/descargar/informe.en.interno.md/").streaming_content).decode()
    assert "# Forensic report" in text and "INTERNAL" in text and "atacante0" in text and "Annex E" in text


def test_la_descarga_solo_admite_los_nombres_que_genera_el_informe(env, tmp_path):
    client, _, _ = env
    folder = tmp_path / "reports" / "analisis-1--three-months"
    folder.mkdir(parents=True)
    (folder / "secreto.txt").write_text("no es un informe", encoding="utf-8")        # otro archivo en la misma carpeta
    assert client.get(CASE + "informe/descargar/secreto.txt/").status_code == 404
    for name in ("informe.es.otro.md", "passwd", "informe.fr.interno.md"):
        assert client.get(CASE + f"informe/descargar/{name}/").status_code == 404
    assert client.get(CASE + "informe/descargar/informe.es.interno.md/").status_code == 404   # válido pero no exportado


def test_un_error_del_informe_se_muestra_sin_romper_la_pagina(env):
    client, _, _ = env
    r = client.post(CASE + "informe/exportar/", {"variant": "publico", "lang": "es"})
    assert r.status_code == 200 and "Variante no válida" in r.content.decode()


def test_la_integridad_se_ve_en_su_pestana(env):
    client, _, _ = env
    page = client.get(CASE + "tab/integridad/").content.decode()
    assert "Cadena de custodia" in page and "verificada" in page and "Último hash" in page


# --- casos sueltos (anteriores a los proyectos) --------------------------------------------------------------------

def test_los_casos_existentes_se_abren_y_se_exportan_igual(tmp_path, monkeypatch):
    make_env(tmp_path, monkeypatch)                                                       # su raíz de casos es tmp_path/cases
    _case(tmp_path, "CASO-VIEJO")
    client = Client()
    assert "CASO-VIEJO" in client.get("/").content.decode()
    assert client.get("/casos/CASO-VIEJO/").status_code == 200
    assert client.get("/casos/CASO-VIEJO/tab/resumen/").status_code == 200
    out = client.post("/casos/CASO-VIEJO/informe/exportar/", {"variant": "compartible", "lang": "es"})
    assert "Informe generado" in out.content.decode()


# --- el servidor real ------------------------------------------------------------------------------------------------

@pytest.fixture()
def live(tmp_path):
    """Arranca `python -m dfir_copilot.web` de verdad (DEBUG apagado, análisis en segundo plano) sobre carpetas de prueba."""
    import socket
    import subprocess
    import sys
    import time
    import urllib.request

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    data, inbox = tmp_path / "data", tmp_path / "data" / "inbox" / "a1"
    inbox.mkdir(parents=True)
    rows, _ = make_idor_dataset()
    write_csv(inbox / "three_months.csv", rows)
    env = {**os.environ, "DFIR_DATA_ROOT": str(data), "DFIR_CASES_ROOT": str(tmp_path / "cases"),
           "DFIR_REPORTS_ROOT": str(tmp_path / "reports"), "DFIR_WEB_SECRET": "x"}
    env.pop("DFIR_WEB_DEBUG", None)
    env.pop("DFIR_WEB_SYNC", None)
    proc = subprocess.Popen([sys.executable, "-m", "dfir_copilot.web", "--port", str(port)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(80):
            try:
                if urllib.request.urlopen(base + "/healthz", timeout=1).status == 200:
                    break
            except OSError:
                time.sleep(0.25)
        else:
            pytest.fail("el servidor no arrancó")
        yield base, inbox
    finally:
        proc.terminate()
        proc.wait(10)


def test_el_servidor_real_sirve_las_paginas_y_los_estaticos(live):
    """Regresión: con DEBUG apagado, `runserver` sin `--insecure` devolvía 404 para el CSS y HTMX y la interfaz no funcionaba. El cliente de
    pruebas no pide archivos estáticos, así que esto solo se ve arrancando el servidor de verdad."""
    import urllib.request

    base, _ = live
    page = urllib.request.urlopen(base + "/", timeout=5).read().decode()
    assert "/static/web/htmx.min.js" in page and "/static/web/app.css" in page
    css = urllib.request.urlopen(base + "/static/web/app.css", timeout=5)
    js = urllib.request.urlopen(base + "/static/web/htmx.min.js", timeout=5)
    assert css.status == js.status == 200 and b"htmx" in js.read()


def test_el_servidor_real_analiza_en_segundo_plano_con_csrf(live):
    """El camino que usa el analista: formulario con CSRF, análisis en un hilo y el estado que se va actualizando solo."""
    import http.cookiejar
    import re
    import time
    import urllib.parse
    import urllib.request

    base, inbox = live
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    home = opener.open(base + "/", timeout=5).read().decode()
    token = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', home).group(1)
    body = urllib.parse.urlencode({"csrfmiddlewaretoken": token, "name": "A1", "source_dir": str(inbox), "language": "es",
                                   "analyst": "eder"}).encode()                              # sin use_llm: análisis 100 % local
    resp = opener.open(urllib.request.Request(base + "/proyectos/nuevo/", data=body), timeout=60)
    assert resp.geturl().endswith("/proyectos/a1/")
    for _ in range(240):
        status = opener.open(base + "/proyectos/a1/estado/", timeout=10).read().decode()
        if "en curso" not in status and "hx-trigger" not in status:
            break
        time.sleep(0.5)
    else:
        pytest.fail("el análisis no terminó")
    assert "chip-done" in status and "Abrir caso" in status and "chip-failed" not in status
    case = opener.open(base + "/proyectos/a1/casos/a1--three-months/tab/resumen/", timeout=30).read().decode()
    assert "Hallazgos de los detectores" in case
    out = urllib.request.Request(base + "/proyectos/nuevo/", data=urllib.parse.urlencode({"name": "x"}).encode())
    with pytest.raises(urllib.error.HTTPError) as exc:                                       # sin token CSRF: 403
        urllib.request.urlopen(out, timeout=10)
    assert exc.value.code == 403


# --- asistente "Nuevo análisis" (entrega A) -------------------------------------------------------------------------------

def wizard(client, **extra):
    data = {"name": "Firewall octubre", "ticket": "INC-77", "description": "borde norte", "analyst": "eder", "language": "es",
            "timezone": "America/Santiago", "max_tokens": "210000", **extra}           # sin use_llm: análisis 100 % local
    return client.post("/analisis/nuevo/", data)


def test_el_inicio_lleva_al_asistente_y_conserva_el_modo_carpeta(tmp_path, monkeypatch):
    make_env(tmp_path, monkeypatch, model=False)
    page = Client().get("/").content.decode()
    assert "Nuevo análisis" in page and 'href="/analisis/nuevo/"' in page and "Carpeta con los archivos" in page


def test_el_asistente_crea_el_analisis_y_pasa_a_los_archivos(tmp_path, monkeypatch):
    make_env(tmp_path, monkeypatch, model=False)
    c = Client()
    assert "Nombre del análisis" in c.get("/analisis/nuevo/").content.decode()
    r = wizard(c)
    assert r.status_code == 302 and r["Location"] == "/proyectos/firewall-octubre/archivos/"
    page = c.get(r["Location"]).content.decode()
    assert "Subir desde tu equipo" in page and "Elegir del servidor" in page and "INC-77" in page and "borde norte" in page
    assert c.post("/analisis/nuevo/", {"name": "", "language": "es"}).status_code == 400
    assert wizard(c).status_code == 400                                          # mismo nombre: no pisa el análisis existente


def test_subir_elegir_del_servidor_analizar_y_custodia(tmp_path, monkeypatch):
    from django.core.files.uploadedfile import SimpleUploadedFile

    _, inbox = make_env(tmp_path, monkeypatch, model=False)
    c = Client()
    wizard(c)
    base = "/proyectos/firewall-octubre/archivos/"
    up = c.post(base + "subir/", {"files": [SimpleUploadedFile("acceso.csv", (inbox / "three_months.csv").read_bytes()),
                                            SimpleUploadedFile("x.exe", b"MZ")]})
    html = up.content.decode()
    assert up.status_code == 200 and "acceso.csv" in html and "x.exe" in html and "no admitido" in html
    listing = c.get(base + "servidor/?ruta=inbox/analisis1").content.decode()
    assert "three_months.csv" in listing and "notas.txt" in listing
    assert c.get(base + "servidor/?ruta=../..").status_code == 400
    assert ">📁 projects<" not in c.get(base + "servidor/").content.decode()   # la carpeta interna de proyectos no se ofrece
    add = c.post(base + "servidor/agregar/", {"paths": ["inbox/analisis1/three_months.csv", "../../etc/passwd"], "modo": "copy"})
    html = add.content.decode()
    assert "three_months.csv" in html and "No se pudo" in html and "etc/passwd" in html
    r = c.post(base + "analizar/")
    assert r.status_code == 302 and r["Location"] == "/proyectos/firewall-octubre/"
    page = c.get(r["Location"]).content.decode()
    assert page.count("Abrir caso") == 2 and "Archivos y custodia" in page and "INC-77" in page
    assert Project.open("firewall-octubre").verify_custody()["ok"]


def test_el_limite_de_tamano_y_csrf_protegen_la_subida(tmp_path, monkeypatch):
    from django.core.files.uploadedfile import SimpleUploadedFile
    from django.test import override_settings

    make_env(tmp_path, monkeypatch, model=False)
    c = Client()
    wizard(c)
    base = "/proyectos/firewall-octubre/archivos/"
    with override_settings(DFIR_MAX_UPLOAD_MB=0):
        r = c.post(base + "subir/", {"files": [SimpleUploadedFile("a.csv", b"x\n1\n")]})
    assert r.status_code == 400 and "límite" in r.content.decode() and Project.open("firewall-octubre").files() == []
    strict = Client(enforce_csrf_checks=True)
    assert strict.post(base + "subir/", {"files": [SimpleUploadedFile("a.csv", b"x\n1\n")]}).status_code == 403
    assert strict.post(base + "servidor/agregar/", {"paths": ["inbox/analisis1/three_months.csv"]}).status_code == 403


def test_un_proyecto_por_carpeta_no_admite_subidas(tmp_path, monkeypatch):
    from django.core.files.uploadedfile import SimpleUploadedFile

    _, inbox = make_env(tmp_path, monkeypatch, model=False)
    c = Client()
    create_project(c, inbox, use_llm="")
    assert c.get("/proyectos/analisis-1/archivos/").status_code == 302
    assert c.post("/proyectos/analisis-1/archivos/subir/", {"files": [SimpleUploadedFile("a.csv", b"x\n")]}).status_code == 404


def test_confirmar_la_zona_desde_el_caso(tmp_path, monkeypatch):
    _, inbox = make_env(tmp_path, monkeypatch, model=False)
    c = Client()
    wizard(c)
    c.post("/proyectos/firewall-octubre/archivos/servidor/agregar/", {"paths": ["inbox/analisis1/three_months.csv"], "modo": "copy"})
    c.post("/proyectos/firewall-octubre/archivos/analizar/")
    cid = Project.open("firewall-octubre").files()[0].case_id
    case = f"/proyectos/firewall-octubre/casos/{cid}/"
    assert "Confirmar la zona horaria" in c.get(case + "tab/resumen/").content.decode()
    bad = c.post(case + "zona/", {"timezone": "America/Bogota", "basis": "analyst_decision", "analyst": "eder"}).content.decode()
    assert "reingestar" in bad
    ok = c.post(case + "zona/", {"timezone": "America/Santiago", "basis": "analyst_decision", "analyst": "eder"}).content.decode()
    assert "registrada como: decisión del analista, sin confirmación externa" in ok and "(eder," in ok


# --- conversación: análisis automático en curso, propuestas pendientes e hilo roto ------------------------------------------

def test_la_pestana_preguntar_avisa_de_las_propuestas_pendientes_del_triaje(env):
    client, _, _ = env                                                           # el triaje automático dejó una aprobación pendiente
    page = client.get(CASE + "tab/preguntar/").content.decode()
    assert "esperando tu decisión" in page
    r = client.post(CASE + "preguntar/", {"question": "¿Algo más?"})
    assert r.status_code == 409 and "Hipótesis" in r.content.decode()


def test_mientras_corre_el_analisis_automatico_no_se_pregunta_ni_se_decide(env, monkeypatch):
    client, sv, _ = env
    monkeypatch.setattr(sv.runner, "running", lambda pid, cid: True)
    assert "sigue en curso" in client.get(CASE + "tab/preguntar/").content.decode()
    for url, data in ((CASE + "preguntar/", {"question": "¿Algo?"}), (CASE + "decidir/", {"decision": "approve", "note": "ok"})):
        r = client.post(url, data)
        assert r.status_code == 409 and "sigue en curso" in r.content.decode()


def test_un_hilo_roto_muestra_el_error_y_se_puede_reiniciar_sin_perder_nada(env, monkeypatch):
    from dfir_copilot.agent.graph import DfirAgent

    client, sv, _ = env
    with monkeypatch.context() as m:                                                # solo este bloque ve el hilo "roto"
        m.setattr(DfirAgent, "phase", lambda self, thread_id="default": "crashed")
        page = client.get(CASE + "tab/preguntar/").content.decode()
        assert "quedó a medias" in page and "Reiniciar conversación" in page and "reset()" not in page
        r = client.post(CASE + "preguntar/", {"question": "¿Algo?"})
        assert r.status_code == 409 and "Reiniciar conversación" in r.content.decode()
    ws = Project.open("analisis-1").workspace("analisis-1--three-months")
    before = len(ws.ledger(ws.engine()).entries())
    assert "Conversación reiniciada" in client.post(CASE + "reiniciar/").content.decode()
    assert len(ws.ledger(ws.engine()).entries()) == before and ws.verify().ok              # el ledger no se toca


# --- pestaña Datos (perfil de ingeniero de datos) -----------------------------------------------------------------------------

def test_la_pestana_datos_muestra_el_desglose_en_alias_y_reales_solo_con_el_interruptor(quiet):
    client, _, _ = quiet
    page = client.get(CASE + "tab/datos/").content.decode()
    assert "Eventos por hora" in page and "Calidad del dato" in page and "Campos" in page and "U-00" in page
    assert "atacante" not in page and "66.6.6." not in page
    real = client.get(CASE + "tab/datos/?reveal=1").content.decode()
    assert "atacante" in real or "66.6.6." in real


def test_un_caso_sin_perfil_ofrece_calcularlo(quiet):
    client, _, _ = quiet
    ws = Project.open("analisis-1").workspace("analisis-1--three-months")
    (ws.dir / "p1" / "perfil_datos.json").unlink()
    assert "Calcular el perfil" in client.get(CASE + "tab/datos/").content.decode()
    done = client.post(CASE + "perfil/").content.decode()
    assert "Perfil calculado" in done and "Eventos por hora" in done and ws.verify().ok
