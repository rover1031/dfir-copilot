"""Informe forense (P2). Lo esencial: determinista; la variante compartible NO lleva valores reales ni el diccionario y un detector de fugas
la bloquea si algo se cuela; las credenciales se redactan siempre; exportar escribe el archivo y lo registra en el ledger."""
import hashlib
import string

import pytest
from test_agent import FULL
from test_privacy_agent import _case

from dfir_copilot.agent.graph import build_agent
from dfir_copilot.agent.hypotheses import HypothesisBook
from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.reporting import labels
from dfir_copilot.reporting.report import (
    ReportError,
    ReportLeak,
    _Builder,
    build_report,
    export_report,
    redact,
)
from dfir_copilot.tools import Toolkit

REAL = ("atacante00", "atacante01", "atacante02", "66.6.6.1", "66.6.6.2", "mercadolibre")


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    """Un caso con una investigación completa: hipótesis confirmada con su intento de refutación y una nota con una credencial."""
    from conftest import ScriptedChat

    tmp = tmp_path_factory.mktemp("rep")
    ws = _case(tmp, "C-REPORT")
    pseudo, ps = ws.pseudonymized()
    ledger = ws.ledger(ws.engine())
    agent = build_agent(pseudo, ledger, ScriptedChat(script=FULL()), pseudonymizer=ps)
    agent.ask("¿Qué pasó?")
    agent.resolve("approve", "Aprobada solo en lo observable; atacante00 usa 66.6.6.1. authtoken=ATUSER-ID-secreto password=hunter2")
    agent.note("La zona horaria no está verificada", status="inconclusive")
    return ws


def has_real(text):
    return [v for v in REAL if v in text]


# --- determinismo y estructura ----------------------------------------------------------------------------------

def test_el_informe_es_determinista(case):
    a = build_report(case, variant="compartible", lang="es", run_replay=False)
    b = build_report(case, variant="compartible", lang="es", run_replay=False)
    assert a.markdown == b.markdown and a.sha256 == b.sha256 == hashlib.sha256(a.markdown.encode()).hexdigest()


def test_tiene_la_estructura_aprobada(case):
    md = build_report(case, variant="interno", lang="es", run_replay=False).markdown
    for heading in ("## Portada", "## 1. Resumen", "## 2. Datos y supuestos", "## 3. Qué vio el modelo", "## 4. Hallazgos",
                    "### 4.1", "### 4.2", "## 5. Línea de tiempo", "## 6. Hipótesis no concluyentes", "## 7. Limitaciones",
                    "## 8. Recomendaciones", "## Anexo A", "## Anexo B", "## Anexo C", "## Anexo D", "## Anexo E"):
        assert heading in md, heading
    assert md.index("## 1.") < md.index("## 8.") < md.index("## Anexo A") < md.index("## Anexo E")


def test_cada_afirmacion_lleva_su_referencia_y_la_hipotesis_su_criterio(case):
    md = build_report(case, variant="compartible", lang="es", run_replay=False).markdown
    assert "`h-" in md and "`q-" in md and "`c-" in md and "`f-" in md
    assert "Criterio de refutación (fijado al proponerla)" in md and "Intentos de refutación" in md and "La habría refutado si" in md
    assert "SELECT count(DISTINCT user_id)" in md                                        # el SQL del intento, no solo su id


# --- privacidad ----------------------------------------------------------------------------------------------------

def test_la_variante_compartible_no_lleva_valores_reales_ni_diccionario(case):
    md = build_report(case, variant="compartible", lang="es", run_replay=False)
    assert not has_real(md.markdown) and "Anexo E" not in md.markdown and md.stats["leak_scan"] == "ok"
    assert "U-00" in md.markdown                                                          # lleva alias, no está vacío


def test_la_variante_interna_lleva_valores_reales_y_el_diccionario(case):
    md = build_report(case, variant="interno", lang="es", run_replay=False).markdown
    assert "atacante00" in md and "66.6.6.1" in md and "## Anexo E" in md and "Valor real" in md


def test_el_detector_de_fugas_bloquea_la_compartible_sin_mostrar_el_valor(case, monkeypatch):
    original = _Builder.summary
    monkeypatch.setattr(_Builder, "summary", lambda self: original(self) + ["Se coló atacante00 en el texto", ""])
    with pytest.raises(ReportLeak) as exc:
        build_report(case, variant="compartible", lang="es", run_replay=False)
    assert "atacante00" not in str(exc.value) and "user_id" in str(exc.value)


def test_lo_que_vino_de_datos_reales_no_va_en_la_compartible(tmp_path):
    ws = _case(tmp_path, "C-LEGACY")
    real = ws.engine()
    ledger = ws.ledger(real)
    Toolkit(real, ledger).call("run_detectors")                                           # caso antiguo: detectores sobre datos reales
    HypothesisBook(ledger).propose("La cuenta atacante00 enumera facturas desde 66.6.6.1", proposed_by="agent",
                                   falsifier="Si atacante00 usa otra IP queda refutada")  # sin sello de copia
    compartible = build_report(ws, variant="compartible", lang="es", run_replay=False)
    assert not has_real(compartible.markdown) and "calculados sobre datos reales no se incluyen" in compartible.markdown
    interno = build_report(ws, variant="interno", lang="es", run_replay=False).markdown
    assert "atacante0" in interno                                                         # la interna sí los muestra


def test_las_recomendaciones_con_valores_reales_se_traducen_a_alias(case):
    r = build_report(case, variant="compartible", lang="es", recommendations="Revisar con IAM la cuenta atacante00 desde 66.6.6.1",
                     run_replay=False)
    assert "Revisar con IAM la cuenta U-" in r.markdown and not has_real(r.markdown)
    assert "atacante00" in build_report(case, variant="interno", lang="es", recommendations="Revisar atacante00",
                                        run_replay=False).markdown


# --- credenciales -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("variant", ["compartible", "interno"])
def test_las_credenciales_se_redactan_siempre(case, variant):
    r = build_report(case, variant=variant, lang="es", run_replay=False)
    assert "ATUSER-ID-secreto" not in r.markdown and "hunter2" not in r.markdown and "[REDACTED]" in r.markdown
    assert r.stats["redactions"] >= 2 and "Credenciales redactadas en el documento" in r.markdown


def test_la_redaccion_no_toca_identificadores_de_columnas():
    text, n = redact("x_token_type y authtoken=ABC123 y Authorization: Bearer abc.def.ghi y token_id")
    assert n == 2 and "x_token_type" in text and "token_id" in text and "ABC123" not in text and "abc.def.ghi" not in text


# --- el replay y los idiomas ------------------------------------------------------------------------------------------

def test_el_anexo_b_muestra_el_estado_de_verificacion(case):
    md = build_report(case, variant="compartible", lang="es", run_replay=True).markdown
    assert "coincide" in md and "NO coincide" not in md


def test_en_ingles_no_queda_texto_en_espanol_en_las_etiquetas(case):
    md = build_report(case, variant="compartible", lang="en", run_replay=False).markdown
    for heading in ("# Forensic report", "## 1. Summary", "## 7. Limitations", "## Annex A", "## Annex D"):
        assert heading in md, heading
    assert "## 1. Resumen" not in md and "Anexo" not in md


def test_todas_las_etiquetas_existen_en_los_dos_idiomas_con_los_mismos_marcadores():
    fmt = string.Formatter()

    def fields(text):
        return {name for _, name, _, _ in fmt.parse(text) if name}

    for key, (es, en) in labels._L.items():
        assert es.strip() and en.strip(), key
        assert fields(es) == fields(en), key


# --- exportar ---------------------------------------------------------------------------------------------------------

def test_exportar_escribe_el_archivo_y_lo_registra_en_el_ledger(case, tmp_path):
    out = export_report(case, variant="compartible", lang="es", recommendations="Revisar con IAM la cuenta atacante00",
                        run_replay=False, out_root=tmp_path, analyst="eder")
    assert out.path == tmp_path / "C-REPORT" / "informe.es.compartible.md" and out.path.exists()
    text = out.path.read_text(encoding="utf-8")
    body, footer = text.split("\n---\n", 1)
    assert hashlib.sha256(body.encode()).hexdigest() == out.report.sha256 and out.report.sha256 in footer
    ledger = case.ledger(case.engine())
    entry = ledger.entries("report_export")[-1]["data"]
    assert entry["sha256"] == out.report.sha256 and entry["variant"] == "compartible" and entry["analyst"] == "eder"
    assert "atacante00" not in (entry["recommendations"] or "") and ledger.verify().ok    # al ledger solo llega la versión en alias
    assert case.verify().ok


def test_las_dos_variantes_se_guardan_en_archivos_distintos(case, tmp_path):
    a = export_report(case, variant="compartible", lang="es", run_replay=False, out_root=tmp_path)
    b = export_report(case, variant="interno", lang="en", run_replay=False, out_root=tmp_path)
    assert a.path != b.path and a.path.exists() and b.path.exists() and a.report.sha256 != b.report.sha256


# --- errores ---------------------------------------------------------------------------------------------------------

def test_un_caso_sin_datos_no_se_puede_informar(tmp_path):
    ws = CaseWorkspace.open_or_create("C-VACIO", root=tmp_path / "cases", analyst="t")
    with pytest.raises(ReportError, match="sin datos|no tiene datos"):
        build_report(ws, run_replay=False)


@pytest.mark.parametrize("kw", [{"variant": "publico"}, {"lang": "fr"}])
def test_variante_o_idioma_no_validos(case, kw):
    with pytest.raises(ReportError):
        build_report(case, run_replay=False, **kw)
