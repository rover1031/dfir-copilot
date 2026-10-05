"""P1-a, entrega 3: presentación del resultado, ejecución local de lo aceptado y script de llamada real. Sin red."""
import json
from types import SimpleNamespace

import duckdb
import pytest
from interp_helpers import GOOD, INVOICE, USER, Scripted, make_profile, ok

from dfir_copilot.agent.llm import LLMConfigError
from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.interpret import (
    PROMPT_VERSION,
    StructuredReply,
    interpret_profile,
    render_interpretation,
    result_to_dict,
    run_accepted_queries,
    summarize_runs,
)
from dfir_copilot.interpret.smoke import main


def sample_result(reply=None, **kw):
    return interpret_profile(Scripted(reply or ok()), make_profile(), derived=[USER, INVOICE], **kw)


def with_bad_query():
    data = json.loads(json.dumps(GOOD))
    data["proposed_queries"].append({"id": "borra_todo", "hypothesis": "h", "priority": "low", "expected_if_true": "e",
                                     "refuted_if": "r", "sql": "DROP TABLE logs"})
    return ok(data)


# --- render --------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("lang, labels", [
    ("es", ["Clasificación: web_access (confianza 0.90)", "Revisión del mapeo (1)", "Consultas aceptadas (1)", "Se refuta si:",
            "Descartado por el validador (1)", "Preguntas para el analista (1)", "Consumo: tokens: entrada 1,200 | salida 400 | total 1,600"]),
    ("en", ["Classification: web_access (confidence 0.90)", "Mapping review (1)", "Accepted queries (1)", "Refuted if:",
            "Discarded by the validator (1)", "Questions for the analyst (1)", "Usage: tokens: input 1,200 | output 400 | total 1,600"]),
])
def test_el_informe_sale_en_el_idioma_pedido_con_todas_las_secciones(lang, labels):
    text = render_interpretation(sample_result(with_bad_query()), lang)
    for label in labels:
        assert label in text, label
    assert "[high] facturas_por_usuario" in text and "- query borra_todo: policy_rejected" in text and PROMPT_VERSION in text
    assert "SELECT user_id, count(DISTINCT x_invoice_id) AS n FROM logs GROUP BY 1 ORDER BY n DESC LIMIT 20" in text  # SQL en una línea


def test_un_informe_sin_elementos_dice_ninguna_en_cada_seccion():
    empty = ok({"classification": GOOD["classification"]})
    assert render_interpretation(sample_result(empty), "es").count("(ninguna)") == 4


def test_el_informe_de_una_respuesta_inutilizable_dice_por_que_e_incluye_los_tokens():
    result = interpret_profile(Scripted(StructuredReply(None, {"input_tokens": 77}, "OutputParserException: roto")), make_profile())
    text = render_interpretation(result, "es")
    assert "no se pudo usar: parse_error - OutputParserException: roto" in text and "entrada 77" in text


def test_si_no_hay_tokens_informados_se_dice_n_d():
    assert "tokens: n/d" in render_interpretation(sample_result(StructuredReply(GOOD, None)), "es")


def test_el_resultado_guardable_es_json_y_no_lleva_datos_de_las_derivadas_ni_el_perfil():
    data = result_to_dict(sample_result(with_bad_query()))
    text = json.dumps(data)
    assert data["ok"] and data["interpretation"]["classification"]["log_type"] == "web_access" and data["discarded"][0]["code"] == "policy_rejected"
    assert data["usage"]["total_tokens"] == 1600 and data["prompt_version"] == PROMPT_VERSION
    for secret in ("REGEX-SECRETA", "RAZON-LIBRE", "an*******", "<data_profile>"):
        assert secret not in text


def test_el_resultado_guardable_de_un_fallo_no_tiene_interpretacion():
    data = result_to_dict(interpret_profile(Scripted(StructuredReply(None, None, "x")), make_profile()))
    assert data["ok"] is False and data["interpretation"] is None and data["discarded"] == [] and data["error"] == "parse_error"


# --- ejecución local sobre datos reales ----------------------------------------------------------------------------
@pytest.fixture()
def engine(tmp_path):
    path = tmp_path / "datos.parquet"
    con = duckdb.connect(":memory:")
    con.execute("CREATE TABLE t AS SELECT range AS source_row, 'u' || (range % 3) AS user_id, 'v' || (range % 7) AS x_invoice_id, "
                "'/ruta/' || (range % 2) AS endpoint, (200 + (range % 2) * 200)::SMALLINT AS status_code FROM range(100)")
    con.execute(f"COPY t TO '{path}' (FORMAT parquet)")
    con.close()
    return QueryEngine(path, verify=False)


def reply_with(*pairs):
    return ok({"classification": GOOD["classification"], "proposed_queries": [
        {"id": i, "hypothesis": "h", "priority": "medium", "expected_if_true": "e", "refuted_if": "r", "sql": s} for i, s in pairs]})


def test_se_ejecutan_las_consultas_aceptadas_y_se_mide_cuantas_fallan_con_datos_reales(engine):
    reply = reply_with(
        ("por_usuario", "SELECT user_id, count(*) AS n FROM logs GROUP BY 1 ORDER BY n DESC"),
        ("sin_filas", "SELECT * FROM logs WHERE status_code = 999"),
        ("conversion_mala", "SELECT CAST(endpoint AS INTEGER) FROM logs"),   # compila en una tabla vacía, falla con datos
    )
    result = sample_result(reply)
    assert [q.id for q in result.reviewed.interpretation.proposed_queries] == ["por_usuario", "sin_filas", "conversion_mala"]  # el validador las acepta
    runs = {r.id: r for r in run_accepted_queries(engine, result)}
    assert (runs["por_usuario"].status, runs["por_usuario"].row_count, runs["por_usuario"].columns) == ("ok", 3, ("user_id", "n"))
    assert runs["sin_filas"].status == "empty" and runs["sin_filas"].rows == []
    assert runs["conversion_mala"].status == "error" and "Conversion" in runs["conversion_mala"].error
    assert summarize_runs(list(runs.values())) == {"accepted": 3, "by_status": {"ok": 1, "empty": 1, "error": 1}, "accepted_but_failed": 1}


def test_el_tope_de_filas_y_el_truncado_se_respetan(engine):
    runs = run_accepted_queries(engine, sample_result(reply_with(("todo", "SELECT source_row FROM logs"))), max_rows=5)
    assert runs[0].row_count == 5 and runs[0].truncated is True


def test_un_timeout_se_informa_como_tal(engine):
    engine.timeout_s = 0.001
    runs = run_accepted_queries(engine, sample_result(reply_with(("pesada", "SELECT count(*) FROM range(5000000000) a, range(3) b, logs"))))
    assert runs[0].status == "timeout"


def test_no_se_ejecuta_nada_si_la_respuesta_no_se_pudo_usar(engine):
    failed = interpret_profile(Scripted(StructuredReply(None, None, "x")), make_profile())
    with pytest.raises(ValueError, match="utilizable"):
        run_accepted_queries(engine, failed)


# --- script de llamada real ----------------------------------------------------------------------------------------
class Draft:
    def __init__(self, profile=None, derived=(), status="ready"):
        self.profile, self.derived, self.status = profile, list(derived), status


def inspector(profile=None, derived=(USER, INVOICE), status="ready"):
    calls = []

    def fake(path, lang):
        calls.append((path, lang))
        return Draft(profile or make_profile(), derived, status)

    fake.calls = calls
    return fake


def factory(llm):
    seen = []

    def make(cfg):
        seen.append(cfg)
        if isinstance(llm, Exception):
            raise llm
        return llm

    make.seen = seen
    return make


def boom(cfg):
    raise AssertionError("no debía crearse ningún cliente")


def test_dry_run_muestra_lo_que_se_enviaria_y_no_crea_ningun_cliente(capsys):
    code = main(["datos.csv", "--dry-run"], inspector=inspector(), llm_factory=boom)
    out = capsys.readouterr().out
    assert code == 0 and "===== PROMPT DE SISTEMA =====" in out and "===== MENSAJE DE USUARIO =====" in out
    assert "<data_profile>" in out and "x_invoice_id VARCHAR" in out and "unos " in out and "tokens de entrada, estimación gruesa" in out
    for secret in ("REGEX-SECRETA", "RAZON-LIBRE", "an*******"):
        assert secret not in out


def test_llamada_completa_sin_confirmar_con_yes(capsys):
    insp, llm = inspector(), Scripted(ok())
    code = main(["datos.csv", "--yes", "--lang", "en"], inspector=insp, llm_factory=factory(llm))
    out = capsys.readouterr().out
    assert code == 0 and insp.calls == [("datos.csv", "en")] and len(llm.calls) == 1
    assert "Classification: web_access" in out and "proveedor=anthropic" in out and "clave=" in out
    assert llm.calls[0][1].startswith("<lang>en</lang>")


@pytest.mark.parametrize("answer, sent", [("s", 1), ("Sí", 1), ("", 0), ("n", 0), ("quizá", 0)])
def test_sin_yes_pide_confirmacion_y_solo_envia_si_se_acepta(capsys, answer, sent):
    llm = Scripted(ok())
    code = main(["datos.csv"], inspector=inspector(), llm_factory=factory(llm), input_fn=lambda prompt: answer)
    assert code == 0 and len(llm.calls) == sent
    assert ("Cancelado: no se envió nada." in capsys.readouterr().out) == (sent == 0)


def test_la_clave_se_muestra_enmascarada_nunca_completa(capsys, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-FAKE-pruebas-1234")
    main(["datos.csv", "--yes"], inspector=inspector(), llm_factory=factory(Scripted(ok())))
    out = capsys.readouterr().out
    assert "clave=…1234" in out and "sk-ant-secreta" not in out


def test_el_timeout_de_la_linea_de_comandos_pisa_al_de_la_configuracion(capsys):
    make = factory(Scripted(ok()))
    main(["datos.csv", "--yes", "--timeout", "180"], inspector=inspector(), llm_factory=make)
    assert make.seen[0].timeout_s == 180.0 and "espera máx. 180 s" in capsys.readouterr().out


@pytest.mark.parametrize("env, expected", [({}, 180.0), ({"LLM_TIMEOUT_S": "60"}, 180.0), ({"LLM_TIMEOUT_S": "300"}, 300.0)])
def test_la_espera_por_defecto_es_la_mayor_entre_la_configurada_y_180(capsys, monkeypatch, env, expected):
    monkeypatch.delenv("LLM_TIMEOUT_S", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    make = factory(Scripted(ok()))
    main(["datos.csv", "--yes"], inspector=inspector(), llm_factory=make)
    assert make.seen[0].timeout_s == expected


def test_configuracion_incompleta_sale_con_2_y_mensaje_accionable(capsys):
    code = main(["datos.csv", "--yes"], inspector=inspector(), llm_factory=factory(LLMConfigError("Falta ANTHROPIC_API_KEY en el archivo .env")))
    assert code == 2 and "Configuración incompleta: Falta ANTHROPIC_API_KEY" in capsys.readouterr().out


def test_un_fallo_del_proveedor_sale_con_1_sin_traza_ni_claves(capsys):
    class Caido:
        def invoke(self, *a):
            raise ConnectionError("sin red sk-ant-FAKE-pruebas-1234")

    code = main(["datos.csv", "--yes"], inspector=inspector(), llm_factory=factory(Caido()))
    out = capsys.readouterr().out
    assert code == 1 and "La llamada falló (ConnectionError)" in out and "Traceback" not in out


def test_una_respuesta_inutilizable_sale_con_3_pero_muestra_los_tokens(capsys):
    code = main(["datos.csv", "--yes"], inspector=inspector(), llm_factory=factory(Scripted(StructuredReply(None, {"input_tokens": 42}, "roto"))))
    out = capsys.readouterr().out
    assert code == 3 and "parse_error" in out and "entrada 42" in out


def test_sin_perfil_o_con_derivadas_invalidas_sale_con_2(capsys):
    assert main(["datos.csv", "--yes"], inspector=lambda p, lang: Draft(None, status="unsupported"), llm_factory=boom) == 2
    assert "estado: unsupported" in capsys.readouterr().out
    bad = SimpleNamespace(name="x_a", type="BLOB", role="other", key="a", hit_pct=1.0, distinct=1)
    assert main(["datos.csv", "--yes"], inspector=inspector(derived=[bad]), llm_factory=boom) == 2
    assert "Tipo no admitido" in capsys.readouterr().out


def test_un_archivo_inexistente_sale_con_2(capsys):
    def missing(path, lang):
        raise FileNotFoundError(path)

    assert main(["no_existe.csv", "--yes"], inspector=missing, llm_factory=boom) == 2
    assert "FileNotFoundError" in capsys.readouterr().out


def test_save_escribe_el_resultado_sin_el_perfil(tmp_path, capsys):
    target = tmp_path / "sub" / "salida.json"
    code = main(["datos.csv", "--yes", "--save", str(target)], inspector=inspector(), llm_factory=factory(Scripted(ok())))
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert code == 0 and saved["ok"] and saved["interpretation"]["proposed_queries"][0]["id"] == "facturas_por_usuario"
    assert "<data_profile>" not in target.read_text(encoding="utf-8") and f"Guardado en {target}" in capsys.readouterr().out
