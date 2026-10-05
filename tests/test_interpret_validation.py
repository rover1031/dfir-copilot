"""P1-a, entrega 1: contrato de salida del LLM y validación de lo que propone. Todo offline, sin API ni datos."""
import json
from pathlib import Path

import pytest
from interp_helpers import make_profile
from pydantic import ValidationError

from dfir_copilot.interpret import (
    MAX_QUERIES,
    AnalystQuestion,
    LogClassification,
    MappingReview,
    ProfileInterpretation,
    ProposedQuery,
    SqlSandbox,
    columns_from_profile,
    review_interpretation,
)


def cls(**kw):
    base = {"log_type": "web_access", "confidence": 0.9, "evidence_fields": ["path"], "rationale": "ruta y código HTTP"}
    return LogClassification(**{**base, **kw})


def query(id="top_endpoints", sql="SELECT endpoint, count(*) AS n FROM logs GROUP BY 1", priority="medium"):
    return ProposedQuery(id=id, hypothesis="h", sql=sql, expected_if_true="e", refuted_if="r", priority=priority)


def interp(**kw):
    return ProfileInterpretation(classification=kw.pop("classification", cls()), **kw)


@pytest.fixture(scope="module")
def columns():
    return columns_from_profile(make_profile(), {"x_invoice_id": "VARCHAR"})


@pytest.fixture(scope="module")
def sandbox(columns):
    with SqlSandbox(columns) as sbx:
        yield sbx


def codes(reviewed, kind=None):
    return [(d.ref, d.code) for d in reviewed.discarded if kind in (None, d.kind)]


# --- columnas del gemelo vacío -------------------------------------------------------------------------------------
def test_las_columnas_son_las_mapeadas_traducidas_a_la_tabla_mas_source_row_y_timestamp(columns):
    assert list(columns) == ["source_row", "timestamp_utc", "src_ip", "user_id", "endpoint", "query_string", "status_code",
                             "timestamp_raw", "x_invoice_id"]
    assert columns["timestamp_utc"] == "TIMESTAMPTZ" and columns["x_invoice_id"] == "VARCHAR"


def test_sin_marca_de_tiempo_en_el_perfil_no_hay_timestamp_utc():
    assert "timestamp_utc" not in columns_from_profile(make_profile({"uri": "path"}, with_timestamp=False))


@pytest.mark.parametrize("derived", [
    {"X_Mayus": "VARCHAR"}, {"x; DROP": "VARCHAR"}, {"user_id": "VARCHAR"}, {"x_a": "VARCHAR); DROP TABLE logs; --"}, {"x_a": "BLOB"},
])
def test_las_derivadas_invalidas_se_rechazan(derived):
    with pytest.raises(ValueError):
        columns_from_profile(make_profile(), derived)


# --- sandbox -------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("sql", [
    "SELECT endpoint, count(*) AS n FROM logs GROUP BY 1 ORDER BY n DESC",
    "WITH a AS (SELECT user_id, count(DISTINCT x_invoice_id) AS f FROM logs GROUP BY 1) SELECT * FROM a WHERE f > 100",
    "SELECT date_trunc('hour', timestamp_utc) AS h, count(*) FROM logs WHERE status_code >= 400 GROUP BY 1;",
])
def test_consultas_validas_pasan(sandbox, sql):
    assert sandbox.check(sql).ok


@pytest.mark.parametrize("sql, code", [
    ("DROP TABLE logs", "policy_rejected"),
    ("SELECT 1 FROM logs; SELECT 2 FROM logs", "policy_rejected"),
    ("INSERT INTO logs SELECT * FROM logs", "policy_rejected"),
    ("COPY (SELECT * FROM logs) TO '/tmp/x.csv'", "policy_rejected"),
    ("SELECT * FROM logs, read_csv('/etc/passwd')", "sql_error"),           # acceso a archivos bloqueado
    ("SELECT session_id FROM logs", "sql_error"),                           # canónica que el log no aporta
    ("SELECT enpoint FROM logs", "sql_error"),                              # errata
    ("SELECT FROM WHERE logs", "policy_rejected"),                          # no interpretable
    ("SELECT 1", "no_logs_reference"),                                      # no lee los datos
])
def test_consultas_no_validas_se_rechazan_con_su_codigo(sandbox, sql, code):
    check = sandbox.check(sql)
    assert not check.ok and check.code == code and check.detail


def test_el_sandbox_se_reutiliza_y_un_fallo_no_afecta_a_la_siguiente(sandbox):
    assert not sandbox.check("DROP TABLE logs").ok
    assert sandbox.check("SELECT count(*) FROM logs").ok


def test_cerrar_el_sandbox_borra_su_carpeta_temporal(columns):
    sbx = SqlSandbox(columns)
    folder = Path(sbx._tmp.name)
    assert folder.exists()
    sbx.close()
    assert not folder.exists()


# --- esquemas ------------------------------------------------------------------------------------------------------
def test_el_esquema_se_serializa_a_json_schema():
    schema = ProfileInterpretation.model_json_schema()
    json.dumps(schema)
    assert set(schema["required"]) == {"classification"} and "refuted_if" in schema["$defs"]["ProposedQuery"]["required"]


@pytest.mark.parametrize("make", [
    lambda: cls(confidence=1.5), lambda: cls(log_type="Web Access"), lambda: cls(rationale=" "),
    lambda: query(id="X"), lambda: query(sql="SELECT 1"), lambda: query(sql="SELECT " + "a" * 5000),
    lambda: ProposedQuery(id="abc", hypothesis="h", sql="SELECT 1 FROM logs", expected_if_true="e", priority="high"),
    lambda: MappingReview(action="inventar", canonical="user_id", field="uid", reason="r"),
    lambda: AnalystQuestion(question="q", why_it_matters="w", extra="no"),
])
def test_el_esquema_rechaza_formas_invalidas(make):
    with pytest.raises(ValidationError):
        make()


# --- revisión ------------------------------------------------------------------------------------------------------
def test_lo_valido_se_conserva_y_no_se_modifica_la_entrada(columns, sandbox):
    raw = interp(proposed_queries=[query()], analyst_questions=[AnalystQuestion(question="¿Zona horaria?", why_it_matters="w")],
                 mapping_review=[MappingReview(action="confirm", canonical="user_id", field="uid", reason="r")])
    before = raw.model_dump()
    out = review_interpretation(raw, make_profile(), columns, sandbox=sandbox)
    assert out.discarded == () and out.interpretation == raw and raw.model_dump() == before


def test_las_consultas_invalidas_se_descartan_con_su_codigo_y_las_validas_siguen(columns, sandbox):
    raw = interp(proposed_queries=[
        query("ok_uno"), query("borra_todo", "DROP TABLE logs"), query("columna_falsa", "SELECT nope FROM logs"),
        query("sin_datos", "SELECT 1 AS uno"), query("ok_dos", "SELECT count(*) FROM logs"),
    ])
    out = review_interpretation(raw, make_profile(), columns, sandbox=sandbox)
    assert [q.id for q in out.interpretation.proposed_queries] == ["ok_uno", "ok_dos"]
    assert codes(out, "query") == [("borra_todo", "policy_rejected"), ("columna_falsa", "sql_error"), ("sin_datos", "no_logs_reference")]


def test_un_id_repetido_se_descarta(columns, sandbox):
    out = review_interpretation(interp(proposed_queries=[query("misma"), query("misma", "SELECT count(*) FROM logs")]),
                                make_profile(), columns, sandbox=sandbox)
    assert len(out.interpretation.proposed_queries) == 1 and codes(out) == [("misma", "duplicate_id")]


def test_se_acepta_hasta_el_tope_de_validas_y_el_resto_se_anota_sin_ejecutarse(columns, sandbox):
    queries = [query(f"consulta_{i:02d}") for i in range(MAX_QUERIES + 2)]
    out = review_interpretation(interp(proposed_queries=queries), make_profile(), columns, sandbox=sandbox)
    assert len(out.interpretation.proposed_queries) == MAX_QUERIES
    assert [c for _, c in codes(out)] == ["over_limit"] * 2


def test_un_tope_distinto_se_respeta(columns, sandbox):
    out = review_interpretation(interp(proposed_queries=[query("uno_a"), query("dos_b")]), make_profile(), columns,
                                max_queries=1, sandbox=sandbox)
    assert [q.id for q in out.interpretation.proposed_queries] == ["uno_a"]


def test_las_consultas_salen_ordenadas_por_prioridad_respetando_el_orden_dentro_de_cada_una(columns, sandbox):
    raw = interp(proposed_queries=[query("baja_a", priority="low"), query("alta_a", priority="high"),
                                   query("media_a", priority="medium"), query("alta_b", priority="high")])
    out = review_interpretation(raw, make_profile(), columns, sandbox=sandbox)
    assert [q.id for q in out.interpretation.proposed_queries] == ["alta_a", "alta_b", "media_a", "baja_a"]


def test_las_preguntas_al_analista_tienen_tope(columns, sandbox):
    qs = [AnalystQuestion(question=f"pregunta {i}", why_it_matters="w") for i in range(7)]
    out = review_interpretation(interp(analyst_questions=qs), make_profile(), columns, sandbox=sandbox)
    assert len(out.interpretation.analyst_questions) == 5 and [c for _, c in codes(out, "question")] == ["over_limit"] * 2


def test_la_evidencia_inexistente_se_quita_pero_la_clasificacion_se_conserva(columns, sandbox):
    out = review_interpretation(interp(classification=cls(evidence_fields=["path", "campo_inventado"])),
                                make_profile(), columns, sandbox=sandbox)
    assert out.interpretation.classification.evidence_fields == ["path"]
    assert out.interpretation.classification.log_type == "web_access"
    assert codes(out, "evidence") == [("campo_inventado", "unknown_field")]


@pytest.mark.parametrize("item, code", [
    (MappingReview(action="confirm", canonical="inventado", field="uid", reason="r"), "unknown_canonical"),
    (MappingReview(action="confirm", canonical="user_id", field="no_existe", reason="r"), "unknown_field"),
    (MappingReview(action="confirm", canonical="user_id", field="extra", reason="r"), "not_in_profile_mapping"),
    (MappingReview(action="reject", canonical="session_id", field="uid", reason="r"), "not_in_profile_mapping"),
    (MappingReview(action="change", canonical="session_id", field="extra", reason="r"), "not_mapped_yet"),
    (MappingReview(action="add", canonical="user_id", field="extra", reason="r"), "already_mapped"),
])
def test_las_opiniones_de_mapeo_que_no_se_sostienen_se_descartan(columns, sandbox, item, code):
    out = review_interpretation(interp(mapping_review=[item]), make_profile(), columns, sandbox=sandbox)
    assert out.interpretation.mapping_review == [] and [c for _, c in codes(out, "mapping")] == [code]


@pytest.mark.parametrize("item", [
    MappingReview(action="confirm", canonical="user_id", field="uid", reason="r"),
    MappingReview(action="reject", canonical="status_code", field="code", reason="r"),
    MappingReview(action="change", canonical="user_id", field="extra", reason="r"),
    MappingReview(action="add", canonical="session_id", field="extra", reason="r"),
])
def test_las_opiniones_de_mapeo_coherentes_se_aceptan(columns, sandbox, item):
    out = review_interpretation(interp(mapping_review=[item]), make_profile(), columns, sandbox=sandbox)
    assert out.interpretation.mapping_review == [item] and out.discarded == ()


def test_sin_sandbox_propio_la_revision_crea_y_cierra_el_suyo(columns):
    out = review_interpretation(interp(proposed_queries=[query()]), make_profile(), columns)
    assert len(out.interpretation.proposed_queries) == 1


def test_una_consulta_sobre_una_columna_no_mapeada_falla_aqui_y_no_en_la_investigacion():
    profile = make_profile({"uri": "path"}, with_timestamp=False)
    out = review_interpretation(interp(proposed_queries=[query("por_usuario", "SELECT user_id FROM logs")]),
                                profile, columns_from_profile(profile))
    assert out.interpretation.proposed_queries == [] and codes(out) == [("por_usuario", "sql_error")]
