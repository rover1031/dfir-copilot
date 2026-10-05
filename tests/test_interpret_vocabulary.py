"""P1-a, entrega 4: los dos vocabularios (perfilador y tabla) y el perfil REAL de three_months.csv como regresión.

Origen: la primera llamada real descartó `confirm:timestamp` por `unknown_canonical` y el modelo nunca vio `endpoint` ni
`query_string`, porque el perfilador dice `timestamp`/`uri` y la tabla dice `timestamp_utc`/`endpoint`/`query_string`.
"""
import hashlib

import pytest
from interp_helpers import GOOD, REAL_DERIVED, Scripted, make_profile, ok, real_profile

from dfir_copilot.interpret import (
    CHARS_PER_TOKEN,
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    TABLE_COLUMNS,
    ProfileInterpretation,
    build_user_message,
    columns_for,
    columns_from_profile,
    estimate_tokens,
    interpret_profile,
    profile_vocabulary,
    review_interpretation,
    wire_schema,
)
from dfir_copilot.profiling.schema_mapper import SchemaMapper
from dfir_copilot.schema import CANONICAL_NAMES

# Las columnas del Parquet real de este caso (DESCRIBE sobre processed/three_months.parquet).
REAL_PARQUET_COLUMNS = {
    "source_row": "BIGINT", "timestamp_utc": "TIMESTAMP WITH TIME ZONE", "src_ip": "VARCHAR", "user_id": "VARCHAR",
    "session_id": "VARCHAR", "http_method": "VARCHAR", "host": "VARCHAR", "endpoint": "VARCHAR", "query_string": "VARCHAR",
    "status_code": "SMALLINT", "user_agent": "VARCHAR", "referer": "VARCHAR", "bytes_out": "BIGINT", "timestamp_raw": "VARCHAR",
    "x_authtoken_type": "VARCHAR", "x_invoice_id": "BIGINT", "x_site_id": "VARCHAR",
}


REAL_CLASSIFICATION = {"log_type": "web", "confidence": 0.9, "evidence_fields": ["http_method", "http_uri"], "rationale": "r"}


def review(mapping_items, derived=("user_id",)):
    raw = ProfileInterpretation.model_validate({**GOOD, "classification": REAL_CLASSIFICATION, "proposed_queries": [],
                                                "mapping_review": mapping_items})
    return review_interpretation(raw, real_profile(), columns_for(real_profile(), REAL_DERIVED), derived_canonical=derived)


def item(action, canonical, field, reason="r"):
    return {"action": action, "canonical": canonical, "field": field, "reason": reason}


# --- columnas con el perfil real -----------------------------------------------------------------------------------
def test_el_perfil_real_valida_y_las_columnas_visibles_son_las_que_existen_en_el_parquet_real():
    cols = columns_for(real_profile(), REAL_DERIVED)
    assert list(cols) == ["source_row", "timestamp_utc", "src_ip", "user_id", "http_method", "host", "endpoint", "query_string",
                          "status_code", "user_agent", "referer", "timestamp_raw", "x_authtoken_type", "x_invoice_id", "x_site_id"]
    missing = set(cols) - set(REAL_PARQUET_COLUMNS)
    assert not missing, f"el modelo vería columnas que el Parquet real no tiene: {missing}"
    assert {n: REAL_PARQUET_COLUMNS[n] for n in ("x_invoice_id", "status_code")} == {"x_invoice_id": "BIGINT", "status_code": "SMALLINT"}
    assert cols["x_invoice_id"] == "BIGINT" and cols["status_code"] == "SMALLINT"


def test_las_columnas_canonicas_sin_mapeo_existen_en_el_parquet_pero_el_modelo_no_las_ve():
    cols = columns_for(real_profile(), REAL_DERIVED)
    assert {"session_id", "bytes_out"} <= set(REAL_PARQUET_COLUMNS) and not {"session_id", "bytes_out"} & set(cols)


@pytest.mark.parametrize("canonical, table_columns", list(TABLE_COLUMNS.items()))
def test_cada_nombre_del_perfilador_se_traduce_a_sus_columnas_de_tabla(canonical, table_columns):
    profile = make_profile({canonical: "path"}, with_timestamp=False)
    assert set(table_columns) <= set(columns_from_profile(profile))
    assert canonical not in columns_from_profile(profile)   # el nombre del perfilador no es una columna


def test_con_marca_de_tiempo_en_el_perfil_hay_utc_y_texto_original_aunque_el_mapeo_no_la_liste():
    cols = columns_from_profile(make_profile({"uri": "path"}, with_timestamp=True))
    assert {"timestamp_utc", "timestamp_raw"} <= set(cols)


def test_un_nombre_canonico_del_perfilador_sin_columna_en_la_tabla_se_ignora_sin_romper():
    profile = make_profile({"dst_ip": "ip", "uri": "path"}, with_timestamp=False)    # dst_ip: la tabla actual no lo tiene
    assert list(columns_from_profile(profile)) == ["source_row", "endpoint", "query_string"]


def test_el_perfilador_y_la_tabla_difieren_solo_donde_se_declara():
    only_profiler = profile_vocabulary() - set(CANONICAL_NAMES)
    assert {"timestamp", "uri"} <= only_profiler                       # los dos que traduce TABLE_COLUMNS
    assert profile_vocabulary() == frozenset(SchemaMapper().canon)


# --- revisión del mapeo con el vocabulario correcto ----------------------------------------------------------------
def test_las_dos_opiniones_que_se_descartaron_en_la_llamada_real_ahora_son_validas():
    out = review([item("confirm", "timestamp", "timestamp"), item("confirm", "uri", "http_uri"),
                  item("confirm", "status_code", "http_staus"), item("change", "user_id", "http_uri")])
    assert out.discarded == () and len(out.interpretation.mapping_review) == 4


def test_cambiar_user_id_sin_derivada_sigue_descartandose():
    out = review([item("change", "user_id", "http_uri")], derived=())
    assert [(d.ref, d.code) for d in out.discarded] == [("change:user_id", "not_mapped_yet")]


@pytest.mark.parametrize("canonical", ["timestamp_utc", "endpoint", "query_string", "source_row", "inventado"])
def test_un_nombre_de_la_tabla_no_vale_como_canonico_del_perfilador(canonical):
    out = review([item("confirm", canonical, "timestamp")])
    assert [d.code for d in out.discarded] == ["unknown_canonical"] and out.interpretation.mapping_review == []


def test_añadir_un_canonico_ya_derivado_se_descarta_como_ya_mapeado():
    out = review([item("add", "user_id", "http_uri")])
    assert [d.code for d in out.discarded] == ["already_mapped"]


# --- lo que ve el modelo -------------------------------------------------------------------------------------------
def test_el_mensaje_lista_los_nombres_canonicos_del_perfilador_y_las_columnas_de_la_tabla():
    msg = build_user_message(real_profile(), REAL_DERIVED, columns_for(real_profile(), REAL_DERIVED), "es")
    names = msg.split("<canonical_names>")[1].split("</canonical_names>")[0].split(", ")
    assert names == sorted(SchemaMapper().canon) and {"timestamp", "uri"} <= set(names)
    for column in ("endpoint VARCHAR", "query_string VARCHAR", "timestamp_raw VARCHAR - Original timestamp text"):
        assert column in msg


def test_el_prompt_explica_la_traduccion_y_se_genera_desde_la_misma_tabla_de_traduccion():
    for profiler_name, columns in TABLE_COLUMNS.items():
        assert f"profiler name '{profiler_name}' becomes column(s) {' and '.join(columns)}" in SYSTEM_PROMPT
    assert "<canonical_names>" in SYSTEM_PROMPT and "{translation}" not in SYSTEM_PROMPT


def test_interpret_profile_trata_una_derivada_canonica_como_ya_mapeada():
    reply = ok({**GOOD, "classification": REAL_CLASSIFICATION, "proposed_queries": [],
                "mapping_review": [item("change", "user_id", "http_uri"), item("add", "user_id", "http_uri")]})
    res = interpret_profile(Scripted(reply), real_profile(), derived=REAL_DERIVED)
    assert [m.action for m in res.reviewed.interpretation.mapping_review] == ["change"]
    assert [(d.ref, d.code) for d in res.reviewed.discarded] == [("add:user_id", "already_mapped")]


def test_la_llamada_completa_con_el_perfil_real_es_coherente_de_punta_a_punta():
    reply = ok({**GOOD, "classification": REAL_CLASSIFICATION, "mapping_review": [item("confirm", "timestamp", "timestamp")], "proposed_queries": [
        {"id": "por_ruta", "hypothesis": "h", "priority": "low", "expected_if_true": "e", "refuted_if": "r",
         "sql": "SELECT endpoint, count(*) AS n, min(timestamp_raw) AS primero FROM logs GROUP BY 1"}]})
    llm = Scripted(reply)
    res = interpret_profile(llm, real_profile(), derived=REAL_DERIVED)
    assert res.ok and res.reviewed.discarded == ()                       # antes de la corrección: unknown_canonical y sql_error
    assert [q.id for q in res.reviewed.interpretation.proposed_queries] == ["por_ruta"]


# --- estimador de tokens -------------------------------------------------------------------------------------------
def test_el_estimador_cuenta_texto_y_esquemas_con_la_razon_medida():
    assert CHARS_PER_TOKEN == 2.1 and estimate_tokens("x" * 2100) == 1000
    assert estimate_tokens("x" * 1050, "y" * 1050) == 1000
    assert estimate_tokens({"a": "b"}) == round(len('{"a":"b"}') / 2.1)


def test_la_estimacion_con_el_esquema_se_acerca_a_lo_medido_en_la_llamada_real():
    """Medido: 12 326 caracteres (sistema + usuario + esquema) = 5 956 tokens de entrada. Tolerancia amplia: es una estimación."""
    assert abs(estimate_tokens("s" * 3195, "u" * 7190, "e" * 1941) - 5956) / 5956 < 0.05
    sin_esquema = estimate_tokens("s" * 3195, "u" * 7190)
    assert sin_esquema < 5956 * 0.9          # olvidar el esquema subestimaría; por eso smoke y notebook lo incluyen


def test_el_esquema_de_respuesta_forma_parte_de_la_estimacion_de_smoke(capsys):
    from dfir_copilot.interpret.smoke import main

    def inspector(path, lang):
        class D:
            profile, derived, status = make_profile(), [], "ready"
        return D()

    profile = make_profile()
    main(["x.csv", "--dry-run"], inspector=inspector)
    out = capsys.readouterr().out
    user = build_user_message(profile, [], columns_for(profile, []), "es")
    esperado = estimate_tokens(SYSTEM_PROMPT, user, wire_schema())
    sin_esquema = estimate_tokens(SYSTEM_PROMPT, user)
    assert f"unos {esperado:,} tokens de entrada" in out and esperado != sin_esquema


# --- el texto del prompt y su versión van juntos -------------------------------------------------------------------
# Si cambias SYSTEM_PROMPT, este test falla: sube PROMPT_VERSION y registra aquí la huella nueva. Así dos resultados con la
# misma versión se hicieron siempre con el mismo prompt y comparar versiones tiene sentido.
PROMPT_FINGERPRINTS = {"p1a-2": "8f59e01f4845", "p1a-3": "5f0c06900a3c"}  # historial: cada versión, su texto


def test_el_texto_del_prompt_coincide_con_la_version_registrada():
    assert PROMPT_VERSION in PROMPT_FINGERPRINTS, f"registra la huella de {PROMPT_VERSION}"
    assert hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()[:12] == PROMPT_FINGERPRINTS[PROMPT_VERSION], \
        "el prompt cambió: sube PROMPT_VERSION y registra la huella nueva"
