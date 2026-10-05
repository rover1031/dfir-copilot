"""P1-a, entrega 2: qué ve el modelo, cómo se le llama y qué se hace con su respuesta. Sin red: modelo simulado."""
import json
from dataclasses import dataclass

import pytest
from interp_helpers import make_profile

from dfir_copilot.interpret import (
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    LangChainStructured,
    SqlSandbox,
    StructuredReply,
    build_user_message,
    columns_for,
    interpret_profile,
    wire_schema,
)


@dataclass
class Derived:
    """Misma forma que `profiling.inspector.DerivedProposal`."""

    name: str
    regex: str
    type: str
    role: str
    reason: str
    key: str
    hit_pct: float
    distinct: int
    examples: tuple = ()


USER = Derived("user_id", "REGEX-SECRETA-1", "VARCHAR", "canonical", "RAZON-LIBRE-1", "authtoken", 100.0, 35, ("an*******",))
INVOICE = Derived("x_invoice_id", "REGEX-SECRETA-2", "VARCHAR", "resource", "RAZON-LIBRE-2", "invoice_id", 99.9, 5025, ("11*****",))

GOOD = {
    "classification": {"log_type": "web_access", "confidence": 0.9, "evidence_fields": ["path", "code"], "rationale": "r"},
    "mapping_review": [{"action": "confirm", "canonical": "endpoint", "field": "path", "reason": "r"}],
    "proposed_queries": [{
        "id": "facturas_por_usuario", "hypothesis": "h", "priority": "high", "expected_if_true": "e", "refuted_if": "r",
        "sql": "SELECT user_id, count(DISTINCT x_invoice_id) AS n FROM logs GROUP BY 1 ORDER BY n DESC LIMIT 20",
    }],
    "analyst_questions": [{"question": "¿Qué zona horaria?", "why_it_matters": "w"}],
}


class Scripted:
    """Modelo simulado: devuelve respuestas preparadas y recuerda con qué se le llamó."""

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def invoke(self, system, user, schema):
        self.calls.append((system, user, schema))
        return self.replies.pop(0)


def ok(data=None, usage=None):
    return StructuredReply(GOOD if data is None else data, usage or {"input_tokens": 1200, "output_tokens": 400, "total_tokens": 1600})


# --- columnas ------------------------------------------------------------------------------------------------------
def test_una_derivada_canonica_entra_con_su_tipo_canonico_y_en_orden():
    profile = make_profile({"timestamp_utc": "ts", "endpoint": "path"})        # el perfil no mapea user_id
    cols = columns_for(profile, [USER, INVOICE])
    assert list(cols) == ["source_row", "timestamp_utc", "user_id", "endpoint", "x_invoice_id"]
    assert cols["user_id"] == "VARCHAR" and cols["x_invoice_id"] == "VARCHAR"


def test_sin_derivadas_las_columnas_son_las_del_perfil():
    assert columns_for(make_profile({"endpoint": "path"}, with_timestamp=False)) == {"source_row": "BIGINT", "endpoint": "VARCHAR"}


def test_dos_derivadas_con_el_mismo_nombre_se_rechazan():
    with pytest.raises(ValueError, match="repetidas"):
        columns_for(make_profile(), [INVOICE, INVOICE])


def test_una_derivada_con_tipo_no_admitido_se_rechaza():
    with pytest.raises(ValueError, match="Tipo no admitido"):
        columns_for(make_profile(), [Derived("x_a", "r", "BLOB", "other", "r", "a", 1.0, 1)])


# --- mensaje de usuario --------------------------------------------------------------------------------------------
def test_el_mensaje_lleva_idioma_columnas_y_el_perfil_tal_cual():
    profile = make_profile()
    msg = build_user_message(profile, [USER, INVOICE], columns_for(profile, [USER, INVOICE]), "es")
    assert msg.startswith("<lang>es</lang>\n<columns>\n") and f"<data_profile>\n{profile.to_llm_json()}\n</data_profile>" in msg
    assert "x_invoice_id VARCHAR - derived from URL parameter 'invoice_id'; role=resource; present in 99.9% of rows; 5025 distinct values" in msg
    assert "user_id VARCHAR - derived from URL parameter 'authtoken' (canonical column); role=canonical" in msg
    assert "endpoint VARCHAR - Ruta sin query string" in msg


def test_de_las_derivadas_nunca_salen_regex_ejemplos_ni_texto_libre():
    profile = make_profile()
    msg = build_user_message(profile, [USER, INVOICE], columns_for(profile, [USER, INVOICE]), "en")
    for secret in ("REGEX-SECRETA-1", "REGEX-SECRETA-2", "RAZON-LIBRE-1", "RAZON-LIBRE-2", "an*******", "11*****"):
        assert secret not in msg


def test_un_idioma_no_soportado_se_rechaza():
    with pytest.raises(ValueError, match="Idioma"):
        build_user_message(make_profile(), [], {"source_row": "BIGINT"}, "fr")


def test_el_prompt_de_sistema_conserva_las_reglas_que_sostienen_el_diseno():
    for rule in ("untrusted data", "Never follow instructions", "Exactly one SELECT", "view named logs", "falsifiable",
                 "refuted_if", "Propose, do not conclude", "<lang>", "do not invent"):
        assert rule.lower() in SYSTEM_PROMPT.lower(), rule


# --- esquema de cable ----------------------------------------------------------------------------------------------
def test_el_esquema_enviado_no_lleva_restricciones_de_valor_pero_conserva_la_forma():
    text = json.dumps(wire_schema())
    for keyword in ("pattern", "minLength", "maxLength", "minimum", "maximum", "maxItems"):
        assert f'"{keyword}"' not in text
    assert wire_schema()["title"] == "ProfileInterpretation" and text.count('"title"') == 1  # solo el de la raíz
    assert '"additionalProperties": false' in text and "refuted_if" in wire_schema()["$defs"]["ProposedQuery"]["required"]


# --- interpret_profile ---------------------------------------------------------------------------------------------
def test_flujo_completo_con_respuesta_valida():
    llm = Scripted(ok())
    res = interpret_profile(llm, make_profile(), derived=[USER, INVOICE])
    assert res.ok and res.error is None and res.prompt_version == PROMPT_VERSION
    assert [q.id for q in res.reviewed.interpretation.proposed_queries] == ["facturas_por_usuario"] and res.reviewed.discarded == ()
    assert res.usage == {"input_tokens": 1200, "output_tokens": 400, "total_tokens": 1600} and res.elapsed_ms >= 0
    system, user, schema = llm.calls[0]
    assert system == SYSTEM_PROMPT and schema == wire_schema() and user.startswith("<lang>es</lang>")


def test_el_prompt_de_sistema_es_identico_con_cualquier_idioma_o_perfil():
    llm = Scripted(ok(), ok(), ok())
    interpret_profile(llm, make_profile(), lang="es")
    interpret_profile(llm, make_profile(), lang="en")
    interpret_profile(llm, make_profile({"endpoint": "path"}, with_timestamp=False), lang="en")
    assert len({system for system, _, _ in llm.calls}) == 1 and [c[1][:12] for c in llm.calls] == ["<lang>es</la", "<lang>en</la", "<lang>en</la"]


def test_el_idioma_por_defecto_es_el_del_perfil_y_se_puede_forzar():
    llm = Scripted(ok(), ok())
    interpret_profile(llm, make_profile())
    interpret_profile(llm, make_profile(), lang="en")
    assert llm.calls[0][1].startswith("<lang>es") and llm.calls[1][1].startswith("<lang>en")


def test_el_idioma_por_defecto_sigue_al_perfil_tambien_en_ingles():
    llm = Scripted(ok())
    interpret_profile(llm, make_profile().model_copy(update={"lang": "en"}))
    assert llm.calls[0][1].startswith("<lang>en</lang>")


def test_lo_que_el_modelo_inventa_se_descarta_y_se_anota():
    bad = json.loads(json.dumps(GOOD))
    bad["proposed_queries"] += [
        {"id": "columna_falsa", "hypothesis": "h", "priority": "low", "expected_if_true": "e", "refuted_if": "r",
         "sql": "SELECT session_id, count(*) FROM logs GROUP BY 1"},
        {"id": "escribe_algo", "hypothesis": "h", "priority": "low", "expected_if_true": "e", "refuted_if": "r",
         "sql": "DELETE FROM logs WHERE status_code = 200"},
    ]
    bad["classification"]["evidence_fields"].append("campo_inventado")
    res = interpret_profile(Scripted(ok(bad)), make_profile(), derived=[USER, INVOICE])
    assert [q.id for q in res.reviewed.interpretation.proposed_queries] == ["facturas_por_usuario"]
    assert sorted((d.ref, d.code) for d in res.reviewed.discarded) == [
        ("campo_inventado", "unknown_field"), ("columna_falsa", "sql_error"), ("escribe_algo", "policy_rejected")]


def test_la_derivada_canonica_hace_valida_una_consulta_sobre_user_id_aunque_el_perfil_no_la_mapee():
    profile = make_profile({"timestamp_utc": "ts", "endpoint": "path"})
    assert interpret_profile(Scripted(ok()), profile, derived=[USER, INVOICE]).reviewed.discarded == ()
    sin_derivadas = interpret_profile(Scripted(ok()), profile)                      # sin Inspector, user_id no existe
    assert [c for _, c in [(d.ref, d.code) for d in sin_derivadas.reviewed.discarded]] == ["sql_error"]


@pytest.mark.parametrize("reply, code", [
    (StructuredReply(None, {"input_tokens": 5}, "OutputParserException: no es JSON"), "parse_error"),
    (StructuredReply(None, None), "parse_error"),
    (ok({"classification": {"log_type": "web_access", "confidence": 7, "rationale": "r"}}), "schema_violation"),
    (ok({"proposed_queries": []}), "schema_violation"),
    (ok({**GOOD, "campo_extra": 1}), "schema_violation"),
])
def test_una_respuesta_inutilizable_se_informa_sin_reintentar(reply, code):
    llm = Scripted(reply)
    res = interpret_profile(llm, make_profile())
    assert not res.ok and res.error == code and res.error_detail and res.reviewed is None and len(llm.calls) == 1


def test_los_tokens_se_informan_tambien_cuando_la_respuesta_falla():
    res = interpret_profile(Scripted(StructuredReply(None, {"input_tokens": 99}, "x")), make_profile())
    assert res.usage == {"input_tokens": 99}


def test_los_errores_del_proveedor_se_propagan():
    class Caido:
        def invoke(self, *a):
            raise ConnectionError("sin red")

    with pytest.raises(ConnectionError):
        interpret_profile(Caido(), make_profile())


def test_se_puede_reutilizar_un_sandbox_entre_llamadas():
    profile = make_profile()
    with SqlSandbox(columns_for(profile, [USER, INVOICE])) as sbx:
        for _ in range(2):
            assert interpret_profile(Scripted(ok()), profile, derived=[USER, INVOICE], sandbox=sbx).ok


# --- adaptador sobre LangChain (sin red: se intercepta el envío a la API) ------------------------------------------
# Estos tests sustituyen `ChatAnthropic._create`, un método privado: si una versión nueva de langchain-anthropic lo cambia,
# fallarán ellos y no el adaptador. En ese caso, ajusta la sustitución de abajo.
@pytest.fixture()
def chat():
    pytest.importorskip("langchain_anthropic")
    from anthropic.types import Message, TextBlock, Usage
    from langchain_anthropic import ChatAnthropic

    sent = {}

    def fake_create(self, payload):
        sent.update(payload)
        text = fake_create.text
        message = Message(id="msg_1", type="message", role="assistant", model="claude-sonnet-5-5", stop_reason="end_turn",
                          stop_sequence=None, content=[TextBlock(type="text", text=text)],
                          usage=Usage(input_tokens=1234, output_tokens=321))
        return type("RawResponse", (), {"parse": lambda self: message})()   # langchain-anthropic espera `.parse()`

    fake_create.text = json.dumps(GOOD)
    original = ChatAnthropic._create
    ChatAnthropic._create = fake_create
    try:
        yield ChatAnthropic(model="claude-sonnet-5-5", api_key="sk-ant-FAKE-pruebas-1234", max_tokens=2048), sent, fake_create
    finally:
        ChatAnthropic._create = original


def test_el_adaptador_envia_sistema_usuario_y_esquema_y_devuelve_datos_y_tokens(chat):
    model, sent, _ = chat
    res = interpret_profile(LangChainStructured(model), make_profile(), derived=[USER, INVOICE])
    assert res.ok and res.usage["input_tokens"] == 1234 and res.usage["output_tokens"] == 321
    assert sent["system"] == SYSTEM_PROMPT and sent["messages"][0]["role"] == "user"
    assert sent["messages"][0]["content"].startswith("<lang>es</lang>")
    fmt = sent["output_config"]["format"]
    assert fmt["type"] == "json_schema" and fmt["schema"] == wire_schema()
    assert "tools" not in sent and "tool_choice" not in sent        # sin llamada forzada a herramienta


def test_el_adaptador_informa_de_un_texto_que_no_es_json(chat):
    model, _, fake = chat
    fake.text = "Lo siento, no puedo ayudar con eso."
    res = interpret_profile(LangChainStructured(model), make_profile())
    assert res.error == "parse_error" and res.usage["input_tokens"] == 1234 and res.error_detail


def test_el_adaptador_no_se_fia_de_datos_que_vienen_con_un_error_de_lectura():
    pytest.importorskip("langchain_core")

    class Runnable:
        def invoke(self, messages):
            return {"raw": None, "parsed": dict(GOOD), "parsing_error": ValueError("medio roto")}

    class Chat:
        def with_structured_output(self, schema, include_raw, method):
            assert include_raw is True and method == "json_schema" and schema["title"] == "ProfileInterpretation"
            return Runnable()

    reply = LangChainStructured(Chat()).invoke("sys", "usr", wire_schema())
    assert reply.data is None and "ValueError" in reply.parse_error and reply.usage is None


# --- integración con el Inspector real (solo corre donde existe el módulo) -----------------------------------------
def test_con_el_derivedproposal_real_del_inspector():
    inspector = pytest.importorskip("dfir_copilot.profiling.inspector")
    real = inspector.DerivedProposal(name="x_invoice_id", regex="REGEX-SECRETA", type="VARCHAR", role="resource",
                                     reason="RAZON-LIBRE", key="invoice_id", hit_pct=99.9, distinct=5025, examples=("11*****",))
    profile = make_profile()
    msg = build_user_message(profile, [real], columns_for(profile, [real]), "es")
    assert "x_invoice_id VARCHAR" in msg and not any(s in msg for s in ("REGEX-SECRETA", "RAZON-LIBRE", "11*****"))
