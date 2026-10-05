"""P1-b.3c: tope de tokens (por pregunta y por caso), notas del analista visibles en cada pregunta, retirar hipótesis y deriva de
esquema en el replay. Lo esencial: el presupuesto corta con limpieza (sin llamadas colgantes), no cuenta dos veces una pregunta con
aprobación, y las notas llegan al modelo solo traducidas a alias."""
import json

import pytest
from test_agent import FALSIFIER, FULL, STATEMENT, call, say
from test_privacy_agent import _case, leaks
from test_privacy_text import fake

from dfir_copilot.agent.graph import DEFAULT_MAX_TOKENS, TokenBudgetExceeded, build_agent
from dfir_copilot.agent.hypotheses import HypothesisBook, HypothesisError, hypothesis_id
from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.evidence.ledger import Ledger
from dfir_copilot.privacy import AmbiguousText, privacy_context
from dfir_copilot.synthetic import make_idor_dataset

OTHER = "Las cuentas del grupo operan siempre desde las mismas cinco IPs sin que otras cuentas las usen"


@pytest.fixture()
def setup(tmp_path, make_engine, scripted):
    engine, _ = make_engine()
    ledger = Ledger.open("B", engine, analyst="eder", root=tmp_path / "ledger")

    def make(script, **kw):
        llm = scripted(script)
        return build_agent(engine, ledger, llm, allow_real=True, **kw), llm

    return make, ledger, engine


def briefing_of(llm, question):
    return next(str(m.content) for m in llm.log[-1]["messages"] if f"PREGUNTA DEL ANALISTA:\n{question}" in str(m.content))


# --- tope de tokens ---------------------------------------------------------------------------------------------

def test_el_tope_por_pregunta_es_210000_por_defecto_y_se_valida(setup):
    make, _, _ = setup
    agent, _ = make([say("x")])
    assert DEFAULT_MAX_TOKENS == 210_000 and agent.max_tokens == 210_000 and agent.budget()["per_question"] == 210_000
    for bad in (0, -5, True, 1.5):
        with pytest.raises(ValueError, match="entero positivo"):
            make([say("x")], max_tokens=bad)
    with pytest.raises(ValueError, match="max_tokens_case"):
        make([say("x")], max_tokens_case=0)


def test_el_tope_de_tokens_corta_con_limpieza(setup):
    """Cada llamada del guion gasta 15 tokens; con tope 40 se corta al 85 % (34): antes de la cuarta llamada."""
    make, ledger, _ = setup
    agent, llm = make([call("describe_dataset") for _ in range(4)], max_tokens=40)
    r = agent.ask("Investiga todo")
    assert r.status == "done" and r.cut_by == "tokens" and "tokens agotado" in r.answer
    assert len(llm.log) == 4 and llm.log[-1]["messages"][-1].content.startswith("AVISO DEL SISTEMA: PRESUPUESTO DE TOKENS")
    assert {c["tools_bound"] for c in llm.log} == {True}                            # no se altera el prefijo
    assert not agent.graph.get_state(agent._config("default")).values["messages"][-1].tool_calls   # sin llamadas colgantes
    assert ledger.entries("agent_turn")[-1]["data"]["cut_by"] == "tokens"


def test_el_corte_por_pasos_se_distingue_del_de_tokens(setup):
    make, ledger, _ = setup
    agent, _ = make([call("describe_dataset") for _ in range(3)], max_steps=2)
    r = agent.ask("Investiga todo")
    assert r.cut_by == "steps" and "pasos agotado" in r.answer
    assert ledger.entries("agent_turn")[-1]["data"]["cut_by"] == "steps"


def test_una_pregunta_normal_no_se_corta(setup):
    make, ledger, _ = setup
    agent, _ = make([call("describe_dataset"), say("Listo.")])
    r = agent.ask("¿Qué hay?")
    assert r.cut_by is None and ledger.entries("agent_turn")[-1]["data"]["cut_by"] is None


def test_el_tope_por_caso_se_calcula_desde_el_ledger_y_bloquea_antes_de_enviar(setup, scripted):
    make, ledger, engine = setup
    agent, llm = make([call("describe_dataset"), say("uno"), call("describe_dataset"), say("dos")], max_tokens_case=50)
    agent.ask("Primera")                                                            # 30 tokens
    assert agent.budget() == {"per_question": DEFAULT_MAX_TOKENS, "case_limit": 50, "case_used": 30, "case_left": 20}
    agent.ask("Segunda")                                                            # 60 en total: pasa el tope
    calls, turns = len(llm.log), len(ledger.entries("agent_turn"))
    with pytest.raises(TokenBudgetExceeded, match="60"):
        agent.ask("Tercera")
    assert len(llm.log) == calls and len(ledger.entries("agent_turn")) == turns     # nada se envió ni se registró
    again = build_agent(engine, ledger, scripted([say("x")]), allow_real=True, max_tokens_case=50)   # otro agente, mismo caso
    with pytest.raises(TokenBudgetExceeded):
        again.ask("Cuarta")


def test_una_pregunta_con_aprobacion_no_cuenta_dos_veces(setup):
    make, ledger, _ = setup
    agent, _ = make(FULL())
    agent.ask("¿Qué pasó?")
    r = agent.resolve("approve", "De acuerdo")
    assert r.tokens == 105 and agent.tokens_used() == 105                           # 7 llamadas de 15; no 90 + 105
    assert [e["data"]["tokens_delta"] for e in ledger.entries("agent_turn")] == [90, 15]


def test_los_turnos_anteriores_sin_delta_cuentan_solo_si_terminaron(setup):
    make, ledger, _ = setup
    agent, _ = make([say("x")])
    for status, tokens in (("needs_approval", 90), ("done", 105)):                   # formato anterior a P1-b.3c
        ledger.append("agent_turn", {"thread_id": "default", "question": "q", "status": status, "answer": None,
                                     "model": "m", "steps": 1, "tokens": tokens, "approvals": []})
    assert agent.tokens_used() == 105


# --- notas del analista -----------------------------------------------------------------------------------------

def test_la_nota_se_traduce_se_sella_y_el_modelo_la_ve_en_cada_pregunta(tmp_path, scripted):
    ws = _case(tmp_path, "C-NOTA")
    real = ws.engine()
    pseudo, ps = ws.pseudonymized()
    ledger = Ledger.open("N1", real, analyst="eder", root=tmp_path / "led")
    llm = scripted([say("a"), say("b")])
    agent = build_agent(pseudo, ledger, llm)
    res = agent.note("Confirmado con IAM: atacante00 usa 66.6.6.1", status="confirmed")
    alias_note = f"Confirmado con IAM: {ps.alias('user_id', 'atacante00')} usa {ps.alias('src_ip', '66.6.6.1')}"
    assert res.text == alias_note
    (entry,) = ledger.entries("note")
    assert entry["data"]["text"] == alias_note and entry["data"]["copy"] == pseudo.copy_id and entry["data"]["analyst"] == "eder"
    agent.ask("¿Y ahora?")
    first = briefing_of(llm, "¿Y ahora?")
    assert "NOTAS DEL ANALISTA" in first and alias_note in first and '"valoracion": "confirmed"' in first
    sent = "\n".join(str(m.content) for c in llm.log for m in c["messages"])
    assert not leaks(sent, {"atacante00", "66.6.6.1"}) and not leaks(ledger.path.read_text(encoding="utf-8"), {"atacante00", "66.6.6.1"})


def test_una_nota_por_otro_camino_no_se_muestra_solo_se_cuenta(tmp_path, scripted):
    ws = _case(tmp_path, "C-NOTA2")
    real = ws.engine()
    pseudo, _ = ws.pseudonymized()
    ledger = Ledger.open("N2", real, analyst="eder", root=tmp_path / "led")
    ledger.note("Apunte directo sobre atacante00 con su IP real", analyst="eder")     # sin sello: puede llevar valores reales
    llm = scripted([say("a")])
    build_agent(pseudo, ledger, llm).ask("Sigue")
    first = briefing_of(llm, "Sigue")
    assert '"notas_no_mostradas": 1' in first and "atacante00" not in first


def test_una_nota_ambigua_no_se_escribe(tmp_path, scripted):
    ws = _case(tmp_path, "C-NOTA3")
    real = ws.engine()
    pseudo, _ = ws.pseudonymized()
    ledger = Ledger.open("N3", real, analyst="eder", root=tmp_path / "led")
    agent = build_agent(pseudo, ledger, scripted([say("x")]), pseudonymizer=fake(pseudo, alias={"user_id": {"12345": "U-0001"}}))
    with pytest.raises(AmbiguousText):
        agent.note("Revisar la cuenta 12345")
    assert ledger.entries("note") == []
    assert agent.note("Hay 12345 filas", literal=("12345",)).text == "Hay 12345 filas"


def test_solo_se_muestran_las_ultimas_diez_notas(setup):
    make, ledger, _ = setup
    agent, llm = make([say("ok")])
    for i in range(1, 13):
        agent.note(f"nota número {i:02d}")
    agent.ask("¿Qué recuerdas?")
    first = briefing_of(llm, "¿Qué recuerdas?")
    assert "nota número 12" in first and "nota número 03" in first
    assert "nota número 02" not in first and "nota número 01" not in first


def test_sin_notas_el_briefing_no_cambia(setup):
    make, _, _ = setup
    agent, llm = make([say("ok")])
    agent.ask("Hola")
    assert "NOTAS DEL ANALISTA" not in briefing_of(llm, "Hola")


def test_el_prompt_pide_hipotesis_atomicas_y_alias_enumerados(setup, tmp_path):
    make, _, _ = setup
    agent, _ = make([say("x")])
    system = agent.system_prompt().content
    assert "UNA afirmación" in system and "notas del analista" in system and "retirada" in system
    ws = _case(tmp_path, "C-PROMPT")
    pseudo, _ = ws.pseudonymized()
    assert "no los abrevies con rangos" in privacy_context(pseudo.manifest)


# --- retirar hipótesis ------------------------------------------------------------------------------------------

def test_retirar_una_hipotesis_duplicada(setup):
    make, ledger, engine = setup
    agent, llm = make([say("ok")])
    old = agent.book.propose(STATEMENT, falsifier=FALSIFIER)[0]["hypothesis_id"]
    new = agent.book.propose(OTHER, falsifier=FALSIFIER)[0]["hypothesis_id"]
    item = agent.retire(old, "Duplicada: la reemplaza una versión mejor formulada", superseded_by=new)
    assert item["status"] == "retirada" and item["superseded_by"] == new and agent.retire(old, "otra vez")["status"] == "retirada"
    with pytest.raises(HypothesisError, match="ya está retirada"):
        agent.book.start_testing(old)
    reborn = HypothesisBook(ledger).get(old)
    assert reborn["status"] == "retirada" and reborn["superseded_by"] == new
    update = ledger.entries("hypothesis_update")[-1]["data"]
    assert update["decided_by"] == "eder" and update["requested_by"] == "analyst" and update["superseded_by"] == new
    agent.ask("Sigue")
    shown = briefing_of(llm, "Sigue")
    assert old in shown and '"estado": "retirada"' in shown and STATEMENT not in shown     # solo el id: no se vuelve a trabajar


def test_no_se_retira_lo_ya_decidido_ni_sin_motivo_ni_a_si_misma(setup):
    make, ledger, engine = setup
    agent, _ = make([say("ok")])
    book = agent.book
    hid = book.propose(STATEMENT, falsifier=FALSIFIER)[0]["hypothesis_id"]
    book.start_testing(hid)
    engine.query("SELECT count(DISTINCT user_id) FROM logs")
    ledger.record_queries(engine.history[-1:])
    ref = ledger.entries("query")[-1]["data"]["query_id"]
    check = {"ref": ref, "would_refute_if": "Hubiera más identidades de las esperadas", "observed": "El recuento coincide"}
    book.decide(book.request_decision(hid, "confirmada", [ref], "Lo respalda", [check]), True, "eder")
    with pytest.raises(HypothesisError, match="no se retira"):
        agent.retire(hid, "Ya no me gusta")
    other = book.propose(OTHER, falsifier=FALSIFIER)[0]["hypothesis_id"]
    with pytest.raises(HypothesisError, match="motivo"):
        agent.retire(other, "   ")
    with pytest.raises(HypothesisError, match="a sí misma"):
        agent.retire(other, "x", superseded_by=other)
    with pytest.raises(HypothesisError, match="desconocida"):
        agent.retire(other, "x", superseded_by="h-nada")
    assert book.get(other)["status"] == "propuesta" and hypothesis_id(OTHER) == other


def test_el_motivo_de_la_retirada_se_traduce_a_alias(tmp_path, scripted):
    ws = _case(tmp_path, "C-RET")
    real = ws.engine()
    pseudo, ps = ws.pseudonymized()
    ledger = Ledger.open("R1", real, analyst="eder", root=tmp_path / "led")
    agent = build_agent(pseudo, ledger, scripted([say("x")]))
    hid = agent.book.propose(STATEMENT, falsifier=FALSIFIER, copy=pseudo.copy_id)[0]["hypothesis_id"]
    agent.retire(hid, "La cuenta atacante00 ya está cubierta por otra hipótesis")
    note = ledger.entries("hypothesis_update")[-1]["data"]["note"]
    assert ps.alias("user_id", "atacante00") in note and not leaks(ledger.path.read_text(encoding="utf-8"), {"atacante00"})


# --- replay: deriva de esquema ----------------------------------------------------------------------------------

def test_un_describe_que_cambia_por_la_vista_no_es_una_alteracion_de_datos(tmp_path, engine_from_rows):
    rows, _ = make_idor_dataset()
    engine = engine_from_rows(rows)
    ledger = Ledger.open("D", engine, analyst="eder", root=tmp_path / "led")
    engine.query("DESCRIBE logs")
    engine.query("SELECT count(*) FROM logs")
    ledger.record_queries(engine.history)
    manifest_path = engine.parquet.with_suffix(".manifest.json")
    manifest = json.loads(manifest_path.read_text())
    manifest["timezone"].update({"assumed": "America/Santiago", "source": "declared", "verified": False})
    manifest_path.write_text(json.dumps(manifest))                                   # ahora la vista añade timestamp_local
    results = ledger.replay(QueryEngine(engine.parquet))
    drift = [r for r in results if r.get("schema_drift")]
    assert len(drift) == 1 and drift[0]["match"] is False and drift[0]["recorded_rows"] + 1 == drift[0]["replayed_rows"]
    assert [r for r in results if not r.get("schema_drift")] and all(r["match"] for r in results if not r.get("schema_drift"))
    last = ledger.entries("replay")[-1]["data"]
    assert last["mismatches"] == [] and last["schema_drift"] == [drift[0]["query_id"]]


def test_una_consulta_de_datos_que_no_coincide_sigue_siendo_un_mismatch(tmp_path, engine_from_rows):
    rows, _ = make_idor_dataset()
    engine = engine_from_rows(rows)
    ledger = Ledger.open("D2", engine, analyst="eder", root=tmp_path / "led")
    engine.query("SELECT count(*) FROM logs")
    ledger.record_queries([{**engine.history[-1], "result_sha256": "0" * 64}])        # mismas filas, otro contenido
    (r,) = ledger.replay(engine)
    assert r["match"] is False and "schema_drift" not in r
    last = ledger.entries("replay")[-1]["data"]
    assert last["mismatches"] == [r["query_id"]] and last["schema_drift"] == []
