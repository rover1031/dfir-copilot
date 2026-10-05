"""P1-b.3b: falsabilidad como estructura. Proponer exige el criterio de refutación (fijado antes de probar); confirmar exige al
menos un intento real de refutarla: una consulta que existe, salió bien y se ejecutó DESPUÉS de proponer. El analista ve ambas
cosas al aprobar. Lo que se puede comprobar por código se comprueba; lo demás (si de verdad buscaba refutarla) lo juzga él."""
import re

import pytest
from test_agent import FALSIFIER, FULL, HID, REFUTE_SQL, STATEMENT, call, propose, say
from test_privacy_agent import _case, leaks

from dfir_copilot.agent.graph import build_agent
from dfir_copilot.agent.hypotheses import HypothesisBook, HypothesisError
from dfir_copilot.evidence.ledger import Ledger

WOULD, SEEN = "Habría identidades ajenas al grupo en esas IPs", "Ninguna otra identidad usa esas IPs"


@pytest.fixture()
def env(tmp_path, make_engine):
    engine, _ = make_engine()
    ledger = Ledger.open("F", engine, analyst="eder", root=tmp_path / "ledger")
    engine.query("SELECT count(*) FROM logs")                                  # anterior a cualquier hipótesis
    ledger.record_queries(engine.history[-1:])
    before = ledger.entries("query")[-1]["data"]["query_id"]
    return ledger, HypothesisBook(ledger), before, engine


def run(ledger, engine, sql="SELECT count(DISTINCT user_id) FROM logs"):
    engine.query(sql)
    ledger.record_queries(engine.history[-1:])
    return ledger.entries("query")[-1]["data"]["query_id"]


def check(ref, would=WOULD, seen=SEEN):
    return {"ref": ref, "would_refute_if": would, "observed": seen}


# --- el registro: reglas objetivas ------------------------------------------------------------------------------

def test_el_criterio_se_guarda_al_proponer_y_sobrevive_a_un_reinicio(env):
    ledger, book, _, _ = env
    item, _ = book.propose(STATEMENT, falsifier="  Si hay otras   identidades en esas IPs ")
    assert item["falsifier"] == "Si hay otras identidades en esas IPs"          # espacios normalizados
    assert ledger.entries("hypothesis")[0]["data"]["falsifier"] == item["falsifier"]
    reborn = HypothesisBook(ledger).get(item["hypothesis_id"])
    assert reborn["falsifier"] == item["falsifier"] and reborn["seq"] == ledger.entries("hypothesis")[0]["seq"]


def test_una_hipotesis_sin_criterio_sigue_siendo_valida_en_el_registro(env):
    """Las anteriores a P1-b.3b (o las del analista) no lo tienen; el que está obligado a darlo es el agente."""
    _, book, _, _ = env
    item, _ = book.propose(STATEMENT)
    assert "falsifier" not in item


def test_confirmar_sin_intentos_de_refutacion_se_rechaza(env):
    ledger, book, before, _ = env
    hid = book.propose(STATEMENT, falsifier=FALSIFIER)[0]["hypothesis_id"]
    book.start_testing(hid)
    with pytest.raises(HypothesisError, match="refutation_checks"):
        book.request_decision(hid, "confirmada", [before], "Lo respalda")


def test_un_intento_anterior_a_la_hipotesis_no_cuenta(env):
    ledger, book, before, _ = env
    hid = book.propose(STATEMENT, falsifier=FALSIFIER)[0]["hypothesis_id"]
    book.start_testing(hid)
    with pytest.raises(HypothesisError, match="ANTES"):
        book.request_decision(hid, "confirmada", [before], "Lo respalda", [check(before)])


def test_un_id_inventado_o_una_consulta_fallida_no_cuentan(env):
    ledger, book, before, engine = env
    hid = book.propose(STATEMENT, falsifier=FALSIFIER)[0]["hypothesis_id"]
    book.start_testing(hid)
    with pytest.raises(Exception):  # noqa: B017,PT011 - DuckDB: la tabla no existe; la consulta queda como `error`
        engine.query("SELECT * FROM tabla_que_no_existe")
    ledger.record_queries(engine.history[-1:])
    failed = ledger.entries("query")[-1]["data"]
    assert failed["status"] == "error"
    for ref in ("q-inventado", failed["query_id"]):
        with pytest.raises(HypothesisError, match="no es una consulta ejecutada con éxito"):
            book.request_decision(hid, "confirmada", [before], "x", [check(ref)])


def test_hay_que_decir_que_la_habria_refutado_y_que_se_observo(env):
    ledger, book, before, engine = env
    hid = book.propose(STATEMENT, falsifier=FALSIFIER)[0]["hypothesis_id"]
    book.start_testing(hid)
    ref = run(ledger, engine)
    for bad in (check(ref, would="no"), check(ref, seen=""), check(ref, would="   ")):
        with pytest.raises(HypothesisError, match="would_refute_if"):
            book.request_decision(hid, "confirmada", [before], "x", [bad])


def test_un_intento_valido_queda_en_la_peticion_el_ledger_y_el_estado_reconstruido(env):
    ledger, book, before, engine = env
    hid = book.propose(STATEMENT, falsifier=FALSIFIER)[0]["hypothesis_id"]
    book.start_testing(hid)
    ref = run(ledger, engine)
    req = book.request_decision(hid, "confirmada", [before], "Lo respalda", [check(ref), check(ref)])
    assert len(req.refutation_checks) == 1 and req.refutation_checks[0]["ref"] == ref   # una vez por consulta
    book.decide(req, approve=True, analyst="eder")
    assert book.get(hid)["refutation_checks"] == [check(ref)]
    assert ledger.entries("hypothesis_update")[-1]["data"]["refutation_checks"] == [check(ref)]
    assert HypothesisBook(ledger).get(hid)["refutation_checks"] == [check(ref)] and ledger.verify().ok


def test_rechazar_no_guarda_los_intentos_y_refutar_no_los_exige(env):
    ledger, book, before, engine = env
    hid = book.propose(STATEMENT, falsifier=FALSIFIER)[0]["hypothesis_id"]
    book.start_testing(hid)
    ref = run(ledger, engine)
    book.decide(book.request_decision(hid, "confirmada", [before], "x", [check(ref)]), approve=False, analyst="eder")
    assert "refutation_checks" not in book.get(hid)
    req = book.request_decision(hid, "refutada", [before], "No encaja")             # refutar: sin intentos
    assert req.refutation_checks == ()


# --- el agente --------------------------------------------------------------------------------------------------

@pytest.fixture()
def setup(tmp_path, make_engine, scripted):
    engine, _ = make_engine()
    ledger = Ledger.open("FA", engine, analyst="eder", root=tmp_path / "ledger")

    def make(script):
        llm = scripted(script)
        return build_agent(engine, ledger, llm, allow_real=True), llm

    return make, ledger


def last_tool(llm):
    return str(llm.log[-1]["messages"][-1].content)


def test_proponer_sin_criterio_de_refutacion_se_rechaza(setup):
    make, ledger = setup
    agent, llm = make([call("propose_hypothesis", statement=STATEMENT, rationale="x"), say("fin")])
    assert agent.ask("Propón").status == "done"
    assert agent.book.all() == [] and ledger.entries("hypothesis") == []
    assert "argumentos inválidos" in last_tool(llm) and "falsifier" in last_tool(llm)


def test_confirmar_sin_intentos_no_llega_al_analista(setup):
    make, ledger = setup

    def confirm_without_checks(messages):
        ref = re.search(r"c-[0-9a-f]{12}", " ".join(str(m.content) for m in messages)).group(0)
        return call("update_hypothesis", hypothesis_id=HID, status="confirmada", evidence_refs=[ref], rationale="Cuatro señales")

    agent, llm = make([call("run_detectors"), propose(), call("update_hypothesis", hypothesis_id=HID, status="en_prueba"),
                       confirm_without_checks, say("No pude probarla.")])
    r = agent.ask("Prueba")
    assert r.status == "done" and r.approvals == [] and agent.book.get(HID)["status"] == "en_prueba"
    assert "refutation_checks" in last_tool(llm) and "no la confirmes" in last_tool(llm)   # el modelo recibe cómo corregirlo


def test_citar_como_refutacion_una_consulta_anterior_se_rechaza_en_el_agente(setup):
    make, ledger = setup

    def confirm_with_old_query(messages):
        # la PRIMERA consulta del hilo, ejecutada antes de proponer la hipótesis
        ref = re.search(r"q-[0-9a-f]{12}", " ".join(str(m.content) for m in messages if m.type == "tool")).group(0)
        return call("update_hypothesis", hypothesis_id=HID, status="confirmada", evidence_refs=[ref], rationale="Lo respalda",
                    refutation_checks=[check(ref)])

    agent, llm = make([call("run_query", sql=REFUTE_SQL), propose(),
                       call("update_hypothesis", hypothesis_id=HID, status="en_prueba"),
                       confirm_with_old_query, say("No pude.")])
    r = agent.ask("Prueba")
    assert r.status == "done" and r.approvals == [] and agent.book.get(HID)["status"] == "en_prueba"
    assert "ANTES" in last_tool(llm)                                                    # el modelo sabe por qué se rechazó


def test_la_vista_de_aprobacion_muestra_el_criterio_y_los_intentos(setup):
    make, ledger = setup
    agent, _ = make(FULL())
    (req,) = agent.ask("¿Qué pasó?").approvals
    assert req["criterio_de_refutacion"] == FALSIFIER
    (attempt,) = req["intentos_de_refutacion"]
    assert attempt["tipo"] == "consulta" and "count(DISTINCT user_id)" in attempt["detalle"]   # ve el SQL, no solo un id
    assert attempt["habria_refutado_si"] == WOULD and attempt["observado"] == SEEN


def test_lo_aprobado_queda_registrado_y_el_briefing_recuerda_el_criterio(setup):
    make, ledger = setup
    agent, llm = make(FULL() + [say("Siguiente pregunta atendida")])
    agent.ask("¿Qué pasó?")
    agent.resolve("approve", "De acuerdo")
    (update,) = [e for e in ledger.entries("hypothesis_update") if e["data"]["decision"] == "approved"]
    assert update["data"]["refutation_checks"][0]["would_refute_if"] == WOULD
    agent.ask("¿Y ahora?")
    briefing = [m for m in llm.log[-1]["messages"] if "PREGUNTA DEL ANALISTA:\n¿Y ahora?" in str(m.content)][0].content
    assert "criterio_de_refutacion" in briefing and FALSIFIER[:40] in briefing


def test_el_criterio_de_una_hipotesis_de_otra_copia_no_llega_al_modelo(tmp_path, scripted):
    ws = _case(tmp_path, "C-FALS")
    real = ws.engine()
    pseudo, _ = ws.pseudonymized()
    ledger = Ledger.open("FB", real, analyst="eder", root=tmp_path / "led")
    HypothesisBook(ledger).propose("La cuenta atacante00 enumera facturas ajenas", proposed_by="agent",
                                   falsifier="Si atacante00 solo usa su propia IP 66.6.6.1 queda refutada")
    llm = scripted([say("ok")])
    build_agent(pseudo, ledger, llm).ask("Sigue")
    first = str(llm.log[0]["messages"][1].content)
    assert "criterio_de_refutacion" in first and "no mostrado" in first
    assert not leaks(first, {"atacante00", "66.6.6.1"})
