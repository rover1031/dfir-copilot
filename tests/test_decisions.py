"""Decisiones del analista sobre las propuestas del agente. Lo esencial: cada propuesta se decide por separado (aprobar una no aprueba
la otra), registrar las decisiones es inmediato y no llama al modelo salvo que pidas que el agente siga, y una propuesta sin decidir
no se rechaza en silencio."""
import re

import pytest
from langchain_core.messages import AIMessage
from test_agent import FALSIFIER, REFUTE_SQL, USAGE, call, say, tool_text

from dfir_copilot.agent.graph import build_agent
from dfir_copilot.agent.hypotheses import hypothesis_id
from dfir_copilot.evidence.ledger import Ledger

S1 = "Cuatro identidades enumeran facturas ajenas desde un conjunto cerrado de cinco IPs"
S2 = "Un cliente automatizado recorre identificadores de factura de forma secuencial"
H1, H2 = hypothesis_id(S1), hypothesis_id(S2)


def two_requests(messages):
    """Un solo mensaje del modelo con DOS peticiones de confirmación: quedan dos aprobaciones pendientes a la vez."""
    case = re.search(r"c-[0-9a-f]{12}", tool_text(messages)).group(0)
    query = re.findall(r"q-[0-9a-f]{12}", str(messages[-1].content))[-1]
    check = [{"ref": query, "would_refute_if": "Habría identidades ajenas al grupo", "observed": "Ninguna otra identidad usa esas IPs"}]
    calls = [{"name": "update_hypothesis", "id": f"call_two_{h}", "type": "tool_call",
              "args": {"hypothesis_id": h, "status": "confirmada", "evidence_refs": [case], "rationale": "Señales independientes",
                       "refutation_checks": check}} for h in (H1, H2)]
    return AIMessage(content="", usage_metadata=USAGE, tool_calls=calls)


def TWO():
    return [call("describe_dataset"), call("run_detectors"),
            call("propose_hypothesis", statement=S1, falsifier=FALSIFIER, rationale="Detectores", test_plan="Contrastar"),
            call("propose_hypothesis", statement=S2, falsifier=FALSIFIER, rationale="Detectores", test_plan="Contrastar"),
            call("update_hypothesis", hypothesis_id=H1, status="en_prueba"), call("update_hypothesis", hypothesis_id=H2, status="en_prueba"),
            call("run_query", sql=REFUTE_SQL), two_requests, say("Resumen tras tus decisiones")]


@pytest.fixture()
def setup(tmp_path, make_engine, scripted):
    engine, truth = make_engine()
    ledger = Ledger.open("D", engine, analyst="eder", root=tmp_path / "ledger")

    def make(script, **kw):
        llm = scripted(script)
        return build_agent(engine, ledger, llm, **{"allow_real": True, **kw}), llm  # datos sintéticos

    return make, ledger, engine, truth


def triage(setup):
    make, ledger, _, _ = setup
    agent, llm = make(TWO())
    r = agent.ask("Triaje")
    assert r.status == "needs_approval" and {a["hypothesis_id"] for a in r.approvals} == {H1, H2}
    return agent, llm, ledger


def test_aprobar_una_no_aprueba_la_otra_y_sin_continuar_no_se_llama_al_modelo(setup):
    agent, llm, ledger = triage(setup)
    calls_before = len(llm.log)
    r = agent.resume([{"hypothesis_id": H1, "decision": "approve", "note": "Revisado: sólido"},
                      {"hypothesis_id": H2, "decision": "reject", "note": "El intento no podía salir distinto"}], continue_agent=False)
    assert r.status == "done" and "sin reanudar al agente" in r.answer and f"{H1} aprobada" in r.answer and f"{H2} rechazada" in r.answer
    assert len(llm.log) == calls_before                                                   # cero llamadas al modelo: instantáneo
    assert agent.book.get(H1)["status"] == "confirmada" and agent.book.get(H2)["status"] != "confirmada"
    assert agent.pending() == [] and agent.phase() == "idle" and ledger.verify().ok


def test_con_continuar_el_agente_sigue_y_ve_las_dos_decisiones(setup):
    agent, llm, _ = triage(setup)
    r = agent.resume([{"hypothesis_id": H1, "decision": "reject", "note": "no"},
                      {"hypothesis_id": H2, "decision": "approve", "note": "sí"}], continue_agent=True)
    assert r.status == "done" and "Resumen tras tus decisiones" in r.answer
    assert agent.book.get(H2)["status"] == "confirmada" and agent.book.get(H1)["status"] != "confirmada"


def test_tras_registrar_sin_continuar_se_puede_seguir_preguntando(setup):
    agent, llm, _ = triage(setup)
    agent.resume([{"hypothesis_id": H1, "decision": "approve", "note": "ok"}, {"hypothesis_id": H2, "decision": "approve", "note": "ok"}],
                 continue_agent=False)
    calls_before = len(llm.log)
    r = agent.ask("¿Y ahora?")                                       # el guion responde con su siguiente mensaje
    assert r.status == "done" and r.answer == "Resumen tras tus decisiones" and len(llm.log) == calls_before + 1


@pytest.mark.parametrize("decisions, error", [
    ([{"hypothesis_id": H1, "decision": "approve", "note": "x"}], "falta"),
    ([{"hypothesis_id": H1, "decision": "approve"}, {"hypothesis_id": H2, "decision": "talvez"}], "approve"),
    ([{"hypothesis_id": H1, "decision": "approve"}, {"hypothesis_id": H2, "decision": "reject"}, {"hypothesis_id": "h-000000000000",
      "decision": "reject"}], "no están pendientes"),
])
def test_una_propuesta_sin_decidir_no_se_rechaza_en_silencio(setup, decisions, error):
    agent, _, _ = triage(setup)
    with pytest.raises(ValueError, match=error):
        agent.resume(decisions, continue_agent=False)
    assert {a["hypothesis_id"] for a in agent.pending()} == {H1, H2}                     # todo sigue pendiente
