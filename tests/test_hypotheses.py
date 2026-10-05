"""Pruebas del registro de hipótesis: ciclo de vida, evidencia obligatoria y persistencia en el ledger."""
import pytest

from dfir_copilot.agent.hypotheses import HypothesisBook, HypothesisError, hypothesis_id
from dfir_copilot.detectors import correlate, run_detectors
from dfir_copilot.evidence.ledger import Ledger, candidate_id

STATEMENT = "Cuatro identidades enumeran facturas ajenas desde un conjunto cerrado de cinco IPs"


@pytest.fixture()
def env(tmp_path, make_engine):
    engine, _ = make_engine()
    ledger = Ledger.open("H", engine, analyst="eder", root=tmp_path / "ledger")
    engine.query("SELECT count(*) FROM logs")
    ledger.record_queries(engine.history)
    ref = ledger.entries("query")[-1]["data"]["query_id"]
    return ledger, HypothesisBook(ledger), ref, engine


def refute(ledger, engine, sql="SELECT count(DISTINCT user_id) FROM logs"):
    """Una consulta ejecutada y registrada AHORA (después de proponer): un intento de refutación válido."""
    engine.query(sql)
    ledger.record_queries(engine.history[-1:])
    return [{"ref": ledger.entries("query")[-1]["data"]["query_id"], "would_refute_if": "Hubiera más identidades de las esperadas",
             "observed": "El recuento coincide con lo esperado"}]


def test_proponer_es_idempotente_e_ignora_espacios_y_mayusculas(env):
    _, book, _, _ = env
    item, created = book.propose(STATEMENT)
    again, created2 = book.propose("  " + STATEMENT.upper() + " ")
    assert created and not created2 and again["hypothesis_id"] == item["hypothesis_id"] == hypothesis_id(STATEMENT)
    assert item["status"] == "propuesta"


@pytest.mark.parametrize("bad", ["corta", "x" * 501, "   "])
def test_longitud_de_la_hipotesis(env, bad):
    _, book, _, _ = env
    with pytest.raises(HypothesisError):
        book.propose(bad)


def test_ciclo_de_vida_completo_con_decision_del_analista(env):
    ledger, book, ref, engine = env
    hid = book.propose(STATEMENT)[0]["hypothesis_id"]
    assert book.start_testing(hid)["status"] == "en_prueba"
    book.start_testing(hid)  # idempotente: no duplica entradas
    assert len([e for e in ledger.entries("hypothesis_update")]) == 1
    req = book.request_decision(hid, "confirmada", [ref], "La consulta lo respalda", refute(ledger, engine))
    assert book.get(hid)["status"] == "en_prueba"  # pedir no cambia nada
    item = book.decide(req, approve=True, analyst="eder", note="de acuerdo")
    assert item["status"] == "confirmada" and item["evidence_refs"] == [ref]
    with pytest.raises(HypothesisError):  # no se reabre
        book.start_testing(hid)
    assert ledger.verify().ok


def test_rechazar_deja_el_estado_y_queda_registrado(env):
    ledger, book, ref, _ = env
    hid = book.propose(STATEMENT)[0]["hypothesis_id"]
    book.start_testing(hid)
    req = book.request_decision(hid, "refutada", [ref], "No encaja")
    item = book.decide(req, approve=False, analyst="eder", note="falta contrastar con IAM")
    assert item["status"] == "en_prueba" and item["evidence_refs"] == []
    assert ledger.entries("hypothesis_update")[-1]["data"]["decision"] == "rejected"


def test_la_peticion_de_cierre_exige_estado_evidencia_y_justificacion(env):
    _, book, ref, _ = env
    hid = book.propose(STATEMENT)[0]["hypothesis_id"]
    with pytest.raises(HypothesisError, match="en_prueba"):  # aún 'propuesta'
        book.request_decision(hid, "confirmada", [ref], "x")
    book.start_testing(hid)
    with pytest.raises(HypothesisError, match="Falta evidencia"):
        book.request_decision(hid, "confirmada", [], "x")
    with pytest.raises(HypothesisError, match="no existen"):
        book.request_decision(hid, "confirmada", ["q-inventado"], "x")
    with pytest.raises(HypothesisError, match="no existen"):  # una hipótesis no es evidencia de sí misma
        book.request_decision(hid, "confirmada", [hid], "x")
    with pytest.raises(HypothesisError, match="justificación"):
        book.request_decision(hid, "confirmada", [ref], "  ")
    with pytest.raises(HypothesisError):
        book.request_decision(hid, "propuesta", [ref], "x")
    with pytest.raises(HypothesisError, match="desconocida"):
        book.request_decision("h-nada", "confirmada", [ref], "x")


def test_el_estado_se_reconstruye_desde_el_ledger(env):
    ledger, book, ref, engine = env
    hid = book.propose(STATEMENT)[0]["hypothesis_id"]
    book.start_testing(hid)
    book.decide(book.request_decision(hid, "confirmada", [ref], "ok", refute(ledger, engine)), True, "eder")
    reborn = HypothesisBook(ledger)
    assert reborn.get(hid)["status"] == "confirmada" and len(reborn.get(hid)["history"]) == 2


def test_el_ledger_acepta_hipotesis_como_referencia_de_notas(env):
    ledger, book, _, _ = env
    hid = book.propose(STATEMENT)[0]["hypothesis_id"]
    assert hid in ledger.known_refs()
    ledger.note("Seguimiento de la hipótesis", refs=[hid])
    assert ledger.verify().ok


def test_el_id_de_caso_candidato_coincide_con_el_del_ledger(env):
    ledger, _, _, engine = env
    runs = run_detectors(engine)
    ledger.record_runs(runs)
    cases = correlate(runs)
    ledger.record_cases(cases)
    recorded = {e["data"]["candidate_id"] for e in ledger.entries("case_candidate")}
    assert recorded == {candidate_id(c, engine.dataset_sha256) for c in cases} and recorded
