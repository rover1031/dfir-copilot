"""Pruebas del ledger de evidencia: trazabilidad, idempotencia y detección de manipulación."""
import json

import pytest

from dfir_copilot.detectors import correlate, run_detectors
from dfir_copilot.engine.query_engine import QueryRejected
from dfir_copilot.evidence.ledger import DatasetMismatch, Ledger, LedgerCorrupt


@pytest.fixture()
def case(tmp_path, make_engine):
    engine, truth = make_engine()
    ledger = Ledger.open("CASO-001", engine, analyst="eder", root=tmp_path / "ledger")
    return ledger, engine, truth, tmp_path / "ledger"


@pytest.fixture()
def recorded(case):
    ledger, engine, truth, root = case
    runs = run_detectors(engine)
    ledger.record_runs(runs)
    return ledger, engine, truth, root, runs


def test_abre_el_caso_y_registra_el_dataset(case):
    ledger, engine, _, _ = case
    (opened,) = ledger.entries()
    assert opened["type"] == "case_opened" and opened["seq"] == 1
    assert opened["data"]["dataset"]["input_sha256"] == engine.dataset_sha256
    assert opened["data"]["dataset"]["timezone_verified"] is False
    assert ledger.verify().ok


def test_registra_hallazgos_con_sus_consultas(case):
    ledger, engine, _, _ = case
    counts = ledger.record_runs(run_detectors(engine))
    assert counts["findings"] == 10 and counts["runs"] == 4
    query_ids = {e["data"]["query_id"] for e in ledger.entries("query")}
    for f in ledger.entries("finding"):
        assert f["data"]["query_ids"] and set(f["data"]["query_ids"]) <= query_ids
    assert ledger.verify().ok


def test_es_idempotente_con_los_hallazgos(recorded):
    ledger, engine, _, _, runs = recorded
    again = ledger.record_runs(runs)  # mismas corridas: nada nuevo salvo el evento de ejecución
    assert again["findings"] == 0 and again["queries"] == 0
    rerun = ledger.record_runs(run_detectors(engine))  # corridas nuevas: consultas nuevas, mismos hallazgos
    assert rerun["findings"] == 0 and rerun["queries"] > 0
    assert len(ledger.entries("finding")) == 10 and ledger.verify().ok


def test_registra_tambien_las_consultas_rechazadas(case):
    ledger, engine, _, _ = case
    with pytest.raises(QueryRejected):
        engine.query("DROP VIEW logs")
    ledger.record_queries(engine.history)
    assert "rejected" in {e["data"]["status"] for e in ledger.entries("query")}


def test_detecta_una_edicion_del_contenido(recorded):
    ledger, _, _, root, _ = recorded
    path = root / "CASO-001.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    i = next(i for i, ln in enumerate(lines) if '"type":"finding"' in ln and '"severity":"medium"' in ln)
    lines[i] = lines[i].replace('"severity":"medium"', '"severity":"low"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = ledger.verify()
    assert not result.ok and "hash" in result.error


def test_detecta_una_entrada_borrada(recorded):
    ledger, _, _, root, _ = recorded
    path = root / "CASO-001.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[3]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not ledger.verify().ok


def test_detecta_una_entrada_forjada(recorded):
    ledger, _, _, root, _ = recorded
    forged = {"seq": ledger.summary()["entries"] + 1, "type": "note", "data": {"text": "falso"},
              "ts_utc": "2020-01-01T00:00:00+00:00", "prev_hash": "f" * 64, "hash": "a" * 64}
    with open(root / "CASO-001.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(forged) + "\n")
    assert not ledger.verify().ok


def test_truncar_el_final_solo_se_detecta_anclando_el_head_hash(recorded):
    """Límite conocido de toda cadena de hashes: por eso el head_hash se ancla fuera del archivo."""
    ledger, _, _, root, _ = recorded
    anchored = ledger.head_hash
    path = root / "CASO-001.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    result = ledger.verify()
    assert result.ok  # la cadena restante sigue siendo coherente...
    assert result.head_hash != anchored  # ...pero el ancla externo revela la truncación


def test_reabrir_continua_la_cadena(recorded):
    ledger, engine, _, root, _ = recorded
    head, total = ledger.head_hash, len(ledger.entries())
    reopened = Ledger.open("CASO-001", engine, root=root)
    assert reopened.head_hash == head and len(reopened.entries()) == total
    reopened.note("Revisado el grupo cerrado")
    assert reopened.verify().ok and reopened.head_hash != head


def test_no_abre_un_ledger_corrupto(recorded):
    ledger, engine, _, root, _ = recorded
    path = root / "CASO-001.jsonl"
    path.write_text(path.read_text(encoding="utf-8").replace('"analyst":"eder"', '"analyst":"otro"'), encoding="utf-8")
    with pytest.raises(LedgerCorrupt):
        Ledger.open("CASO-001", engine, root=root)


def test_rechaza_un_dataset_distinto(case, make_engine):
    _, _, _, root = case
    other_engine, _ = make_engine(seed=99)
    with pytest.raises(DatasetMismatch):
        Ledger.open("CASO-001", other_engine, root=root)


@pytest.mark.parametrize("bad", ["../x", "a/b", "", ".oculto", "x" * 70])
def test_id_de_caso_invalido(make_engine, tmp_path, bad):
    engine, _ = make_engine()
    with pytest.raises(ValueError):
        Ledger.open(bad, engine, root=tmp_path / "l")


def test_casos_candidatos_y_notas_enlazadas(recorded):
    ledger, _, truth, _, runs = recorded
    assert ledger.record_cases(correlate(runs)) == len(truth.attacker_actors)
    assert ledger.record_cases(correlate(runs)) == 0  # idempotente
    candidate = ledger.entries("case_candidate")[0]["data"]
    note = ledger.note("Confirmado contra el ticket", refs=[candidate["candidate_id"]],
                       status="confirmed", analyst="eder")
    assert note["data"]["refs"] == [candidate["candidate_id"]] and ledger.verify().ok


def test_notas_invalidas(recorded):
    ledger, *_ = recorded
    with pytest.raises(ValueError):
        ledger.note("   ")
    with pytest.raises(ValueError):
        ledger.note("x", status="quizas")
    with pytest.raises(KeyError):
        ledger.note("x", refs=["f-inexistente"])


def test_los_casos_exigen_hallazgos_registrados(case, make_engine):
    ledger, engine, _, _ = case
    with pytest.raises(KeyError):
        ledger.record_cases(correlate(run_detectors(engine)))


def test_replay_reproduce_las_consultas(recorded):
    ledger, engine, _, _, _ = recorded
    results = ledger.replay(engine)
    assert results and all(r["match"] for r in results)


def test_replay_con_otro_dataset_falla(recorded, make_engine):
    ledger, *_ = recorded
    other_engine, _ = make_engine(seed=99)
    with pytest.raises(DatasetMismatch):
        ledger.replay(other_engine)


# --- varias instancias sobre el mismo caso (p. ej. dos notebooks abiertos) -------------------------
def test_dos_instancias_no_bifurcan_la_cadena(case):
    ledger, engine, _, root = case
    other = Ledger.open("CASO-001", engine, root=root)  # "otro notebook"
    ledger.note("desde A")
    other.note("desde B")  # B no sabía de A
    ledger.note("otra vez desde A")
    result = ledger.verify()
    assert result.ok and result.entries == 4
    assert [e["seq"] for e in other.entries()] == [1, 2, 3, 4]  # B ve lo que escribió A
    assert ledger.head_hash == other.head_hash


def test_escrituras_concurrentes_desde_hilos_mantienen_la_cadena(case):
    import threading

    ledger, engine, _, root = case
    errors = []

    def worker(n):
        try:
            mine = Ledger.open("CASO-001", engine, root=root)
            for i in range(15):
                mine.note(f"hilo {n} nota {i}")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    result = ledger.verify()
    assert result.ok and result.entries == 1 + 4 * 15


def test_refresh_y_lecturas_ven_lo_que_escribio_otra_instancia(case):
    ledger, engine, _, root = case
    other = Ledger.open("CASO-001", engine, root=root)
    other.note("nota de B")
    assert len(ledger.entries("note")) == 1  # A la ve sin escribir nada
    ledger.refresh()
    assert ledger.summary()["counts"]["note"] == 1


# --- replay: una sola entrada, sin ensuciar el historial -------------------------------------------
def test_replay_deja_una_entrada_y_no_ensucia_el_historial(recorded):
    ledger, engine, _, _, _ = recorded
    before_queries = len(ledger.entries("query"))
    history_len = len(engine.history)
    results = ledger.replay(engine)
    assert len(engine.history) == history_len  # las re-ejecuciones no son consultas nuevas
    ledger.record_queries(engine.history)  # y por tanto no se duplican al registrar el historial
    assert len(ledger.entries("query")) == before_queries
    (entry,) = ledger.entries("replay")
    assert entry["data"]["queries"] == len(results) and entry["data"]["matches"] == len(results)
    assert entry["data"]["mismatches"] == [] and ledger.verify().ok
