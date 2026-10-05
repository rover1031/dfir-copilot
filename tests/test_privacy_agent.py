"""P1-b.2b: el agente y el toolkit consultan la copia seudonimizada; el ledger y el replay saben sobre qué copia corrió cada
consulta. Lo esencial: NADA de lo que recibe el modelo contiene un valor real, y la verificación (replay) sigue funcionando
copia por copia."""
import copy as _copy
import json
import re

import pytest
from test_agent import FULL, HID, STATEMENT, call, propose, say

from dfir_copilot.agent.graph import build_agent
from dfir_copilot.agent.hypotheses import HypothesisBook, hypothesis_id
from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.evidence.ledger import (
    CopyMismatch,
    CopyNotRegistered,
    DatasetMismatch,
    Ledger,
    query_id,
)
from dfir_copilot.privacy import PrivacyError, PrivacyPolicy, detector_parity, privacy_context
from dfir_copilot.synthetic import make_idor_dataset, write_csv
from dfir_copilot.tools import Toolkit

EMAIL, INNER_IP = "ops@acme.com", "10.9.8.7"


def _rows(user_agent_variants=False):
    rows, _ = make_idor_dataset()
    # un cliente automatizado que lleva un correo y una IP dentro del User-Agent: pasa en logs reales
    out = [r.replace('"wget"', f'"wget ({EMAIL} {INNER_IP})"') for r in rows]
    if user_agent_variants:  # dos User-Agent que solo se distinguen por un token largo: la copia los funde en uno
        out = [r.replace(f'"wget ({EMAIL} {INNER_IP})"',
                         '"wget ABCDEFGHIJKLMNOPQRSTUVWXYZ0123"' if i % 2 else '"wget 9876543210ZYXWVUTSRQPONMLKJI"')
               for i, r in enumerate(out)]
    return out


def _case(tmp_path, name="C-B2B", **kw):
    csv = write_csv(tmp_path / "three_months.csv", _rows(**kw))
    ws = CaseWorkspace.open_or_create(name, root=tmp_path / "cases", analyst="eder")
    ws.add_raw(csv)
    ws.ingest(csv, "web_access_meli")
    return ws


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("b2b")
    ws = _case(tmp)
    real = ws.engine()
    pseudo, ps = ws.pseudonymized()
    return ws, real, pseudo, ps


def real_values(real, ps) -> set[str]:
    """Todo valor real que el diccionario oculta, más los que van dentro del User-Agent."""
    values = {EMAIL, INNER_IP, "mercadolibre"}
    for col, kind in ps.treatments.items():
        if kind in ("alias", "ip"):
            values |= {str(v) for (v,) in real.query(f"SELECT DISTINCT {col} FROM logs WHERE {col} IS NOT NULL").rows}
    mn = real.query("SELECT min(x_invoice_id) FROM logs").rows[0][0]
    values |= {str(mn)[:7]}  # prefijo de los números de factura reales (118822…, 229933…)
    return {v for v in values if len(v) >= 6}


def leaks(text: str, values: set[str]) -> list[str]:
    return sorted(v for v in values if v in text)


# --- identidad de la copia en el motor ---------------------------------------------------------------------------

def test_el_motor_distingue_su_copia_y_la_sella_en_cada_consulta(world):
    _, real, pseudo, _ = world
    assert real.copy_kind == "real" and pseudo.copy_kind == "pseudonymized"
    assert real.copy_id.startswith("real:") and pseudo.copy_id.startswith("pseudonymized:")
    assert real.dataset_sha256 == pseudo.dataset_sha256            # mismo origen: ese hash NO distingue las copias
    for engine in (real, pseudo):
        engine.query("SELECT count(*) FROM logs")
        assert engine.history[-1]["copy"] == engine.copy_id


def test_el_sello_evita_que_la_misma_consulta_en_ambas_copias_comparta_id(world):
    """Sin el sello, `SELECT count(*)` da el mismo registro en ambas copias y el ledger daría por hecha la primera."""
    _, real, pseudo, _ = world
    real.query("SELECT count(*) FROM logs")
    pseudo.query("SELECT count(*) FROM logs")
    a, b = dict(real.history[-1]), dict(pseudo.history[-1])
    a["elapsed_ms"] = b["elapsed_ms"] = 0
    a["executed_at_utc"] = b["executed_at_utc"] = "2026-10-05T00:00:00+00:00"
    sin_sello = ({k: v for k, v in a.items() if k != "copy"}, {k: v for k, v in b.items() if k != "copy"})
    assert query_id(sin_sello[0]) == query_id(sin_sello[1])        # el defecto que el sello corrige
    assert query_id(a) != query_id(b)


# --- ledger -----------------------------------------------------------------------------------------------------

def test_el_ledger_se_abre_con_los_datos_reales_y_no_con_la_copia(world, tmp_path):
    _, _, pseudo, _ = world
    with pytest.raises(ValueError, match="REALES"):
        Ledger.open("X", pseudo, root=tmp_path)


def test_registrar_la_copia_es_idempotente_y_no_guarda_valores(world, tmp_path):
    ws, real, pseudo, ps = world
    ledger = Ledger.open("R1", real, analyst="t", root=tmp_path)
    assert ledger.record_copy(real) is False                       # las reales las identifica case_opened
    assert ledger.record_copy(pseudo) is True and ledger.record_copy(pseudo) is False
    (entry,) = ledger.entries("data_copy")
    d = entry["data"]
    assert d["copy_id"] == pseudo.copy_id and d["policy"]["version"] == "priv-1"
    assert d["source_parquet_sha256"] == real.parquet_sha256 and d["parquet_sha256"] == pseudo.parquet_sha256
    assert d["treatments"]["user_id"] == "alias" and d["aliases_sha256"]
    assert not leaks(json.dumps(d), real_values(real, ps))        # procedencia sí, valores no
    assert ledger.copies() == {pseudo.copy_id: d} and ledger.verify().ok


def test_una_copia_construida_desde_otro_parquet_se_rechaza(world, tmp_path):
    _, real, pseudo, _ = world
    ledger = Ledger.open("R2", real, analyst="t", root=tmp_path)
    forged = _copy.copy(pseudo)
    forged.manifest = _copy.deepcopy(pseudo.manifest)
    forged.manifest["source_parquet"]["sha256"] = "0" * 64
    with pytest.raises(CopyMismatch, match="otro Parquet"):
        ledger.record_copy(forged)
    forged.manifest = _copy.deepcopy(pseudo.manifest)
    forged.manifest["input"]["sha256"] = "1" * 64
    with pytest.raises(DatasetMismatch):
        ledger.record_copy(forged)
    assert ledger.entries("data_copy") == []


def test_consultas_de_una_copia_sin_registrar_se_rechazan_sin_escribir_nada(world, tmp_path):
    _, real, pseudo, _ = world
    ledger = Ledger.open("R3", real, analyst="t", root=tmp_path)
    real.query("SELECT count(*) FROM logs")
    pseudo.query("SELECT count(*) FROM logs")
    before = len(ledger.entries())
    with pytest.raises(CopyNotRegistered, match="record_copy"):
        ledger.record_queries([real.history[-1], pseudo.history[-1]])
    assert len(ledger.entries()) == before                         # o entran todas o ninguna
    ledger.record_copy(pseudo)
    assert ledger.record_queries([real.history[-1], pseudo.history[-1]]) == 2


# --- lo que ve el modelo -----------------------------------------------------------------------------------------

def test_ninguna_herramienta_entrega_valores_reales(world, tmp_path):
    _, real, pseudo, ps = world
    secrets = real_values(real, ps)
    ledger = Ledger.open("T1", real, analyst="t", root=tmp_path)
    kit = Toolkit(pseudo, ledger)
    calls = [("describe_dataset", {}), ("run_detectors", {}),
             ("run_query", {"sql": "SELECT * FROM logs LIMIT 50"}),
             ("run_query", {"sql": "SELECT DISTINCT user_agent, query_string, endpoint, referer FROM logs"}),
             *[("profile", {"kind": "top", "dimension": d, "n": 20}) for d in ("user_id", "src_ip", "user_agent", "endpoint",
                                                                             "referer", "host", "x_invoice_id")],
             ("profile", {"kind": "activity", "dimension": "src_ip", "n": 20}),
             ("build_timeline", {"dimension": "user_id", "value": "U-0001"})]
    for name, args in calls:
        out = kit.call(name, args)
        assert out.ok, (name, out.text[:200])
        assert not leaks(out.text, secrets), (name, leaks(out.text, secrets))
    assert [e["data"]["copy"] for e in ledger.entries("tool_call")] == [pseudo.copy_id] * len(calls)


def test_los_hallazgos_salen_en_alias_aunque_el_user_agent_lleve_valores(world, tmp_path):
    _, real, pseudo, ps = world
    ledger = Ledger.open("T2", real, analyst="t", root=tmp_path)
    out = Toolkit(pseudo, ledger).call("run_detectors")
    assert "wget ({email} {ip})" in out.text and EMAIL not in out.text and INNER_IP not in out.text
    entities = {list(f["entity"].values())[0] for f in out.data["findings"] if "user_id" in f["entity"]}
    assert entities and all(re.fullmatch(r"U-\d{4}", e) for e in entities)
    # lo mismo sobre los datos reales SÍ habría filtrado: es la razón de correr los detectores sobre la copia
    leaked = Toolkit(real, Ledger.open("T2r", real, analyst="t", root=tmp_path)).call("run_detectors")
    assert EMAIL in leaked.text


def test_describe_dataset_explica_la_copia_al_modelo(world, tmp_path):
    _, real, pseudo, _ = world
    kit = Toolkit(pseudo, Ledger.open("T3", real, analyst="t", root=tmp_path))
    privacy = kit.call("describe_dataset").data["privacy"]
    assert privacy["policy"] == "priv-1" and privacy["copy_id"] == pseudo.copy_id
    assert privacy["treatments"]["x_invoice_id"] == "shift" and "session_id" not in privacy["treatments"]  # vacía: no se lista
    assert "privacy" not in Toolkit(real).call("describe_dataset").data   # con datos reales no hay nada que describir


def test_la_nota_de_la_zona_horaria_no_llega_al_modelo(world, tmp_path):
    """`timezone.note` es texto libre del analista (quién declaró la zona y cuándo): P1-a ya decidió no enviarlo."""
    _, real, pseudo, _ = world
    marked = _copy.copy(pseudo)
    marked.manifest = _copy.deepcopy(pseudo.manifest)
    marked.manifest["timezone"]["note"] = "Declarada por Eder Ríos el 2026-10-03 tras hablar con el dueño"
    out = Toolkit(marked).call("describe_dataset")
    assert out.ok and "Eder" not in out.text and "note" not in out.data["timezone"]
    assert out.data["timezone"]["assumed"] == pseudo.manifest["timezone"]["assumed"]   # lo útil se conserva


def test_el_prompt_de_sistema_describe_la_copia_con_los_tratamientos_reales(world):
    _, _, pseudo, _ = world
    text = privacy_context(pseudo.manifest)
    assert "user_id→U-0001" in text and "src_ip→IP-0001" in text and "src_ip_scope" in text and "src_ip_net" in text
    assert "desplazadas" in text and "x_invoice_id" in text and "{id}" in text and "{token}" in text
    assert "Sin cambios" in text and "timestamp_utc" in text and "session_id" not in text   # columna sin datos: no se menciona
    assert privacy_context(world[1].manifest) == ""                                           # datos reales: nada que decir


def test_las_excepciones_de_politica_se_reflejan_en_el_prompt(tmp_path):
    ws = _case(tmp_path, "C-OVR")
    engine, _ = ws.pseudonymized(PrivacyPolicy(overrides={"x_token_type": "keep"}))
    keep = privacy_context(engine.manifest).split("Sin cambios:")[1]
    assert "x_token_type" in keep


# --- el agente --------------------------------------------------------------------------------------------------

def test_el_agente_rechaza_datos_reales_salvo_que_se_permita(world, tmp_path, scripted):
    _, real, pseudo, _ = world
    ledger = Ledger.open("A1", real, analyst="t", root=tmp_path)
    with pytest.raises(PrivacyError, match="seudonimizada"):
        build_agent(real, ledger, scripted([say("x")]))
    build_agent(real, ledger, scripted([say("x")]), allow_real=True)   # sintéticos: permitido, y el turno lo sella
    build_agent(pseudo, ledger, scripted([say("x")]))


def test_transcripcion_completa_sin_valores_reales_y_con_el_ledger_al_dia(world, tmp_path, scripted):
    """Una investigación entera con aprobación: todo lo que el modelo recibe (prompt, briefing, herramientas, aprobación) se
    escanea contra los valores reales; después, el ledger dice sobre qué copia corrió cada cosa."""
    ws, real, pseudo, ps = world
    ledger = Ledger.open("A2", real, analyst="eder", root=tmp_path)
    llm = scripted(FULL())
    agent = build_agent(pseudo, ledger, llm)
    r = agent.ask("¿Qué pasó?")
    assert r.status == "needs_approval"
    r = agent.resolve("approve", "Coincide con IAM")
    assert r.status == "done"

    sent = "\n".join(str(m.content) for call_ in llm.log for m in call_["messages"])
    assert "COPIA SEUDONIMIZADA" in sent and "<datos_del_log>" in sent and re.search(r"U-\d{4}", sent)   # el escaneo no es vacío
    assert not leaks(sent, real_values(real, ps))

    types = [e["type"] for e in ledger.entries()]
    assert types.index("data_copy") < types.index("query")        # la copia se registra antes de la primera consulta
    for kind in ("tool_call", "agent_turn"):
        assert {e["data"]["copy"] for e in ledger.entries(kind)} == {pseudo.copy_id}
    assert {e["data"]["copy"] for e in ledger.entries("query")} == {pseudo.copy_id}
    assert ledger.entries("hypothesis")[0]["data"]["copy"] == pseudo.copy_id
    assert agent.book.get(HID)["status"] == "confirmada" and ledger.verify().ok


def test_una_hipotesis_de_otra_copia_no_vuelve_al_modelo(world, tmp_path, scripted):
    """Caso real: un caso con hipótesis escritas cuando el agente veía datos reales no debe reinyectarlas por el briefing."""
    _, real, pseudo, ps = world
    ledger = Ledger.open("A3", real, analyst="t", root=tmp_path)
    old = "La cuenta atacante00 enumera facturas desde 66.6.6.1"
    HypothesisBook(ledger).propose(old, proposed_by="agent")                       # sin sello: anterior a P1-b.2b
    llm = scripted([say("ok")])
    agent = build_agent(pseudo, ledger, llm)
    agent.ask("Sigue")
    first = str(llm.log[0]["messages"][1].content)
    assert hypothesis_id(old) in first and "texto no mostrado" in first            # el id y el estado se conservan
    assert "atacante00" not in first and "66.6.6.1" not in first

    llm2 = scripted([propose(), say("hecho"), say("ok")])
    agent2 = build_agent(pseudo, ledger, llm2)
    agent2.ask("Propón")
    agent2.ask("Otra")                                                              # formulada sobre ESTA copia: sí se ve
    second = [m for m in llm2.log[-1]["messages"] if "PREGUNTA DEL ANALISTA:\nOtra" in str(m.content)]
    assert len(second) == 1 and STATEMENT in str(second[0].content)


def test_con_datos_reales_permitidos_el_briefing_sigue_mostrando_el_texto(world, tmp_path, scripted):
    _, real, _, _ = world
    ledger = Ledger.open("A4", real, analyst="t", root=tmp_path)
    HypothesisBook(ledger).propose("Hipótesis anterior sobre datos sintéticos", proposed_by="agent")
    llm = scripted([say("ok")])
    build_agent(real, ledger, llm, allow_real=True).ask("Sigue")
    assert "Hipótesis anterior sobre datos sintéticos" in str(llm.log[0]["messages"][1].content)


# --- replay copia por copia -------------------------------------------------------------------------------------

def test_el_replay_enruta_cada_consulta_a_su_copia(world, tmp_path, scripted):
    ws, real, pseudo, _ = world
    ledger = Ledger.open("P1", real, analyst="eder", root=tmp_path)
    agent = build_agent(pseudo, ledger, scripted([call("run_detectors"), call("run_query", sql="SELECT count(*) FROM logs"),
                                                  say("fin")]))
    agent.ask("Investiga")
    real.query("SELECT count(DISTINCT user_id) FROM logs")                         # una consulta del analista, sobre lo real
    ledger.record_queries(real.history[-1:])
    copies = {e["data"]["copy"] for e in ledger.entries("query")}
    assert copies == {real.copy_id, pseudo.copy_id}

    results = ledger.replay([real, pseudo])
    assert results and all(r["match"] and not r.get("skipped") for r in results)
    assert {r["copy"] for r in results} == copies
    last = ledger.entries("replay")[-1]["data"]
    assert last["mismatches"] == [] and last["skipped"] == []
    assert set(last["by_copy"]) == copies and all(c["queries"] == c["matches"] for c in last["by_copy"].values())


def test_replay_con_un_solo_motor_no_verifica_la_otra_copia_y_lo_dice(world, tmp_path, scripted):
    _, real, pseudo, _ = world
    ledger = Ledger.open("P2", real, analyst="eder", root=tmp_path)
    build_agent(pseudo, ledger, scripted([call("run_query", sql="SELECT count(*) FROM logs"), say("fin")])).ask("x")
    real.query("SELECT count(*) FROM logs")
    ledger.record_queries(real.history[-1:])
    results = ledger.replay(real)                                                   # solo los datos reales
    skipped = [r for r in results if r.get("skipped")]
    assert skipped and all(r["copy"] == pseudo.copy_id and r["match"] is False for r in skipped)
    assert [r for r in results if not r.get("skipped")] and all(r["match"] for r in results if not r.get("skipped"))
    last = ledger.entries("replay")[-1]["data"]
    assert last["mismatches"] == [] and last["skipped"] == [r["query_id"] for r in skipped]  # no verificada ≠ alterada


def test_replay_rechaza_una_copia_con_otra_politica(world, tmp_path, scripted):
    ws, real, pseudo, _ = world
    ledger = Ledger.open("P3", real, analyst="eder", root=tmp_path)
    build_agent(pseudo, ledger, scripted([call("run_query", sql="SELECT count(*) FROM logs"), say("fin")])).ask("x")
    other, _ = ws.pseudonymized(PrivacyPolicy(overrides={"x_token_type": "keep"}))
    assert other.copy_id != pseudo.copy_id
    with pytest.raises(CopyMismatch, match="no está registrada"):
        ledger.replay([real, other])


def test_las_consultas_anteriores_al_sello_se_reejecutan_sobre_los_datos_reales(world, tmp_path):
    _, real, pseudo, _ = world
    ledger = Ledger.open("P4", real, analyst="eder", root=tmp_path)
    real.query("SELECT count(*) FROM logs")
    legacy = {k: v for k, v in real.history[-1].items() if k != "copy"}              # ledger de antes de P1-b.2b
    ledger.record_queries([legacy])
    (r,) = ledger.replay(real)
    assert r["copy"] == "real" and r["match"] and not r.get("skipped")


# --- paridad de detectores --------------------------------------------------------------------------------------

def test_los_detectores_dan_lo_mismo_sobre_la_copia(world):
    _, real, pseudo, ps = world
    rep = detector_parity(real, pseudo, ps)
    assert rep["equivalent"], rep
    breadth = rep["detectors"]["resource_breadth"]
    assert breadth["matched"] > 0 and breadth["only_real"] == [] and breadth["only_pseudo"] == []
    # la lista de User-Agent difiere por el scrub; se informa por nombre de métrica, nunca por valor
    text = rep["detectors"]["automation_clients"]["text_differences"]
    assert text and all(t["metric"] in ("herramientas",) for t in text)
    assert not leaks(json.dumps(rep), real_values(real, ps))


def test_la_paridad_detecta_cuando_la_copia_si_cambia_el_resultado(tmp_path):
    ws = _case(tmp_path, "C-PAR", user_agent_variants=True)
    real, (pseudo, ps) = ws.engine(), ws.pseudonymized()
    n_real = real.query("SELECT count(DISTINCT user_agent) FROM logs").rows[0][0]
    n_pseudo = pseudo.query("SELECT count(DISTINCT user_agent) FROM logs").rows[0][0]
    assert n_pseudo < n_real                                                         # el scrub fundió User-Agent distintos
    rep = detector_parity(real, pseudo, ps)
    diffs = rep["detectors"]["resource_breadth"]["numeric_differences"]
    assert not rep["equivalent"] and any(d["metric"] == "user_agents" and d["pseudo"] < d["real"] for d in diffs)
