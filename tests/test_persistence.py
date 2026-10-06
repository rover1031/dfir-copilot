"""P1-c: la conversación del agente persiste en disco. Lo esencial: una aprobación pendiente y una conversación en curso sobreviven a
un reinicio (agente nuevo, guardado nuevo, ledger reabierto), un hilo no se reanuda con otro prompt u otra copia, y el archivo no
crece sin límite ni es ejecutable."""
import json

import pytest
from test_agent import FULL, HID, call, say
from test_privacy_agent import _case

from dfir_copilot.agent.graph import build_agent
from dfir_copilot.agent.persist import CheckpointFileError, FileCheckpointer, ThreadStale
from dfir_copilot.evidence.ledger import Ledger


@pytest.fixture()
def setup(tmp_path, make_engine, scripted):
    engine, _ = make_engine()
    root = tmp_path / "ledger"
    path = tmp_path / "agent" / "threads.json"

    def boot(script, **kw):
        """Un 'arranque' del kernel: ledger reabierto, guardado leído del disco y agente nuevo."""
        ledger = Ledger.open("P", engine, analyst="eder", root=root)
        llm = scripted(script)
        agent = build_agent(engine, ledger, llm, allow_real=True, checkpointer=FileCheckpointer(path), **kw)
        return agent, llm, ledger

    return boot, path, engine


def test_una_aprobacion_pendiente_sobrevive_a_un_reinicio(setup):
    boot, _, _ = setup
    agent1, _, _ = boot(FULL())
    r1 = agent1.ask("¿Qué pasó?")
    assert r1.status == "needs_approval"

    agent2, llm2, ledger2 = boot([say("Resumen final tras reiniciar")])               # otro arranque
    assert agent2.pending() == r1.approvals                                           # la petición sigue ahí
    r2 = agent2.resolve("approve", "Revisado tras reiniciar")
    assert r2.status == "done" and "Resumen final" in r2.answer
    assert agent2.book.get(HID)["status"] == "confirmada" and ledger2.verify().ok
    # el modelo ve la conversación de antes del reinicio, no un hilo vacío
    seen = " ".join(str(m.content) for m in llm2.log[-1]["messages"])
    assert "run_detectors" in seen or "datos_del_log" in seen


def test_los_tokens_no_se_cuentan_dos_veces_tras_reiniciar(setup):
    boot, _, _ = setup
    boot(FULL())[0].ask("¿Qué pasó?")
    agent2, _, ledger2 = boot([say("fin")])
    r = agent2.resolve("approve", "ok")
    assert r.tokens == 105 and agent2.tokens_used() == 105                            # 7 llamadas de 15; no 90 + 105
    assert [e["data"]["tokens_delta"] for e in ledger2.entries("agent_turn")] == [90, 15]


def test_una_conversacion_en_curso_se_retoma_y_el_modelo_ve_lo_anterior(setup):
    boot, _, _ = setup
    agent1, _, _ = boot([call("describe_dataset"), say("Primera respuesta")])
    agent1.ask("Primera pregunta")
    agent2, llm2, _ = boot([say("Segunda respuesta")])
    r = agent2.ask("Segunda pregunta")
    assert r.status == "done" and r.answer == "Segunda respuesta"
    sent = " ".join(str(m.content) for m in llm2.log[0]["messages"])
    assert "Primera pregunta" in sent and "Segunda pregunta" in sent and "Primera respuesta" in sent
    assert "describe_dataset" in sent or "dataset_sha256" in sent                      # también el resultado de la herramienta


def test_el_guardado_se_compacta_a_un_punto_por_hilo(setup, tmp_path, monkeypatch, scripted):
    boot, path, engine = setup
    agent, _, _ = boot(FULL())
    agent.ask("¿Qué pasó?")
    assert len(agent._checkpointer.storage["default"][""]) == 1                      # un solo punto, también con aprobación pendiente
    agent.resolve("approve", "ok")
    assert len(agent._checkpointer.storage["default"][""]) == 1
    compacted = path.stat().st_size

    other = tmp_path / "sin_compactar.json"
    monkeypatch.setattr(FileCheckpointer, "compact", lambda self, thread_id: None)    # lo mismo, sin compactar
    ledger = Ledger.open("P2", engine, analyst="eder", root=tmp_path / "led2")
    plain = build_agent(engine, ledger, scripted(FULL()), allow_real=True, checkpointer=FileCheckpointer(other))
    plain.ask("¿Qué pasó?")
    plain.resolve("approve", "ok")
    assert len(plain._checkpointer.storage["default"][""]) > 1 and compacted < other.stat().st_size


def test_un_hilo_creado_con_otro_prompt_o_copia_no_se_reanuda(setup):
    boot, path, _ = setup
    boot([say("hola")])[0].ask("Primera")
    for field_, other in (("prompt_sha", "otro-prompt"), ("copy_id", "pseudonymized:otra-copia")):
        agent, llm, ledger = boot([say("no debe llamarse")])
        agent._checkpointer.set_meta("default", **{field_: other})
        before = len(ledger.entries())
        with pytest.raises(ThreadStale, match="reset"):
            agent.ask("Segunda")
        assert llm.log == [] and len(ledger.entries()) == before                       # nada se envió ni se registró
        agent._checkpointer.set_meta("default", **{field_: "restaurar"})
        agent._checkpointer.set_meta("default", prompt_sha=agent.prompt_sha, copy_id=agent.engine.copy_id)


def test_una_aprobacion_pendiente_de_un_hilo_obsoleto_no_se_reanuda_y_sigue_pendiente(setup):
    boot, _, _ = setup
    boot(FULL())[0].ask("¿Qué pasó?")
    agent2, _, ledger2 = boot([say("fin")])
    agent2._checkpointer.set_meta("default", prompt_sha="otro-prompt")
    with pytest.raises(ThreadStale):
        agent2.resolve("approve", "ok")
    assert len(agent2.pending()) == 1 and agent2.book.get(HID)["status"] == "en_prueba"
    agent2.reset()                                                                     # descartarlo es explícito
    agent2.ask("Empiezo de nuevo")                                                     # y el hilo nuevo se crea sin problema


def test_threads_lista_los_hilos_y_si_se_pueden_continuar(setup):
    boot, _, _ = setup
    agent, _, _ = boot(FULL())
    agent.ask("¿Qué pasó?")
    (info,) = agent.threads()
    assert info["thread_id"] == "default" and info["continuable"] is True and info["pending"] is True and info["created_at"]
    agent._checkpointer.set_meta("default", prompt_sha="otro")
    assert agent.threads()[0]["continuable"] is False


def test_reset_borra_el_hilo_tambien_del_disco(setup):
    boot, path, _ = setup
    agent, _, _ = boot([say("hola")])
    agent.ask("Primera")
    agent.reset()
    reloaded = FileCheckpointer(path)
    assert reloaded.threads() == [] and agent.pending() == []
    assert json.loads(path.read_text())["storage"] == []


def test_el_archivo_es_json_y_uno_dañado_se_explica(setup, tmp_path):
    boot, path, _ = setup
    boot([say("hola")])[0].ask("Primera")
    data = json.loads(path.read_text(encoding="utf-8"))                               # JSON plano: nada ejecutable al cargarse
    assert data["format"] == 1 and set(data) == {"format", "meta", "storage", "writes", "blobs"}
    bad = tmp_path / "roto.json"
    bad.write_text("{no es json", encoding="utf-8")
    with pytest.raises(CheckpointFileError, match="No se pudo leer"):
        FileCheckpointer(bad)
    future = tmp_path / "futuro.json"
    future.write_text(json.dumps({"format": 99}), encoding="utf-8")
    with pytest.raises(CheckpointFileError, match="Formato"):
        FileCheckpointer(future)


def test_sin_checkpointer_el_hilo_sigue_en_memoria(tmp_path, make_engine, scripted):
    engine, _ = make_engine()
    ledger = Ledger.open("M", engine, analyst="eder", root=tmp_path / "ledger")
    agent = build_agent(engine, ledger, scripted([say("hola")]), allow_real=True)
    agent.ask("Primera")
    assert [t["thread_id"] for t in agent.threads()] == ["default"] and not (tmp_path / "agent").exists()


def test_el_caso_guarda_el_hilo_en_su_carpeta_sin_alterar_la_custodia(tmp_path, scripted):
    ws = _case(tmp_path, "C-P1C")
    pseudo, _ = ws.pseudonymized()
    agent = build_agent(pseudo, ws.ledger(), scripted([say("hola")]), checkpointer=ws.checkpointer())
    agent.ask("Primera")
    assert (ws.dir / "agent" / "threads.json").exists() and ws.agent_dir == ws.dir / "agent"
    assert ws.verify().ok
    again = build_agent(pseudo, ws.ledger(), scripted([say("otra")]), checkpointer=ws.checkpointer())
    assert again.threads()[0]["continuable"] is True


# --- dos instancias sobre el mismo caso (la interfaz abierta mientras el triaje automático corre en segundo plano) ----------

def test_la_interfaz_abierta_antes_del_triaje_ve_lo_que_el_triaje_dejo_pendiente(setup):
    """Regresión: la interfaz leía el guardado UNA vez; si el caso se abría con el triaje en marcha, se quedaba con una foto vieja,
    no veía las propuestas por aprobar y declaraba el hilo 'a medias'."""
    boot, _, _ = setup
    web, _, _ = boot([say("respuesta")])                                                 # la interfaz abre el caso primero
    pipe, _, _ = boot(FULL())                                                            # el triaje corre en otra instancia
    r = pipe.ask("Triaje inicial")
    assert r.status == "needs_approval"
    assert web.pending() == r.approvals and web._phase("default") == "awaiting_approval"


def test_una_instancia_con_una_foto_vieja_no_pisa_lo_que_guardo_otra(setup):
    boot, _, _ = setup
    web, _, _ = boot([say("respuesta")])                                                 # foto tomada antes del triaje
    pipe, _, _ = boot(FULL())
    r = pipe.ask("Triaje inicial")
    web.reset("otro-hilo")                                                               # la instancia vieja escribe algo
    later, _, _ = boot([say("x")])
    assert later.pending() == r.approvals                                                # y aun así la aprobación pendiente sigue en disco
