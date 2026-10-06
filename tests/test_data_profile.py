"""Etapa `profile`: el desglose de ingeniero de datos. Lo esencial: cifras exactas sobre el dataset completo (comprobables a mano),
sobre la copia con alias, con su hash en el ledger, idempotente, compatible con estados guardados antes de existir la etapa, y que
el triaje del agente parte de ese desglose."""
import hashlib
import json

import pytest
from conftest import ScriptedChat
from langchain_core.messages import AIMessage

from dfir_copilot.pipeline import STEPS, Deps, run_pipeline
from dfir_copilot.projects import Project, ProjectSettings

HEADER = "timestamp,ip_origen,src_port,ip_destino,dst_port,protocolo,accion,bytes_sent,bytes_received,rule_id,user_origen,device_name\n"


def small_firewall(path):
    """12 filas: 10 a minuto seguido, una DUPLICADA exacta y una tras un hueco de 4 h 51 min (17 460 s)."""
    rows = [f"2026-10-04 10:{i:02d}:00,10.0.0.{1 + i % 3},{40000 + i},8.8.8.8,53,UDP,ALLOW,100,200,RULE_DNS_OUT,ana,FW-1" for i in range(10)]
    rows.append(rows[3])
    rows.append("2026-10-04 15:00:00,10.0.0.9,41000,192.168.5.5,445,TCP,DROP,0,0,RULE_DEFAULT_DENY,,FW-1")
    path.write_text(HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return path


@pytest.fixture()
def analyzed(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_DATA_ROOT", str(tmp_path))
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    p = Project.create("Perfil", root=tmp_path / "projects", base=tmp_path, settings=ProjectSettings(use_llm=False))
    p.add_from_server(small_firewall(inbox / "fw.csv"))
    st = run_pipeline(p, p.files()[0], Deps())
    return p, st


def test_el_perfil_da_cifras_exactas_comprobables(analyzed):
    p, st = analyzed
    assert st["steps"]["profile"]["status"] == "done" and "12 filas" in st["steps"]["profile"]["message"]
    ws = p.workspace(p.files()[0].case_id)
    prof = json.loads((ws.dir / "p1" / "perfil_datos.json").read_text())
    assert prof["rows"] == 12 and prof["quality"]["duplicate_rows"] == 1
    assert prof["time"]["largest_gaps"][0][2] == 17460 and prof["time"]["unreadable"] == 0
    cols = {c["name"]: c for c in prof["columns"]}
    assert cols["src_ip"]["distinct"] == 4 and all(v.startswith("IP-") for v, _ in cols["src_ip"]["top"])     # en alias
    assert cols["action"]["top"] == [["ALLOW", 11], ["DROP", 1]] and cols["dst_port"]["stats"]["max"] == 445
    assert cols["user_id"]["filled"] == 11 and cols["user_id"]["empty"] == 1
    scopes = {ip["column"]: {s: n for s, n, _ in ip["scopes"]} for ip in prof["ips"]}
    assert scopes["src_ip"] == {"private": 12} and scopes["dst_ip"] == {"public": 11, "private": 1}
    assert sum(prof["time"]["per_hour"]) == 12 and prof["time"]["per_hour"][10] == 11


def test_el_perfil_queda_en_el_ledger_con_su_hash_y_no_se_repite(analyzed):
    p, _ = analyzed
    ws = p.workspace(p.files()[0].case_id)
    entries = ws.ledger(ws.engine()).entries("data_profile")
    data = (ws.dir / "p1" / "perfil_datos.json").read_bytes()
    assert len(entries) == 1 and entries[0]["data"]["sha256"] == hashlib.sha256(data).hexdigest() and ws.verify().ok
    st = run_pipeline(p, p.files()[0], Deps())
    assert len(ws.ledger(ws.engine()).entries("data_profile")) == 1 and st["steps"]["profile"]["status"] == "done"


def test_un_estado_guardado_antes_de_la_etapa_se_migra_sin_repetir_lo_hecho(analyzed):
    p, _ = analyzed
    cid = p.files()[0].case_id
    old = p.status(cid)
    old["steps"].pop("profile")                                                       # como lo dejó la versión anterior
    p.save_status(cid, old)
    (p.workspace(cid).dir / "p1" / "perfil_datos.json").unlink()
    st = run_pipeline(p, p.files()[0], Deps())
    assert list(st["steps"]) == list(STEPS) and st["steps"]["profile"]["status"] == "done"
    assert st["steps"]["detectors"]["status"] == "done" and st["steps"]["detectors"]["started_at"] == old["steps"]["detectors"]["started_at"]


def test_el_triaje_parte_del_perfil(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_DATA_ROOT", str(tmp_path))
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    usage = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
    chat = ScriptedChat(script=[AIMessage(content="Triaje hecho", usage_metadata=usage)])
    p = Project.create("Triaje", root=tmp_path / "projects", base=tmp_path, settings=ProjectSettings(use_llm=True))
    p.add_from_server(small_firewall(inbox / "fw.csv"))
    st = run_pipeline(p, p.files()[0], Deps(agent_llm=lambda: chat))
    assert st["steps"]["triage"]["status"] in ("done", "needs_attention"), st
    ws = p.workspace(p.files()[0].case_id)
    question = ws.ledger(ws.engine()).entries("agent_turn")[0]["data"]["question"]
    assert "PERFIL DE DATOS" in question and "12 filas" in question and "10.0.0." not in question            # en alias
