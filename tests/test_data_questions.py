"""Perfil ampliado (entidades, relaciones, primera/última aparición, formatos) y preguntas rápidas sin modelo. Lo esencial: cifras exactas
comprobables a mano, el mismo código sirve para web, firewall y endpoint (genérico por columnas), y lo que no sabe responder lo dice."""
import pytest
from test_data_profile import small_firewall

from dfir_copilot.data_profile import build_profile
from dfir_copilot.data_questions import answer
from dfir_copilot.pipeline import Deps, run_pipeline
from dfir_copilot.projects import Project, ProjectSettings
from dfir_copilot.synthetic import make_idor_dataset, write_csv
from dfir_copilot.synthetic_endpoint import make_endpoint_dataset, write_endpoint
from dfir_copilot.synthetic_firewall import make_firewall_dataset


def analyze(tmp_path, monkeypatch, name, raw):
    monkeypatch.setenv("DFIR_DATA_ROOT", str(tmp_path))
    p = Project.create(name, root=tmp_path / "projects", base=tmp_path, settings=ProjectSettings(use_llm=False))
    p.add_from_server(raw)
    run_pipeline(p, p.files()[0], Deps())
    ws = p.workspace(p.files()[0].case_id)
    pseudo, _ = ws.pseudonymized()
    return ws, pseudo, build_profile(pseudo)


@pytest.fixture()
def fw(tmp_path, monkeypatch):
    (tmp_path / "inbox").mkdir()
    return analyze(tmp_path, monkeypatch, "Pequeno", small_firewall(tmp_path / "inbox" / "fw.csv"))


def test_entidades_relaciones_y_apariciones_con_cifras_exactas(fw):
    ws, pseudo, prof = fw
    ents = {e["column"]: e["distinct"] for e in prof["entities"]}
    assert ents["ip"] == 6 and ents["src_ip"] == 4 and ents["dst_ip"] == 2 and ents["user_id"] == 1 and ents["host"] == 1
    rel = {(r["from"], r["to"]): r for r in prof["relations"]}
    assert rel[("src_ip", "dst_ip")]["pairs"] == 4 and rel[("rule_name", "action")]["top"][0][2:] == [11]
    (src,) = [f for f in prof["first_last"] if f["column"] == "src_ip"]
    assert sum(x[1] for x in src["top"]) == 12 and all(x[0].startswith("IP-") for x in src["top"])     # en alias
    real = build_profile(ws.engine())                                                     # sobre el dato real: formatos de verdad
    fmt = {c["name"]: c["formats"] for c in real["columns"] if c.get("formats")}
    assert fmt["src_ip"] == [["ipv4", 100.0]] and {c["name"]: c["formats"] for c in prof["columns"] if c.get("formats")}["src_ip"] == [["alias", 100.0]]


@pytest.mark.parametrize("question, expected", [
    ("¿Cuántas columnas hay?", "columnas"), ("¿Cuántas IPs distintas hay?", "IPs en total (origen o destino): 6"),
    ("cuántas IPs de origen hay", "IPs de origen: 4"), ("¿Cuántos usuarios hay?", "usuarios: 1"), ("how many users", "usuarios: 1"),
    ("¿cuántas filas hay?", "12 filas"), ("¿Qué campos están vacíos?", "vacía"), ("¿hay filas duplicadas?", "1 fila"),
    ("¿Cuál es el rango de fechas?", "2026-10-04"), ("¿hay huecos?", "Hueco típico"), ("¿Quién habla con quién?", "pares distintos"),
])
def test_las_preguntas_frecuentes_se_responden_sin_modelo(fw, question, expected):
    _, pseudo, prof = fw
    a = answer(question, prof, pseudo)
    assert a.matched and expected in a.text, a.text


def test_rankings_y_primera_aparicion_consultan_el_dataset_y_muestran_la_consulta(fw):
    _, pseudo, prof = fw
    top = answer("top 2 de dst_port", prof, pseudo)
    assert top.rows == [["53", 11], ["445", 1]] and "LIMIT 2" in top.sql
    (alias,) = [r[0] for r in pseudo.query("SELECT src_ip FROM logs WHERE dst_port = 445").rows]
    seen = answer(f"¿Cuándo apareció {alias}?", prof, pseudo)
    assert seen.matched and seen.rows[0][:2] == ["src_ip", 1] and seen.rows[0][2] == seen.rows[0][3]


def test_lo_que_no_sabe_responder_lo_dice(fw):
    _, pseudo, prof = fw
    a = answer("¿qué opinas del ataque?", prof, pseudo)
    assert not a.matched and "agente" in a.text


def test_el_mismo_codigo_sirve_para_web_firewall_y_endpoint(tmp_path, monkeypatch):
    (tmp_path / "inbox").mkdir()
    rows, _ = make_idor_dataset(normal_requests=300, attacker_requests=150, out_of_pool=60)
    _, _, web = analyze(tmp_path, monkeypatch, "Web", write_csv(tmp_path / "inbox" / "web.csv", rows))
    fw_rows, ft = make_firewall_dataset(hosts=12, days=31)
    edr_rows, _ = make_endpoint_dataset(fw_rows, ft)
    _, _, edr = analyze(tmp_path, monkeypatch, "Edr", write_endpoint(edr_rows, tmp_path / "inbox" / "edr.csv"))
    assert {"usuarios", "rutas (URL)"} <= {e["label"] for e in web["entities"]}
    assert {"equipos / hosts", "procesos", "IPs de destino"} <= {e["label"] for e in edr["entities"]}
    assert ("host", "process_name") in {(r["from"], r["to"]) for r in edr["relations"]}
    assert answer("top 3 procesos", edr).rows[0][0] == "rundll32.exe"                   # el ejecutable, no el alias de la ruta
    assert answer("¿Cuántos usuarios hay?", web).matched
