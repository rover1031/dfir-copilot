"""Entrega D2: correlación entre fuentes. Lo esencial: con un firewall y un endpoint del mismo periodo, el desfase de relojes se estima
bien, las conexiones casan, y cada hallazgo del firewall (que solo conoce la IP) se atribuye al equipo y al proceso plantados; nada de esto
llega al modelo con valores reales."""
import hashlib
import json

import pytest

from dfir_copilot.correlation import correlate_project, digest_for
from dfir_copilot.pipeline import Deps, PipelineRunner, run_pipeline
from dfir_copilot.projects import Project, ProjectSettings
from dfir_copilot.synthetic_endpoint import make_endpoint_dataset, write_endpoint
from dfir_copilot.synthetic_firewall import make_firewall_dataset, write_firewall


def build(tmp_path, monkeypatch, skew=2.5, name="Corr", runner=False, timezone=None):
    monkeypatch.setenv("DFIR_DATA_ROOT", str(tmp_path))
    inbox = tmp_path / "inbox"
    inbox.mkdir(exist_ok=True)
    fw, ft = make_firewall_dataset(hosts=20, days=35)
    edr, et = make_endpoint_dataset(fw, ft, clock_skew_s=skew)
    write_firewall(fw, inbox / "firewall.csv", "paloalto")
    write_endpoint(edr, inbox / "falcon.csv", "falcon_csv")
    p = Project.create(name, root=tmp_path / "projects", base=tmp_path, settings=ProjectSettings(use_llm=False, timezone=timezone))
    for f in ("firewall.csv", "falcon.csv"):
        p.add_from_server(inbox / f)
    if runner:
        r = PipelineRunner(sync=True)
        for f in p.files():
            r.submit(p, f, Deps())
    else:
        for f in p.files():
            run_pipeline(p, f, Deps())
    return p, ft, et, edr


@pytest.fixture()
def corr(tmp_path, monkeypatch):
    p, ft, et, edr = build(tmp_path, monkeypatch)
    return p, ft, et, edr, correlate_project(p)


def test_el_desfase_se_estima_y_las_conexiones_casan(corr):
    _, ft, et, edr, r = corr
    (pr,) = r["pairs"]
    network = sum(1 for e in edr if e["event"] == "network")
    assert r["status"] == pr["status"] == "ok" and abs(pr["skew_s"] - et.clock_skew_s) < 0.01
    assert pr["edr_events"] == pr["paired"] == pr["matched"] == network
    assert ft.beacon_dst in [ip for ip, *_ in r["shared_ips"]["top"]]


def test_cada_hallazgo_del_firewall_se_atribuye_al_equipo_y_proceso_plantados(corr):
    _, ft, et, _, r = corr
    att = {a["detector"]: a for a in r["pairs"][0]["attributions"]}
    top = lambda d: att[d]["procesos"][0][:2]  # noqa: E731
    assert top("beaconing") == [et.beacon_host, "rundll32.exe"] and att["beaconing"]["tambien_en_endpoint"] == [et.beacon_host]
    assert top("volume_outlier") == [et.exfil_host, "rclone.exe"]
    assert top("service_fanout") == [et.host_of_ip[ft.scanners[0]], "advanced_ip_scanner.exe"]
    risky = [a for a in r["pairs"][0]["attributions"] if a["detector"] == "risky_outbound"]
    assert risky and all(p[1] in ("mstsc.exe", "ssh.exe", "explorer.exe") for a in risky for p in a["procesos"])


def test_queda_en_el_ledger_de_cada_caso_con_su_hash(corr):
    p, *_ = corr
    data = (p.dir / "correlacion.json").read_bytes()
    for f in p.files():
        if f.supported:
            ws = p.workspace(f.case_id)
            (e,) = ws.ledger(ws.engine()).entries("correlation")
            assert e["data"]["sha256"] == hashlib.sha256(data).hexdigest() and ws.verify().ok


def test_el_resumen_para_el_agente_no_lleva_valores_reales(corr):
    p, ft, et, _, r = corr
    fw_case = next(f.case_id for f in p.files() if f.name == "firewall.csv")
    _, ps = p.workspace(fw_case).pseudonymized()
    text = digest_for(r, ps)
    assert "rundll32.exe" in text and "EQUIPO-" in text and "2.5" in text
    for secret in (*et.host_of_ip.values(), *et.host_of_ip.keys(), ft.beacon_dst):
        assert secret not in text, secret


def test_sin_pareja_de_fuentes_o_con_relojes_muy_desfasados_se_dice(tmp_path, monkeypatch):
    p, *_ = build(tmp_path, monkeypatch, skew=500.0)
    (pr,) = correlate_project(p, max_skew_s=120)["pairs"]
    assert pr["status"] == "sin_pares" and "NAT" in pr["reason"]
    solo = Project.create("Solo", root=tmp_path / "projects", base=tmp_path)
    solo.add_from_server(tmp_path / "inbox" / "firewall.csv")
    assert correlate_project(solo)["status"] == "no_aplica"


def test_se_correlaciona_sola_al_terminar_el_segundo_archivo(tmp_path, monkeypatch):
    p, *_ = build(tmp_path, monkeypatch, name="Auto", runner=True)
    r = json.loads((p.dir / "correlacion.json").read_text())
    assert r["status"] == "ok" and r["pairs"][0]["status"] == "ok" and not (p.dir / "correlacion_error.txt").exists()


def test_una_zona_horaria_mal_declarada_se_detecta_como_desfase_de_horas_enteras(tmp_path, monkeypatch):
    """El CSV del firewall no trae zona: declarado America/Bogota (UTC-5) frente a un EDR en UTC, las fuentes quedan 5 h desfasadas."""
    p, *_ = build(tmp_path, monkeypatch, timezone="America/Bogota")
    (pr,) = correlate_project(p)["pairs"]
    assert pr["status"] == "sin_pares" and pr["hour_offset_hint"]["hours"] == -5 and "zona horaria" in pr["reason"]
