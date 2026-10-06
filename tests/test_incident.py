"""Vista del incidente (entrega E1). Lo esencial: todas las fuentes juntas SIN perder la procedencia de cada dato, una línea de tiempo en
UTC con las horas del endpoint corregidas por el desfase (y marcadas), nada con valores reales, y un tope de tokens para el incidente."""
import json

import pytest

from dfir_copilot import incident
from dfir_copilot.correlation import correlate_project
from dfir_copilot.pipeline import Deps, run_pipeline
from dfir_copilot.projects import Project, ProjectSettings
from dfir_copilot.synthetic_endpoint import make_endpoint_dataset, write_endpoint
from dfir_copilot.synthetic_firewall import make_firewall_dataset, write_firewall

NETWORK = {"service_fanout", "policy_contradiction", "risky_outbound", "volume_outlier", "blocked_then_allowed"}
ENDPOINT = {"lolbin_network", "suspicious_parent", "suspicious_cmdline"}


@pytest.fixture()
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_DATA_ROOT", str(tmp_path))
    (tmp_path / "inbox").mkdir()
    fw, ft = make_firewall_dataset(hosts=12, days=31)
    edr, et = make_endpoint_dataset(fw, ft)
    write_firewall(fw, tmp_path / "inbox" / "firewall.csv", "paloalto")
    write_endpoint(edr, tmp_path / "inbox" / "falcon.csv", "falcon_csv")
    p = Project.create("Inc", root=tmp_path / "projects", base=tmp_path, settings=ProjectSettings(use_llm=False))
    for f in ("firewall.csv", "falcon.csv"):
        p.add_from_server(tmp_path / "inbox" / f)
    for f in p.files():
        run_pipeline(p, f, Deps())
    correlate_project(p)
    return p, ft, et


def test_cada_fuente_y_cada_hallazgo_conservan_su_procedencia(world):
    p, _, _ = world
    srcs = incident.sources(p)
    assert {s["label"] for s in srcs} == {"Firewall", "Endpoint"}
    custody = {e["file"]: e["sha256"] for e in p.custody()}
    assert all(s["sha"] == custody[s["file"]] for s in srcs)
    rows = incident.findings(srcs)
    assert {r["source"]["label"] for r in rows if r["detector"] in NETWORK} == {"Firewall"}
    assert {r["source"]["label"] for r in rows if r["detector"] in ENDPOINT} == {"Endpoint"}
    order = {"high": 0, "medium": 1, "low": 2}
    assert [order[r["severity"]] for r in rows] == sorted(order[r["severity"]] for r in rows)


def test_la_linea_de_tiempo_ordenada_corregida_y_sin_valores_reales(world):
    p, ft, et = world
    events = incident.timeline(p, incident.sources(p))
    assert [e["dt"] for e in events] == sorted(e["dt"] for e in events)
    assert {e["kind"] for e in events} >= {"custodia", "hallazgo", "correlación"}
    # se corrigen las horas que vienen DEL DATO del endpoint; la entrada en la custodia es hora de esta máquina y no se toca
    data = [e for e in events if e["kind"] == "hallazgo" and e["source"]]
    assert all(e["corrected"] for e in data if e["source"]["label"] == "Endpoint")
    assert not any(e["corrected"] for e in data if e["source"]["label"] == "Firewall")
    assert not any(e["corrected"] for e in events if e["kind"] == "custodia")
    text = " ".join(e["text"] for e in events)
    for secret in (et.beacon_host, ft.beacon_hosts[0], ft.beacon_dst, *et.host_of_ip.values()):
        assert secret not in text, secret
    corr = next(e for e in events if e["kind"] == "correlación" and "rundll32.exe" in e["text"])
    start = next(e for e in events if e["kind"] == "hallazgo" and "beaconing" in e["text"] and e["source"]["label"] == "Endpoint"
                 and e["text"].startswith("Empieza"))
    assert start["dt"] == corr["dt"]                                  # el inicio de la baliza, no el de toda la actividad de la IP


def test_el_tope_de_tokens_del_incidente_suma_todas_las_fuentes(world):
    p, _, _ = world
    meta = json.loads(p.meta_path.read_text())
    meta["settings"]["max_tokens_incident"] = 1000
    p.meta_path.write_text(json.dumps(meta))
    assert incident.tokens(p)["total"] == 0 and not incident.over_budget(p)
    for f in (f for f in p.files() if f.supported):                                                 # 600 tokens en cada fuente
        (p.cases_dir / f.case_id / "p1" / "interpretacion.json").write_text(json.dumps({"usage": {"input_tokens": 500, "output_tokens": 100}}))
    t = incident.tokens(p)
    assert t["total"] == 1200 and len(t["per_source"]) == 2 and t["pct"] == 120.0 and incident.over_budget(p)
