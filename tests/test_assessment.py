"""Entrega E2: diccionario compartido, valoración del incidente e informe del incidente. Lo esencial: la misma IP tiene el mismo alias en
todas las fuentes de un análisis nuevo (los antiguos no cambian); el modelo nunca ve valores reales; sus citas se verifican y un veredicto
sin evidencia citable se rebaja por código; y el informe compartible no lleva valores reales."""
import json

import pytest

from dfir_copilot import incident
from dfir_copilot.assessment import assess, build_context
from dfir_copilot.correlation import correlate_project
from dfir_copilot.interpret.structured import StructuredReply
from dfir_copilot.pipeline import Deps, run_pipeline
from dfir_copilot.projects import Project, ProjectSettings
from dfir_copilot.reporting.incident_report import build, export
from dfir_copilot.synthetic_endpoint import make_endpoint_dataset, write_endpoint
from dfir_copilot.synthetic_firewall import make_firewall_dataset, write_firewall


class FakeLLM:
    def __init__(self, data):
        self.data, self.calls = data, 0

    def invoke(self, system, user, schema):
        self.calls += 1
        self.seen = user
        return StructuredReply(self.data, {"input_tokens": 9000, "output_tokens": 600})


def verdict(refs_for, verdict="incidente_probable"):
    return {"verdict": verdict, "confidence": "media", "summary": "Baliza periódica atribuida a rundll32 tras una cadena Word→PowerShell.",
            "attack_type": "Malware con C2", "mitre": ["T1071", "T1218.011", "no-es-tecnica"],
            "evidence_for": [{"ref": r, "explanation": "evidencia citada"} for r in refs_for],
            "evidence_against": [{"ref": "C1", "explanation": "podría ser un agente legítimo"}], "gaps": ["DNS"], "next_steps": ["aislar el equipo"]}


@pytest.fixture()
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_DATA_ROOT", str(tmp_path))
    monkeypatch.setenv("DFIR_REPORTS_ROOT", str(tmp_path / "reports"))
    (tmp_path / "inbox").mkdir()
    fw, ft = make_firewall_dataset(hosts=12, days=31)
    edr, et = make_endpoint_dataset(fw, ft)
    write_firewall(fw, tmp_path / "inbox" / "firewall.csv", "paloalto")
    write_endpoint(edr, tmp_path / "inbox" / "falcon.csv", "falcon_csv")
    p = Project.create("Val", root=tmp_path / "projects", base=tmp_path, settings=ProjectSettings(use_llm=False))
    for f in ("firewall.csv", "falcon.csv"):
        p.add_from_server(tmp_path / "inbox" / f)
    for f in p.files():
        run_pipeline(p, f, Deps())
    correlate_project(p)
    return p, ft, et


def secrets(ft, et):
    return {et.beacon_host, ft.beacon_hosts[0], ft.beacon_dst, *et.host_of_ip.values()}


def test_un_analisis_nuevo_comparte_alias_entre_fuentes_y_uno_antiguo_no(world, tmp_path):
    p, ft, _ = world
    aliases = {f.name: tuple(p.workspace(f.case_id).pseudonymized()[1].alias_text(v).text for v in (ft.beacon_hosts[0], ft.beacon_dst))
               for f in p.files() if f.supported}
    assert len(set(aliases.values())) == 1 and p.dictionary_path.exists()
    old = Project.create("Viejo", tmp_path / "inbox", root=tmp_path / "projects", base=tmp_path)
    assert old.dictionary_path is None


def test_el_contexto_del_modelo_no_lleva_valores_reales(world):
    p, ft, et = world
    text, refs = build_context(p)
    assert not [s for s in secrets(ft, et) if s in text]
    assert any(r.startswith("f-") for r in refs) and "C1" in refs and refs["C1"] == "Correlación"


def test_las_citas_se_verifican_y_las_tecnicas_se_validan(world):
    p, _, _ = world
    _, refs = build_context(p)
    fid = next(r for r in refs if r.startswith("f-"))
    llm = FakeLLM(verdict([fid, "C1", "f-000000000000"]))
    r = assess(p, llm)
    v = r["assessment"]
    assert r["ok"] and r["discarded_refs"] == 1 and [e["ref"] for e in v["evidence_for"]] == [fid, "C1"]
    assert v["evidence_for"][0]["source"] in ("Firewall", "Endpoint") and v["mitre"] == ["T1071", "T1218.011"]
    assert incident.tokens(p)["total"] == 9600
    for s in incident.sources(p):
        (e,) = s["ws"].ledger(s["ws"].engine()).entries("incident_assessment")
        assert e["data"]["verdict"] == "incidente_probable"


def test_un_veredicto_sin_evidencia_citable_se_rebaja_por_codigo(world):
    p, _, _ = world
    r = assess(p, FakeLLM(verdict(["f-000000000000"], "incidente_confirmado")))
    assert r["assessment"]["verdict"] == "no_concluyente" and "Rebajado por código" in r["code_notes"][0]


def test_con_el_tope_alcanzado_no_se_llama_al_modelo(world):
    p, _, _ = world
    meta = json.loads(p.meta_path.read_text())
    meta["settings"]["max_tokens_incident"] = 1000
    p.meta_path.write_text(json.dumps(meta))
    assess(p, FakeLLM(verdict(["C1"])))                                       # gasta 9600 > 1000
    llm = FakeLLM(verdict(["C1"]))
    r = assess(p, llm)
    assert not r["ok"] and "tope" in r["error"] and llm.calls == 0


def test_el_informe_del_incidente_compartible_e_interno(world):
    p, ft, et = world
    assess(p, FakeLLM(verdict(["C1"])))
    shared = build(p, "compartible")
    for section in ("## 1. Valoración", "## 2. Fuentes", "## 4. Correlación", "## 5. Línea de tiempo", "## 7. Conclusiones"):
        assert section in shared
    assert "Incidente probable" in shared and not [s for s in secrets(ft, et) if s in shared]
    assert et.beacon_host in build(p, "interno")
    r = export(p, "compartible")
    assert r["path"].exists()
    for s in incident.sources(p):
        assert any(e["data"].get("scope") == "incident" and e["data"]["sha256"] == r["sha256"]
                   for e in s["ws"].ledger(s["ws"].engine()).entries("report_export"))
