"""La demostración que correrá el evaluador funciona de punta a punta con datos sintéticos y sin modelo: crea los dos análisis, analiza cada
log, lee el boletín PDF y no pisa un análisis existente salvo que se pida."""
import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("pymupdf")

DEMO = Path(__file__).resolve().parents[1] / "tools" / "demo.py"


def _load():
    spec = importlib.util.spec_from_file_location("demo", DEMO)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("DFIR_DATA_ROOT", str(data))
    monkeypatch.setenv("DFIR_PROJECTS_ROOT", str(data / "projects"))
    monkeypatch.setenv("DFIR_REPORTS_ROOT", str(tmp_path / "reports"))
    monkeypatch.delenv("DFIR_GEOIP_DB", raising=False)
    return data


def test_la_demo_crea_y_analiza_todo_sin_modelo(env):
    from dfir_copilot.documents import service as D
    from dfir_copilot.projects import Project

    demo = _load()
    summary = demo.run_demo(log=lambda *_: None)
    projects = {p.name: p for p in Project.list()}
    assert set(projects) == {"Demo IDOR", "Demo incidente"} and len(summary) == 2
    for states in summary.values():
        assert states and all(s in ("done", "needs_attention") for s in states.values()), states
    inc = projects["Demo incidente"]
    pdf = next(f for f in inc.files() if f.kind == "document")
    data = D.load(inc.dir / "documents" / pdf.case_id)
    values = {i.value for i in data["extraction"].iocs}
    assert "CVE-2024-21762" in values and "c2.ejemplo-malicioso.test" in values


def test_no_pisa_un_analisis_existente_salvo_con_reiniciar(env):
    from dfir_copilot.projects import Project, ProjectError

    demo = _load()
    demo.run_demo(log=lambda *_: None)
    with pytest.raises(ProjectError, match="--reiniciar"):
        demo.run_demo(log=lambda *_: None)
    demo.run_demo(reset=True, log=lambda *_: None)
    assert sorted(p.name for p in Project.list()) == ["Demo IDOR", "Demo incidente"]
