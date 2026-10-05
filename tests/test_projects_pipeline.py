"""Proyectos (una carpeta -> un caso por archivo) y análisis automático por etapas. Lo esencial: la carpeta de origen no puede salir de la raíz de
datos; el análisis local no depende del modelo; cada etapa es idempotente y se puede reintentar sin repetir lo hecho."""
import json
import threading

import pytest
from conftest import ScriptedChat
from interp_helpers import Scripted, StructuredReply, ok
from test_agent import FULL, say

from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.pipeline import STEPS, Deps, PipelineRunner, llm_status, new_status, run_pipeline
from dfir_copilot.projects import Project, ProjectError, ProjectSettings, slugify
from dfir_copilot.synthetic import make_idor_dataset, write_csv


@pytest.fixture()
def base(tmp_path):
    inbox = tmp_path / "inbox" / "analisis1"
    inbox.mkdir(parents=True)
    rows, _ = make_idor_dataset()
    write_csv(inbox / "three_months.csv", rows)
    (inbox / "notas.txt").write_text("no es un log", encoding="utf-8")
    return tmp_path, inbox


def make_project(base, name="Análisis 1", **settings):
    tmp, inbox = base
    return Project.create(name, inbox, ProjectSettings(analyst="eder", **settings), root=tmp / "projects", base=tmp)


def csv_of(project):
    return next(f for f in project.files() if f.name == "three_months.csv")


# --- proyectos -----------------------------------------------------------------------------------------------------

def test_un_proyecto_descubre_sus_archivos_y_da_un_caso_a_cada_uno(base):
    project = make_project(base)
    assert project.id == "analisis-1" and project.name == "Análisis 1"
    files = {f.name: f for f in project.files()}
    assert files["three_months.csv"].supported and files["three_months.csv"].case_id == "analisis-1--three-months"
    assert not files["notas.txt"].supported and files["notas.txt"].reason == "formato no soportado"
    assert project.file("analisis-1--three-months").name == "three_months.csv"
    with pytest.raises(ProjectError):
        project.file("otro")


def test_los_ids_de_caso_son_validos_y_no_chocan(base):
    tmp, inbox = base
    for name in ("Informe Final.csv", "informe-final.csv", "Ünïcode ✓.json"):
        (inbox / name).write_text("a\n1\n", encoding="utf-8")
    project = make_project(base)
    ids = [f.case_id for f in project.files()]
    assert len(ids) == len(set(ids))
    import re
    assert all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", i) for i in ids)


def test_la_carpeta_de_origen_debe_estar_dentro_de_la_raiz_de_datos(base):
    tmp, inbox = base
    for bad in ("/etc", str(tmp / "inbox" / ".." / ".."), "/", str(tmp / "no-existe")):
        with pytest.raises(ProjectError):
            Project.create("x", bad, root=tmp / "projects", base=tmp)
    link = tmp / "inbox" / "enlace"
    link.symlink_to("/etc")                                                              # un enlace que escapa de la raíz
    with pytest.raises(ProjectError, match="dentro de"):
        Project.create("y", link, root=tmp / "projects", base=tmp)


def test_nombre_duplicado_vacio_o_ajustes_invalidos(base):
    make_project(base)
    with pytest.raises(ProjectError, match="Ya existe"):
        make_project(base)
    with pytest.raises(ProjectError):
        make_project(base, name="  ")
    for bad in ({"language": "fr"}, {"max_tokens": 0}, {"timezone": "America/Santigo"}, {"timezone": "UTC-3"}):
        with pytest.raises(ProjectError):
            ProjectSettings(**bad)
    assert slugify("Ñandú · Año 2020!") == "nandu-ano-2020"


def test_los_ajustes_sobreviven_a_reabrir_el_proyecto(base):
    make_project(base, timezone="America/Santiago", language="en", use_llm=False, max_tokens=50_000, max_tokens_case=900_000)
    tmp, _ = base
    again = Project.open("analisis-1", root=tmp / "projects")
    s = again.settings
    assert (s.timezone, s.language, s.use_llm, s.max_tokens, s.max_tokens_case) == ("America/Santiago", "en", False, 50_000, 900_000)
    assert [p.id for p in Project.list(tmp / "projects")] == ["analisis-1"]
    with pytest.raises(ProjectError):
        Project.open("../etc", root=tmp / "projects")


# --- análisis automático ---------------------------------------------------------------------------------------------

def test_el_analisis_local_no_necesita_el_modelo(base):
    project = make_project(base, timezone="America/Santiago", use_llm=False)
    st = run_pipeline(project, csv_of(project), Deps())
    steps = {k: v["status"] for k, v in st["steps"].items()}
    assert steps["draft"] in ("done", "needs_attention") and steps["ingest"] in ("done", "needs_attention")
    assert steps["copy"] == "done" and steps["detectors"] == "done"
    assert steps["interpret"] == steps["explore"] == steps["triage"] == "skipped"
    assert st["state"] in ("done", "needs_attention") and "hallazgo(s)" in st["steps"]["detectors"]["message"]
    ws = project.workspace(csv_of(project).case_id)
    assert ws.meta["dataset"] and ws.verify().ok and ws.ledger(ws.engine()).entries("finding")


def test_la_zona_declarada_al_crear_el_proyecto_queda_en_el_mapping_sin_verificar(base):
    project = make_project(base, timezone="America/Santiago", use_llm=False)
    run_pipeline(project, csv_of(project), Deps())
    ws = project.workspace(csv_of(project).case_id)
    tz = ws.engine().manifest["timezone"]
    assert tz["assumed"] == "America/Santiago" and tz["verified"] is False and "analisis-1" in tz["note"] and "eder" in tz["note"]


def test_un_archivo_no_soportado_se_detiene_en_el_primer_paso_con_su_motivo(base):
    project = make_project(base, use_llm=False)
    notas = next(f for f in project.files() if f.name == "notas.txt")
    st = run_pipeline(project, notas, Deps())
    assert st["state"] == "failed" and st["steps"]["draft"]["status"] == "failed"
    assert "no soportado" in st["steps"]["draft"]["message"]
    assert all(st["steps"][s]["status"] == "skipped" for s in STEPS[1:])


def test_las_etapas_con_modelo_dejan_las_hipotesis_pendientes_de_aprobacion(base):
    project = make_project(base, use_llm=True)
    deps = Deps(agent_llm=lambda: ScriptedChat(script=FULL()), structured_llm=lambda: Scripted(ok()))
    st = run_pipeline(project, csv_of(project), deps)
    assert st["steps"]["interpret"]["status"] == "done" and st["steps"]["explore"]["status"] == "done"
    assert "ejecutadas en local" in st["steps"]["explore"]["message"]
    assert st["steps"]["triage"]["status"] == "needs_attention" and "pendiente(s) de tu aprobación" in st["steps"]["triage"]["message"]
    ws = project.workspace(csv_of(project).case_id)
    assert json.loads((ws.dir / "p1" / "interpretacion.json").read_text())["ok"] is True
    assert (ws.dir / "p1" / "consultas.json").exists() and (ws.agent_dir / "threads.json").exists()   # y el hilo queda en disco


def test_una_respuesta_inutilizable_del_modelo_no_detiene_el_analisis(base):
    project = make_project(base, use_llm=True)
    deps = Deps(agent_llm=None, structured_llm=lambda: Scripted(StructuredReply(None, {}, parse_error="no es JSON")))
    st = run_pipeline(project, csv_of(project), deps)
    assert st["steps"]["interpret"]["status"] == "needs_attention" and "parse_error" in st["steps"]["interpret"]["message"]
    assert st["steps"]["ingest"]["status"] in ("done", "needs_attention") and st["steps"]["detectors"]["status"] == "done"


def test_sin_clave_las_etapas_del_modelo_se_saltan_con_su_motivo(base, monkeypatch):
    from dfir_copilot.agent.llm import LLMConfigError

    project = make_project(base, use_llm=True)

    def no_key():
        raise LLMConfigError("falta ANTHROPIC_API_KEY")

    st = run_pipeline(project, csv_of(project), Deps(agent_llm=no_key, structured_llm=no_key))
    assert st["steps"]["interpret"]["status"] == "skipped" and "modelo no configurado" in st["steps"]["interpret"]["message"]
    assert st["steps"]["triage"]["status"] == "skipped" and st["steps"]["detectors"]["status"] == "done"


def test_un_fallo_se_registra_detiene_y_al_reintentar_reanuda_sin_repetir(base, monkeypatch):
    project = make_project(base, use_llm=False)
    from dfir_copilot import pipeline as pl

    boom = {"on": True}
    original = pl.Pipeline._step_copy

    def flaky(self):
        if boom["on"]:
            raise RuntimeError("disco lleno")
        return original(self)

    monkeypatch.setattr(pl.Pipeline, "_step_copy", flaky)
    st = run_pipeline(project, csv_of(project), Deps())
    assert st["state"] == "failed" and st["steps"]["copy"]["status"] == "failed" and "disco lleno" in st["steps"]["copy"]["message"]
    assert st["steps"]["ingest"]["status"] in ("done", "needs_attention") and st["steps"]["detectors"]["status"] == "pending"
    rows_before = CaseWorkspace.open(csv_of(project).case_id, root=project.cases_dir).meta["dataset"]["ingested_at_utc"]
    boom["on"] = False
    st = run_pipeline(project, csv_of(project), Deps())
    assert st["state"] in ("done", "needs_attention") and st["steps"]["copy"]["status"] == "done" and st["steps"]["detectors"]["status"] == "done"
    assert CaseWorkspace.open(csv_of(project).case_id, root=project.cases_dir).meta["dataset"]["ingested_at_utc"] == rows_before  # no re-ingirió


def test_reanalizar_no_repite_lo_ya_hecho(base):
    project = make_project(base, use_llm=True)
    deps = Deps(agent_llm=lambda: ScriptedChat(script=[*FULL()]), structured_llm=None)
    first = run_pipeline(project, csv_of(project), deps)
    ws = project.workspace(csv_of(project).case_id)
    entries = len(ws.ledger(ws.engine()).entries())
    again = run_pipeline(project, csv_of(project), Deps(agent_llm=lambda: ScriptedChat(script=[say("no debe llamarse")])))
    assert len(ws.ledger(ws.engine()).entries()) == entries                              # nada nuevo en el ledger
    assert again["steps"]["triage"]["status"] == first["steps"]["triage"]["status"] == "needs_attention"


def test_si_se_pierde_el_estado_el_ledger_evita_repetir_el_triaje_y_los_detectores(base):
    project = make_project(base, use_llm=True)
    run_pipeline(project, csv_of(project), Deps(agent_llm=lambda: ScriptedChat(script=FULL())))
    ws = project.workspace(csv_of(project).case_id)
    entries = len(ws.ledger(ws.engine()).entries())
    project.status_path(csv_of(project).case_id).unlink()                                 # se pierde el archivo de estado
    st = run_pipeline(project, csv_of(project), Deps(agent_llm=lambda: ScriptedChat(script=[say("no debe llamarse")])))
    assert st["steps"]["triage"]["message"] == "ya hay un triaje en este caso"
    assert st["steps"]["detectors"]["message"] == "los detectores ya se ejecutaron"
    assert len(ws.ledger(ws.engine()).entries()) == entries                              # ni consultas ni turnos nuevos


def test_si_el_modelo_se_configura_despues_el_triaje_se_reintenta(base):
    project = make_project(base, use_llm=True)
    st = run_pipeline(project, csv_of(project), Deps())                                    # sin modelo
    assert st["steps"]["triage"]["status"] == "skipped"
    st = run_pipeline(project, csv_of(project), Deps(agent_llm=lambda: ScriptedChat(script=FULL())))
    assert st["steps"]["triage"]["status"] == "needs_attention"


def test_el_estado_se_guarda_por_etapa_y_en_disco(base):
    project = make_project(base, use_llm=False)
    seen = []
    run_pipeline(project, csv_of(project), Deps(), on_update=lambda s: seen.append(s["state"]))
    assert "running" in seen and seen[-1] in ("done", "needs_attention")
    saved = project.status(csv_of(project).case_id)
    assert set(saved["steps"]) == set(STEPS) and saved["started_at"] and saved["finished_at"]
    assert all(s["started_at"] for k, s in saved["steps"].items() if s["status"] in ("done", "needs_attention"))


# --- ejecución en segundo plano ---------------------------------------------------------------------------------------

def test_el_runner_no_lanza_dos_veces_el_mismo_archivo(base):
    project = make_project(base, use_llm=False)
    source = csv_of(project)
    gate, started = threading.Event(), threading.Event()

    from dfir_copilot import pipeline as pl

    original = pl.run_pipeline

    def slow(*a, **kw):
        started.set()
        gate.wait(10)
        return original(*a, **kw)

    pl.run_pipeline = slow
    try:
        runner = PipelineRunner(workers=1)
        assert runner.submit(project, source, Deps()) is True
        started.wait(10)
        assert runner.running(project.id, source.case_id) and runner.submit(project, source, Deps()) is False
        assert project.status(source.case_id)["state"] == "running"                      # la interfaz ya lo ve en curso
        gate.set()
        for _ in range(200):
            if not runner.running(project.id, source.case_id):
                break
            threading.Event().wait(0.1)
        assert not runner.running(project.id, source.case_id)
        assert project.status(source.case_id)["state"] in ("done", "needs_attention")
    finally:
        pl.run_pipeline = original
        gate.set()


def test_new_status_y_llm_status(base):
    project = make_project(base)
    st = new_status(csv_of(project))
    assert st["state"] == "pending" and list(st["steps"]) == list(STEPS)
    ok_, msg = llm_status()
    assert isinstance(ok_, bool) and isinstance(msg, str)
