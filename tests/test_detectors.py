"""Pruebas de detectores contra un dataset sintético con verdad conocida."""
import pytest

from dfir_copilot.detectors import available, run_detectors
from dfir_copilot.detectors.base import Finding
from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.ingest.ingestor import ingest_csv
from dfir_copilot.synthetic import make_idor_dataset, write_csv


def build_engine(tmp_path, **kwargs):
    rows, truth = make_idor_dataset(**kwargs)
    csv = write_csv(tmp_path / "synthetic.csv", rows)
    manifest = ingest_csv(csv, source="web_access_meli", out_dir=tmp_path / "out")
    return QueryEngine(manifest["output"]["path"]), truth


@pytest.fixture()
def attacked(tmp_path):
    return build_engine(tmp_path)


def test_el_detector_esta_registrado():
    assert "resource_breadth" in available()


def test_encuentra_a_todos_los_atacantes_y_solo_a_ellos(attacked):
    engine, truth = attacked
    (run,) = run_detectors(engine, names=["resource_breadth"])
    assert run.status == "ok"
    flagged = {f.entity["user_id"] for f in run.findings}
    assert flagged == set(truth.attacker_actors)  # recall 1.0 y precisión 1.0


def test_sin_ataque_no_hay_falsos_positivos(tmp_path):
    engine, _ = build_engine(tmp_path, n_attackers=0)
    (run,) = run_detectors(engine, names=["resource_breadth"])
    assert run.status == "ok" and run.findings == ()


def test_el_hallazgo_trae_evidencia_trazable(attacked):
    engine, _ = attacked
    (run,) = run_detectors(engine, names=["resource_breadth"])
    f = run.findings[0]
    assert isinstance(f, Finding) and f.severity in {"low", "medium", "high"}
    assert f.metrics["recursos_distintos"] > f.metrics["umbral"] > f.metrics["mediana_pares"]
    assert f.evidence == run.queries
    assert all(q["sql"] and q["status"] == "ok" and q["dataset_sha256"] for q in f.evidence)
    assert any("HAVING" in q["sql"] for q in f.evidence)  # la consulta que produjo el hallazgo está incluida


def test_no_aplicable_si_la_columna_no_tiene_datos(attacked):
    engine, _ = attacked
    (run,) = run_detectors(engine, names=["resource_breadth"],
                           params={"resource_breadth": {"resource_col": "session_id"}})
    assert run.status == "not_applicable" and "session_id" in run.reason


def test_no_aplicable_si_la_columna_no_existe(attacked):
    engine, _ = attacked
    (run,) = run_detectors(engine, names=["resource_breadth"],
                           params={"resource_breadth": {"actor_col": "no_existe"}})
    assert run.status == "not_applicable"


def test_no_aplicable_con_pocos_pares(tmp_path):
    engine, _ = build_engine(tmp_path, n_normal=2, n_attackers=1)
    (run,) = run_detectors(engine, names=["resource_breadth"])
    assert run.status == "not_applicable" and "pares" in run.reason
