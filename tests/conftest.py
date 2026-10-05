"""Fixtures compartidas: motores de consulta sobre datasets sintéticos con verdad conocida."""
import itertools

import pytest

from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.ingest.ingestor import ingest_csv
from dfir_copilot.synthetic import make_idor_dataset, write_csv


@pytest.fixture()
def engine_from_rows(tmp_path):
    """Devuelve una función rows -> QueryEngine (admite varios datasets por test)."""
    counter = itertools.count()

    def build(rows):
        d = tmp_path / f"ds{next(counter)}"
        d.mkdir()
        manifest = ingest_csv(write_csv(d / "synthetic.csv", rows), "web_access_meli", out_dir=d / "out")
        return QueryEngine(manifest["output"]["path"])

    return build


@pytest.fixture()
def make_engine(engine_from_rows):
    """Devuelve una función **kwargs -> (QueryEngine, GroundTruth) con un ataque IDOR sintético."""

    def build(**kwargs):
        rows, truth = make_idor_dataset(**kwargs)
        return engine_from_rows(rows), truth

    return build
