"""P1-b.1: perfilador analítico renombrado y resumen que cuenta actores por rol (no `user_id` fijo)."""
import pytest
from test_timezone import NAIVE, ingest

from dfir_copilot.engine import profiler as canonical
from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.evidence.ledger import Ledger
from dfir_copilot.profiling import LogProfiler as RawFileProfiler
from dfir_copilot.tools.toolkit import Toolkit


def test_el_nombre_nuevo_no_choca_con_el_perfilador_de_archivos_y_el_antiguo_sigue_funcionando():
    assert canonical.LogProfiler is canonical.CanonicalProfiler          # alias para notebooks antiguos
    assert canonical.CanonicalProfiler is not RawFileProfiler


@pytest.fixture()
def engine_without_identity(tmp_path):
    """Un log sin columna de identidad: el actor que se infiere es la IP."""
    manifest, _ = ingest(tmp_path, [f"2020-11-0{1 + i % 3} 10:0{i % 10}:00" for i in range(30)],
                         {"format": NAIVE, "timezone": "UTC"})
    return QueryEngine(manifest["output"]["path"])


def overview(prof, **kw):
    r = prof.overview(**kw)
    return dict(zip(r.columns, r.rows[0], strict=True))


def test_el_resumen_no_cuenta_columnas_que_el_log_no_aporta(engine_without_identity):
    ov = overview(canonical.CanonicalProfiler(engine_without_identity))
    assert "user_id_distintos" not in ov and "session_id_distintos" not in ov      # existen, pero vacías: 0 parecería un dato
    assert ov["src_ip_distintos"] == 9 and ov["filas"] == 30


def test_el_resumen_cuenta_el_actor_del_caso_aunque_no_sea_user_id(engine_without_identity):
    ov = overview(canonical.CanonicalProfiler(engine_without_identity), actor="src_ip")
    assert ov["actores_distintos"] == ov["src_ip_distintos"] == 9


def test_un_actor_que_no_es_columna_se_rechaza(engine_without_identity):
    with pytest.raises(ValueError, match="Dimensión desconocida"):
        canonical.CanonicalProfiler(engine_without_identity).overview(actor="actor; DROP TABLE logs")


def test_describe_del_toolkit_usa_el_rol_de_actor(engine_without_identity, tmp_path):
    kit = Toolkit(engine_without_identity, Ledger.open("C", engine_without_identity, analyst="t", root=tmp_path / "led"))
    data = kit.call("describe_dataset").data
    assert kit.roles.actor == "src_ip" and data["overview"]["actores_distintos"] == 9
    assert "user_id_distintos" not in data["overview"]
    assert kit.call("profile", {"kind": "overview"}).ok


def test_sin_manifiesto_no_se_oculta_ninguna_columna(engine_without_identity):
    prof = canonical.CanonicalProfiler(engine_without_identity)
    prof.empty = set()                                                        # como un motor sin manifiesto
    assert "user_id_distintos" in overview(prof)
