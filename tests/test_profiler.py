"""Pruebas del perfilador sobre un dataset sintético con un ataque conocido."""
import pytest

from dfir_copilot.engine.profiler import LogProfiler
from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.ingest.ingestor import ingest_csv

HEADER = "timestamp,http_staus,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"


def row(day, month, hhmm, status, invoice, site, user, ip, ua="Mozilla/5.0"):
    # El timestamp del origen es AAAA-DD-MM
    return (
        f"2020-{day:02d}-{month:02d}T{hhmm},{status},mercadolibre.com,"
        f"/invoices/search?invoice_id={invoice}&site_id={site}&authtoken=ATUSER-ID-{user},"
        f'GET,https://mercadolibre.com/billing,"{ua}",{ip}'
    )


def synthetic_rows():
    rows = []
    # alice: uso normal, 5 facturas propias consultadas 2 veces, siempre 200
    for i in range(10):
        rows.append(row(1, 10, f"10:{i:02d}", 200, 118822001 + i % 5, "MeliCO", "alice", "10.0.0.1"))
    # bob: 4 peticiones, una con 401
    for i, st in enumerate([200, 200, 200, 401]):
        rows.append(row(2, 10, f"11:{i:02d}", st, 229933001 + i, "MeliAR", "bob", "10.0.0.2"))
    # ataque IDOR: IP externa con el token de alice recorre 30 facturas consecutivas ajenas
    for i in range(30):
        st = 401 if i % 3 == 2 else 200
        rows.append(
            row(5, 12, f"03:{i:02d}", st, 229933100 + i, "MeliAR", "alice", "66.6.6.6", "Scrapy/2.3.0")
        )
    return rows


@pytest.fixture()
def profiler(tmp_path):
    csv = tmp_path / "synthetic.csv"
    csv.write_text(HEADER + "\n".join(synthetic_rows()) + "\n", encoding="utf-8")
    m = ingest_csv(csv, source="web_access_meli", out_dir=tmp_path / "out")
    return LogProfiler(QueryEngine(m["output"]["path"]))


def test_overview(profiler):
    r = profiler.overview()
    cols = dict(zip(r.columns, r.rows[0]))
    assert cols["filas"] == 44
    assert cols["user_id_distintos"] == 2 and cols["src_ip_distintos"] == 3


def test_top_ordena_y_calcula_porcentaje(profiler):
    r = profiler.top("user_agent")
    assert r.rows[0][:2] == ("Scrapy/2.3.0", 30)
    assert r.rows[1][:2] == ("Mozilla/5.0", 14)
    assert round(sum(row[2] for row in r.rows), 1) == 100.0


def test_top_con_filtro(profiler):
    r = profiler.top("user_id", filters={"src_ip": "66.6.6.6"})
    assert r.rows[0][:2] == ("alice", 30)


def test_filtro_numerico(profiler):
    r = profiler.top("status_code", filters={"status_code": 401})
    assert r.rows == [(401, 11, 100.0)]  # 1 de bob + 10 del ataque


def test_status_by_calcula_error(profiler):
    r = profiler.status_by("src_ip")
    por_ip = {row[0]: row for row in r.rows}
    assert por_ip["66.6.6.6"][1] == 30 and por_ip["66.6.6.6"][6] == 33.3  # 10 de 30


def test_activity_por_usuario(profiler):
    r = profiler.activity("user_id")
    alice = next(row for row in r.rows if row[0] == "alice")
    assert alice[1] == 40 and alice[3] == 2  # peticiones, ips


def test_timeline_diaria(profiler):
    r = profiler.timeline("day")
    assert [row[1] for row in r.rows] == [10, 4, 30]


def test_dimension_derivada_de_la_fuente_esta_disponible(profiler):
    assert profiler.top("x_site_id").rows[0][0] in {"MeliAR", "MeliCO"}


@pytest.mark.parametrize(
    "dim",
    ["no_existe", "user_id; DROP VIEW logs", 'user_id") FROM logs --', "1=1", ""],
)
def test_dimensiones_invalidas_se_rechazan(profiler, dim):
    with pytest.raises(ValueError):
        profiler.top(dim)


@pytest.mark.parametrize("n", [0, -1, 1001, "5", True, None])
def test_limite_invalido(profiler, n):
    with pytest.raises(ValueError):
        profiler.top("src_ip", n=n)


def test_bucket_y_filtros_invalidos(profiler):
    with pytest.raises(ValueError):
        profiler.timeline("year; DROP")
    with pytest.raises(ValueError):
        profiler.top("src_ip", filters={"src_ip": 1.5})
    with pytest.raises(ValueError):
        profiler.top("src_ip", filters={"no_existe": "x"})
