"""Pruebas de seguridad y límites del motor de consultas."""
import duckdb
import pytest

from dfir_copilot.engine.query_engine import QueryEngine, QueryRejected, QueryTimeout
from dfir_copilot.ingest.ingestor import ingest_csv

HEADER = "timestamp,http_staus,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
ROWS = [
    '2020-01-12T00:16,201,mercadolibre.com,/invoices/search?invoice_id=229933235&site_id=MeliMX&authtoken=ATUSER-ID-jaxsonbuyer,GET,https://mercadolibre.com/billing,"Mozilla/5.0",27.0.2.178',
    '2020-31-12T23:59,200,mercadolibre.com,/invoices/search?invoice_id=229933999&site_id=MeliBR&authtoken=TEST-ID-websecuser,GET,,wget,99.247.33.186',
    '2020-01-10T00:00,408,mercadolibre.com,/invoices/search?invoice_id=118824252&site_id=MeliCO&authtoken=TEST-ID-developuser,GET,google.com,crawler4j,1.0.0.1',
]


@pytest.fixture()
def built(tmp_path):
    csv = tmp_path / "sample.csv"
    csv.write_text(HEADER + "\n".join(ROWS) + "\n", encoding="utf-8")
    manifest = ingest_csv(csv, source="web_access_meli", out_dir=tmp_path / "out")
    return tmp_path, manifest


@pytest.fixture()
def engine(built):
    _, manifest = built
    return QueryEngine(manifest["output"]["path"], timeout_s=1.0, max_rows=2)


def test_select_valido_con_trazabilidad(built):
    _, m = built
    eng = QueryEngine(m["output"]["path"])
    res = eng.query("SELECT count(*) AS n FROM logs;")
    assert res.rows == [(3,)] and not res.truncated
    assert res.dataset_sha256 == m["input"]["sha256"]
    assert eng.history[-1]["status"] == "ok"


def test_timestamps_salen_como_texto_iso(engine):
    res = engine.query("SELECT timestamp_utc FROM logs WHERE source_row = 1")
    assert res.rows == [("2020-12-01 00:16:00+00",)]


def test_tope_de_filas(engine):
    res = engine.query("SELECT * FROM logs")
    assert res.row_count == 2 and res.truncated


def test_esquema_consultable(built):
    _, m = built
    eng = QueryEngine(m["output"]["path"])
    assert any(r[0] == "x_invoice_id" for r in eng.query("DESCRIBE logs").rows)


def test_max_rows_por_llamada_nunca_supera_el_tope_del_motor(engine):
    assert engine.query("SELECT * FROM logs", max_rows=100).row_count == 2


@pytest.mark.parametrize(
    "sql",
    [
        "DROP VIEW logs",
        "CREATE TABLE x AS SELECT 1",
        "INSERT INTO logs VALUES (1)",
        "COPY logs TO '/tmp/exfil.csv'",
        "EXPORT DATABASE '/tmp/e'",
        "ATTACH ':memory:' AS m",
        "INSTALL httpfs",
        "LOAD httpfs",
        "SET enable_external_access = true",
        "PRAGMA database_list",
        "EXPLAIN SELECT 1",
        "SELECT 1; SELECT 2",
        "SELECT 1; DROP VIEW logs",
        "",
    ],
)
def test_sentencias_no_select_se_rechazan(engine, sql):
    with pytest.raises(QueryRejected):
        engine.query(sql)
    assert engine.history[-1]["status"] == "rejected"


@pytest.mark.parametrize(
    "template",
    [
        "SELECT * FROM read_csv('{other}')",
        "SELECT * FROM read_text('{other}')",
        "SELECT * FROM glob('{dir}/*')",
        "SELECT * FROM sniff_csv('{other}')",
        "SELECT * FROM read_csv('https://example.com/x.csv')",
    ],
)
def test_select_no_puede_leer_otros_archivos_ni_red(built, engine, template):
    tmp, _ = built
    other = tmp / "otro.csv"
    other.write_text("a,b\n1,2\n", encoding="utf-8")
    with pytest.raises(duckdb.Error):
        engine.query(template.format(other=other, dir=tmp))


def test_no_expone_variables_de_entorno(engine, monkeypatch):
    monkeypatch.setenv("JUPYTER_TOKEN", "secreto")
    with pytest.raises(duckdb.Error):  # si una versión futura añade getenv, este test debe avisar
        engine.query("SELECT getenv('JUPYTER_TOKEN')")


def test_configuracion_bloqueada(engine):
    with pytest.raises(duckdb.Error):
        engine._con.execute("SET enable_external_access = true")


def test_timeout_cancela_y_el_motor_sigue_usable(engine):
    with pytest.raises(QueryTimeout):
        engine.query(
            "SELECT sum(hash(a.range * b.range)) FROM range(1000000) a, range(1000000) b"
        )
    assert engine.history[-1]["status"] == "timeout"
    assert engine.query("SELECT 1 AS ok").rows == [(1,)]


def test_detecta_parquet_alterado(built):
    _, m = built
    with open(m["output"]["path"], "ab") as fh:
        fh.write(b"\x00")
    with pytest.raises(ValueError, match="alterado"):
        QueryEngine(m["output"]["path"])
