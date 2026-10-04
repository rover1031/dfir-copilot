"""Pruebas de regresión del ingestor con un CSV mínimo que cubre los casos críticos."""
import hashlib
import json

import duckdb
import pytest

from dfir_copilot.ingest.ingestor import ingest_csv

HEADER = "timestamp,http_staus,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
ROWS = [
    # fecha AAAA-DD-MM: 12 de enero en el texto = 1 de diciembre real
    '2020-01-12T00:16,201,mercadolibre.com,/invoices/search?invoice_id=229933235&site_id=MeliMX&authtoken=ATUSER-ID-jaxsonbuyer,GET,https://mercadolibre.com/billing,"Mozilla/5.0 (Windows NT 10.0) ",27.0.2.178',
    # día 31: solo es válido con día antes que mes
    '2020-31-12T23:59,200,mercadolibre.com,/invoices/search?invoice_id=229933999&site_id=MeliBR&authtoken=TEST-ID-websecuser,GET,,wget,99.247.33.186',
    # invoice_id no numérico: debe quedar NULL (y contarse en null_counts)
    '2020-01-10T00:00,408,mercadolibre.com,/invoices/search?invoice_id=abc&site_id=MeliBR&authtoken=TEST-ID-developuser,GET,google.com,crawler4j,1.0.0.1',
]


@pytest.fixture()
def result(tmp_path):
    csv = tmp_path / "sample.csv"
    csv.write_text(HEADER + "\n".join(ROWS) + "\n", encoding="utf-8")
    manifest = ingest_csv(csv, source="web_access_meli", out_dir=tmp_path / "out")
    return csv, manifest


def _rows(manifest, sql):
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    return con.execute(sql.format(p=manifest["output"]["path"])).fetchall()


def test_no_se_pierden_filas(result):
    _, m = result
    assert m["input"]["rows"] == m["output"]["rows"] == len(ROWS)


def test_fecha_es_dia_antes_que_mes(result):
    _, m = result
    assert m["time_range_utc"] == ["2020-10-01 00:00:00+00", "2020-12-31 23:59:00+00"]
    (ts,), = _rows(m, "SELECT CAST(timestamp_utc AS VARCHAR) FROM '{p}' WHERE source_row = 1")
    assert ts == "2020-12-01 00:16:00+00"
    assert m["null_counts"]["timestamp_utc"] == 0


def test_user_id_acepta_ambos_prefijos(result):
    _, m = result
    got = _rows(m, "SELECT user_id, x_token_type FROM '{p}' ORDER BY source_row")
    assert got == [("jaxsonbuyer", "ATUSER"), ("websecuser", "TEST"), ("developuser", "TEST")]


def test_invoice_id_no_numerico_queda_visible(result):
    _, m = result
    assert m["null_counts"]["x_invoice_id"] == 1


def test_cadena_de_custodia(result):
    csv, m = result
    assert m["input"]["sha256"] == hashlib.sha256(csv.read_bytes()).hexdigest()
    assert any("Zona horaria NO verificada" in w for w in m["warnings"])
    assert json.loads((csv.parent / "out" / "sample.manifest.json").read_text())["source"] == "web_access_meli"
