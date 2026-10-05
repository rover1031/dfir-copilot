"""P0-B1: ingesta multi-formato (CSV, TSV, JSON/NDJSON, Parquet, .gz), rutas anidadas, fechas y casos reutilizables."""
import gzip
import json
from datetime import datetime, timedelta

import duckdb
import pytest
import yaml

from dfir_copilot.cases import CaseError, CaseWorkspace
from dfir_copilot.ingest.ingestor import ingest_csv, ingest_file
from dfir_copilot.profiling import LogProfiler
from dfir_copilot.profiling.readers import SourceSpec, leaf_exprs, open_source, relation_sql, restricted_connection

T0 = datetime(2024, 5, 1, 10, 0, 0)
N = 40
UA = ["Mozilla/5.0 (X11; Linux)", "curl/8.4.0", "Scrapy/2.3.0"]


def events():
    """Los mismos 40 eventos lógicos, que cada test escribe en un formato distinto."""
    return [{"ts": T0 + timedelta(seconds=37 * i), "ip": f"10.0.{i % 4}.{i + 1}", "method": ["GET", "POST"][i % 2],
             "path": f"/api/orders/{i % 7}", "query": f"id={1000 + i}&site=MeliCO", "status": [200, 404, 500][i % 3],
             "ua": UA[i % 3], "user": f"user{i % 5}"} for i in range(N)]


def uri(e):
    return f"{e['path']}?{e['query']}"


CORE = "SELECT CAST(timestamp_utc AS VARCHAR), src_ip, http_method, endpoint, query_string, status_code, user_agent"
EXPECTED = sorted((e["ts"].strftime("%Y-%m-%d %H:%M:%S+00"), e["ip"], e["method"], e["path"], e["query"], e["status"], e["ua"])
                  for e in events())


def write_mapping(tmp_path, fields, ts, fmt, name="m", **extra):
    path = tmp_path / f"{name}.yaml"
    path.write_text(yaml.safe_dump({"source": name, "format": fmt, "fields": fields, "timestamp": ts, **extra},
                                   allow_unicode=True), encoding="utf-8")
    return path


def run(tmp_path, data, mapping, out="out"):
    manifest = ingest_file(data, "x", out_dir=tmp_path / out, mapping_path=mapping)
    rows = duckdb.connect().execute(f"{CORE} FROM read_parquet('{manifest['output']['path']}')").fetchall()
    return manifest, sorted(rows)


FLAT = {"timestamp": "ts", "src_ip": "ip", "http_method": "method", "uri": "uri", "status_code": "status", "user_agent": "ua"}
NAIVE = {"format": "%Y-%m-%d %H:%M:%S", "timezone": "UTC"}


def csv_text(sep=","):
    head = sep.join(["ts", "ip", "method", "uri", "status", "ua"])
    return head + "\n" + "\n".join(sep.join([e["ts"].strftime("%Y-%m-%d %H:%M:%S"), e["ip"], e["method"], uri(e),
                                              str(e["status"]), e["ua"]]) for e in events()) + "\n"


def nested(e):
    return {"@timestamp": e["ts"].strftime("%Y-%m-%dT%H:%M:%SZ"), "source": {"ip": e["ip"]},
            "http": {"request": {"method": e["method"]}, "response": {"status_code": e["status"]}},
            "url": {"original": uri(e)}, "user_agent": {"original": e["ua"]}}


NESTED = {"timestamp": "@timestamp", "src_ip": "source.ip", "http_method": "http.request.method",
          "uri": "url.original", "status_code": "http.response.status_code", "user_agent": "user_agent.original"}


# --- el mismo contenido en cualquier formato da las mismas filas canónicas -----------------------------------------
def test_csv(tmp_path):
    f = tmp_path / "a.csv"
    f.write_text(csv_text(), encoding="utf-8")
    manifest, rows = run(tmp_path, f, write_mapping(tmp_path, FLAT, NAIVE, "csv"))
    assert rows == EXPECTED and manifest["input"]["format"] == "csv" and manifest["input"]["encoding"] == "utf-8"


def test_tsv(tmp_path):
    f = tmp_path / "a.tsv"
    f.write_text(csv_text("\t"), encoding="utf-8")
    assert run(tmp_path, f, write_mapping(tmp_path, FLAT, NAIVE, "tsv"))[1] == EXPECTED


def test_csv_de_excel_en_espanol_latin1_y_punto_y_coma(tmp_path):
    f = tmp_path / "excel.csv"
    f.write_bytes(csv_text(";").replace("Mozilla/5.0 (X11; Linux)", "Mozilla/5.0 (Bogotá)").encode("latin-1"))
    manifest, rows = run(tmp_path, f, write_mapping(tmp_path, FLAT, NAIVE, "csv"))
    expected = sorted(r[:6] + ("Mozilla/5.0 (Bogotá)" if r[6].startswith("Mozilla") else r[6],) for r in EXPECTED)
    assert manifest["input"]["encoding"] == "latin-1" and rows == expected  # el acento sobrevive a la conversión


def test_ndjson_anidado(tmp_path):
    f = tmp_path / "a.ndjson"
    f.write_text("\n".join(json.dumps(nested(e)) for e in events()), encoding="utf-8")
    manifest, rows = run(tmp_path, f, write_mapping(tmp_path, NESTED, {"format": "native", "timezone": "UTC"}, "json"))
    assert rows == EXPECTED and manifest["input"]["format"] == "json"


def test_json_en_arreglo(tmp_path):
    f = tmp_path / "a.json"
    f.write_text(json.dumps([nested(e) for e in events()]), encoding="utf-8")
    assert run(tmp_path, f, write_mapping(tmp_path, NESTED, {"format": "native", "timezone": "UTC"}, "json"))[1] == EXPECTED


def test_ndjson_gz_y_nombre_de_salida_sin_extension_de_origen(tmp_path):
    f = tmp_path / "export.ndjson.gz"
    with gzip.open(f, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(json.dumps(nested(e)) for e in events()))
    manifest, rows = run(tmp_path, f, write_mapping(tmp_path, NESTED, {"format": "native", "timezone": "UTC"}, "auto"))
    assert rows == EXPECTED and manifest["input"]["compression"] == "gzip"
    assert manifest["output"]["path"].endswith("/export.parquet")


def test_json_con_claves_planas_con_puntos_y_fecha_epoch_en_milisegundos(tmp_path):
    """Estilo LogScale: 'http.request.method' es UNA clave, no una estructura."""
    f = tmp_path / "flat.json"
    f.write_text("\n".join(json.dumps({
        "@timestamp": int((e["ts"] - datetime(1970, 1, 1)).total_seconds() * 1000),
        "source.ip": e["ip"], "http.request.method": e["method"], "url.original": uri(e),
        "http.response.status_code": str(e["status"]), "user_agent.original": e["ua"]}) for e in events()), encoding="utf-8")
    manifest, rows = run(tmp_path, f, write_mapping(tmp_path, NESTED, {"format": "epoch_ms", "timezone": "UTC"}, "json"))
    assert rows == EXPECTED


def test_parquet_tipado_con_zona_horaria(tmp_path):
    f = tmp_path / "a.parquet"
    src = tmp_path / "src.csv"
    src.write_text(csv_text(), encoding="utf-8")
    duckdb.connect().execute(
        f"COPY (SELECT CAST(ts AS TIMESTAMPTZ) AS ts, ip, method, uri, CAST(status AS INTEGER) AS status, ua "
        f"FROM read_csv('{src}')) TO '{f}' (FORMAT PARQUET)")
    manifest, rows = run(tmp_path, f, write_mapping(tmp_path, FLAT, {"format": "native", "timezone": "UTC"}, "parquet"))
    assert rows == EXPECTED and manifest["input"]["format"] == "parquet"


# --- fechas -----------------------------------------------------------------------------------------------------
def _local_csv(path, stamp):
    """Los mismos eventos con la fecha escrita a la hora de Bogotá (UTC-5), en el formato `stamp`."""
    lines = ["ts,ip,method,uri,status,ua"] + [",".join([(e["ts"] - timedelta(hours=5)).strftime(stamp), e["ip"], e["method"],
                                                        uri(e), str(e["status"]), e["ua"]]) for e in events()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_hora_local_sin_desfase_se_convierte_con_la_zona_del_mapping(tmp_path):
    f = _local_csv(tmp_path / "local.csv", "%Y-%m-%d %H:%M:%S")
    mapping = write_mapping(tmp_path, FLAT, {"format": "%Y-%m-%d %H:%M:%S", "timezone": "America/Bogota"}, "csv")
    assert run(tmp_path, f, mapping)[1] == EXPECTED  # 05:00 en Bogotá es 10:00 UTC


def test_iso8601_con_desfase_en_el_dato_ignora_la_zona_del_mapping(tmp_path):
    f = _local_csv(tmp_path / "off.csv", "%Y-%m-%dT%H:%M:%S-05:00")
    mapping = write_mapping(tmp_path, FLAT, {"format": "iso8601", "timezone_in_data": True, "timezone": "Asia/Tokyo"}, "csv")
    assert run(tmp_path, f, mapping)[1] == EXPECTED


def test_iso8601_sin_desfase_usa_la_zona_del_mapping(tmp_path):
    f = _local_csv(tmp_path / "naive.csv", "%Y-%m-%dT%H:%M:%S")
    mapping = write_mapping(tmp_path, FLAT, {"format": "iso8601", "timezone_in_data": False, "timezone": "America/Bogota"}, "csv")
    assert run(tmp_path, f, mapping)[1] == EXPECTED


def test_nginx_meses_en_espanol_con_desfase_y_linea_de_peticion(tmp_path):
    months = ["ene", "abr", "ago", "dic"]
    f = tmp_path / "nginx.csv"
    f.write_text("time_local,remote_addr,request,status\n" + "\n".join(
        f'{10 + i:02d}/{months[i % 4]}/2024:10:00:00 -0500,203.0.113.{i},"GET /api/o/{i}?tok=abc HTTP/1.1",200'
        for i in range(8)), encoding="utf-8")
    mapping = write_mapping(tmp_path, {"timestamp": "time_local", "src_ip": "remote_addr", "request_line": "request",
                                       "status_code": "status"}, {"format": "%d/%b/%Y:%H:%M:%S %z", "timezone": "UTC"}, "csv")
    manifest = ingest_file(f, "x", out_dir=tmp_path / "o", mapping_path=mapping)
    rows = duckdb.connect().execute(
        f"SELECT CAST(timestamp_utc AS VARCHAR), http_method, endpoint, query_string FROM read_parquet('{manifest['output']['path']}') "
        f"ORDER BY source_row").fetchall()
    assert rows[0] == ("2024-01-10 15:00:00+00", "GET", "/api/o/0", "tok=abc") and len(rows) == 8
    assert {r[0][:7] for r in rows} == {"2024-01", "2024-04", "2024-08", "2024-12"}


# --- rutas, derivadas y errores ----------------------------------------------------------------------------------
def test_derivada_desde_una_ruta_anidada_del_origen(tmp_path):
    f = tmp_path / "a.ndjson"
    f.write_text("\n".join(json.dumps(nested(e)) for e in events()), encoding="utf-8")
    mapping = write_mapping(tmp_path, NESTED, {"format": "native", "timezone": "UTC"}, "json",
                            derived={"x_site": {"from": "url.original", "regex": "site=([^&]+)"},
                                     "user_id": {"from": "user_agent.original", "regex": "^(\\w+)"}})
    manifest = ingest_file(f, "x", out_dir=tmp_path / "o", mapping_path=mapping)
    got = duckdb.connect().execute(f"SELECT DISTINCT x_site, user_id FROM read_parquet('{manifest['output']['path']}') "
                                   f"ORDER BY 2").fetchall()
    assert got == [("MeliCO", "Mozilla"), ("MeliCO", "Scrapy"), ("MeliCO", "curl")]


def test_una_columna_inexistente_falla_sugiriendo_la_correcta(tmp_path):
    f = tmp_path / "a.csv"
    f.write_text(csv_text(), encoding="utf-8")
    bad = dict(FLAT, src_ip="ipp")
    with pytest.raises(ValueError, match="src_ip.*'ipp'.*ip"):
        ingest_file(f, "x", out_dir=tmp_path / "o", mapping_path=write_mapping(tmp_path, bad, NAIVE, "csv"))


def test_derivada_vacia_genera_aviso(tmp_path):
    f = tmp_path / "a.csv"
    f.write_text(csv_text(), encoding="utf-8")
    mapping = write_mapping(tmp_path, FLAT, NAIVE, "csv", derived={"x_nada": {"from": "query_string", "regex": "zzz=([^&]+)"}})
    manifest = ingest_file(f, "x", out_dir=tmp_path / "o", mapping_path=mapping)
    assert any("x_nada" in w and "vacía" in w for w in manifest["warnings"])


def test_json_que_cambia_de_tipo_despues_de_la_muestra_se_reintenta(tmp_path):
    f = tmp_path / "var.ndjson"
    lines = [json.dumps({"ts": "2024-05-01T10:00:00Z", "ip": "1.1.1.1", "uri": "/a", "status": 200}) for _ in range(30_000)]
    lines.append(json.dumps({"ts": "2024-05-01T10:00:01Z", "ip": "1.1.1.1", "uri": "/a", "status": "no-es-numero"}))
    f.write_text("\n".join(lines), encoding="utf-8")
    mapping = write_mapping(tmp_path, {"timestamp": "ts", "src_ip": "ip", "uri": "uri", "status_code": "status"},
                            {"format": "native", "timezone": "UTC"}, "json")
    manifest = ingest_file(f, "x", out_dir=tmp_path / "o", mapping_path=mapping)
    assert manifest["output"]["rows"] == 30_001 and manifest["null_counts"]["status_code"] == 1


def test_ingest_csv_es_el_nombre_historico_de_ingest_file(tmp_path):
    f = tmp_path / "a.ndjson"
    f.write_text("\n".join(json.dumps(nested(e)) for e in events()), encoding="utf-8")
    mapping = write_mapping(tmp_path, NESTED, {"format": "native", "timezone": "UTC"}, "json")
    assert ingest_csv(f, "x", out_dir=tmp_path / "o", mapping_path=mapping)["output"]["rows"] == N


def test_validacion_del_mapping_multiformato(tmp_path):
    from dfir_copilot.ingest.ingestor import load_mapping
    both = write_mapping(tmp_path, {**FLAT, "request_line": "uri"}, NAIVE, "csv", name="both")
    with pytest.raises(ValueError, match="request_line"):
        load_mapping("x", both)
    nofmt = write_mapping(tmp_path, FLAT, {"timezone": "UTC"}, "csv", name="nofmt")
    with pytest.raises(ValueError, match="timestamp requiere 'format'"):
        load_mapping("x", nofmt)


# --- lectura común -------------------------------------------------------------------------------------------------
def test_las_rutas_hoja_coinciden_con_las_del_perfilador(tmp_path):
    f = tmp_path / "a.ndjson"
    f.write_text("\n".join(json.dumps(nested(e)) for e in events()), encoding="utf-8")
    con = restricted_connection(f)
    spec, _, _ = open_source(con, f)
    leaves = leaf_exprs(con, relation_sql(spec, explicit=True))
    assert set(leaves) == {fl.path for fl in LogProfiler(f).profile().fields}
    assert leaves["http.request.method"][0] == 'src."http"."request"."method"'


def test_la_conexion_restringida_solo_lee_su_archivo(tmp_path):
    ok, other = tmp_path / "ok.csv", tmp_path / "otro.csv"
    ok.write_text("a\n1\n", encoding="utf-8")
    other.write_text("a\n2\n", encoding="utf-8")
    con = restricted_connection(ok)
    assert con.execute(f"SELECT count(*) FROM read_csv('{ok}')").fetchone()[0] == 1
    with pytest.raises(duckdb.Error):
        con.execute(f"SELECT * FROM read_csv('{other}')")
    with pytest.raises(duckdb.Error):
        con.execute("SET enable_external_access = true")


def test_relation_explicita_fija_separador_y_encabezado():
    sql = relation_sql(SourceSpec("/x.csv", "csv", None, "utf-8", ";", True), explicit=True)
    assert "delim=';'" in sql and "header=true" in sql
    assert "delim" not in relation_sql(SourceSpec("/x.csv", "csv", None, "utf-8", ";", True))


# --- espacio por caso reutilizable ------------------------------------------------------------------------------
def test_open_or_create_permite_re_ejecutar_un_notebook(tmp_path):
    a = CaseWorkspace.open_or_create("C1", root=tmp_path, analyst="eder")
    f = tmp_path / "a.csv"
    f.write_text(csv_text(), encoding="utf-8")
    a.ingest(f, write_mapping(tmp_path, FLAT, NAIVE, "csv"))
    b = CaseWorkspace.open_or_create("C1", root=tmp_path)
    assert b.dir == a.dir and b.meta["dataset"]["rows"] == N and b.meta["analyst"] == "eder"


def test_open_or_create_no_reutiliza_una_carpeta_a_medias(tmp_path):
    (tmp_path / "C2" / "raw").mkdir(parents=True)
    with pytest.raises(CaseError, match="case.json"):
        CaseWorkspace.open_or_create("C2", root=tmp_path)


def test_el_caso_ingiere_un_json_y_su_verificacion_pasa(tmp_path):
    f = tmp_path / "a.ndjson"
    f.write_text("\n".join(json.dumps(nested(e)) for e in events()), encoding="utf-8")
    ws = CaseWorkspace.create("C3", root=tmp_path / "cases")
    ws.add_raw(f)
    ws.ingest(f, write_mapping(tmp_path, NESTED, {"format": "native", "timezone": "UTC"}, "json"))
    ws.ledger()
    assert ws.verify().ok and len(ws.engine().query("SELECT * FROM logs").rows) == N
