"""Pruebas de la fase local (P0): lectura multi-formato, perfilado, mapeo bilingüe y privacidad del Data Profile."""
import gzip
import json

import duckdb
import pytest

from dfir_copilot.profiling import DataProfile, LogProfiler, SchemaMapper, SourceError, normalize_name
from dfir_copilot.profiling.i18n import catalog, placeholders, t
from dfir_copilot.synthetic import make_idor_dataset, write_csv


def profile(path, **kw):
    return LogProfiler(path, **kw).profile()


def mapping(p):
    return {m.canonical: m.field for m in p.mapping}


def codes(p):
    return {w.code for w in p.warnings}


# --- fixtures de archivos de distintos tipos -------------------------------------------------------------
@pytest.fixture()
def web_csv(tmp_path):
    rows, _ = make_idor_dataset()
    return write_csv(tmp_path / "three_months.csv", rows), rows


@pytest.fixture()
def spanish_csv(tmp_path):
    lines = ["fecha;ip_origen;usuario;url;estado;navegador"] + [
        f"2024-05-{1 + i % 28:02d} 1{i % 10}:0{i % 6}:00;10.0.{i % 4}.{i};josé.muñoz{i % 3};"
        f"/facturas/buscar?id={i};{[200, 404, 500][i % 3]};Mozilla/5.0" for i in range(60)]
    path = tmp_path / "exportacion.csv"
    path.write_bytes("\n".join(lines).encode("latin-1"))
    return path


EDR = [{"@timestamp": f"2024-05-01T10:{i % 60:02d}:00Z", "host": {"name": f"WS{i % 3:02d}"},
        "user": {"name": "ana.gomez"}, "event": {"action": ["process_start", "network_connect"][i % 2]},
        "source": {"ip": f"10.9.0.{i}"},
        "process": {"name": "powershell.exe", "pid": 4000 + i, "command_line": "powershell -enc SQBFAFgA",
                    "parent": {"name": "winword.exe"}, "hash": {"sha256": "ab" * 32}}} for i in range(50)]


@pytest.fixture()
def edr_ndjson(tmp_path):
    path = tmp_path / "edr.ndjson"
    path.write_text("\n".join(json.dumps(r) for r in EDR), encoding="utf-8")
    return path


# --- web: el caso del proyecto ----------------------------------------------------------------------------
def test_web_csv_perfil_y_mapeo(web_csv):
    path, rows = web_csv
    p = profile(path)
    assert p.dataset.row_count == len(rows) and p.source.format == "csv" and p.source.delimiter == ","
    assert mapping(p) == {"timestamp": "timestamp", "src_ip": "source_ip", "host": "http_host",
                          "http_method": "http_method", "uri": "http_uri", "status_code": "http_staus",
                          "user_agent": "http_user_agent", "referer": "http_referer"}
    assert p.log_type_hints[0].type == "web"


def test_columna_con_error_tipografico_se_mapea_por_contenido(web_csv):
    p = profile(web_csv[0])
    m = next(m for m in p.mapping if m.canonical == "status_code")
    assert m.field == "http_staus" and m.method == "semantic"


def test_detecta_sola_la_trampa_dia_mes(web_csv):
    """El error que cometimos al principio del proyecto: ahora el perfil lo evita y lo explica."""
    p = profile(web_csv[0])
    assert p.timestamp.format == "%Y-%d-%mT%H:%M" and p.timestamp.parse_pct_full == 100.0
    assert p.timestamp.min_utc.startswith("2020-10-01") and p.timestamp.max_utc.startswith("2020-12-31")
    rejected = {a.name: a.pct for a in p.timestamp.alternatives}
    assert rejected["iso8601"] < 50 and "warn.timestamp_rejected_alt" in codes(p)


def test_token_en_la_url_y_claves_de_parametros(web_csv):
    p = profile(web_csv[0])
    uri = next(f for f in p.fields if f.path == "http_uri")
    assert set(uri.url_param_keys) == {"invoice_id", "site_id", "authtoken"}
    assert uri.secret_in_values_pct == 100.0 and "warn.secret_in_values" in codes(p)


def test_valores_categoricos_solo_si_son_vocabulario_tecnico(web_csv):
    p = profile(web_csv[0])
    by = {f.path: f for f in p.fields}
    assert by["http_staus"].enum_values == ["200", "304", "400", "401"]
    assert by["http_method"].enum_values == ["GET"]
    assert by["source_ip"].enum_values is None  # IPs: nunca


# --- bilingüe ---------------------------------------------------------------------------------------------
def test_csv_de_excel_en_espanol_latin1_y_punto_y_coma(spanish_csv):
    p = profile(spanish_csv, lang="es")
    assert (p.source.encoding, p.source.delimiter) == ("latin-1", ";")
    assert mapping(p) == {"timestamp": "fecha", "src_ip": "ip_origen", "user_id": "usuario", "uri": "url",
                          "status_code": "estado", "user_agent": "navegador"}
    msg = next(w.message for w in p.warnings if w.code == "warn.encoding_fallback")
    assert "no es UTF-8" in msg


def test_los_avisos_salen_en_el_idioma_pedido(spanish_csv):
    en = profile(spanish_csv, lang="en")
    msg = next(w.message for w in en.warnings if w.code == "warn.encoding_fallback")
    assert "not valid UTF-8" in msg and en.lang == "en"
    assert en.log_type_hints[0].label == "Web / API access"


@pytest.mark.parametrize("raw, expected", [
    ("Dirección IP", "direccion_ip"), ("sourceIPAddress", "source_ip_address"), ("@timestamp", "timestamp"),
    ("SHA256HashData", "sha256_hash_data"), ("cs(User-Agent)", "cs_user_agent"), ("c-ip", "c_ip"),
    ("IP Origen", "ip_origen"), ("Fecha y Hora", "fecha_y_hora"), ("ImageFileName", "image_file_name"),
])
def test_normalizacion_de_nombres(raw, expected):
    assert normalize_name(raw) == expected


def test_catalogo_bilingue_completo_y_coherente():
    for key, entry in catalog().items():
        assert set(entry) == {"es", "en"}, key
        assert placeholders(entry["es"]) == placeholders(entry["en"]), key
    with pytest.raises(ValueError):
        t("warn.empty", "fr")


# --- multi-formato ------------------------------------------------------------------------------------------
def test_ndjson_anidado_de_edr(edr_ndjson):
    p = profile(edr_ndjson, lang="en")
    assert p.dataset.nested and p.source.format == "json"
    m = mapping(p)
    assert m["process_name"] == "process.name" and m["parent_process"] == "process.parent.name"
    assert m["command_line"] == "process.command_line" and m["file_hash"] == "process.hash.sha256"
    assert m["user_id"] == "user.name" and m["host"] == "host.name"
    assert p.log_type_hints[0].type == "edr" and p.timestamp.field == "@timestamp"


def test_json_en_arreglo_y_comprimido_dan_el_mismo_resultado(tmp_path, edr_ndjson):
    array = tmp_path / "edr.json"
    array.write_text(json.dumps(EDR), encoding="utf-8")
    gz = tmp_path / "edr.ndjson.gz"
    with gzip.open(gz, "wt") as fh:
        fh.write(edr_ndjson.read_text(encoding="utf-8"))
    base = mapping(profile(edr_ndjson))
    assert mapping(profile(array)) == base and mapping(profile(gz)) == base
    assert profile(gz).source.compression == "gzip"


def test_estilo_falcon_epoch_en_milisegundos(tmp_path):
    recs = [{"timestamp": str(1714557600000 + i * 60000), "ComputerName": f"H{i % 4}", "UserName": "svc_backup",
             "event_simpleName": "ProcessRollup2", "ImageFileName": "\\Device\\HarddiskVolume3\\cmd.exe",
             "CommandLine": "cmd.exe /c whoami", "SHA256HashData": "cd" * 32} for i in range(30)]
    path = tmp_path / "falcon.json"
    path.write_text("\n".join(json.dumps(r) for r in recs), encoding="utf-8")
    p = profile(path)
    assert p.timestamp.format == "epoch_ms" and p.timestamp.min_utc.startswith("2024-05-01 10:00:00")
    m = mapping(p)
    assert (m["host"], m["user_id"], m["command_line"], m["file_hash"]) == (
        "ComputerName", "UserName", "CommandLine", "SHA256HashData")
    assert p.log_type_hints[0].type == "edr"  # proceso + comando + hash pesan más que usuario + evento


def test_parquet_tipado_de_firewall(tmp_path):
    path = tmp_path / "fw.parquet"
    duckdb.connect().execute(
        f"COPY (SELECT TIMESTAMPTZ '2024-05-01 10:00:00+00' + INTERVAL (range) MINUTE AS event_time, "
        f"'10.0.0.' || (range % 9) AS src_ip, '172.16.0.1' AS dst_ip, 443 AS dst_port, 'tcp' AS protocol, "
        f"CASE WHEN range % 3 = 0 THEN 'deny' ELSE 'allow' END AS action FROM range(100)) TO '{path}' (FORMAT PARQUET)")
    p = profile(path)
    assert p.source.format == "parquet" and p.log_type_hints[0].type == "firewall"
    assert p.timestamp.format.startswith("native:") and p.timestamp.timezone_in_data is True
    assert next(f for f in p.fields if f.path == "action").enum_values == ["allow", "deny"]


def test_tsv_en_espanol(tmp_path):
    path = tmp_path / "fw.tsv"
    path.write_text("fecha_hora\tip_origen\tip_destino\tpuerto_destino\tprotocolo\taccion\n" + "\n".join(
        f"2024-05-{1 + i % 20:02d} 10:00:00\t10.0.0.{i}\t172.16.0.1\t443\ttcp\t{['permitir', 'denegar'][i % 2]}"
        for i in range(20)), encoding="utf-8")
    p = profile(path)
    assert p.source.format == "tsv" and mapping(p)["dst_port"] == "puerto_destino"
    assert p.log_type_hints[0].type == "firewall"


def test_nginx_meses_en_espanol_y_linea_de_peticion(tmp_path):
    months = ["ene", "abr", "ago", "dic", "may"]
    path = tmp_path / "nginx.csv"
    path.write_text("time_local,remote_addr,request,status\n" + "\n".join(
        f'{10 + i % 9:02d}/{months[i % 5]}/2024:10:00:00 -0500,203.0.113.{i},"GET /api/o/{i} HTTP/1.1",200'
        for i in range(40)), encoding="utf-8")
    p = profile(path)
    assert p.timestamp.format == "%d/%b/%Y:%H:%M:%S %z" and p.timestamp.parse_pct_full == 100.0
    assert p.timestamp.timezone_in_data is True and p.timestamp.min_utc == "2024-01-10 15:00:00+00"
    assert "warn.request_line" in codes(p)


def test_json_con_esquema_variable_se_reintenta_leyendo_todo(tmp_path):
    path = tmp_path / "variable.ndjson"
    lines = [json.dumps({"ts": "2024-05-01T10:00:00Z", "port": 80}) for _ in range(30_000)]
    lines.append(json.dumps({"ts": "2024-05-01T10:00:00Z", "port": "no-es-numero"}))
    path.write_text("\n".join(lines), encoding="utf-8")
    p = profile(path)
    assert p.dataset.row_count == 30_001 and "warn.schema_retry" in codes(p)


# --- regla de oro: nada crudo sale ------------------------------------------------------------------------
def test_ningun_valor_crudo_aparece_en_el_perfil(web_csv, spanish_csv, edr_ndjson):
    sensitive = ["josé", "muñoz", "10.0.", "10.1.", "66.6.6", "/facturas", "atacante", "normal0", "ATUSER-ID",
                 "ana.gomez", "WS0", "powershell -enc", "SQBFAFgA", "abab", "winword"]
    for path in (web_csv[0], spanish_csv, edr_ndjson):
        payload = profile(path).to_llm_json()
        assert not [s for s in sensitive if s in payload], path.name


def test_el_perfil_solo_lleva_el_nombre_del_archivo_no_la_ruta(web_csv):
    p = profile(web_csv[0])
    assert p.source.file_name == "three_months.csv" and str(web_csv[0].parent) not in p.to_llm_json()


def test_el_perfil_es_liviano_y_cumple_el_contrato(web_csv, edr_ndjson):
    for path in (web_csv[0], edr_ndjson):
        payload = profile(path).to_llm_json()
        assert len(payload.encode("utf-8")) < 16_000
        DataProfile.model_validate_json(payload)  # el JSON serializado sigue cumpliendo el esquema
    assert "properties" in DataProfile.json_schema()


def test_el_perfil_es_reproducible(web_csv):
    a = profile(web_csv[0]).model_dump(exclude={"generated_at_utc"})
    b = profile(web_csv[0]).model_dump(exclude={"generated_at_utc"})
    assert a == b


def test_el_hash_identifica_el_archivo_exacto(web_csv):
    import hashlib
    path = web_csv[0]
    assert profile(path).source.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


# --- mapeador: ambigüedad y ampliación --------------------------------------------------------------------
def test_dos_columnas_candidatas_se_marcan_como_ambiguas(tmp_path):
    path = tmp_path / "proxy.csv"
    path.write_text("timestamp,client_ip,x_forwarded_for,url\n" + "\n".join(
        f"2024-05-01T10:00:0{i % 10},10.0.0.{i},190.1.1.{i},/a" for i in range(20)), encoding="utf-8")
    p = profile(path)
    amb = next(a for a in p.ambiguous if a["canonical"] == "src_ip")
    assert {c["field"] for c in amb["candidates"]} == {"client_ip", "x_forwarded_for"}
    assert "warn.mapping_ambiguous" in codes(p)


def test_el_diccionario_se_amplia_sin_tocar_codigo(tmp_path):
    path = tmp_path / "raro.csv"
    path.write_text("cuando,quien\n2024-05-01 10:00:00,ana\n", encoding="utf-8")
    mapper = SchemaMapper(extra={"user_id": {"aliases": ["quien"]}, "timestamp": {"aliases": ["cuando"]}})
    assert mapping(LogProfiler(path, mapper=mapper).profile()) == {"timestamp": "cuando", "user_id": "quien"}


# --- errores y casos límite -------------------------------------------------------------------------------
def test_formato_no_soportado_con_mensaje_bilingue(tmp_path):
    path = tmp_path / "datos.xlsx"
    path.write_bytes(b"PK\x03\x04")
    with pytest.raises(SourceError, match="Unsupported format"):
        profile(path, lang="en")
    with pytest.raises(SourceError, match="No existe"):
        profile(tmp_path / "no_esta.csv", lang="es")


def test_archivo_sin_registros(tmp_path):
    path = tmp_path / "vacio.csv"
    path.write_text("timestamp,src_ip\n", encoding="utf-8")
    p = profile(path)
    assert p.dataset.row_count == 0 and "warn.empty" in codes(p)


def test_limite_de_campos_en_json_muy_ancho(tmp_path):
    path = tmp_path / "ancho.ndjson"
    path.write_text("\n".join(json.dumps({f"campo_{j}": j for j in range(200)}) for _ in range(5)), encoding="utf-8")
    p = LogProfiler(path, max_fields=50).profile()
    assert p.dataset.field_count == 200 and p.dataset.profiled_fields == 50
    assert "warn.fields_truncated" in codes(p)
