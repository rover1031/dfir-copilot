"""Pruebas del contrato de los mappings (cómo se incorpora una fuente nueva) y de la calidad de la ingesta."""
import copy

import duckdb
import pytest
import yaml

from dfir_copilot.ingest import ingestor
from dfir_copilot.ingest.ingestor import ingest_csv, load_mapping

HEADER = "timestamp,http_staus,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
ROW = ('2020-01-12T00:16,200,mercadolibre.com,/invoices/search?invoice_id=229933235&site_id=MeliMX'
       '&authtoken=ATUSER-ID-jaxsonbuyer,GET,https://mercadolibre.com/billing,"Mozilla/5.0",27.0.2.178')

VALID = {
    "source": "fuente_x",
    "format": "csv",
    "fields": {"timestamp": "timestamp", "src_ip": "source_ip", "http_method": "http_method", "host": "http_host",
               "uri": "http_uri", "status_code": "http_staus", "user_agent": "http_user_agent",
               "referer": "http_referer"},
    "timestamp": {"format": "%Y-%d-%mT%H:%M", "timezone": "UTC", "timezone_verified": False},
    "derived": {"x_invoice_id": {"from": "query_string", "regex": "invoice_id=([^&]+)", "type": "BIGINT"},
                "user_id": {"from": "query_string", "regex": "authtoken=ATUSER-ID-([^&]+)"}},
}


@pytest.fixture()
def mappings(tmp_path, monkeypatch):
    """Directorio temporal de mappings: permite probar archivos YAML sin tocar los reales."""
    monkeypatch.setattr(ingestor, "MAPPINGS_DIR", tmp_path / "mappings")
    (tmp_path / "mappings").mkdir()

    def write(mapping, name="fuente_x"):
        (tmp_path / "mappings" / f"{name}.yaml").write_text(yaml.safe_dump(mapping, allow_unicode=True), encoding="utf-8")

    return write


def variant(**changes):
    m = copy.deepcopy(VALID)
    for key, value in changes.items():
        if value is None:
            m.pop(key, None)
        else:
            m[key] = value
    return m


def test_el_mapping_valido_carga_y_registra_su_hash(mappings):
    mappings(VALID)
    m = load_mapping("fuente_x")
    assert m["source"] == "fuente_x" and len(m["_sha256"]) == 64


@pytest.mark.parametrize("bad, match", [
    (variant(source=None), "falta 'source'"),
    (variant(format=None), "falta 'format'"),
    (variant(fields=None), "falta 'fields'"),
    (variant(timestamp=None), "falta 'timestamp'"),
    (variant(format="xlsx"), "no soportado"),
    (variant(fields={"uri": "http_uri"}), "incluir 'timestamp'"),
    (variant(fields={"timestamp": "timestamp"}), "'uri' o 'endpoint'"),
    (variant(fields={**VALID["fields"], "campo_raro": "x"}), "desconocido"),
    (variant(derived={"X-Malo": {"from": "query_string", "regex": "a"}}), "inválido"),
    (variant(derived={"factura": {"from": "query_string", "regex": "a"}}), "empezar por x_"),
    (variant(derived={"x_a": {"from": "query_string"}}), "requiere 'from' y 'regex'"),
    (variant(derived={"x_a": {"from": "query_string", "regex": "a", "type": "BLOB"}}), "Tipo no permitido"),
])
def test_mappings_invalidos_se_rechazan_con_un_mensaje_claro(mappings, bad, match):
    mappings(bad)
    with pytest.raises(ValueError, match=match):
        load_mapping("fuente_x")


def test_mapping_inexistente(mappings):
    with pytest.raises(FileNotFoundError):
        load_mapping("no_existe")


def test_una_derivada_que_apunta_a_una_columna_inexistente_falla_al_ingestar(mappings, tmp_path):
    mappings(variant(derived={"x_a": {"from": "columna_inventada", "regex": "(a)"}}))
    csv = tmp_path / "datos.csv"
    csv.write_text(HEADER + ROW + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no existe en el origen"):
        ingest_csv(csv, "fuente_x", out_dir=tmp_path / "out")


def test_una_regex_con_comillas_no_rompe_ni_inyecta_sql(mappings, tmp_path):
    mappings(variant(derived={"x_raro": {"from": "query_string", "regex": "(o'brien)'\\); DROP TABLE x; --"}}))
    csv = tmp_path / "datos.csv"
    csv.write_text(HEADER + ROW + "\n", encoding="utf-8")
    manifest = ingest_csv(csv, "fuente_x", out_dir=tmp_path / "out")
    assert manifest["null_counts"]["x_raro"] == 1 and manifest["output"]["rows"] == 1


def test_la_zona_horaria_del_mapping_se_aplica_al_convertir_a_utc(mappings, tmp_path):
    """'00:16' hora de Bogotá (UTC-5, sin horario de verano) son las 05:16 UTC."""
    mappings(variant(timestamp={"format": "%Y-%d-%mT%H:%M", "timezone": "America/Bogota", "timezone_verified": True}))
    csv = tmp_path / "datos.csv"
    csv.write_text(HEADER + ROW + "\n", encoding="utf-8")
    manifest = ingest_csv(csv, "fuente_x", out_dir=tmp_path / "out")
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    (ts,) = con.execute(f"SELECT CAST(timestamp_utc AS VARCHAR) FROM '{manifest['output']['path']}'").fetchone()
    assert ts == "2020-12-01 05:16:00+00"
    # Contrato ampliado en P1-a/5a: procedencia, nota, si se aplicó y el conteo de horas ambiguas o inexistentes.
    assert manifest["timezone"] == {"assumed": "America/Bogota", "verified": True, "source": "declared", "note": None,
                                    "applied": True, "dst_nonexistent_rows": 0, "dst_ambiguous_rows": 0}
    assert not any("Zona horaria" in w for w in manifest["warnings"])  # verificada: sin advertencia


def test_timestamps_ilegibles_no_abortan_la_ingesta_pero_se_avisan(mappings, tmp_path):
    mappings(VALID)
    csv = tmp_path / "datos.csv"
    bad_row = ROW.replace("2020-01-12T00:16", "no-es-una-fecha")
    csv.write_text(HEADER + ROW + "\n" + bad_row + "\n", encoding="utf-8")
    manifest = ingest_csv(csv, "fuente_x", out_dir=tmp_path / "out")
    assert manifest["input"]["rows"] == manifest["output"]["rows"] == 2  # no se pierde ninguna fila
    assert manifest["null_counts"]["timestamp_utc"] == 1
    assert any("no interpretable" in w for w in manifest["warnings"])


@pytest.mark.parametrize("regex, match", [
    ("o'brien'); DROP TABLE x; --", "regex inválida"),   # paréntesis sin abrir
    ("(?=adelante)x", "regex inválida"),                # RE2 no admite lookahead
    ("invoice_id=\\d+", "grupo de captura"),           # sin paréntesis de captura devolvería siempre vacío
])
def test_una_regex_defectuosa_se_detecta_al_cargar_el_mapping(mappings, regex, match):
    mappings(variant(derived={"x_a": {"from": "query_string", "regex": regex}}))
    with pytest.raises(ValueError, match=match):
        load_mapping("fuente_x")
