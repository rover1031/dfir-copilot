"""Zona horaria por archivo (P1-a, entrega 5a): validación temprana, procedencia, horas que el cambio de horario repite o
salta, Inspector con zona declarada, y su registro en el manifiesto, el ledger y el contexto del agente."""
from types import SimpleNamespace

import duckdb
import pytest
import yaml

from dfir_copilot.agent.graph import DfirAgent
from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.evidence.ledger import Ledger
from dfir_copilot.ingest.ingestor import carries_own_zone, check_timezone, ingest_file, load_mapping, timezone_source
from dfir_copilot.profiling import inspect_source

FIELDS = {"timestamp": "ts", "src_ip": "ip", "http_method": "method", "uri": "uri", "status_code": "status"}


def write_csv(path, stamps):
    path.write_text("ts,ip,method,uri,status\n" + "\n".join(
        f"{s},10.0.0.{i % 9},GET,/api/item?id={i},200" for i, s in enumerate(stamps)) + "\n", encoding="utf-8")
    return path


def write_mapping(tmp_path, ts, name="m"):
    path = tmp_path / f"{name}.yaml"
    path.write_text(yaml.safe_dump({"source": name, "format": "csv", "fields": FIELDS, "timestamp": ts}), encoding="utf-8")
    return path


def ingest(tmp_path, stamps, ts, name="m"):
    csv = write_csv(tmp_path / f"{name}.csv", stamps)
    manifest = ingest_file(csv, name, out_dir=tmp_path / f"out_{name}", mapping_path=write_mapping(tmp_path, ts, name))
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    utc = [r[0] for r in con.execute(f"SELECT CAST(timestamp_utc AS VARCHAR) FROM '{manifest['output']['path']}' "
                                     "ORDER BY source_row").fetchall()]
    return manifest, utc


def mapping_error(tmp_path, ts):
    with pytest.raises(ValueError) as exc:
        load_mapping("x", write_mapping(tmp_path, ts))
    return str(exc.value)


NAIVE = "%Y-%m-%d %H:%M:%S"


# --- validación del nombre de la zona ------------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["UTC", "America/Santiago", "America/Bogota", "Asia/Kathmandu", "Europe/Madrid"])
def test_un_nombre_iana_exacto_es_valido(name):
    assert check_timezone(name) == name


@pytest.mark.parametrize("name, suggestion", [("America/Santigo", "America/Santiago"), ("america/santiago", "America/Santiago"),
                                              ("AMERICA/BOGOTA", "America/Bogota"), ("Europe/Madird", "Europe/Madrid")])
def test_una_errata_o_mayusculas_distintas_se_rechazan_con_sugerencia(name, suggestion):
    with pytest.raises(ValueError, match="desconocida|Unknown") as exc:
        check_timezone(name)
    assert suggestion in str(exc.value)


@pytest.mark.parametrize("name", ["UTC-3", "-03:00", "CLT", "Chile", "", "   "])
def test_desfases_abreviaturas_y_nombres_inventados_se_rechazan(name):
    with pytest.raises(ValueError):
        check_timezone(name)


def test_un_valor_que_no_es_texto_se_rechaza():
    with pytest.raises(ValueError):
        check_timezone(-3)


@pytest.mark.parametrize("name, sign", [("Etc/GMT+3", "UTC-3"), ("Etc/GMT-5", "UTC+5")])
def test_etc_gmt_se_rechaza_explicando_que_el_signo_va_al_reves(name, sign):
    with pytest.raises(ValueError) as exc:
        check_timezone(name)
    assert sign in str(exc.value) and "timezone_fixed_offset" in str(exc.value)


@pytest.mark.parametrize("name", ["EST", "MST", "HST"])
def test_abreviaturas_de_desfase_fijo_se_rechazan_salvo_que_se_pida(name):
    with pytest.raises(ValueError, match="America/New_York"):
        check_timezone(name)
    assert check_timezone(name, fixed_offset_ok=True) == name


def test_la_zona_se_valida_al_cargar_el_mapping_y_no_al_ingerir(tmp_path):
    assert "America/Santiago" in mapping_error(tmp_path, {"format": NAIVE, "timezone": "America/Santigo"})


# --- claves y procedencia en el mapping ----------------------------------------------------------------------------
def test_una_clave_mal_escrita_en_timestamp_ya_no_se_ignora(tmp_path):
    message = mapping_error(tmp_path, {"format": NAIVE, "timezone": "UTC", "timezone_verifed": True})
    assert "timezone_verifed" in message and "timezone_verified" in message


@pytest.mark.parametrize("ts", [
    {"format": NAIVE, "timezone": "UTC", "timezone_verified": "si"},
    {"format": NAIVE, "timezone": "UTC", "timezone_note": 3},
    {"format": NAIVE, "timezone": "UTC", "timezone_source": "lo_dijo_alguien"},
])
def test_tipos_y_valores_invalidos_en_timestamp_se_rechazan(tmp_path, ts):
    mapping_error(tmp_path, ts)


def test_timezone_source_in_data_exige_un_formato_que_traiga_la_zona(tmp_path):
    assert "in_data" in mapping_error(tmp_path, {"format": NAIVE, "timezone": "UTC", "timezone_source": "in_data"})
    load_mapping("x", write_mapping(tmp_path, {"format": "%Y-%m-%d %H:%M:%S %z", "timezone": "UTC", "timezone_source": "in_data"}))


@pytest.mark.parametrize("ts", [{"format": NAIVE, "timezone": "America/Santiago", "timezone_source": "default"},
                                {"format": NAIVE, "timezone": "UTC", "timezone_verified": True, "timezone_source": "default"}])
def test_default_significa_utc_sin_declarar_ni_verificar(tmp_path, ts):
    assert "default" in mapping_error(tmp_path, ts)


@pytest.mark.parametrize("ts, source_type, expected", [
    ({"format": NAIVE, "timezone": "UTC"}, None, "default"),
    ({"format": NAIVE, "timezone": "UTC", "timezone_verified": True}, None, "declared"),
    ({"format": NAIVE, "timezone": "America/Santiago"}, None, "declared"),
    ({"format": "epoch_ms", "timezone": "UTC"}, None, "in_data"),
    ({"format": "%d/%b/%Y:%H:%M:%S %z", "timezone": "UTC"}, None, "in_data"),
    ({"format": "iso8601", "timezone_in_data": True, "timezone": "UTC"}, None, "in_data"),
    ({"format": "native", "timezone": "UTC"}, "TIMESTAMP WITH TIME ZONE", "in_data"),
    ({"format": "native", "timezone": "America/Bogota"}, "TIMESTAMP", "declared"),
    ({"format": NAIVE, "timezone": "America/Bogota", "timezone_source": "declared"}, None, "declared"),
])
def test_la_procedencia_se_deduce_del_mapping_si_no_se_declara(ts, source_type, expected):
    assert timezone_source(ts, source_type) == expected


def test_carries_own_zone_solo_con_formatos_que_traen_zona():
    assert carries_own_zone({"format": "epoch_s"}) and carries_own_zone({"format": "%Y %z"})
    assert not carries_own_zone({"format": NAIVE}) and not carries_own_zone({"format": "iso8601"})
    assert not carries_own_zone({"format": "native"}, "TIMESTAMP")


# --- horas que el cambio de horario repite o salta -----------------------------------------------------------------
def test_chile_sin_cambios_de_horario_en_el_periodo_del_caso(tmp_path):
    """El caso three_months: de octubre a diciembre de 2020 Santiago estuvo en UTC-3 sin transiciones."""
    manifest, utc = ingest(tmp_path, ["2020-10-01 00:00:00", "2020-11-01 00:04:00", "2020-12-31 23:59:00"],
                           {"format": NAIVE, "timezone": "America/Santiago"})
    assert utc == ["2020-10-01 03:00:00+00", "2020-11-01 03:04:00+00", "2021-01-01 02:59:00+00"]
    tz = manifest["timezone"]
    assert (tz["dst_nonexistent_rows"], tz["dst_ambiguous_rows"], tz["source"], tz["applied"]) == (0, 0, "declared", True)
    assert not any("cambio de horario" in w or "daylight" in w for w in manifest["warnings"])


def test_horas_repetidas_e_inexistentes_se_cuentan_y_se_avisan(tmp_path):
    stamps = ["2021-04-03 12:00:00",   # normal
              "2021-04-03 23:30:00",   # retroceso: ocurre dos veces
              "2021-09-05 00:30:00",   # avance: no existe
              "2021-09-05 12:00:00"]   # normal
    manifest, utc = ingest(tmp_path, stamps, {"format": NAIVE, "timezone": "America/Santiago"})
    # Lo que hace DuckDB (verificado): la hora repetida se lee como su SEGUNDA ocurrencia; la inexistente se desplaza.
    assert utc == ["2021-04-03 15:00:00+00", "2021-04-04 03:30:00+00", "2021-09-05 04:30:00+00", "2021-09-05 15:00:00+00"]
    assert (manifest["timezone"]["dst_nonexistent_rows"], manifest["timezone"]["dst_ambiguous_rows"]) == (1, 1)
    warnings = " ".join(manifest["warnings"])
    assert "1 filas tienen una hora local que no existe" in warnings and "1 filas tienen una hora local que ocurre dos veces" in warnings


def test_nueva_york_cuenta_toda_la_hora_ambigua_y_toda_la_inexistente(tmp_path):
    minutes = [f"2021-03-14 0{h}:{m:02d}:00" for h in (1, 2, 3) for m in range(0, 60, 10)]      # 02:xx no existe
    minutes += [f"2021-11-07 0{h}:{m:02d}:00" for h in (0, 1, 2) for m in range(0, 60, 10)]     # 01:xx ocurre dos veces
    manifest, _ = ingest(tmp_path, minutes, {"format": NAIVE, "timezone": "America/New_York"})
    assert (manifest["timezone"]["dst_nonexistent_rows"], manifest["timezone"]["dst_ambiguous_rows"]) == (6, 6)


def test_una_zona_sin_cambios_de_horario_da_cero(tmp_path):
    manifest, utc = ingest(tmp_path, ["2021-03-14 02:30:00", "2021-11-07 01:30:00"], {"format": NAIVE, "timezone": "America/Bogota"})
    assert utc == ["2021-03-14 07:30:00+00", "2021-11-07 06:30:00+00"]
    assert (manifest["timezone"]["dst_nonexistent_rows"], manifest["timezone"]["dst_ambiguous_rows"]) == (0, 0)


def test_media_hora_de_desfase_y_cambio_de_media_hora(tmp_path):
    """Lord Howe adelanta y atrasa 30 minutos: la comprobación no puede suponer saltos de una hora."""
    stamps = ["2021-10-03 02:10:00", "2021-04-04 01:40:00", "2021-06-01 12:00:00"]  # inexistente, repetida, normal
    manifest, _ = ingest(tmp_path, stamps, {"format": NAIVE, "timezone": "Australia/Lord_Howe"})
    assert (manifest["timezone"]["dst_nonexistent_rows"], manifest["timezone"]["dst_ambiguous_rows"]) == (1, 1)


def test_con_utc_no_se_comprueba_nada(tmp_path):
    manifest, _ = ingest(tmp_path, ["2021-03-14 02:30:00"], {"format": NAIVE, "timezone": "UTC"})
    assert manifest["timezone"]["dst_nonexistent_rows"] is None and manifest["timezone"]["source"] == "default"


def test_un_desfase_fijo_pedido_explicitamente_se_aplica_y_no_tiene_cambios(tmp_path):
    manifest, utc = ingest(tmp_path, ["2021-03-14 02:30:00"],
                           {"format": NAIVE, "timezone": "Etc/GMT+3", "timezone_fixed_offset": True})
    assert utc == ["2021-03-14 05:30:00+00"] and manifest["timezone"]["dst_ambiguous_rows"] is None   # Etc/GMT+3 = UTC-3


# --- declaraciones que no se aplican -------------------------------------------------------------------------------
def test_una_zona_declarada_con_un_formato_que_trae_la_suya_se_avisa_y_no_se_aplica(tmp_path):
    manifest, utc = ingest(tmp_path, ["2021-06-01T10:00:00-05:00"],
                           {"format": "iso8601", "timezone_in_data": True, "timezone": "Asia/Tokyo"})
    tz = manifest["timezone"]
    assert utc == ["2021-06-01 15:00:00+00"] and (tz["applied"], tz["source"], tz["verified"]) == (False, "in_data", True)
    assert any("Asia/Tokyo no se aplica" in w for w in manifest["warnings"])
    assert not any("NO verificada" in w for w in manifest["warnings"])     # la zona viaja en el dato: no hay nada que verificar


def test_zona_utc_con_formato_que_trae_zona_no_genera_aviso(tmp_path):
    manifest, _ = ingest(tmp_path, ["2021-06-01T10:00:00Z"], {"format": "iso8601", "timezone_in_data": True, "timezone": "UTC"})
    assert not any("no se aplica" in w for w in manifest["warnings"])


# --- registro: manifiesto, ledger y contexto del agente ------------------------------------------------------------
def test_la_nota_y_la_procedencia_llegan_al_manifiesto_y_al_ledger(tmp_path):
    note = "Asumida por el analista el 2026-10-05; pendiente de confirmar con el dueño del export"
    manifest, _ = ingest(tmp_path, ["2020-11-01 00:04:00"],
                         {"format": NAIVE, "timezone": "America/Santiago", "timezone_verified": False, "timezone_note": note})
    assert manifest["timezone"]["note"] == note and manifest["timezone"]["verified"] is False
    engine = QueryEngine(manifest["output"]["path"])
    opened = Ledger.open("TZ-CASE", engine, analyst="eder", root=tmp_path / "ledger").entries("case_opened")[0]["data"]
    assert opened["dataset"]["timezone_assumed"] == "America/Santiago"
    assert (opened["dataset"]["timezone_source"], opened["dataset"]["timezone_note"]) == ("declared", note)


def test_un_manifiesto_anterior_sin_procedencia_sigue_abriendo_casos(tmp_path):
    manifest, _ = ingest(tmp_path, ["2020-11-01 00:04:00"], {"format": NAIVE, "timezone": "UTC"})
    engine = QueryEngine(manifest["output"]["path"])
    engine.manifest["timezone"] = {"assumed": "UTC", "verified": False}            # forma de antes de 5a
    opened = Ledger.open("OLD", engine, analyst="eder", root=tmp_path / "ledger").entries("case_opened")[0]["data"]
    assert opened["dataset"]["timezone_source"] is None and opened["dataset"]["timezone_note"] is None


def agent_context(tz: dict, local_timezone=None) -> str:
    engine = SimpleNamespace(manifest={"timezone": tz, "output": {"rows": 10}, "null_counts": {}, "time_range_utc": ["a", "b"]},
                             dataset_sha256="abc123456789xyz", local_timezone=local_timezone)
    agent = SimpleNamespace(engine=engine, _dst_line=DfirAgent._dst_line)
    agent._local_line = lambda: DfirAgent._local_line(agent)
    return DfirAgent.system_prompt(agent).content


def test_el_agente_ve_la_procedencia_y_las_horas_afectadas_por_el_cambio_de_horario():
    text = agent_context({"assumed": "America/Santiago", "verified": False, "source": "declared",
                          "dst_nonexistent_rows": 2, "dst_ambiguous_rows": 5})
    assert "America/Santiago (origen: declared, verificada: False)" in text
    assert "5 filas con hora local repetida y 2 con hora local inexistente" in text


def test_sin_horas_afectadas_ni_procedencia_el_contexto_no_inventa_nada():
    text = agent_context({"assumed": "UTC", "verified": False})        # manifiesto anterior a 5a
    assert "origen: sin registrar" in text and "Cambio de horario" not in text


# --- Inspector con zona declarada ----------------------------------------------------------------------------------
def naive_csv(tmp_path, n=300):
    return write_csv(tmp_path / "naive.csv", [f"2020-11-{1 + i % 28:02d} {i % 24:02d}:00:00" for i in range(n)])


def test_el_inspector_escribe_la_zona_declarada_su_procedencia_y_la_nota(tmp_path):
    draft = inspect_source(naive_csv(tmp_path), timezone="America/Santiago", timezone_note="lo indicó el cliente")
    ts = draft.mapping["timestamp"]
    assert (ts["timezone"], ts["timezone_source"], ts["timezone_note"], ts["timezone_verified"]) == \
        ("America/Santiago", "declared", "lo indicó el cliente", False)
    codes = {d.code for d in draft.decisions}
    assert "timezone_declared" in codes and "timezone_unverified" not in codes
    assert "America/Santiago, declared" in draft.render()
    saved = draft.save(tmp_path / "d.yaml")
    assert yaml.safe_load(saved.read_text(encoding="utf-8")) == draft.mapping       # la garantía del borrador se mantiene
    manifest = ingest_file(tmp_path / "naive.csv", "d", out_dir=tmp_path / "o", mapping_path=saved)
    assert (manifest["timezone"]["source"], manifest["timezone"]["note"]) == ("declared", "lo indicó el cliente")


def test_sin_zona_declarada_el_inspector_se_comporta_como_antes(tmp_path):
    ts = inspect_source(naive_csv(tmp_path)).mapping["timestamp"]
    assert ts == {"format": "iso8601", "timezone": "UTC", "timezone_in_data": False, "timezone_verified": False}  # sin claves nuevas


def test_una_errata_en_la_zona_falla_antes_de_perfilar(tmp_path):
    with pytest.raises(ValueError, match="America/Santiago"):
        inspect_source(tmp_path / "no_existe.csv", timezone="America/Santigo")   # ni siquiera se abre el archivo


def test_una_nota_sin_zona_se_rechaza(tmp_path):
    with pytest.raises(ValueError, match="timezone"):
        inspect_source(naive_csv(tmp_path), timezone_note="sin zona")


def test_si_el_dato_trae_la_zona_la_declarada_no_se_usa_y_se_dice(tmp_path):
    f = write_csv(tmp_path / "off.csv", [f"2021-06-{1 + i % 28:02d}T{i % 24:02d}:00:00-05:00" for i in range(300)])
    draft = inspect_source(f, timezone="Asia/Tokyo")
    ts = draft.mapping["timestamp"]
    assert ts["timezone"] == "UTC" and ts["timezone_verified"] is True and "timezone_source" not in ts
    assert "timezone_ignored" in {d.code for d in draft.decisions}


def test_un_desfase_fijo_en_el_inspector_exige_pedirlo(tmp_path):
    with pytest.raises(ValueError, match="UTC-3"):
        inspect_source(naive_csv(tmp_path), timezone="Etc/GMT+3")
    ts = inspect_source(naive_csv(tmp_path), timezone="Etc/GMT+3", timezone_fixed_offset=True).mapping["timestamp"]
    assert ts["timezone_fixed_offset"] is True
