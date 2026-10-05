"""Hora local del cliente (P1-a, entrega 5b): columna `timestamp_local` en el motor, línea de tiempo cortada en la medianoche
local, y lo que el modelo ve de la zona declarada."""
import json

import pytest
from interp_helpers import GOOD, REAL_DERIVED, Scripted, ok, real_profile
from test_interpret_vocabulary import REAL_CLASSIFICATION, REAL_PARQUET_COLUMNS
from test_timezone import NAIVE, agent_context, ingest, mapping_error

from dfir_copilot.engine.profiler import CanonicalProfiler
from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.ingest.ingestor import local_timezone
from dfir_copilot.interpret import (
    SYSTEM_PROMPT,
    build_user_message,
    columns_for,
    interpret_profile,
)
from dfir_copilot.interpret.context import timezone_block
from dfir_copilot.interpret.smoke import main

SANTIAGO = {"format": NAIVE, "timezone": "America/Santiago"}
DECLARED = {"format": "%Y-%d-%mT%H:%M", "timezone": "America/Santiago", "timezone_source": "declared", "timezone_verified": False}


def engine_for(tmp_path, stamps, ts, name="m"):
    manifest, _ = ingest(tmp_path, stamps, ts, name)
    return QueryEngine(manifest["output"]["path"])


# --- motor ---------------------------------------------------------------------------------------------------------
def test_con_zona_declarada_el_motor_expone_la_hora_local(tmp_path):
    engine = engine_for(tmp_path, ["2020-11-01 00:04:00"], SANTIAGO)
    assert engine.local_timezone == "America/Santiago"
    columns = dict((r[0], r[1]) for r in engine.query("DESCRIBE logs").rows)
    assert columns["timestamp_local"] == "TIMESTAMP"
    row = engine.query("SELECT timestamp_utc, timestamp_local FROM logs").rows[0]
    assert row == ("2020-11-01 03:04:00+00", "2020-11-01 00:04:00")      # ambas como texto, sin ambigüedad de zona


@pytest.mark.parametrize("stamps, ts", [
    (["2020-11-01 00:04:00"], {"format": NAIVE, "timezone": "UTC"}),                                         # nadie la declaró
    (["2021-06-01T10:00:00-05:00"], {"format": "iso8601", "timezone_in_data": True, "timezone": "Asia/Tokyo"}),  # va en el dato
])
def test_sin_zona_declarada_no_hay_hora_local(tmp_path, stamps, ts):
    engine = engine_for(tmp_path, stamps, ts)
    assert engine.local_timezone is None
    assert "timestamp_local" not in {r[0] for r in engine.query("DESCRIBE logs").rows}


@pytest.mark.parametrize("tz, expected", [
    ({"assumed": "America/Santiago", "source": "declared", "applied": True}, "America/Santiago"),
    ({"assumed": "Asia/Tokyo", "source": "declared", "applied": False}, None),     # declarada pero el dato traía la suya
    ({"assumed": "UTC", "source": "declared", "applied": True}, None),             # UTC confirmado: la local sería UTC
    ({"assumed": "UTC", "source": "default", "applied": True}, None),
    ({"assumed": "America/Bogota", "source": "in_data", "applied": False}, None),
    (None, None),
])
def test_cuando_hay_hora_local_segun_el_manifiesto(tz, expected):
    assert local_timezone(tz) == expected


def test_declarar_una_zona_con_un_formato_que_trae_la_suya_se_rechaza(tmp_path):
    message = mapping_error(tmp_path, {"format": "epoch_ms", "timezone": "America/Santiago", "timezone_source": "declared"})
    assert "epoch_ms" in message and "in_data" in message


def test_un_manifiesto_anterior_a_5a_con_zona_distinta_de_utc_cuenta_como_declarada(tmp_path):
    manifest, _ = ingest(tmp_path, ["2020-11-01 00:04:00"], {"format": NAIVE, "timezone": "America/Bogota"})
    path = tmp_path / "out_m" / "m.manifest.json"
    old = json.loads(path.read_text(encoding="utf-8"))
    old["timezone"] = {"assumed": "America/Bogota", "verified": False}
    path.write_text(json.dumps(old), encoding="utf-8")
    assert QueryEngine(manifest["output"]["path"]).local_timezone == "America/Bogota"


def test_la_hora_local_no_toca_el_parquet_ni_su_hash(tmp_path):
    manifest, _ = ingest(tmp_path, ["2020-11-01 00:04:00"], SANTIAGO)
    engine = QueryEngine(manifest["output"]["path"])           # verify=True: el hash del Parquet sigue coincidiendo
    assert engine.parquet_sha256 == manifest["output"]["sha256"]


# --- línea de tiempo -----------------------------------------------------------------------------------------------
def test_la_linea_de_tiempo_corta_los_dias_en_la_medianoche_del_cliente(tmp_path):
    """23:30 del 31 de octubre en Santiago son las 02:30 UTC del 1 de noviembre: en UTC caerían en el mismo día."""
    engine = engine_for(tmp_path, ["2020-10-31 23:30:00", "2020-11-01 00:30:00"], SANTIAGO)
    res = CanonicalProfiler(engine).timeline("day")
    assert res.columns == ("periodo_local", "peticiones")
    assert [list(r) for r in res.rows] == [["2020-10-31 00:00:00", 1], ["2020-11-01 00:00:00", 1]]


def test_sin_zona_declarada_la_linea_de_tiempo_sigue_en_utc(tmp_path):
    engine = engine_for(tmp_path, ["2020-10-31 23:30:00", "2020-11-01 00:30:00"], {"format": NAIVE, "timezone": "UTC"})
    res = CanonicalProfiler(engine).timeline("day")
    assert res.columns == ("periodo", "peticiones") and len(res.rows) == 2


# --- agente --------------------------------------------------------------------------------------------------------
def test_el_agente_sabe_que_columna_usar_para_horas_locales():
    text = agent_context({"assumed": "America/Santiago", "verified": False, "source": "declared"}, "America/Santiago")
    assert "timestamp_local: hora local en America/Santiago" in text and "ordenar eventos" in text
    assert "timestamp_local" not in agent_context({"assumed": "UTC", "verified": False})


# --- lo que ve el modelo -------------------------------------------------------------------------------------------
def test_con_zona_declarada_el_modelo_ve_timestamp_local_junto_a_las_columnas_de_tiempo():
    cols = columns_for(real_profile(), REAL_DERIVED, DECLARED)
    names = list(cols)
    assert cols["timestamp_local"] == "TIMESTAMP"
    assert names.index("timestamp_local") < names.index("x_authtoken_type")
    assert set(cols) - {"timestamp_local"} <= set(REAL_PARQUET_COLUMNS)   # el resto existe en tu Parquet real


@pytest.mark.parametrize("timestamp", [None, {"format": NAIVE, "timezone": "UTC"},
                                       {"format": "iso8601", "timezone_in_data": True, "timezone": "Asia/Tokyo"}])
def test_sin_zona_declarada_no_hay_timestamp_local_para_el_modelo(timestamp):
    assert "timestamp_local" not in columns_for(real_profile(), REAL_DERIVED, timestamp)


def test_el_bloque_de_zona_corrige_el_rango_utc_del_perfil():
    block = timezone_block(real_profile(), DECLARED)
    assert block.startswith("status: declared") and "America/Santiago" in block and "NOT yet verified" in block
    assert "2020-10-01 03:00:00+00 to 2021-01-01 02:59:00+00" in block   # el perfil decía 00:00 a 23:59 suponiendo UTC
    assert "VERIFIED with the export owner" in timezone_block(real_profile(), {**DECLARED, "timezone_verified": True})


@pytest.mark.parametrize("timestamp, status", [(None, "not_declared"), ({"format": NAIVE, "timezone": "UTC"}, "not_declared"),
                                                ({"format": "epoch_ms", "timezone": "UTC"}, "in_data")])
def test_el_bloque_de_zona_dice_cuando_nadie_la_declaro_o_viene_en_el_dato(timestamp, status):
    assert timezone_block(real_profile(), timestamp).startswith(f"status: {status}")


def test_la_nota_del_analista_nunca_llega_al_modelo():
    timestamp = {**DECLARED, "timezone_note": "NOTA-PRIVADA confirmado por Fulano por correo"}
    msg = build_user_message(real_profile(), REAL_DERIVED, columns_for(real_profile(), REAL_DERIVED, timestamp), "es", timestamp)
    assert "NOTA-PRIVADA" not in msg and "Fulano" not in msg
    assert "<timezone>status: declared" in msg and "timestamp_local TIMESTAMP - Local time in America/Santiago" in msg


def reply_with_local_query():
    return ok({**GOOD, "classification": REAL_CLASSIFICATION, "mapping_review": [], "proposed_queries": [
        {"id": "fuera_de_horario", "hypothesis": "h", "priority": "high", "expected_if_true": "e", "refuted_if": "r",
         "sql": "SELECT user_id, count(*) FILTER (WHERE hour(timestamp_local) NOT BETWEEN 8 AND 18) AS fuera "
                "FROM logs GROUP BY 1 ORDER BY fuera DESC LIMIT 20"}]})


def test_una_consulta_en_hora_local_se_acepta_solo_si_la_zona_esta_declarada():
    with_zone = interpret_profile(Scripted(reply_with_local_query()), real_profile(), derived=REAL_DERIVED, timestamp=DECLARED)
    assert [q.id for q in with_zone.reviewed.interpretation.proposed_queries] == ["fuera_de_horario"]
    without = interpret_profile(Scripted(reply_with_local_query()), real_profile(), derived=REAL_DERIVED)
    assert [(d.ref, d.code) for d in without.reviewed.discarded] == [("fuera_de_horario", "sql_error")]


def test_la_zona_declarada_llega_al_mensaje_que_recibe_el_modelo():
    llm = Scripted(ok({**GOOD, "classification": REAL_CLASSIFICATION, "mapping_review": [], "proposed_queries": []}))
    interpret_profile(llm, real_profile(), derived=REAL_DERIVED, timestamp=DECLARED)
    assert "<timezone>status: declared" in llm.calls[0][1]


def test_el_prompt_explica_cuando_preguntar_por_la_zona_y_que_columna_usar():
    for rule in ("TIME ZONE", "do not ask the analyst which zone", "timestamp_local", "order events and measure gaps"):
        assert rule in SYSTEM_PROMPT, rule


# --- script ---------------------------------------------------------------------------------------------------------
class Draft:
    def __init__(self, timestamp):
        self.profile, self.derived, self.status = real_profile(), list(REAL_DERIVED), "ready"
        self.mapping = {"timestamp": timestamp}


def test_tz_en_el_script_llega_al_inspector_y_al_mensaje(capsys):
    seen = {}

    def inspector(path, lang, **kw):
        seen.update(kw)
        return Draft({**DECLARED, **({"timezone_note": kw["timezone_note"]} if "timezone_note" in kw else {})})

    code = main(["x.csv", "--dry-run", "--tz", "America/Santiago", "--tz-note", "NOTA-X"], inspector=inspector)
    out = capsys.readouterr().out
    assert code == 0 and seen == {"timezone": "America/Santiago", "timezone_note": "NOTA-X"}
    assert "<timezone>status: declared" in out and "timestamp_local TIMESTAMP" in out and "NOTA-X" not in out


def test_tz_note_sin_tz_es_un_error(capsys):
    assert main(["x.csv", "--dry-run", "--tz-note", "sola"], inspector=lambda p, lang, **kw: Draft(None)) == 2
    assert "--tz-note" in capsys.readouterr().out


def test_sin_tz_el_script_llama_al_inspector_como_antes(capsys):
    assert main(["x.csv", "--dry-run"], inspector=lambda path, lang: Draft({"format": NAIVE, "timezone": "UTC"})) == 0
    assert "<timezone>status: not_declared" in capsys.readouterr().out
