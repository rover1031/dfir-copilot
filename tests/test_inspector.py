"""P0-B1: el Inspector genera un borrador de mapping revisable, con análisis local de valores y sin filtrar datos."""
import json
import random
from datetime import datetime, timedelta

import duckdb
import pytest
import yaml

from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.detectors import run_detectors
from dfir_copilot.detectors.roles import resolve_roles
from dfir_copilot.i18n import catalog, placeholders
from dfir_copilot.ingest.ingestor import MAPPINGS_DIR, ingest_file
from dfir_copilot.profiling import inspect_source, mask
from dfir_copilot.synthetic import make_idor_dataset, write_csv


@pytest.fixture(scope="module")
def idor(tmp_path_factory):
    d = tmp_path_factory.mktemp("idor")
    rows, truth = make_idor_dataset()
    return write_csv(d / "three_months.csv", rows), truth, rows


def codes(draft):
    return {d.code for d in draft.decisions}


def parquet_cols(manifest, cols):
    return duckdb.connect().execute(
        f"SELECT {cols} FROM read_parquet('{manifest['output']['path']}') ORDER BY source_row").fetchall()


# --- el caso del proyecto --------------------------------------------------------------------------------------------
def test_borrador_del_caso_web(idor):
    draft = inspect_source(idor[0])
    assert draft.status == "ready" and draft.log_type == "web"
    assert draft.mapping["fields"] == {"timestamp": "timestamp", "src_ip": "source_ip", "host": "http_host",
                                       "http_method": "http_method", "uri": "http_uri", "status_code": "http_staus",
                                       "user_agent": "http_user_agent", "referer": "http_referer"}
    assert draft.mapping["timestamp"] == {"format": "%Y-%d-%mT%H:%M", "timezone": "UTC", "timezone_verified": False}
    assert draft.mapping["roles"] == {"actor": "user_id", "resource": "x_invoice_id"}


def test_columnas_derivadas_de_la_url_con_su_tipo_y_su_rol(idor):
    by = {d.name: d for d in inspect_source(idor[0]).derived}
    assert by["x_invoice_id"].type == "BIGINT" and by["x_invoice_id"].role == "resource"
    assert by["x_site_id"].role == "dimension" and by["x_site_id"].distinct == 4
    assert by["user_id"].role == "identity" and "ATUSER" in by["user_id"].regex
    assert by["x_authtoken_type"].role == "credential_type" and by["x_authtoken_type"].distinct == 1


def test_el_borrador_marca_lo_que_el_analista_debe_confirmar(idor):
    draft = inspect_source(idor[0])
    assert {"timezone_unverified", "derived_identity", "credential_in_url"} <= codes(draft)
    assert all(d.level == "review" for d in draft.decisions)  # nada bloquea, todo se revisa


def test_el_mapping_del_inspector_equivale_al_escrito_a_mano(idor, tmp_path):
    """La prueba de fondo: mismo CSV, mapping automático vs. mapping manual -> mismas columnas derivadas."""
    path = inspect_source(idor[0]).save(tmp_path / "draft.yaml")
    auto = ingest_file(idor[0], "draft", out_dir=tmp_path / "a", mapping_path=path)
    hand = ingest_file(idor[0], "web_access_meli", out_dir=tmp_path / "h")
    cols = "timestamp_utc::VARCHAR, src_ip, user_id, http_method, host, endpoint, query_string, status_code, x_invoice_id, x_site_id"
    assert parquet_cols(auto, cols) == parquet_cols(hand, cols)
    assert auto["roles"] == hand["roles"] and auto["null_counts"]["user_id"] == 0


def test_los_detectores_encuentran_a_los_atacantes_con_el_mapping_automatico(idor, tmp_path):
    from dfir_copilot.engine.query_engine import QueryEngine
    path = inspect_source(idor[0]).save(tmp_path / "draft.yaml")
    manifest = ingest_file(idor[0], "draft", out_dir=tmp_path / "a", mapping_path=path)
    engine = QueryEngine(manifest["output"]["path"])
    runs = run_detectors(engine, roles=resolve_roles(engine))
    flagged = {f.entity.get("user_id") for r in runs for f in r.findings} - {None}
    assert set(idor[1].attacker_actors) <= flagged and not set(idor[1].normal_actors) & flagged


def test_el_yaml_se_carga_sin_perdida_y_es_reproducible(idor):
    a, b = inspect_source(idor[0]), inspect_source(idor[0])
    assert yaml.safe_load(a.to_yaml()) == a.mapping and a.to_yaml() == b.to_yaml()
    assert a.mapping["inspector"]["file_sha256"] == a.profile.source.sha256


# --- privacidad ----------------------------------------------------------------------------------------------------
def test_mask():
    assert mask("ana.gomez") == "an*******" and mask("ab") == "ab" and mask("x") == "x"
    assert mask("a" * 40) == "aa" + "*" * 8


def test_ni_el_yaml_ni_el_informe_contienen_valores_crudos(idor):
    draft = inspect_source(idor[0])
    text = draft.to_yaml() + draft.render()
    leaks = [s for s in ("atacante00", "normal00", "normal11", "66.6.6", "10.1.0.1", "118822000", "229933000") if s in text]
    assert not leaks


def test_inspeccionar_no_modifica_el_archivo(idor):
    import hashlib
    before = hashlib.sha256(idor[0].read_bytes()).hexdigest()
    inspect_source(idor[0])
    assert hashlib.sha256(idor[0].read_bytes()).hexdigest() == before


# --- generalización de la lógica de derivadas ----------------------------------------------------------------------
def _rows_with_param(n, make_value, key="authtoken"):
    return [f"2020-{1 + i % 28:02d}-10T10:{i % 60:02d},200,h,/a?{key}={make_value(i)}&site_id=X,GET,-,Mozilla/5.0,10.0.0.{i % 200}"
            for i in range(n)]


def _csv(tmp_path, rows, name="x.csv"):
    return write_csv(tmp_path / name, rows)


def test_varios_prefijos_de_credencial_quedan_en_la_regex_ordenados(tmp_path):
    draft = inspect_source(_csv(tmp_path, _rows_with_param(300, lambda i: f"{['ATUSER', 'TEST'][i % 2]}-ID-user{i % 9}")))
    (user,) = [d for d in draft.derived if d.name == "user_id"]
    assert "(?:ATUSER|TEST)" in user.regex and user.distinct == 9


def test_un_token_unico_por_peticion_no_es_una_identidad(tmp_path):
    draft = inspect_source(_csv(tmp_path, _rows_with_param(300, lambda i: f"ATUSER-ID-n{i:06d}")))
    assert "user_id" not in {d.name for d in draft.derived} and "actor" not in draft.mapping.get("roles", {}).keys() - {"actor"}
    assert draft.mapping["roles"].get("actor") == "src_ip"  # sin identidad, se analiza por IP


def test_un_parametro_con_nombre_de_campo_canonico_se_usa_tal_cual(tmp_path):
    draft = inspect_source(_csv(tmp_path, _rows_with_param(300, lambda i: f"ana{i % 6}", key="username")))
    (user,) = [d for d in draft.derived if d.role == "canonical"]
    assert user.name == "user_id" and user.key == "username" and draft.mapping["roles"]["actor"] == "user_id"


def test_parametros_raros_o_numericos_cortos(tmp_path):
    rows = [f"2020-{1 + i % 28:02d}-10T10:{i % 60:02d},200,h,/a?page={i % 3}&q=texto{i}&rare=1,GET,-,Mozilla/5.0,10.0.0.{i % 200}"
            if i % 40 else "2020-01-10T10:00,200,h,/a?page=1,GET,-,Mozilla/5.0,10.0.0.1" for i in range(400)]
    by = {d.name: d for d in inspect_source(_csv(tmp_path, rows)).derived}
    assert by["x_page"].role == "dimension" and by["x_page"].type == "BIGINT"
    assert by["x_q"].role == "other" and "x_rare" in by  # q: texto casi único; rare: presente en el 97 %
    assert by["x_q"].hit_pct > 90


def test_parametros_en_menos_del_5_por_ciento_se_ignoran(tmp_path):
    rows = [f"2020-{1 + i % 28:02d}-10T10:{i % 60:02d},200,h,/a?{'z=1' if i == 0 else 'k=1'}&site_id=X,GET,-,Mozilla/5.0,10.0.0.{i % 200}"
            for i in range(400)]
    assert "x_z" not in {d.name for d in inspect_source(_csv(tmp_path, rows)).derived}


# --- otros formatos de log web -------------------------------------------------------------------------------------
def test_nginx_con_linea_de_peticion_completa(tmp_path):
    f = tmp_path / "nginx.csv"
    f.write_text("time_local,remote_addr,request,status\n" + "\n".join(
        f'{1 + i % 28:02d}/{["ene", "abr", "ago", "dic"][i % 4]}/2024:10:00:00 -0500,203.0.113.{i},"GET /api/o/{i}?tok=abc{i % 3} HTTP/1.1",200'
        for i in range(120)), encoding="utf-8")
    draft = inspect_source(f)
    assert draft.mapping["fields"]["request_line"] == "request" and "uri" not in draft.mapping["fields"]
    assert "http_method" not in draft.mapping["fields"] and draft.mapping["timestamp"]["format"] == "%d/%b/%Y:%H:%M:%S %z"
    assert draft.mapping["timestamp"]["timezone_verified"] is True  # el desfase viaja en el dato
    manifest = ingest_file(f, "n", out_dir=tmp_path / "o", mapping_path=draft.save(tmp_path / "n.yaml"))
    assert parquet_cols(manifest, "http_method, endpoint")[0] == ("GET", "/api/o/0") and manifest["null_counts"]["timestamp_utc"] == 0


def test_json_ecs_anidado_de_punta_a_punta(tmp_path):
    rng = random.Random(3)
    f = tmp_path / "gw.ndjson"
    f.write_text("\n".join(json.dumps({
        "@timestamp": (datetime(2024, 5, 1) + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": {"ip": f"10.0.0.{i % 50}"}, "http": {"request": {"method": "GET"}, "response": {"status_code": rng.choice([200, 404])}},
        "url": {"original": f"/orders?order_id={1000 + i % 300}&user={['ana', 'luis', 'eva'][i % 3]}"},
        "user_agent": {"original": "curl/8.0"}}) for i in range(400)), encoding="utf-8")
    draft = inspect_source(f)
    assert draft.mapping["fields"] == {"timestamp": "@timestamp", "src_ip": "source.ip", "http_method": "http.request.method",
                                       "status_code": "http.response.status_code", "uri": "url.original",
                                       "user_agent": "user_agent.original"}
    assert draft.mapping["format"] == "json" and draft.mapping["timestamp"]["format"] == "native"
    assert draft.mapping["roles"] == {"actor": "user_id", "resource": "x_order_id"}
    manifest = ingest_file(f, "gw", out_dir=tmp_path / "o", mapping_path=draft.save(tmp_path / "gw.yaml"))
    assert manifest["output"]["rows"] == 400 and manifest["null_counts"]["user_id"] == 0
    assert "timezone_unverified" in codes(draft)  # el JSON tipado no dice si la hora era UTC o local


def test_csv_en_espanol_con_acentos(tmp_path):
    lines = ["fecha;ip_origen;usuario;url;estado;navegador"] + [
        f"2024-05-{1 + i % 28:02d} 1{i % 10}:0{i % 6}:00;10.0.{i % 4}.{i};josé.muñoz{i % 3};/facturas/buscar?id={i};{[200, 404, 500][i % 3]};Mozilla/5.0"
        for i in range(90)]
    f = tmp_path / "es.csv"
    f.write_bytes("\n".join(lines).encode("latin-1"))
    draft = inspect_source(f, lang="es")
    assert draft.mapping["fields"]["user_id"] == "usuario" and draft.mapping["fields"]["status_code"] == "estado"
    assert ingest_file(f, "es", out_dir=tmp_path / "o", mapping_path=draft.save(tmp_path / "es.yaml"))["output"]["rows"] == 90


# --- lo que NO se puede ingerir se dice claro ----------------------------------------------------------------------
def _edr_events(n=60):
    """Telemetría de endpoint al estilo Falcon: proceso, línea de comandos y hash; sin URL."""
    return [{"@timestamp": 1790000000000 + i * 1000, "#event_simpleName": ["ProcessRollup2", "DnsRequest"][i % 2],
             "ComputerName": f"HOST{i % 5}", "UserName": f"usuario{i % 4}", "event.action": "process_start",
             "ImageFileName": "/usr/bin/bash", "CommandLine": f"bash -c id{i}", "ParentBaseFileName": "sshd",
             "process.pid": str(500 + i), "SHA256HashData": f"{i:064x}", "MD5HashData": f"{i:032x}"} for i in range(n)]


def test_telemetria_edr_se_ingiere_con_el_esquema_de_endpoint(tmp_path):
    """Antes de la entrega D1 no era ingerible; ahora tiene su esquema (equipo, proceso, línea de comandos, hash...)."""
    f = tmp_path / "export.json"
    f.write_text(json.dumps(_edr_events()), encoding="utf-8")
    draft = inspect_source(f, lang="es")
    assert draft.status == "ready" and draft.log_type == "edr" and draft.mapping["schema"] == "endpoint"
    assert {"host", "process_name", "command_line", "parent_process", "file_hash", "process_id"} <= set(draft.mapping["fields"])
    assert draft.mapping["roles"]["actor"] == "host" and "unsupported_log_type" not in codes(draft)


def test_fecha_ambigua_bloquea_hasta_que_el_analista_decida(tmp_path):
    f = tmp_path / "amb.csv"
    f.write_text("fecha,ip,url,estado\n" + "\n".join(
        f"{1 + i % 12:02d}/{1 + (i // 12) % 12:02d}/2024 10:00:00,10.0.0.{i},/a?x={i},200" for i in range(200)), encoding="utf-8")
    draft = inspect_source(f)
    assert draft.status == "needs_review" and "date_order_ambiguous" in codes(draft)
    assert [d.level for d in draft.decisions if d.code == "date_order_ambiguous"] == ["required"]


def test_ambiguedad_de_mapeo_se_informa(tmp_path):
    f = tmp_path / "proxy.csv"
    f.write_text("timestamp,client_ip,x_forwarded_for,url,status\n" + "\n".join(
        f"2024-05-01T10:00:0{i % 10},10.0.0.{i},190.1.1.{i},/a?q={i},200" for i in range(120)), encoding="utf-8")
    draft = inspect_source(f)
    assert "mapping_ambiguous" in codes(draft)
    assert draft.mapping["fields"]["src_ip"] == "client_ip"  # gana el alias preferido, pero se pide confirmación


# --- bilingüe ------------------------------------------------------------------------------------------------------
def test_el_borrador_sale_en_el_idioma_pedido(idor):
    es, en = inspect_source(idor[0], lang="es"), inspect_source(idor[0], lang="en")
    assert "REVÍSALO" in es.to_yaml() and "REVIEW it" in en.to_yaml()
    assert "LISTO PARA REVISAR" in es.render() and "READY FOR REVIEW" in en.render()
    assert es.mapping["fields"] == en.mapping["fields"] and es.mapping["derived"] == en.mapping["derived"]  # solo cambia el texto
    assert {d.code for d in es.decisions} == {d.code for d in en.decisions}


def test_catalogo_bilingue_coherente_con_los_mensajes_del_inspector():
    for key, entry in catalog().items():
        assert placeholders(entry["es"]) == placeholders(entry["en"]), key
        assert "{key}" not in entry["es"], key  # `key` choca con el primer parámetro de t()


# --- de punta a punta con un caso ----------------------------------------------------------------------------------
def test_flujo_completo_inspeccionar_aprobar_ingerir_y_sellar(idor, tmp_path):
    draft = inspect_source(idor[0])
    approved = draft.save(tmp_path / "aprobado.yaml")
    ws = CaseWorkspace.open_or_create("C-INSPECTOR", root=tmp_path / "cases")
    ws.add_raw(idor[0])
    manifest = ws.ingest(idor[0], approved)
    assert manifest["roles"] == {"actor": "user_id", "resource": "x_invoice_id"}
    ws.ledger()
    report = ws.verify()
    assert report.ok and ws.sealed
    assert ws.mapping_path.read_text(encoding="utf-8") == approved.read_text(encoding="utf-8")


def test_el_borrador_del_repositorio_sigue_siendo_valido():
    assert yaml.safe_load((MAPPINGS_DIR / "web_access_meli.yaml").read_text(encoding="utf-8"))["roles"]["actor"] == "user_id"


# --- cobertura medida sobre el archivo completo (no solo la muestra) ----------------------------------------------
def _token_rows(extra_prefix_rows=3, malformed=0):
    rng = random.Random(1)

    def row(i, token):
        return (f"2020-{1 + i % 28:02d}-10T10:{i % 60:02d},200,h,/invoices/search?invoice_id={1000 + i % 500}"
                f"&site_id=MeliCO&authtoken={token},GET,-,Mozilla/5.0,10.0.0.{i % 200}")

    rows = [row(i, f"ATUSER-ID-normal{i % 30:02d}") for i in range(30000)]
    rows += [row(i, f"TEST-ID-websectest{i % 3}") for i in range(extra_prefix_rows)]
    rows += [row(i, "basura") for i in range(malformed)]
    rng.shuffle(rows)
    return rows


def test_un_prefijo_raro_que_no_cae_en_la_muestra_entra_igual_en_la_regex(tmp_path):
    """Caso real: el grupo secundario usa el prefijo TEST (~0,1 % de las filas). Con una muestra que no lo contiene,
    la regex dejaba esas cuentas con user_id vacío, sin ningún aviso."""
    csv = _csv(tmp_path, _token_rows())
    draft = inspect_source(csv, sample_rows=500)
    (user,) = [d for d in draft.derived if d.name == "user_id"]
    assert "(?:ATUSER|TEST)" in user.regex
    manifest = ingest_file(csv, "d", out_dir=tmp_path / "o", mapping_path=draft.save(tmp_path / "d.yaml"))
    got = duckdb.connect().execute(f"SELECT count(*) FROM read_parquet('{manifest['output']['path']}') "
                                   f"WHERE user_id LIKE 'websectest%'").fetchone()[0]
    assert got == 3


def test_las_filas_que_la_regex_no_cubre_se_cuentan_sobre_el_archivo_completo(tmp_path):
    draft = inspect_source(_csv(tmp_path, _token_rows(malformed=40)), sample_rows=500)
    gaps = [d for d in draft.decisions if d.code == "derived_coverage_gap"]
    assert {g.message.split("'")[1] for g in gaps} == {"user_id", "x_authtoken_type"}
    assert all("40 filas" in g.message and "authtoken=" in g.message for g in gaps) and all(g.level == "review" for g in gaps)


def test_un_archivo_limpio_no_genera_avisos_de_cobertura(idor):
    assert "derived_coverage_gap" not in codes(inspect_source(idor[0]))


def test_las_estadisticas_de_las_derivadas_salen_del_archivo_completo(tmp_path):
    by = {d.name: d for d in inspect_source(_csv(tmp_path, _token_rows()), sample_rows=300).derived}
    assert by["x_invoice_id"].distinct == 500 and by["x_invoice_id"].hit_pct == 100.0  # la muestra solo ve ~250
    assert by["user_id"].distinct == 33 and by["user_id"].hit_pct == 100.0              # 30 normales + 3 TEST, exactos


def test_el_inspector_funciona_con_una_muestra_mayor_que_el_archivo(tmp_path):
    draft = inspect_source(_csv(tmp_path, _token_rows(0)), sample_rows=10_000_000)
    assert draft.status == "ready" and "user_id" in {d.name for d in draft.derived}
