"""P0-B2: integridad ledger/dataset, huella de resultados, espacio por caso, colisiones de salida y roles."""
import json

import pytest

from dfir_copilot.cases import CaseError, CaseLocked, CaseWorkspace
from dfir_copilot.detectors import run_detectors
from dfir_copilot.detectors.roles import RoleError, Roles, detector_params, resolve_roles
from dfir_copilot.engine.query_engine import QueryEngine, result_digest
from dfir_copilot.evidence.ledger import DatasetMismatch, Ledger, MappingMismatch, ParquetMismatch
from dfir_copilot.i18n import catalog, placeholders
from dfir_copilot.ingest.ingestor import MAPPINGS_DIR, OutputCollision, ingest_csv, load_mapping
from dfir_copilot.synthetic import make_idor_dataset, write_csv
from dfir_copilot.tools.toolkit import Toolkit


def mapping_variant(tmp_path, tz="America/Bogota", extra=""):
    text = (MAPPINGS_DIR / "web_access_meli.yaml").read_text(encoding="utf-8")
    path = tmp_path / f"variant_{abs(hash((tz, extra)))}.yaml"
    path.write_text(text.replace('timezone: "UTC"', f'timezone: "{tz}"') + extra, encoding="utf-8")
    return path


@pytest.fixture()
def csv_file(tmp_path):
    rows, _ = make_idor_dataset()
    return write_csv(tmp_path / "export.csv", rows)


@pytest.fixture()
def no_identity_rows():
    """Log web sin identidad ni parámetros derivados: solo IP, ruta y estado."""
    return [f"2020-{1 + i % 28:02d}-10T10:{i % 60:02d},200,example.com,/page/{i % 7},GET,-,Mozilla/5.0,10.0.{i % 5}.{i % 200}"
            for i in range(120)]


# --- agujero 1: re-ingerir con otro mapping cambia las horas y nadie se enteraba ------------------------------
def test_reingerir_con_otro_mapping_cambia_las_horas(tmp_path, csv_file):
    a = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "a")
    b = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "b", mapping_path=mapping_variant(tmp_path))
    assert a["input"]["sha256"] == b["input"]["sha256"]          # mismo CSV...
    assert a["time_range_utc"][0] != b["time_range_utc"][0]      # ...pero otro instante del primer evento
    assert a["mapping"]["sha256"] != b["mapping"]["sha256"]


def test_el_ledger_rechaza_un_dataset_re_ingerido_con_otro_mapping(tmp_path, csv_file):
    a = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "a")
    b = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "b", mapping_path=mapping_variant(tmp_path))
    root = tmp_path / "ledger"
    Ledger.open("C1", QueryEngine(a["output"]["path"]), root=root)
    with pytest.raises(MappingMismatch, match="mapping"):
        Ledger.open("C1", QueryEngine(b["output"]["path"]), root=root)
    assert issubclass(MappingMismatch, DatasetMismatch)  # los except DatasetMismatch existentes siguen valiendo


def test_el_ledger_rechaza_un_parquet_alterado_aunque_el_manifiesto_mienta(tmp_path, csv_file):
    a = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "a")
    b = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "b", mapping_path=mapping_variant(tmp_path))
    root = tmp_path / "ledger"
    Ledger.open("C1", QueryEngine(a["output"]["path"]), root=root)
    forged = tmp_path / "forged"
    forged.mkdir()
    (forged / "export.parquet").write_bytes((tmp_path / "b" / "export.parquet").read_bytes())  # datos de B
    (forged / "export.manifest.json").write_text(json.dumps(a), encoding="utf-8")                # manifiesto de A
    with pytest.raises(ParquetMismatch, match="Parquet"):
        Ledger.open("C1", QueryEngine(forged / "export.parquet", verify=False), root=root)
    assert b["output"]["sha256"] != a["output"]["sha256"]


def test_reabrir_el_mismo_dataset_sigue_funcionando(tmp_path, csv_file):
    a = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "a")
    root = tmp_path / "ledger"
    Ledger.open("C1", QueryEngine(a["output"]["path"]), root=root)
    Ledger.open("C1", QueryEngine(a["output"]["path"], verify=False), root=root)  # sin verificar: lo calcula el ledger


def test_un_ledger_anterior_sin_hashes_se_acepta_como_antes(tmp_path, csv_file):
    """Ledgers creados antes de esta comprobación no guardaban mapping/parquet: no deben dejar de abrirse."""
    b = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "b", mapping_path=mapping_variant(tmp_path))
    engine = QueryEngine(b["output"]["path"])
    root = tmp_path / "ledger"
    root.mkdir()
    old = Ledger(root / "OLD.jsonl", engine.dataset_sha256)
    old.append("case_opened", {"case_id": "OLD", "dataset": {"input_sha256": engine.dataset_sha256}})
    Ledger.open("OLD", engine, root=root)


# --- agujero 2: dos archivos con el mismo nombre en la misma carpeta de salida -------------------------------
def test_otro_archivo_con_el_mismo_nombre_ya_no_pisa_el_parquet(tmp_path, csv_file):
    ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "out")
    other = tmp_path / "otra"
    other.mkdir()
    rows, _ = make_idor_dataset(seed=99)
    different = write_csv(other / "export.csv", rows)
    with pytest.raises(OutputCollision, match="OTRO archivo|ANOTHER file"):
        ingest_csv(different, "web_access_meli", out_dir=tmp_path / "out")


def test_reingerir_el_mismo_archivo_es_idempotente_y_overwrite_permite_reemplazar(tmp_path, csv_file):
    first = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "out")
    again = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "out")
    assert first["output"]["sha256"] == again["output"]["sha256"]  # el Parquet es determinista
    other = tmp_path / "otra"
    other.mkdir()
    different = write_csv(other / "export.csv", make_idor_dataset(seed=99)[0])
    replaced = ingest_csv(different, "web_access_meli", out_dir=tmp_path / "out", overwrite=True)
    assert replaced["input"]["sha256"] != first["input"]["sha256"]


# --- huella de resultado y replay ------------------------------------------------------------------------------
def test_la_huella_ignora_el_orden_pero_no_los_valores():
    cols = ("a", "b")
    assert result_digest(cols, [(1, "x"), (2, "y")]) == result_digest(cols, [(2, "y"), (1, "x")])
    assert result_digest(cols, [(1, "x")]) != result_digest(cols, [(1, "z")])
    assert result_digest(("a", "c"), [(1, "x")]) != result_digest(cols, [(1, "x")])
    assert result_digest(cols, [(0.1 + 0.2, "x")]) == result_digest(cols, [(0.3, "x")])  # ruido de flotantes


def test_el_historial_guarda_limite_y_huella(make_engine):
    engine, _ = make_engine()
    engine.query("SELECT src_ip FROM logs", max_rows=7)
    h = engine.history[-1]
    assert h["limit"] == 7 and len(h["result_sha256"]) == 64 and h["truncated"]
    with pytest.raises(Exception):  # noqa: B017
        engine.query("SELECT columna_inexistente FROM logs")
    assert engine.history[-1]["result_sha256"] is None


def test_el_motor_expone_el_hash_real_del_parquet(tmp_path, csv_file):
    m = ingest_csv(csv_file, "web_access_meli", out_dir=tmp_path / "a")
    assert QueryEngine(m["output"]["path"]).parquet_sha256 == m["output"]["sha256"]
    assert QueryEngine(m["output"]["path"], verify=False).parquet_sha256 is None


@pytest.fixture()
def case(tmp_path, make_engine):
    engine, _ = make_engine()
    return Ledger.open("C1", engine, root=tmp_path / "ledger"), engine


def test_replay_compara_tambien_el_contenido(case):
    ledger, engine = case
    engine.query("SELECT status_code, count(*) AS n FROM logs GROUP BY 1")  # sin ORDER BY
    ledger.record_queries(engine.history)
    results = ledger.replay(engine)
    assert [r["hash_match"] for r in results] == [True] and all(r["match"] for r in results)
    (entry,) = ledger.entries("replay")
    assert entry["data"]["hash_checked"] == 1 and entry["data"]["hash_mismatches"] == []


def test_replay_detecta_un_resultado_distinto_con_el_mismo_numero_de_filas(case):
    ledger, engine = case
    engine.query("SELECT status_code, count(*) AS n FROM logs GROUP BY 1")
    forged = {**engine.history[-1], "result_sha256": "0" * 64}  # mismas filas, otro contenido
    ledger.record_queries([forged])
    (r,) = ledger.replay(engine)
    assert r["recorded_rows"] == r["replayed_rows"] and r["hash_match"] is False and r["match"] is False
    assert ledger.entries("replay")[-1]["data"]["hash_mismatches"] == [r["query_id"]]


def test_replay_usa_el_mismo_tope_y_no_compara_contenido_truncado(case):
    ledger, engine = case
    engine.query("SELECT src_ip FROM logs", max_rows=5)  # truncada: LIMIT sin ORDER BY elige filas al azar
    ledger.record_queries(engine.history)
    (r,) = ledger.replay(engine)
    assert r["replayed_rows"] == 5 and r["hash_match"] is None and r["match"] is True


def test_replay_con_entradas_antiguas_sin_huella(case):
    ledger, engine = case
    engine.query("SELECT count(*) AS n FROM logs")
    old = {k: v for k, v in engine.history[-1].items() if k not in ("result_sha256", "limit")}
    ledger.record_queries([old])
    (r,) = ledger.replay(engine)
    assert r["hash_match"] is None and r["match"] is True


# --- espacio por caso ------------------------------------------------------------------------------------------
def test_estructura_del_caso_y_validacion_del_id(tmp_path):
    ws = CaseWorkspace.create("IDOR-2020Q4", root=tmp_path, analyst="eder")
    assert {p.name for p in ws.dir.iterdir()} == {"raw", "processed", "ledger", "case.json"}
    with pytest.raises(CaseError):
        CaseWorkspace.create("IDOR-2020Q4", root=tmp_path)
    for bad in ("../evil", "", "a b", "x/y", ".oculto"):
        with pytest.raises(CaseError):
            CaseWorkspace.create(bad, root=tmp_path)
    with pytest.raises(CaseError):
        CaseWorkspace.open("NO-EXISTE", root=tmp_path)
    assert CaseWorkspace.list_cases(tmp_path) == [
        {"case_id": "IDOR-2020Q4", "analyst": "eder", "created_at_utc": ws.meta["created_at_utc"], "ingested": False}]


def test_dos_casos_con_archivos_del_mismo_nombre_no_se_pisan(tmp_path):
    (tmp_path / "s1").mkdir()
    (tmp_path / "s2").mkdir()
    csv1 = write_csv(tmp_path / "s1" / "export.csv", make_idor_dataset(seed=1)[0])
    csv2 = write_csv(tmp_path / "s2" / "export.csv", make_idor_dataset(seed=2, n_normal=5)[0])
    a, b = (CaseWorkspace.create(n, root=tmp_path / "cases") for n in ("CASO-A", "CASO-B"))
    a.ingest(csv1, "web_access_meli")
    b.ingest(csv2, "web_access_meli")
    assert a.engine().query("SELECT count(*) FROM logs").rows != b.engine().query("SELECT count(*) FROM logs").rows
    assert a.verify().ok and b.verify().ok


def test_el_dataset_se_sella_al_abrir_el_ledger(tmp_path, csv_file):
    ws = CaseWorkspace.create("C1", root=tmp_path / "cases")
    ws.ingest(csv_file, "web_access_meli")
    ws.ingest(csv_file, mapping_variant(tmp_path))  # antes de sellar se puede rehacer
    assert not ws.sealed
    ws.ledger()
    assert ws.sealed
    with pytest.raises(CaseLocked, match="sellado|sealed"):
        ws.ingest(csv_file, "web_access_meli")


def test_el_mapping_aprobado_se_copia_dentro_del_caso(tmp_path, csv_file):
    ws = CaseWorkspace.create("C1", root=tmp_path / "cases")
    variant = mapping_variant(tmp_path)
    manifest = ws.ingest(csv_file, variant)
    assert ws.mapping_path.read_text(encoding="utf-8") == variant.read_text(encoding="utf-8")
    assert manifest["mapping"]["path"] == str(ws.mapping_path)


def test_ingest_sin_dataset_y_engine_sin_ingesta(tmp_path):
    ws = CaseWorkspace.create("C1", root=tmp_path)
    with pytest.raises(CaseError):
        ws.engine()
    assert ws.verify().checks[0].ok is None


def test_add_raw_copia_verificada_solo_lectura_y_rechaza_cambios(tmp_path, csv_file):
    ws = CaseWorkspace.create("C1", root=tmp_path / "cases")
    dest = ws.add_raw(csv_file)
    assert dest.read_bytes() == csv_file.read_bytes() and not dest.stat().st_mode & 0o222
    assert ws.add_raw(csv_file) == dest  # idempotente
    csv_file.write_text(csv_file.read_text(encoding="utf-8") + "2020-01-01T00:00,200,h,/x,GET,-,ua,1.1.1.1\n")
    with pytest.raises(CaseError, match="raw"):
        ws.add_raw(csv_file)


def test_add_raw_con_enlace_simbolico_para_archivos_enormes(tmp_path, csv_file):
    ws = CaseWorkspace.create("C1", root=tmp_path / "cases")
    assert ws.add_raw(csv_file, link=True).is_symlink()


@pytest.fixture()
def sealed_case(tmp_path, csv_file):
    ws = CaseWorkspace.create("C1", root=tmp_path / "cases")
    ws.add_raw(csv_file)
    ws.ingest(csv_file, "web_access_meli")
    ws.ledger()
    return ws


def failed(report):
    return {c.key for c in report.checks if c.ok is False}


def test_verify_de_un_caso_intacto(sealed_case):
    report = sealed_case.verify()
    assert report.ok and failed(report) == set() and len(report.checks) == 6


def test_verify_detecta_el_parquet_alterado(sealed_case):
    pq = sealed_case.processed_dir / sealed_case.meta["dataset"]["parquet"]
    pq.write_bytes(pq.read_bytes() + b"x")
    assert {"parquet_manifest", "parquet_ledger"} <= failed(sealed_case.verify())


def test_verify_detecta_el_mapping_alterado(sealed_case):
    sealed_case.mapping_path.write_text(sealed_case.mapping_path.read_text(encoding="utf-8") + "\n# retoque\n")
    assert {"mapping_manifest", "mapping_ledger"} <= failed(sealed_case.verify())


def test_verify_detecta_el_original_alterado(sealed_case):
    raw = next(sealed_case.raw_dir.iterdir())
    raw.chmod(0o644)
    raw.write_text(raw.read_text(encoding="utf-8") + "extra\n")
    assert failed(sealed_case.verify()) == {"raw"}


def test_verify_detecta_el_ledger_editado(sealed_case):
    path = sealed_case.ledger_path
    path.write_text(path.read_text(encoding="utf-8").replace('"analyst":null', '"analyst":"otro"'))
    report = sealed_case.verify()  # no lanza: informa
    assert failed(report) == {"ledger_chain"} and not report.ok


def test_verify_es_bilingue(sealed_case):
    assert "Ledger hash chain" in sealed_case.verify().render("en")
    assert "Cadena de hashes del ledger" in sealed_case.verify().render("es")


def test_catalogo_bilingue_sigue_coherente():
    for key, entry in catalog().items():
        assert placeholders(entry["es"]) == placeholders(entry["en"]), key


# --- roles ---------------------------------------------------------------------------------------------------
def test_roles_declarados_en_el_mapping(make_engine):
    engine, _ = make_engine()
    assert engine.manifest["roles"] == {"actor": "user_id", "resource": "x_invoice_id"}
    roles = resolve_roles(engine)
    assert (roles.actor, roles.resource) == ("user_id", "x_invoice_id")
    assert roles.sources == {"actor": "mapping", "resource": "mapping"}


def test_roles_inferidos_cuando_el_manifiesto_no_los_trae(make_engine):
    engine, _ = make_engine()
    engine.manifest.pop("roles")  # como un dataset ingerido antes de B2
    roles = resolve_roles(engine, lang="en")
    assert (roles.actor, roles.resource) == ("user_id", "x_invoice_id")
    assert roles.sources == {"actor": "inferred", "resource": "inferred"} and "inferred" in " ".join(roles.notes)


def test_sin_identidad_el_actor_es_la_ip_y_el_recurso_el_endpoint(engine_from_rows, no_identity_rows):
    engine = engine_from_rows(no_identity_rows)
    engine.manifest.pop("roles")
    roles = resolve_roles(engine)
    assert (roles.actor, roles.resource) == ("src_ip", "endpoint")
    runs = {r.name: r for r in run_detectors(engine, roles=roles)}
    assert not [r for r in runs.values() if r.status == "error"]
    assert runs["actor_ip_cluster"].status == "not_applicable" and "IP" in runs["actor_ip_cluster"].reason


def test_override_manual_y_errores_claros(make_engine, engine_from_rows, no_identity_rows):
    engine, _ = make_engine()
    assert resolve_roles(engine, overrides={"actor": "src_ip"}).sources["actor"] == "override"
    with pytest.raises(RoleError, match="no existe|does not exist"):
        resolve_roles(engine, overrides={"actor": "columna_fantasma"}, lang="es")
    with pytest.raises(RoleError, match="sin datos|no tiene datos|no data|has no data"):
        resolve_roles(engine_from_rows(no_identity_rows), overrides={"actor": "user_id"})


def test_resolver_roles_no_ensucia_el_historial(make_engine):
    engine, _ = make_engine()
    before = len(engine.history)
    resolve_roles(engine)
    assert len(engine.history) == before


def test_los_detectores_dan_lo_mismo_con_roles_que_con_los_valores_por_defecto(make_engine):
    engine, _ = make_engine()
    shape = lambda runs: [(r.name, r.status, sorted(f.summary for f in r.findings)) for r in runs]  # noqa: E731
    assert shape(run_detectors(engine)) == shape(run_detectors(engine, roles=resolve_roles(engine)))


def test_un_parametro_explicito_gana_a_los_roles(make_engine):
    engine, _ = make_engine()
    roles = resolve_roles(engine)
    runs = run_detectors(engine, names=["resource_breadth"], roles=roles,
                         params={"resource_breadth": {"resource_col": "x_site_id"}})
    assert detector_params(roles)["resource_breadth"]["resource_col"] == "x_invoice_id"
    assert runs[0].status in ("ok", "not_applicable")


def test_roles_en_el_mapping_se_validan(tmp_path):
    bad_col = tmp_path / "m1.yaml"
    bad_col.write_text((MAPPINGS_DIR / "web_access_meli.yaml").read_text(encoding="utf-8").replace(
        "actor: user_id", "actor: columna_fantasma"), encoding="utf-8")
    with pytest.raises(ValueError, match="columna_fantasma"):
        load_mapping("x", bad_col)
    bad_role = tmp_path / "m2.yaml"
    bad_role.write_text((MAPPINGS_DIR / "web_access_meli.yaml").read_text(encoding="utf-8").replace(
        "actor: user_id", "jefe: user_id"), encoding="utf-8")
    with pytest.raises(ValueError, match="jefe"):
        load_mapping("x", bad_role)


def test_el_ledger_registra_los_roles_una_sola_vez_si_no_cambian(case):
    ledger, engine = case
    roles = resolve_roles(engine)
    assert ledger.record_roles(roles) is True and ledger.record_roles(roles) is False
    assert ledger.record_roles(Roles("src_ip", "endpoint", {"actor": "override", "resource": "override"})) is True
    assert [e["data"]["actor"] for e in ledger.entries("roles")] == ["user_id", "src_ip"]


def test_toolkit_usa_y_registra_los_roles(case):
    ledger, engine = case
    kit = Toolkit(engine, ledger)
    assert kit.call("describe_dataset").data["roles"] == {
        "actor": "user_id", "resource": "x_invoice_id", "sources": {"actor": "mapping", "resource": "mapping"}}
    assert kit.call("run_detectors").ok and kit.call("run_detectors").ok
    assert len(ledger.entries("roles")) == 1


def test_toolkit_sin_identidad_no_se_rompe(engine_from_rows, no_identity_rows, tmp_path):
    engine = engine_from_rows(no_identity_rows)
    engine.manifest.pop("roles")
    out = Toolkit(engine).call("run_detectors")
    assert out.ok and {d["name"]: d["status"] for d in out.data["detectors"]}["actor_ip_cluster"] == "not_applicable"
