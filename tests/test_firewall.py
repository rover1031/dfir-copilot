"""P3 (primera pieza): logs de firewall. Lo esencial: que el análisis NO dependa del formato del fabricante, que los detectores encuentren
exactamente lo plantado por el simulador (ni más ni menos), y que la copia seudonimizada no cambie ni un hallazgo ni filtre una IP real."""
import copy
import json

import pytest

from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.detectors import available, run_detectors
from dfir_copilot.detectors.roles import resolve_roles
from dfir_copilot.ingest.ingestor import _validate
from dfir_copilot.privacy.parity import detector_parity
from dfir_copilot.profiling import inspect_source
from dfir_copilot.synthetic_firewall import STYLES, make_firewall_dataset, write_firewall


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("fw")
    rows, truth = make_firewall_dataset(hosts=30, days=40)
    cases = {}
    for style in STYLES:
        raw = write_firewall(rows, tmp / f"fw_{style}.{'ndjson' if style == 'ecs_json' else 'csv'}", style)
        draft = inspect_source(raw, lang="es")
        mapping = tmp / f"{style}.yaml"
        draft.save(mapping)
        ws = CaseWorkspace.open_or_create(f"FW-{style}".replace("_", "-"), root=tmp / "cases", analyst="eder")
        ws.add_raw(raw)
        manifest = ws.ingest(raw, mapping)
        cases[style] = (draft, ws, manifest)
    return rows, truth, cases


def detect(engine):
    return {r.name: r for r in run_detectors(engine, roles=resolve_roles(engine))}


def signature(runs):
    return {(name, tuple(sorted(f.entity.items())), f.severity) for name, r in runs.items() for f in r.findings}


# --- el simulador --------------------------------------------------------------------------------------------------------

def test_el_simulador_es_reproducible_y_su_verdad_es_coherente():
    a, ta = make_firewall_dataset(seed=5, hosts=20, days=35)
    b, tb = make_firewall_dataset(seed=5, hosts=20, days=35)
    c, _ = make_firewall_dataset(seed=6, hosts=20, days=35)
    assert a == b and ta == tb and a != c
    assert ta.rows == len(a) and [r["ts"] for r in a] == sorted(r["ts"] for r in a)
    anomalous = {*ta.scanners, *ta.contradiction_hosts, *ta.risky_hosts, *ta.exfil_hosts, *ta.beacon_hosts, *ta.bypass_hosts}
    assert len(anomalous) == 1 + 3 + 2 + 1 + 1 + 1  # cada anomalía cae en hosts distintos: no se confunden entre sí


def test_el_simulador_nunca_permite_bajo_una_regla_de_descarte_salvo_lo_plantado():
    rows, truth = make_firewall_dataset(hosts=20, days=35)
    odd = [r for r in rows if r["rule"] == "RULE_DEFAULT_DENY" and r["action"] == "ALLOW"]
    assert odd == []
    allowed_under_block = {r["src_ip"] for r in rows if r["rule"] == truth.contradiction_rule and r["action"] == "ALLOW"}
    assert allowed_under_block == set(truth.contradiction_hosts)


# --- formatos ------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("style", STYLES)
def test_el_inspector_acepta_cada_formato_como_log_de_red(world, style):
    draft, _, manifest = world[2][style]
    fields = draft.mapping["fields"]
    assert draft.status == "ready" and draft.log_type == "firewall" and draft.mapping["schema"] == "network"
    assert {"timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "rule_name", "bytes_out", "bytes_in"} <= set(fields)
    assert draft.mapping["roles"] == {"actor": "src_ip", "resource": "dst_ip"}
    assert manifest["log_schema"] == "network" and manifest["output"]["rows"] == world[1].rows


def test_los_cuatro_formatos_dicen_exactamente_lo_mismo(world):
    sigs = {style: signature(detect(world[2][style][1].engine())) for style in STYLES}
    first = sigs[STYLES[0]]
    assert first and all(sig == first for sig in sigs.values()), {s: sorted(first ^ sig) for s, sig in sigs.items() if sig != first}


# --- detectores ----------------------------------------------------------------------------------------------------------

def test_los_detectores_de_red_encuentran_exactamente_lo_plantado(world):
    _, truth, cases = world
    runs = detect(cases["generic_es"][1].engine())
    assert set(runs) == set(available("network")) and all(r.status == "ok" for r in runs.values())

    def entities(name, key):
        return sorted(f.entity[key] for f in runs[name].findings)

    assert entities("service_fanout", "src_ip") == list(truth.scanners)
    assert entities("policy_contradiction", "rule_name") == [truth.contradiction_rule]
    assert set(runs["policy_contradiction"].findings[0].related["src_ip"]) == set(truth.contradiction_hosts)
    assert entities("risky_outbound", "src_ip") == sorted(truth.risky_hosts)
    assert entities("volume_outlier", "src_ip") == list(truth.exfil_hosts)
    assert runs["volume_outlier"].findings[0].related["dst_ip"] == [truth.exfil_dst]
    assert entities("beaconing", "src_ip") == list(truth.beacon_hosts)
    beacon = runs["beaconing"].findings[0].metrics
    assert beacon["destino"] == truth.beacon_dst and abs(beacon["intervalo_medio_s"] - 600) < 5 and beacon["variacion"] < 0.02
    assert entities("blocked_then_allowed", "src_ip") == list(truth.bypass_hosts)
    bypass = runs["blocked_then_allowed"].findings[0].metrics
    assert bypass["destino"] == truth.bypass_dst and bypass["pares"] == 12


def test_cada_hallazgo_lleva_sus_consultas_de_respaldo_y_todas_salieron_bien(world):
    runs = detect(world[2]["generic_es"][1].engine())
    for run in runs.values():
        for f in run.findings:
            assert f.evidence, f"{f.detector}: hallazgo sin consultas de respaldo"
            assert all(q["status"] == "ok" and q["sql"] for q in f.evidence)


def test_un_log_web_sigue_corriendo_solo_sus_detectores():
    web, net = set(available("web")), set(available("network"))
    assert web == {"resource_breadth", "automation_clients", "actor_ip_cluster", "activity_ramp"}
    assert {"service_fanout", "policy_contradiction", "risky_outbound", "volume_outlier", "beaconing", "blocked_then_allowed"} <= net
    assert not (net - web) & web and {"resource_breadth", "activity_ramp"} <= net  # los dos genéricos sirven para ambos


# --- privacidad ----------------------------------------------------------------------------------------------------------

def test_la_copia_seudonimizada_no_cambia_ningun_hallazgo_y_no_filtra_ips(world):
    _, truth, cases = world
    ws = cases["generic_es"][1]
    real = ws.engine()
    pseudo, ps = ws.pseudonymized()
    parity = detector_parity(real, pseudo, ps)
    assert parity["equivalent"], parity
    assert ps.treatments["dst_ip"] == "ip" and ps.treatments["src_ip"] == "ip"
    one = lambda sql: {v for (v,) in pseudo.query(sql).rows}  # noqa: E731
    assert all(v.startswith("DST-") for v in one("SELECT DISTINCT dst_ip FROM logs WHERE dst_ip IS NOT NULL"))
    assert all(v.startswith("IP-") for v in one("SELECT DISTINCT src_ip FROM logs WHERE src_ip IS NOT NULL"))
    src_nets, dst_nets = one("SELECT DISTINCT src_ip_net FROM logs WHERE src_ip_net IS NOT NULL"), one(
        "SELECT DISTINCT dst_ip_net FROM logs WHERE dst_ip_net IS NOT NULL")
    assert src_nets and dst_nets and src_nets.isdisjoint(dst_nets)  # alias de red de origen y de destino: nunca el mismo texto
    for col in ("action", "rule_name", "protocol", "dst_port"):  # vocabulario técnico: igual que en el dato real
        sql = f"SELECT DISTINCT {col} FROM logs WHERE {col} IS NOT NULL"
        assert one(sql) == {v for (v,) in real.query(sql).rows}
    text = json.dumps([[f.summary, f.metrics, f.entity, f.related] for r in detect(pseudo).values() for f in r.findings], default=str)
    secrets = {*truth.scanners, *truth.risky_hosts, *truth.exfil_hosts, *truth.beacon_hosts, truth.exfil_dst, truth.beacon_dst, truth.bypass_dst}
    assert [s for s in secrets if s in text] == []


# --- mapping --------------------------------------------------------------------------------------------------------------

def test_un_mapping_de_red_exige_origen_y_destino_y_un_esquema_conocido(world):
    mapping = copy.deepcopy(world[2]["generic_es"][0].mapping)
    _validate(mapping)
    no_dst = copy.deepcopy(mapping)
    del no_dst["fields"]["dst_ip"]
    with pytest.raises(ValueError, match="dst_ip"):
        _validate(no_dst)
    odd = copy.deepcopy(mapping)
    odd["schema"] = "dns"
    with pytest.raises(ValueError, match="schema desconocido"):
        _validate(odd)


def test_un_log_web_no_gana_columnas_de_red(tmp_path):
    from dfir_copilot.ingest.ingestor import ingest_file
    from dfir_copilot.synthetic import make_idor_dataset, write_csv

    rows, _ = make_idor_dataset(normal_requests=200, attacker_requests=100, out_of_pool=50)
    manifest = ingest_file(write_csv(tmp_path / "w.csv", rows), "web_access_meli", out_dir=tmp_path / "out")
    assert "log_schema" not in manifest
    import duckdb
    cols = {r[0] for r in duckdb.connect().execute(f"DESCRIBE SELECT * FROM '{manifest['output']['path']}'").fetchall()}
    assert not ({"dst_ip", "dst_port", "action", "rule_name", "bytes_in"} & cols)
