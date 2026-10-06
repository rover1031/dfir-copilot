"""Entrega D1: logs de endpoint (EDR). Lo esencial: Falcon y Sysmon dan los mismos hallazgos; los detectores encuentran exactamente la
cadena plantada; y en la copia que ve el modelo no queda ninguna ruta con usuario, línea de comandos ni nombre de equipo real, pero sí
el nombre del ejecutable y las señales técnicas de la línea de comandos."""
import copy
from datetime import timedelta

import pytest

from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.detectors import run_detectors
from dfir_copilot.detectors.roles import resolve_roles
from dfir_copilot.ingest.ingestor import _validate
from dfir_copilot.privacy.parity import detector_parity
from dfir_copilot.profiling import inspect_source
from dfir_copilot.synthetic_endpoint import STYLES, make_endpoint_dataset, write_endpoint
from dfir_copilot.synthetic_firewall import make_firewall_dataset


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("edr")
    fw, ft = make_firewall_dataset(hosts=20, days=35)
    rows, truth = make_endpoint_dataset(fw, ft)
    cases = {}
    for style in STYLES:
        raw = write_endpoint(rows, tmp / f"edr_{style}.{'ndjson' if style == 'sysmon_ecs' else 'csv'}", style)
        draft = inspect_source(raw, lang="es")
        draft.save(tmp / f"{style}.yaml")
        ws = CaseWorkspace.open_or_create(f"EDR-{style}".replace("_", "-"), root=tmp / "cases", analyst="eder")
        ws.add_raw(raw)
        ws.ingest(raw, tmp / f"{style}.yaml")
        cases[style] = (draft, ws)
    return fw, ft, rows, truth, cases


def detect(engine):
    return {r.name: r for r in run_detectors(engine, roles=resolve_roles(engine))}


@pytest.mark.parametrize("style", STYLES)
def test_falcon_y_sysmon_se_reconocen_como_endpoint(world, style):
    draft, ws = world[4][style]
    assert draft.status == "ready" and draft.log_type == "edr" and draft.mapping["schema"] == "endpoint"
    assert {"host", "process_name", "command_line", "parent_process", "file_hash", "dst_ip", "dst_port"} <= set(draft.mapping["fields"])
    assert draft.mapping["roles"] == {"actor": "host", "resource": "process_name"} and ws.engine().manifest["log_schema"] == "endpoint"


def test_los_detectores_encuentran_exactamente_la_cadena_plantada(world):
    _, ft, _, truth, cases = world
    runs = detect(cases["falcon_csv"][1].engine())
    one = lambda name: [(f.entity, f.metrics, f.related) for f in runs[name].findings]  # noqa: E731
    ((ent, m, rel),) = one("lolbin_network")
    assert ent == {"host": truth.beacon_host} and m["proceso"] == "rundll32.exe" and truth.beacon_dst in rel["dst_ip"]
    ((ent, m, _),) = one("suspicious_parent")
    assert ent == {"host": truth.beacon_host} and (m["padre"], m["hijo"]) == truth.chain
    ((ent, m, _),) = one("suspicious_cmdline")
    assert ent == {"host": truth.beacon_host} and m["proceso"] == "powershell.exe" and {"encoded", "hidden", "bypass"} <= set(m["senales"].split(","))
    assert [f.entity["src_ip"] for f in runs["beaconing"].findings] == [ft.beacon_hosts[0]]
    anomalous = {truth.host_of_ip[ip] for ip in (*ft.scanners, *ft.risky_hosts, *ft.exfil_hosts, *ft.beacon_hosts)}
    assert {f.entity["host"] for f in runs["resource_breadth"].findings} <= anomalous      # solo equipos con algo plantado


def test_los_dos_formatos_dicen_lo_mismo(world):
    sigs = {s: {(n, tuple(sorted(f.entity.items())), f.severity) for n, r in detect(world[4][s][1].engine()).items() for f in r.findings}
            for s in STYLES}
    assert sigs["falcon_csv"] and sigs["falcon_csv"] == sigs["sysmon_ecs"]


def test_la_copia_no_revela_rutas_lineas_de_comandos_ni_equipos_pero_conserva_lo_util(world):
    _, _, rows, truth, cases = world
    ws = cases["falcon_csv"][1]
    real, (pseudo, ps) = ws.engine(), ws.pseudonymized()
    assert detector_parity(real, pseudo, ps)["equivalent"]
    text = " ".join(str(v) for row in pseudo.query(
        "SELECT DISTINCT process_name, parent_process, command_line, host, user_id FROM logs", max_rows=100000).rows for v in row)
    users = {r["user"] for r in rows if r["user"] != "SYSTEM"}
    for secret in ("C:\\Users", "\\Device\\", "Downloads", "factura.docm", *users, *truth.host_of_ip.values()):
        assert secret not in text, secret
    bases = {v for (v,) in pseudo.query("SELECT DISTINCT process_name_base FROM logs").rows}
    assert {"rundll32.exe", "powershell.exe", "winword.exe", "chrome.exe"} <= bases
    flags = {v for (v,) in pseudo.query("SELECT DISTINCT command_line_flags FROM logs WHERE command_line_flags IS NOT NULL").rows}
    assert flags == {"encoded,hidden,bypass"}


def test_el_simulador_esta_emparejado_con_el_firewall_y_con_reloj_desfasado(world):
    fw, ft, rows, truth, _ = world
    assert truth.host_of_ip[ft.beacon_hosts[0]] == truth.beacon_host and truth.clock_skew_s == 2.5
    fw_beacon = [r["ts"] for r in fw if (r["src_ip"], r["dst_ip"]) == (ft.beacon_hosts[0], ft.beacon_dst)]
    edr_beacon = [e["ts"] for e in rows if e["event"] == "network" and e["host"] == truth.beacon_host and e["remote_ip"] == ft.beacon_dst]
    assert len(edr_beacon) == len(fw_beacon) and edr_beacon[0] - fw_beacon[0] == timedelta(seconds=2.5)
    assert [e["ts"] for e in rows] == sorted(e["ts"] for e in rows)


def test_un_mapping_de_endpoint_exige_equipo_y_proceso(world):
    mapping = copy.deepcopy(world[4]["falcon_csv"][0].mapping)
    _validate(mapping)
    del mapping["fields"]["host"]
    with pytest.raises(ValueError, match="host"):
        _validate(mapping)


def _texto_base(world, col):
    """Lo que el informe compartible puede mostrar de una columna de proceso: sus valores `_base` (el ejecutable, sin ruta)."""
    ws = world[4]["falcon_csv"][1]
    pseudo, ps = ws.pseudonymized()
    rows = pseudo.query(f"SELECT DISTINCT {col}_base FROM logs WHERE {col}_base IS NOT NULL", max_rows=100000).rows
    return ps, " ".join(str(v) for (v,) in rows)


def test_el_escaneo_de_fugas_no_bloquea_el_ejecutable_suelto_de_falcon(world):
    from dfir_copilot.privacy.pseudonymize import real_hits

    for col in ("process_name", "parent_process"):
        ps, text = _texto_base(world, col)
        assert text, col
        assert real_hits(ps, text) == [], col


def test_sin_la_excepcion_el_proceso_padre_de_falcon_si_se_marcaria(world):
    """Prueba de que la excepción hace falta: find_real a secas marca el padre cuando Falcon lo entrega como nombre suelto."""
    ps, text = _texto_base(world, "parent_process")
    assert any(h["column"] == "parent_process" for h in ps.find_real(text))
