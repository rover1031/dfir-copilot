"""Logs de texto (entrega B). Lo esencial: el syslog nativo de PAN-OS da EXACTAMENTE los mismos hallazgos que el CSV exportado de
Palo Alto; un log de acceso Nginx/Apache trae su zona en el dato; lo que no se reconoce se dice, y las líneas rotas se cuentan."""
import pytest

from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.detectors import run_detectors
from dfir_copilot.detectors.roles import resolve_roles
from dfir_copilot.ingest.text_logs import TextLogError, detect, text_to_csv
from dfir_copilot.profiling import inspect_source
from dfir_copilot.projects import Project
from dfir_copilot.synthetic_firewall import make_firewall_dataset, write_firewall, write_panos_syslog

ACCESS = [
    '203.0.113.7 - ana [04/Oct/2026:13:55:36 -0500] "GET /invoices/search?id=10 HTTP/1.1" 200 512 "https://x.test/" "Mozilla/5.0"',
    '198.51.100.2 - - [04/Oct/2026:13:55:40 -0500] "POST /login HTTP/1.1" 401 - "-" "curl/8.0"',
    'línea rota que no es un log',
    '10.0.0.5 - - [04/Oct/2026:14:00:00 -0500] "GET /health HTTP/1.1" 200 2',
]


def ingest(tmp, name, raw):
    draft = inspect_source(raw, lang="es")
    mp = tmp / f"{name}.yaml"
    draft.save(mp)
    ws = CaseWorkspace.open_or_create(name, root=tmp / "cases", analyst="eder")
    ws.add_raw(raw)
    ws.ingest(raw, mp)
    return draft, ws


def signature(ws):
    eng = ws.engine()
    return {(r.name, tuple(sorted(f.entity.items())), f.severity) for r in run_detectors(eng, roles=resolve_roles(eng)) for f in r.findings}


def test_el_syslog_de_panos_da_los_mismos_hallazgos_que_el_csv_de_palo_alto(tmp_path):
    rows, truth = make_firewall_dataset(hosts=20, days=35)
    syslog = write_panos_syslog(rows, tmp_path / "pa.log")
    assert detect(syslog) == "panos"
    (part,) = text_to_csv(syslog, lambda label: tmp_path / f"pa__{label}.csv")
    assert part["format"] == "panos-traffic" and part["rows"] == len(rows) and part["skipped"] == 0
    d1, native = ingest(tmp_path, "nativo", part["path"])
    d2, export = ingest(tmp_path, "export", write_firewall(rows, tmp_path / "pa.csv", "paloalto"))
    assert d1.mapping["schema"] == "network" and d1.status == "ready"
    sig = signature(native)
    assert sig and sig == signature(export)
    assert any(name == "beaconing" and dict(entity)["src_ip"] == truth.beacon_hosts[0] for name, entity, _ in sig)


def test_traffic_y_threat_salen_en_csv_separados_y_las_lineas_rotas_se_cuentan(tmp_path):
    rows, _ = make_firewall_dataset(hosts=10, days=31)
    syslog = write_panos_syslog(rows[:50], tmp_path / "pa.log")
    lines = syslog.read_text().splitlines()
    threat = lines[0].replace(",TRAFFIC,end,", ",THREAT,url,").split(",")
    threat[31:34] = ["\"malo.example/descarga.exe\"", "9999", "malware", "high"]
    syslog.write_text("\n".join(lines + [",".join(threat), "basura que no es syslog"]) + "\n")
    parts = {p["format"]: p for p in text_to_csv(syslog, lambda label: tmp_path / f"pa__{label}.csv")}
    assert parts["panos-traffic"]["rows"] == 50 and parts["panos-threat"]["rows"] == 1
    assert parts["panos-traffic"]["skipped"] == 1                                       # la línea de basura, contada
    text = parts["panos-threat"]["path"].read_text()
    assert "malo.example/descarga.exe" in text and "high" in text


def test_un_log_de_acceso_nginx_trae_su_zona_en_el_dato(tmp_path):
    raw = tmp_path / "access.log"
    raw.write_text("\n".join(ACCESS) + "\n")
    assert detect(raw) == "combined"
    (part,) = text_to_csv(raw, lambda label: tmp_path / f"a__{label}.csv")
    assert part["rows"] == 3 and part["skipped"] == 1
    draft, ws = ingest(tmp_path, "acceso", part["path"])
    assert ws.engine().manifest["timezone"]["source"] == "in_data"
    got = ws.engine().query("SELECT src_ip, http_method, endpoint, status_code, user_id FROM logs ORDER BY timestamp_utc").rows
    assert got[0] == ("203.0.113.7", "GET", "/invoices/search", 200, "ana") and got[1][4] is None


def test_un_texto_no_reconocido_se_dice_y_queda_como_evidencia(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_DATA_ROOT", str(tmp_path))
    raw = tmp_path / "otro.log"
    raw.write_text("esto no es ningún formato conocido\nni esto\n")
    assert detect(raw) is None
    with pytest.raises(TextLogError, match="Palo Alto"):
        text_to_csv(raw, lambda label: tmp_path / f"x__{label}.csv")
    p = Project.create("Texto", root=tmp_path / "projects", base=tmp_path)
    recs = p.add_from_server(raw)
    assert [r["action"] for r in recs] == ["added", "derivation_failed"] and "Palo Alto" in recs[1]["error"]
    rows, _ = make_firewall_dataset(hosts=10, days=31)
    recs = p.add_from_server(write_panos_syslog(rows[:30], tmp_path / "pa.log"))
    assert [r["action"] for r in recs] == ["added", "derived"] and recs[1]["format"] == "panos-traffic"
    kinds = {f.name: (f.kind, f.supported) for f in p.files()}
    assert kinds["pa.log"] == ("text", False) and kinds["pa__traffic.csv"] == ("log", True)
