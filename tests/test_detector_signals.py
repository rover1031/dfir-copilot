"""Pruebas de los detectores de señales y de la correlación, contra verdad conocida."""
from dfir_copilot.detectors import available, correlate, run_detectors
from dfir_copilot.synthetic import make_idor_dataset


def flagged(run, key="user_id"):
    return {f.entity[key] for f in run.findings}


def test_registro_completo():
    assert {"resource_breadth", "automation_clients", "actor_ip_cluster", "activity_ramp"} <= set(available())


# --- automation_clients -------------------------------------------------------------------
def test_automation_encuentra_solo_a_los_atacantes(make_engine):
    engine, truth = make_engine()
    (run,) = run_detectors(engine, names=["automation_clients"])
    assert run.status == "ok" and flagged(run) == set(truth.attacker_actors)
    assert all(f.metrics["pct_automatizado"] == 100.0 for f in run.findings)


def test_automation_sin_ataque_no_hay_hallazgos(make_engine):
    engine, _ = make_engine(n_attackers=0)
    (run,) = run_detectors(engine, names=["automation_clients"])
    assert run.status == "ok" and run.findings == ()


def test_automation_si_todo_es_automatizado_deja_de_ser_senal(engine_from_rows):
    rows, _ = make_idor_dataset()
    rows = ['"'.join([p, "python-requests/2.25", s]) for p, _, s in (r.split('"') for r in rows)]
    (run,) = run_detectors(engine_from_rows(rows), names=["automation_clients"])
    assert run.findings
    assert all(f.severity == "info" and f.metrics["automatizacion_es_la_norma"] for f in run.findings)


def test_automation_herramienta_ofensiva_es_high(engine_from_rows):
    rows, _ = make_idor_dataset()
    rows = [r.replace("Scrapy/2.3.0 (+https://scrapy.org)", "sqlmap/1.4") for r in rows]
    (run,) = run_detectors(engine_from_rows(rows), names=["automation_clients"])
    assert {f.severity for f in run.findings} == {"high"}


# --- actor_ip_cluster ---------------------------------------------------------------------
def test_cluster_cerrado_con_los_atacantes_y_sus_ips(make_engine):
    engine, truth = make_engine()
    (run,) = run_detectors(engine, names=["actor_ip_cluster"])
    (f,) = run.findings
    assert f.severity == "high" and f.metrics["cerrado"] is True
    assert set(f.related["user_id"]) == set(truth.attacker_actors)
    assert set(f.related["src_ip"]) == set(truth.attacker_ips)


def test_cluster_que_comparte_una_ip_con_un_normal_no_es_cerrado(engine_from_rows):
    rows, _ = make_idor_dataset()
    i = next(i for i, r in enumerate(rows) if "ATUSER-ID-normal00" in r)
    rows[i] = rows[i].rsplit(",", 1)[0] + ",66.6.6.1"  # un usuario normal aparece en una IP del grupo
    (run,) = run_detectors(engine_from_rows(rows), names=["actor_ip_cluster"])
    (f,) = run.findings
    assert f.metrics["cerrado"] is False and f.metrics["ips_compartidas"] == 1 and f.severity == "medium"


def test_cluster_sin_ataque_no_hay_hallazgos(make_engine):
    engine, _ = make_engine(n_attackers=0)
    (run,) = run_detectors(engine, names=["actor_ip_cluster"])
    assert run.status == "ok" and run.findings == ()


# --- activity_ramp ------------------------------------------------------------------------
def test_ramp_encuentra_solo_a_los_atacantes(make_engine):
    engine, truth = make_engine()
    (run,) = run_detectors(engine, names=["activity_ramp"])
    assert run.status == "ok" and flagged(run) == set(truth.attacker_actors)
    assert all(f.metrics["ratio"] >= 3 for f in run.findings)


def test_ramp_sin_ataque_no_hay_hallazgos(make_engine):
    engine, _ = make_engine(n_attackers=0)
    (run,) = run_detectors(engine, names=["activity_ramp"])
    assert run.status == "ok" and run.findings == ()


def test_ramp_no_aplicable_con_un_periodo_demasiado_corto(engine_from_rows):
    rows, _ = make_idor_dataset()
    rows = ["2020-01-10T10:00," + r.split(",", 1)[1] for r in rows]  # todo el log en un solo día
    (run,) = run_detectors(engine_from_rows(rows), names=["activity_ramp"])
    assert run.status == "not_applicable" and "día" in run.reason


# --- correlación --------------------------------------------------------------------------
def test_correlacion_eleva_a_high_solo_a_los_atacantes(make_engine):
    engine, truth = make_engine()
    cases = correlate(run_detectors(engine))
    assert {c.entity for c in cases} == set(truth.attacker_actors)
    assert all(c.severity == "high" and c.signals >= 3 for c in cases)
    assert all("actor_ip_cluster" in c.detectors for c in cases)  # la señal del grupo llega vía `related`


def test_correlacion_sin_ataque_no_produce_casos(make_engine):
    engine, _ = make_engine(n_attackers=0)
    assert correlate(run_detectors(engine)) == []
