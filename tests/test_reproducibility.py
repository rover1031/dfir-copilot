"""Reproducibilidad: una consulta con empates en el corte de un LIMIT da resultados distintos en cada ejecución y no se puede verificar.
Caso real de este proyecto: `GROUP BY 1 ORDER BY 2 DESC LIMIT 8` con 11 valores empatados en el octavo puesto. El modelo recibe el aviso
al ejecutarla, y el replay distingue "no determinista" de "alterada".

El no determinismo de DuckDB depende de los hilos y del tamaño de los datos, así que aquí se simula con un motor que da un hash distinto
en cada ejecución de las consultas marcadas; el mecanismo real se midió aparte (8 resultados distintos en 10 ejecuciones)."""
from test_agent import call, say

from dfir_copilot.agent.graph import build_agent
from dfir_copilot.evidence.ledger import Ledger
from dfir_copilot.tools import Toolkit, ToolLimits

FLAKY = "SELECT user_id, count(*) AS n FROM logs GROUP BY 1 ORDER BY 2 DESC LIMIT 3 /* FLAKY */"
STABLE_LIMIT = "SELECT user_id, count(*) AS n FROM logs GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 3"


class Flaky:
    """Envuelve un motor: las consultas con 'FLAKY' devuelven un hash distinto en cada ejecución; con 'CONSTANT', siempre el mismo
    pero distinto del registrado. Cuenta cuántas veces se ejecutó cada tipo."""

    def __init__(self, inner):
        self.inner, self.runs, self.n = inner, 0, 0

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def query(self, sql, **kw):
        res = self.inner.query(sql, **kw)
        self.runs += 1
        if "FLAKY" in sql:
            self.n += 1
            self.inner.history[-1]["result_sha256"] = f"{self.n:064d}"
        elif "CONSTANT" in sql:
            self.inner.history[-1]["result_sha256"] = "1" * 64
        return res


# --- run_query avisa ----------------------------------------------------------------------------------------------

def test_una_consulta_no_reproducible_con_limit_avisa_y_se_registra_una_sola_vez(tmp_path, make_engine):
    engine, _ = make_engine()
    ledger = Ledger.open("R", engine, analyst="eder", root=tmp_path / "led")
    flaky = Flaky(engine)
    out = Toolkit(flaky, ledger).call("run_query", {"sql": FLAKY})
    assert out.ok and out.data["reproducible"] is False and "desempates" in out.data["warning"]
    assert len([e for e in ledger.entries("query") if "FLAKY" in e["data"]["sql"]]) == 1   # el control no es una consulta más


def test_una_consulta_reproducible_no_lleva_aviso(tmp_path, make_engine):
    engine, _ = make_engine()
    out = Toolkit(engine, Ledger.open("R2", engine, analyst="eder", root=tmp_path / "led")).call("run_query", {"sql": STABLE_LIMIT})
    assert out.ok and "reproducible" not in out.data and "warning" not in out.data


def test_sin_limit_no_se_ejecuta_dos_veces_y_el_control_se_puede_apagar(tmp_path, make_engine):
    engine, _ = make_engine()
    flaky = Flaky(engine)
    kit = Toolkit(flaky, Ledger.open("R3", engine, analyst="eder", root=tmp_path / "led"))
    before = flaky.runs
    kit.call("run_query", {"sql": "SELECT count(*) AS n FROM logs"})
    assert flaky.runs - before == 1                                                     # sin LIMIT: una sola ejecución
    before = flaky.runs
    kit.call("run_query", {"sql": STABLE_LIMIT})
    assert flaky.runs - before == 2                                                     # con LIMIT: la consulta y su control
    off = Toolkit(Flaky(engine), limits=ToolLimits(check_reproducible=False))
    before = off.engine.runs
    out = off.call("run_query", {"sql": FLAKY})
    assert off.engine.runs - before == 1 and "reproducible" not in out.data


def test_un_fallo_del_control_no_rompe_la_consulta(tmp_path, make_engine):
    engine, _ = make_engine()

    class Breaks(Flaky):
        def query(self, sql, **kw):
            if "SEGUNDA" in sql and getattr(self, "again", False):
                raise RuntimeError("falla solo el control")
            self.again = "SEGUNDA" in sql
            return super().query(sql, **kw)

    out = Toolkit(Breaks(engine)).call("run_query", {"sql": "SELECT 1 AS uno /* SEGUNDA */ LIMIT 1"})
    assert out.ok and "reproducible" not in out.data


# --- el replay distingue no determinista de alterada --------------------------------------------------------------

def test_el_replay_marca_como_no_determinista_lo_que_no_da_lo_mismo_dos_veces(tmp_path, make_engine):
    engine, _ = make_engine()
    ledger = Ledger.open("R4", engine, analyst="eder", root=tmp_path / "led")
    engine.query(FLAKY)
    ledger.record_queries(engine.history[-1:])
    (r,) = ledger.replay(Flaky(engine))
    assert r["match"] is False and r["nondeterministic"] is True
    last = ledger.entries("replay")[-1]["data"]
    assert last["mismatches"] == [] and last["nondeterministic"] == [r["query_id"]]       # no es una alteración


def test_una_consulta_estable_con_otro_contenido_sigue_siendo_un_mismatch(tmp_path, make_engine):
    engine, _ = make_engine()
    ledger = Ledger.open("R5", engine, analyst="eder", root=tmp_path / "led")
    engine.query("SELECT count(*) AS n FROM logs /* CONSTANT */")
    ledger.record_queries(engine.history[-1:])
    (r,) = ledger.replay(Flaky(engine))                                                   # siempre el mismo hash, pero no el registrado
    assert r["match"] is False and "nondeterministic" not in r
    last = ledger.entries("replay")[-1]["data"]
    assert last["mismatches"] == [r["query_id"]] and last["nondeterministic"] == []


def test_el_replay_no_repite_lo_que_ya_coincide(tmp_path, make_engine):
    engine, _ = make_engine()
    ledger = Ledger.open("R6", engine, analyst="eder", root=tmp_path / "led")
    engine.query(STABLE_LIMIT)
    ledger.record_queries(engine.history[-1:])
    flaky = Flaky(engine)
    (r,) = ledger.replay(flaky)
    assert r["match"] is True and flaky.runs == 1                                         # sin sospecha no hay ejecuciones de más


# --- el modelo lo sabe -----------------------------------------------------------------------------------------------

def test_el_prompt_exige_orden_total_con_limit(tmp_path, make_engine, scripted):
    engine, _ = make_engine()
    agent = build_agent(engine, Ledger.open("R7", engine, analyst="eder", root=tmp_path / "led"), scripted([say("x")]), allow_real=True)
    system = agent.system_prompt().content
    assert "desempates" in system and "no se puede verificar" in system and "no es reproducible" in system


def test_el_aviso_llega_al_modelo_dentro_de_la_respuesta_de_la_herramienta(tmp_path, make_engine, scripted):
    engine, _ = make_engine()
    llm = scripted([call("run_query", sql=FLAKY), say("Repito con desempates")])
    agent = build_agent(Flaky(engine), Ledger.open("R8", engine, analyst="eder", root=tmp_path / "led"), llm, allow_real=True)
    agent.ask("Top de usuarios")
    tool_text = " ".join(str(m.content) for m in llm.log[-1]["messages"] if m.type == "tool")
    assert '"reproducible": false' in tool_text and "desempates" in tool_text
