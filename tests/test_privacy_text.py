"""P1-b.3a: lo que escribe el analista (preguntas y notas) se traduce a alias antes de llegar al modelo. Lo esencial: ningún
valor real sale hacia el modelo ni queda en el ledger; lo dudoso se bloquea ANTES de enviar; y se ve exactamente lo enviado."""
import json
import time

import pytest
from test_agent import FULL, call, say
from test_privacy_agent import _case, leaks, real_values

from dfir_copilot.agent.graph import AgentBusy, build_agent
from dfir_copilot.evidence.ledger import Ledger
from dfir_copilot.privacy import AmbiguousText, Pseudonymizer


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    ws = _case(tmp_path_factory.mktemp("b3a"), "C-B3A")
    real = ws.engine()
    pseudo, ps = ws.pseudonymized()
    return ws, real, pseudo, ps


def one(real, column, where=""):
    return real.query(f"SELECT DISTINCT {column} FROM logs WHERE {column} IS NOT NULL {where} ORDER BY 1 LIMIT 1").rows[0][0]


def fake(pseudo, **dictionaries):
    """Un diccionario a medida sobre el manifiesto de la copia, para probar casos que el dataset sintético no tiene."""
    ps = Pseudonymizer(pseudo.manifest)
    ps._to_alias = {c: dict(m) for c, m in dictionaries.get("alias", {}).items()}
    ps._shift = dict(dictionaries.get("shift", {}))
    return ps


# --- el traductor -----------------------------------------------------------------------------------------------

def test_los_valores_reales_pasan_a_alias_y_se_pueden_revelar_de_vuelta(world):
    _, real, pseudo, ps = world
    user, ip = one(real, "user_id", "AND user_id LIKE 'atacante%'"), "66.6.6.1"
    text = f"¿Qué hizo {user} desde {ip}? Compáralo con {user}."
    res = ps.alias_text(text)
    assert not leaks(res.text, {user, ip}) and ps.alias("user_id", user) in res.text and ps.alias("src_ip", ip) in res.text
    assert {(s["column"], s["count"]) for s in res.substitutions} == {("user_id", 2), ("src_ip", 1)}
    assert ps.reveal_any(res.text) == text                                   # ida y vuelta: nada se pierde ni se inventa
    assert not leaks(json.dumps(res.substitutions), {user, ip})              # el recuento no lleva el valor


def test_la_red_tambien_se_traduce_y_el_texto_sin_valores_no_cambia(world):
    _, real, _, ps = world
    net = ps._to_real["src_ip_net"]
    alias, real_net = next(iter(net.items()))
    assert ps.alias_text(f"la red {real_net} es sospechosa").text == f"la red {alias} es sospechosa"
    plain = "¿Hay actividad anómala sobre /invoices/search en octubre?"
    res = ps.alias_text(plain)
    assert res.text == plain and res.substitutions == () and res.literal_used == 0


def test_limites_de_palabra_una_ip_no_se_toca_dentro_de_otra(world):
    _, real, _, ps = world
    a, b = "10.1.0.1", "10.1.0.10"
    res = ps.alias_text(f"{a}, {b}, {b}0 y {a}.")                           # 10.1.0.100 no existe: debe quedar como está
    assert res.text == f"{ps.alias('src_ip', a)}, {ps.alias('src_ip', b)}, {b}0 y {ps.alias('src_ip', a)}."


def test_ante_un_solape_gana_el_valor_mas_largo(world):
    _, _, pseudo, _ = world
    ps = fake(pseudo, alias={"referer": {"https://sitio.example/pago": "REF-0001"}, "host": {"sitio.example": "H-0001"}})
    assert ps.alias_text("revisa https://sitio.example/pago hoy").text == "revisa REF-0001 hoy"
    assert ps.alias_text("revisa sitio.example hoy").text == "revisa H-0001 hoy"


def test_lo_ambiguo_se_bloquea_con_la_pista_y_literal_lo_deja_pasar(world):
    _, _, pseudo, _ = world
    ps = fake(pseudo, alias={"user_id": {"12345": "U-0001", "ana": "U-0002", "usuario.largo": "U-0003"}},
              shift={"x_invoice_id": 118822000})
    with pytest.raises(AmbiguousText) as exc:
        ps.alias_text("mira al usuario 12345 y a ana")
    assert {i["token"]: i["hint"] for i in exc.value.items} == {"12345": "su alias es U-0001", "ana": "su alias es U-0002"}
    assert "literal" in str(exc.value)
    with pytest.raises(AmbiguousText, match="lo ve como 123"):
        ps.alias_text("¿quién consultó la factura 118822123?")
    ok = ps.alias_text("hay 12345 filas", literal=("12345",))                  # el analista confirma que es una cifra
    assert ok.text == "hay 12345 filas" and ok.literal_used == 1
    assert ps.alias_text("el usuario.largo y 5232 facturas, 118821999 y 4478619").text == \
        "el U-0003 y 5232 facturas, 118821999 y 4478619"                       # cifras normales y números por debajo del rango


def test_el_coste_con_decenas_de_miles_de_valores_es_razonable(world):
    _, _, pseudo, _ = world
    ips = {f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}": f"IP-{i:05d}" for i in range(60000)}
    ps = fake(pseudo, alias={"src_ip": ips})
    text = "¿Qué hizo 10.0.0.7 frente a 10.0.1.9? " * 15
    t0 = time.perf_counter()
    res = ps.alias_text(text)
    assert time.perf_counter() - t0 < 2.0 and "IP-00007" in res.text and "10.0.0.7" not in res.text


# --- el agente --------------------------------------------------------------------------------------------------

def test_la_pregunta_con_valores_reales_llega_al_modelo_en_alias_y_el_ledger_tambien(world, tmp_path, scripted):
    _, real, pseudo, ps = world
    user, ip = "atacante00", "66.6.6.1"
    ledger = Ledger.open("Q1", real, analyst="eder", root=tmp_path)
    llm = scripted([call("describe_dataset"), say("Es el grupo U-0001.")])
    agent = build_agent(pseudo, ledger, llm)
    r = agent.ask(f"¿Qué hizo {user} desde {ip}?")

    sent = "\n".join(str(m.content) for c in llm.log for m in c["messages"])
    assert not leaks(sent, real_values(real, ps)) and ps.alias("user_id", user) in sent
    assert r.sent == f"¿Qué hizo {ps.alias('user_id', user)} desde {ps.alias('src_ip', ip)}?"   # lo que el analista ve
    assert {s["column"] for s in r.substitutions} == {"user_id", "src_ip"}
    (turn,) = ledger.entries("agent_turn")
    assert turn["data"]["question"] == r.sent and turn["data"]["text_substitutions"] == 2 and turn["data"]["text_literal"] == 0
    assert not leaks(ledger.path.read_text(encoding="utf-8"), {user, ip})                       # tampoco en el ledger


def test_preview_muestra_lo_que_se_enviaria_sin_llamar_al_modelo(world, tmp_path, scripted):
    _, real, pseudo, ps = world
    llm = scripted([])
    agent = build_agent(pseudo, Ledger.open("Q2", real, analyst="t", root=tmp_path), llm)
    res = agent.preview("¿Y 66.6.6.2?")
    assert res.text == f"¿Y {ps.alias('src_ip', '66.6.6.2')}?" and llm.log == []


def test_una_pregunta_ambigua_ni_se_envia_ni_se_registra(world, tmp_path, scripted):
    _, real, pseudo, _ = world
    ps = fake(pseudo, alias={"user_id": {"12345": "U-0001"}})
    ledger = Ledger.open("Q3", real, analyst="t", root=tmp_path)
    llm = scripted([say("ok")])
    agent = build_agent(pseudo, ledger, llm, pseudonymizer=ps)
    with pytest.raises(AmbiguousText):
        agent.ask("¿Qué hizo el usuario 12345?")
    assert llm.log == [] and ledger.entries("agent_turn") == []
    r = agent.ask("Hay 12345 filas en octubre", literal=("12345",))
    assert r.status == "done" and r.sent == "Hay 12345 filas en octubre"
    assert ledger.entries("agent_turn")[0]["data"]["text_literal"] == 1


def test_la_nota_de_aprobacion_se_traduce_antes_de_llegar_al_modelo_y_al_registro(world, tmp_path, scripted):
    _, real, pseudo, ps = world
    ledger = Ledger.open("Q4", real, analyst="eder", root=tmp_path)
    llm = scripted(FULL())
    agent = build_agent(pseudo, ledger, llm)
    assert agent.ask("¿Qué pasó?").status == "needs_approval"
    r = agent.resolve("approve", "Confirmado: atacante00 usa 66.6.6.1 según IAM")
    alias_note = f"Confirmado: {ps.alias('user_id', 'atacante00')} usa {ps.alias('src_ip', '66.6.6.1')} según IAM"
    assert r.status == "done" and r.sent == alias_note and len(r.substitutions) == 2
    seen = " ".join(str(m.content) for m in llm.log[-1]["messages"])
    assert alias_note in seen and not leaks(seen, {"atacante00", "66.6.6.1"})
    assert ledger.entries("hypothesis_update")[-1]["data"]["note"] == alias_note
    assert not leaks(ledger.path.read_text(encoding="utf-8"), {"atacante00", "66.6.6.1"})


def test_una_nota_ambigua_deja_la_aprobacion_pendiente(world, tmp_path, scripted):
    _, real, pseudo, ps0 = world
    ps = fake(pseudo, alias={"user_id": {"12345": "U-0001"}})
    ledger = Ledger.open("Q5", real, analyst="eder", root=tmp_path)
    agent = build_agent(pseudo, ledger, scripted(FULL()), pseudonymizer=ps)
    agent.ask("¿Qué pasó?")
    before = len(ledger.entries())
    with pytest.raises(AmbiguousText):
        agent.resolve("approve", "Revisé la cuenta 12345")
    assert len(agent.pending()) == 1 and len(ledger.entries()) == before     # nada avanzó ni se escribió
    with pytest.raises(AgentBusy):
        agent.ask("otra cosa")
    assert agent.resolve("approve", "Revisé la cuenta 12345", literal=("12345",)).status == "done"


def test_con_datos_reales_permitidos_el_texto_va_tal_cual(world, tmp_path, scripted):
    _, real, _, _ = world
    ledger = Ledger.open("Q6", real, analyst="t", root=tmp_path)
    agent = build_agent(real, ledger, scripted([say("ok")]), allow_real=True)   # sintéticos: no hay copia ni diccionario
    assert agent.preview("¿Qué hizo atacante00?").text == "¿Qué hizo atacante00?"
    r = agent.ask("¿Qué hizo atacante00?")
    assert r.sent == "¿Qué hizo atacante00?" and "text_substitutions" not in ledger.entries("agent_turn")[0]["data"]
