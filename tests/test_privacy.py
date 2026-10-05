"""P1-b.2a: copia seudonimizada del dataset. Lo esencial: ningún valor sensible sobrevive, las agregaciones dan lo mismo, los
alias son estables y el diccionario (local) permite volver a los valores reales."""
import json

import duckdb
import pytest

from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.ingest.ingestor import ingest_file, sha256_file
from dfir_copilot.privacy import PrivacyPolicy, Pseudonymizer, build_pseudonymized
from dfir_copilot.privacy.pseudonymize import ip_scope
from dfir_copilot.synthetic import make_idor_dataset, write_csv


@pytest.fixture(scope="module")
def real(tmp_path_factory):
    d = tmp_path_factory.mktemp("priv")
    rows, _ = make_idor_dataset(normal_requests=800, attacker_requests=400, out_of_pool=200)
    manifest = ingest_file(write_csv(d / "three_months.csv", rows), "web_access_meli", out_dir=d / "out")
    return manifest


@pytest.fixture(scope="module")
def pseudo(real):
    return build_pseudonymized(real["output"]["path"], real)


def sql(path, query):
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    return con.execute(query.replace(" FROM T", f" FROM read_parquet('{path}')")).fetchall()


def test_ningun_valor_sensible_sobrevive_en_la_copia(real, pseudo):
    r, p = real["output"]["path"], pseudo["output"]["path"]
    for col in ("src_ip", "user_id", "host", "referer"):
        values = {v for (v,) in sql(r, f"SELECT DISTINCT CAST({col} AS VARCHAR) FROM T WHERE {col} IS NOT NULL")}
        leaked = sql(p, "SELECT count(*) FROM T WHERE " + " OR ".join(
            f"CAST({c} AS VARCHAR) IN ({', '.join(repr(v) for v in values)})"
            for c in ("src_ip", "user_id", "host", "referer", "query_string", "endpoint", "user_agent")))[0][0]
        assert values and leaked == 0, col
    with open(p, "rb") as fh:
        text = fh.read()
    for (user,) in sql(r, "SELECT DISTINCT user_id FROM T LIMIT 5"):
        assert user.encode() not in text                                       # ni dentro del archivo binario


def test_las_agregaciones_dan_lo_mismo_con_alias(real, pseudo):
    q = ("SELECT count(*), count(DISTINCT src_ip), count(DISTINCT user_id), count(DISTINCT x_invoice_id), "
         "max(x_invoice_id) - min(x_invoice_id), count(*) FILTER (WHERE status_code >= 400) FROM T")
    assert sql(real["output"]["path"], q) == sql(pseudo["output"]["path"], q)
    per_actor = "SELECT count(*) AS n, count(DISTINCT x_invoice_id) FROM T GROUP BY user_id ORDER BY 1, 2"
    assert sql(real["output"]["path"], per_actor) == sql(pseudo["output"]["path"], per_actor)


def test_el_desplazamiento_conserva_diferencias_y_oculta_los_numeros(real, pseudo):
    lag = ("SELECT count(*) FILTER (WHERE abs(d) = 1) FROM (SELECT x_invoice_id - lag(x_invoice_id) OVER "
           "(PARTITION BY user_id ORDER BY source_row) AS d FROM T)")
    assert sql(real["output"]["path"], lag) == sql(pseudo["output"]["path"], lag)   # un barrido secuencial se sigue viendo
    assert sql(pseudo["output"]["path"], "SELECT min(x_invoice_id) FROM T")[0][0] == 0
    assert sql(real["output"]["path"], "SELECT min(x_invoice_id) FROM T")[0][0] > 0


def test_alias_con_formato_estable_y_columnas_de_red(pseudo):
    p = pseudo["output"]["path"]
    sample = sql(p, "SELECT user_id, src_ip, host, src_ip_scope, src_ip_net FROM T LIMIT 1")[0]
    assert sample[0].startswith("U-") and sample[1].startswith("IP-") and sample[2].startswith("H-")
    assert sample[3] in ("public", "private", "loopback", "link_local", "shared", "reserved") and sample[4].startswith("N-")
    # misma /24, mismo alias de red; alias de IP y de red distintos entre sí
    nets = sql(p, "SELECT count(DISTINCT src_ip_net), count(DISTINCT src_ip) FROM T")[0]
    assert 0 < nets[0] <= nets[1]


def test_parametros_y_rutas_sin_valores(pseudo):
    p = pseudo["output"]["path"]
    (qs,) = sql(p, "SELECT DISTINCT query_string FROM T LIMIT 1")[0]
    assert "invoice_id=*" in qs and "authtoken=*" in qs and "ATUSER" not in qs and "TEST" not in qs


def test_es_determinista(real, tmp_path):
    a = build_pseudonymized(real["output"]["path"], real, tmp_path / "a")
    b = build_pseudonymized(real["output"]["path"], real, tmp_path / "b")
    q = "SELECT * REPLACE (CAST(timestamp_utc AS VARCHAR) AS timestamp_utc) FROM T ORDER BY source_row"
    assert sql(a["output"]["path"], q) == sql(b["output"]["path"], q)
    assert sha256_file(a["aliases"]["path"]) == sha256_file(b["aliases"]["path"])


def test_el_diccionario_revela_y_aliasa_en_ambos_sentidos(real, pseudo):
    ps = Pseudonymizer(pseudo)
    real_row = sql(real["output"]["path"], "SELECT user_id, src_ip, x_invoice_id FROM T ORDER BY source_row LIMIT 1")[0]
    alias_row = sql(pseudo["output"]["path"], "SELECT user_id, src_ip, x_invoice_id FROM T ORDER BY source_row LIMIT 1")[0]
    for col, r, a in zip(("user_id", "src_ip", "x_invoice_id"), real_row, alias_row, strict=True):
        assert ps.alias(col, r) == a and ps.reveal(col, a) == r
    assert ps.reveal_any(f"El actor {alias_row[0]} usa {alias_row[1]}") == f"El actor {real_row[0]} usa {real_row[1]}"


def test_revelar_texto_respeta_los_limites_de_cada_alias(pseudo, tmp_path):
    ps = Pseudonymizer(pseudo)
    ps._to_real = {"host": {"H-0001": "real-host"}, "x_path": {"PATH-0001": "real-path"}, "user_id": {"U-0001": "ana"}}
    assert ps.reveal_any("H-0001, PATH-0001, U-00012, U-0001.") == "real-host, real-path, U-00012, ana."
    assert ps.reveal_any("XH-0001 no es un alias; tampoco a_U-0001") == "XH-0001 no es un alias; tampoco a_U-0001"


def test_un_diccionario_alterado_se_rechaza(pseudo, tmp_path):
    altered = json.loads(json.dumps(pseudo))
    altered["aliases"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="alterado"):
        Pseudonymizer(altered)


def test_la_politica_admite_excepciones_y_las_registra(real, tmp_path):
    policy = PrivacyPolicy(overrides={"x_token_type": "keep"})
    m = build_pseudonymized(real["output"]["path"], real, tmp_path, policy)
    assert m["treatments"]["x_token_type"] == "keep" and m["policy"]["overrides"] == {"x_token_type": "keep"}
    assert {v for (v,) in sql(m["output"]["path"], "SELECT DISTINCT x_token_type FROM T")} <= {"ATUSER", "TEST"}
    assert m["output"]["path"] != build_pseudonymized(real["output"]["path"], real, tmp_path / "def")["output"]["path"].replace(
        str(tmp_path / "def"), str(tmp_path))                                    # otra política, otro archivo
    with pytest.raises(ValueError, match="Tratamiento"):
        PrivacyPolicy(overrides={"src_ip": "mostrar"})


def test_las_columnas_vacias_no_se_tocan(real, pseudo):
    assert pseudo["treatments"]["session_id"] == "keep" and pseudo["treatments"]["user_id"] == "alias"


def test_el_motor_abre_la_copia_verificando_su_hash(pseudo):
    engine = QueryEngine(pseudo["output"]["path"])
    assert engine.dataset_sha256 == pseudo["input"]["sha256"]                     # el mismo archivo original
    assert engine.query("SELECT count(DISTINCT user_id) FROM logs").rows[0][0] > 0


@pytest.mark.parametrize("value, scope, net", [
    ("10.1.2.3", "private", "10.1.2.0/24"), ("192.168.0.9", "private", "192.168.0.0/24"),
    ("8.8.8.8", "public", "8.8.8.0/24"), ("127.0.0.1", "loopback", "127.0.0.0/24"),
    ("100.64.1.1", "shared", "100.64.1.0/24"), ("169.254.1.1", "link_local", "169.254.1.0/24"),
    ("2001:db8::1", "reserved", "2001:db8::/64"), ("no-es-ip", "invalid", None),
])
def test_alcance_y_red_de_cada_ip(value, scope, net):
    assert ip_scope(value) == (scope, net)


def test_mascaras_de_ruta_y_user_agent(tmp_path):
    csv = tmp_path / "w.csv"
    csv.write_text("ts,ip,method,uri,status,ua\n"
                   "2021-01-01 10:00:00,10.0.0.1,GET,/users/12345/invoices/98765?k=v,200,curl/8.0 from 10.9.8.7 ana@x.com abcdefghijklmnopqrstuvwxyz0123\n",
                   encoding="utf-8")
    mp = tmp_path / "m.yaml"
    mp.write_text("source: w\nformat: csv\nfields: {timestamp: ts, src_ip: ip, http_method: method, uri: uri, status_code: status, "
                  "user_agent: ua}\ntimestamp: {format: '%Y-%m-%d %H:%M:%S', timezone: UTC}\n", encoding="utf-8")
    m = ingest_file(csv, "w", out_dir=tmp_path / "o", mapping_path=mp)
    p = build_pseudonymized(m["output"]["path"], m)
    endpoint, ua = sql(p["output"]["path"], "SELECT endpoint, user_agent FROM T")[0]
    assert endpoint == "/users/{id}/invoices/{id}"
    assert ua == "curl/8.0 from {ip} {email} {token}"


def test_el_caso_crea_la_copia_una_vez_y_la_reutiliza(real, tmp_path):
    rows, _ = make_idor_dataset(normal_requests=300, attacker_requests=100, out_of_pool=50)
    csv = write_csv(tmp_path / "three_months.csv", rows)
    ws = CaseWorkspace.open_or_create("C-PRIV", root=tmp_path / "cases", analyst="t")
    ws.add_raw(csv)
    ws.ingest(csv, "web_access_meli")
    engine, ps = ws.pseudonymized()
    first = engine.parquet_sha256
    engine2, _ = ws.pseudonymized()
    assert engine2.parquet_sha256 == first and engine.query("SELECT user_id FROM logs LIMIT 1").rows[0][0].startswith("U-")
    assert ws.verify().ok                                                         # la copia no altera la custodia del caso


def test_la_clasificacion_en_sql_coincide_con_la_de_python():
    """IPv4 se clasifica en SQL (escala a millones de IPs); debe dar exactamente lo mismo que `ip_scope`."""
    import random

    from dfir_copilot.privacy.pseudonymize import IPV4_RANGES, IPV4_RE, _ipv4_sql

    rng = random.Random(0)
    sample = [f"{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}" for _ in range(3000)]
    for _, nets in IPV4_RANGES:                       # bordes exactos de cada rango
        for n in nets:
            import ipaddress
            net = ipaddress.ip_network(n)
            sample += [str(net.network_address), str(net.broadcast_address),
                       str(net.network_address - 1) if int(net.network_address) else "0.0.0.0",
                       str(net.broadcast_address + 1) if int(net.broadcast_address) < 2**32 - 1 else "255.255.255.255"]
    sample += ["010.1.2.3", "256.1.1.1", "1.2.3", "::1", "fe80::1", "fd00::5", "2001:db8::1", "2800:3f0::1", "ff02::1", "nada"]
    con = duckdb.connect()
    con.execute("CREATE TABLE t (v VARCHAR)")
    con.executemany("INSERT INTO t VALUES (?)", [(v,) for v in sample])
    scope_sql, net_sql = _ipv4_sql("v")
    in_sql = dict((v, (s, n)) for v, s, n in con.execute(
        f"SELECT v, {scope_sql}, {net_sql} FROM t WHERE regexp_full_match(v, '{IPV4_RE}')").fetchall())
    for v in sample:
        expected = ip_scope(v)
        if v in in_sql:
            assert in_sql[v] == expected, v
        else:                                          # lo que no es IPv4 estricta lo clasifica Python
            assert expected[0] == "invalid" or ":" in v, v


@pytest.mark.parametrize("value, scope", [("224.0.0.1", "reserved"), ("ff02::1", "reserved"), ("fd00::5", "private"),
                                           ("2800:3f0::1", "public"), ("192.0.2.10", "reserved"), ("010.1.2.3", "invalid")])
def test_multicast_documentacion_y_ceros_a_la_izquierda(value, scope):
    assert ip_scope(value)[0] == scope
