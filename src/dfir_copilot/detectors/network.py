"""Detectores para logs de red (firewalls y flujos). Corren solo sobre logs con `log_schema: network` (ver `Detector.applies_to`).

Dos reglas de diseño que vienen de lo aprendido en el proyecto:
* **Dan lo mismo sobre los datos reales y sobre la copia seudonimizada.** No dependen de ver una IP en claro: para saber si un destino es
  externo usan la columna `<ip>_scope` que la copia ya trae y, si no existe (datos reales), la calculan con la MISMA tabla de rangos que la
  seudonimización (`IPV4_RANGES`).
* **Orden total en todo `ORDER BY ... LIMIT`** (con desempates): una consulta con empates en el corte no es reproducible y el replay no la puede verificar.

Las heurísticas de nombres (una regla "de bloqueo", una acción "de permitir") son un indicio y se dicen como tal en el resumen del hallazgo.
"""
from __future__ import annotations

import math

from dfir_copilot.detectors.base import Detector, Finding, NotApplicable, ensure_columns, register

ALLOW = ("lower(CAST(action AS VARCHAR)) IN ('allow','allowed','accept','accepted','permit','permitted','pass','permitir','permitido',"
         "'aceptar','aceptado')")
DENY = ("lower(CAST(action AS VARCHAR)) IN ('block','blocked','deny','denied','drop','dropped','reject','rejected','discard','bloquear',"
        "'bloqueado','denegar','denegado','rechazado','descartado','reset-both','reset-client','reset-server','drop-icmp')")
BLOCKISH_RULE = r"(?i)(block|deny|drop|reject|bloq|deneg|rechaz)"
# Puertos de administración y de protocolos heredados que no deberían salir a Internet desde la red interna.
RISKY_PORTS = (21, 22, 23, 135, 137, 138, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986)


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def scope_sql(engine, col: str) -> str:
    """Expresión SQL con el alcance de una columna IP ('public', 'private', ...): la columna `<col>_scope` si existe (copia seudonimizada)
    o su cálculo con la tabla de rangos de la seudonimización (datos reales). Lo que no es IPv4 válida sale 'invalid'."""
    cols = {r[0] for r in engine.query("DESCRIBE logs").rows}  # determinista: queda como evidencia y el replay la verifica
    if f"{col}_scope" in cols:
        return _q(f"{col}_scope")
    from dfir_copilot.privacy.pseudonymize import IPV4_RE, _ipv4_sql  # import tardío: privacy importa los detectores

    scope, _ = _ipv4_sql(_q(col))
    return f"CASE WHEN regexp_full_match({_q(col)}, {_lit(IPV4_RE)}) THEN {scope} ELSE 'invalid' END"


def _robust(engine, per_sql: str, value: str, k: float, floor: float, min_actors: int):
    """(n, mediana, escala, umbral) de `value` entre los actores de `per_sql`, con la escala robusta (MAD) y un suelo."""
    n, med, mad = engine.query(
        f"WITH per AS ({per_sql}), st AS (SELECT median({value}) AS med, count(*) AS n FROM per), "
        f"dev AS (SELECT median(abs(per.{value} - st.med)) AS mad FROM per CROSS JOIN st) "
        f"SELECT st.n, st.med, dev.mad FROM st CROSS JOIN dev").rows[0]
    if n < min_actors:
        raise NotApplicable(f"solo {n} actores; se necesitan al menos {min_actors} pares")
    scale = max(1.4826 * float(mad), floor)
    return n, float(med), scale, float(med) + k * scale


def _severity(z: float, k: float) -> str:
    return "high" if z > 4 * k else "medium" if z > 2 * k else "low"


@register
class ServiceFanout(Detector):
    name = "service_fanout"
    applies_to = ("network",)
    description = ("Orígenes que contactan muchos más destinos y puertos distintos que sus pares "
                   "(barrido de hosts o de puertos).")

    def __init__(self, actor_col: str = "src_ip", k: float = 3.0, floor_pct: float = 0.05, min_actors: int = 5, min_services: int = 10):
        self.actor_col, self.k, self.floor_pct = actor_col, float(k), float(floor_pct)
        self.min_actors, self.min_services = int(min_actors), int(min_services)

    def run(self, engine) -> list[Finding]:
        a = _q(self.actor_col)
        ensure_columns(engine, [self.actor_col, "dst_ip"])
        svc = "dst_ip || ':' || coalesce(CAST(dst_port AS VARCHAR), '-')"
        per = f"SELECT {a} AS actor, count(DISTINCT {svc}) AS servicios FROM logs WHERE {a} IS NOT NULL AND dst_ip IS NOT NULL GROUP BY 1"
        n, med, scale, threshold = _robust(engine, per, "servicios", self.k, 0.0, self.min_actors)
        scale = max(scale, self.floor_pct * med)
        threshold = med + self.k * scale
        try:
            ensure_columns(engine, ["action"])
            denied = f"round(100.0 * count(*) FILTER (WHERE {DENY}) / count(*), 1)"
        except NotApplicable:
            denied = "CAST(NULL AS DOUBLE)"
        flagged = engine.query(
            f"SELECT {a} AS actor, count(DISTINCT {svc}) AS servicios, count(DISTINCT dst_ip) AS ips, count(DISTINCT dst_port) AS puertos, "
            f"count(*) AS conexiones, {denied} AS pct_denegado FROM logs WHERE {a} IS NOT NULL AND dst_ip IS NOT NULL "
            f"GROUP BY 1 HAVING count(DISTINCT {svc}) > {threshold!r} AND count(DISTINCT {svc}) >= {self.min_services} "
            f"ORDER BY servicios DESC, actor LIMIT 100")
        out = []
        for actor, servicios, ips, puertos, conexiones, pct in flagged.rows:
            z = (servicios - med) / scale
            out.append(Finding(
                detector=self.name, title="Barrido de destinos y puertos", severity=_severity(z, self.k), entity={self.actor_col: actor},
                summary=(f"{actor} contactó {servicios} servicios distintos ({ips} destinos, {puertos} puertos), {servicios / max(med, 1):.1f}x "
                         f"la mediana de sus pares ({med:g})."),
                metrics={"servicios": servicios, "destinos": ips, "puertos": puertos, "conexiones": conexiones,
                         "pct_denegado": None if pct is None else float(pct), "mediana_pares": med, "z_robusto": round(z, 2),
                         "umbral": round(threshold, 1), "actores_comparados": n},
                mitre=("T1046",)))
        return out


@register
class PolicyContradiction(Detector):
    name = "policy_contradiction"
    applies_to = ("network",)
    description = "Reglas cuyo nombre indica bloqueo pero que aparecen con acción de permitir (regla mal nombrada o bloqueo eludido)."

    def __init__(self, min_events: int = 3):
        self.min_events = int(min_events)

    def run(self, engine) -> list[Finding]:
        ensure_columns(engine, ["rule_name", "action", "src_ip"])
        res = engine.query(
            f"WITH r AS (SELECT rule_name, src_ip, count(*) AS n, count(*) FILTER (WHERE {ALLOW}) AS allowed FROM logs "
            f"WHERE rule_name IS NOT NULL AND regexp_matches(rule_name, {_lit(BLOCKISH_RULE)}) GROUP BY 1, 2), "
            f"t AS (SELECT rule_name, sum(n) AS total, sum(allowed) AS allowed, count(*) FILTER (WHERE allowed > 0) AS srcs FROM r GROUP BY 1), "
            f"top AS (SELECT rule_name, src_ip, row_number() OVER (PARTITION BY rule_name ORDER BY allowed DESC, src_ip) AS rk "
            f"FROM r WHERE allowed > 0) "
            f"SELECT t.rule_name, t.total, t.allowed, t.srcs, list(top.src_ip ORDER BY top.rk) FILTER (WHERE top.rk <= 10) AS top_srcs "
            f"FROM t LEFT JOIN top USING (rule_name) WHERE t.allowed >= {self.min_events} "
            f"GROUP BY t.rule_name, t.total, t.allowed, t.srcs ORDER BY t.allowed DESC, t.rule_name LIMIT 50")
        out = []
        for rule, total, allowed, srcs, top_srcs in res.rows:
            share = allowed / total
            out.append(Finding(
                detector=self.name, title="Acción de permitir bajo una regla de bloqueo",
                severity="high" if share >= 0.5 else "medium" if share >= 0.1 else "low", entity={"rule_name": rule},
                summary=(f"{int(allowed)} de {int(total)} eventos bajo la regla '{rule}' terminaron en acción de permitir ({share:.0%}), "
                         f"desde {srcs} origen(es). Por el nombre es una regla de bloqueo: o está mal nombrada o el bloqueo se eludió."),
                metrics={"eventos": int(total), "permitidos": int(allowed), "pct_permitido": round(100 * share, 1), "origenes": int(srcs)},
                related={"src_ip": list(top_srcs or [])}))
        return out


@register
class RiskyOutbound(Detector):
    name = "risky_outbound"
    applies_to = ("network",)
    description = "Conexiones PERMITIDAS de la red interna hacia Internet por puertos de administración o heredados (SSH, RDP, SMB)."

    def __init__(self, min_events: int = 3):
        self.min_events = int(min_events)

    def run(self, engine) -> list[Finding]:
        ensure_columns(engine, ["src_ip", "dst_ip", "dst_port", "action"])
        src, dst = scope_sql(engine, "src_ip"), scope_sql(engine, "dst_ip")
        res = engine.query(
            f"SELECT src_ip, count(*) AS eventos, count(DISTINCT dst_ip) AS destinos, list_sort(list(DISTINCT dst_port)) AS puertos, "
            f"CAST(min(timestamp_utc) AS VARCHAR) AS primera, CAST(max(timestamp_utc) AS VARCHAR) AS ultima FROM logs "
            f"WHERE {ALLOW} AND {src} = 'private' AND {dst} = 'public' AND dst_port IN ({', '.join(map(str, RISKY_PORTS))}) "
            f"GROUP BY 1 HAVING count(*) >= {self.min_events} ORDER BY eventos DESC, src_ip LIMIT 100")
        out = []
        for actor, eventos, destinos, puertos, primera, ultima in res.rows:
            sev = "high" if eventos >= 50 or destinos >= 5 else "medium" if eventos >= 10 else "low"
            out.append(Finding(
                detector=self.name, title="Administración o protocolos heredados hacia Internet", severity=sev, entity={"src_ip": actor},
                summary=(f"{actor} tuvo {eventos} conexiones permitidas hacia {destinos} destino(s) externo(s) por puertos de administración o "
                         f"heredados ({', '.join(map(str, puertos))})."),
                metrics={"eventos": eventos, "destinos": destinos, "puertos": list(puertos), "primera": primera, "ultima": ultima},
                mitre=("T1021",)))
        return out


@register
class VolumeOutlier(Detector):
    name = "volume_outlier"
    applies_to = ("network",)
    description = "Orígenes que envían a Internet un volumen de datos muy superior al de sus pares (posible exfiltración)."

    def __init__(self, k: float = 3.0, floor: float = 0.7, min_actors: int = 5, min_bytes: int = 1_000_000):  # floor 0.7 = duplicar (ln 2)
        self.k, self.floor, self.min_actors, self.min_bytes = float(k), float(floor), int(min_actors), int(min_bytes)

    def run(self, engine) -> list[Finding]:
        ensure_columns(engine, ["src_ip", "dst_ip", "bytes_out"])
        dst = scope_sql(engine, "dst_ip")
        per = (f"SELECT src_ip AS actor, ln(1.0 + sum(bytes_out)) AS lb, sum(bytes_out) AS bytes, count(*) AS eventos FROM logs "
               f"WHERE src_ip IS NOT NULL AND bytes_out IS NOT NULL AND {dst} = 'public' GROUP BY 1")
        n, med, scale, threshold = _robust(engine, per, "lb", self.k, self.floor, self.min_actors)
        res = engine.query(
            f"WITH per AS ({per}), top AS (SELECT src_ip, dst_ip, sum(bytes_out) AS b, row_number() OVER (PARTITION BY src_ip "
            f"ORDER BY sum(bytes_out) DESC, dst_ip) AS rk FROM logs WHERE src_ip IS NOT NULL AND bytes_out IS NOT NULL AND {dst} = 'public' "
            f"GROUP BY 1, 2) SELECT per.actor, per.bytes, per.eventos, per.lb, top.dst_ip, top.b FROM per JOIN top ON top.src_ip = per.actor "
            f"AND top.rk = 1 WHERE per.lb > {threshold!r} AND per.bytes >= {self.min_bytes} ORDER BY per.bytes DESC, per.actor LIMIT 100")
        out = []
        for actor, total, eventos, lb, top_dst, top_bytes in res.rows:
            z = (lb - med) / scale
            out.append(Finding(
                detector=self.name, title="Volumen de salida anómalo", severity=_severity(z, self.k), entity={"src_ip": actor},
                summary=(f"{actor} envió {int(total):,} bytes a Internet en {eventos} conexiones, frente a una mediana de "
                         f"{math.expm1(med):,.0f} entre sus pares; el principal destino ({top_dst}) recibió {int(top_bytes):,}."),
                metrics={"bytes_enviados": int(total), "conexiones": eventos, "mediana_pares_bytes": round(math.expm1(med)),
                         "z_robusto": round(z, 2), "umbral_log": round(threshold, 2), "actores_comparados": n,
                         "destino_principal_bytes": int(top_bytes)},
                related={"dst_ip": [top_dst]}, mitre=("T1048",)))
        return out


@register
class Beaconing(Detector):
    name = "beaconing"
    applies_to = ("network",)
    description = "Conexiones periódicas y regulares de un origen hacia un mismo destino externo (posible baliza de comando y control)."

    def __init__(self, min_events: int = 12, min_gap_s: float = 5.0, max_gap_s: float = 7200.0, max_cv: float = 0.15):
        self.min_events, self.min_gap, self.max_gap, self.max_cv = int(min_events), float(min_gap_s), float(max_gap_s), float(max_cv)

    def run(self, engine) -> list[Finding]:
        ensure_columns(engine, ["src_ip", "dst_ip", "timestamp_utc"])
        dst = scope_sql(engine, "dst_ip")
        res = engine.query(
            f"WITH ev AS (SELECT src_ip, dst_ip, dst_port, timestamp_utc, lag(timestamp_utc) OVER (PARTITION BY src_ip, dst_ip, dst_port "
            f"ORDER BY timestamp_utc, source_row) AS prev FROM logs WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL AND {dst} = 'public'), "
            f"d AS (SELECT src_ip, dst_ip, dst_port, (epoch_ms(timestamp_utc) - epoch_ms(prev)) / 1000.0 AS gap FROM ev WHERE prev IS NOT NULL) "
            f"SELECT src_ip, dst_ip, dst_port, count(*) + 1 AS eventos, avg(gap) AS media, stddev_pop(gap) AS sd FROM d "
            f"GROUP BY 1, 2, 3 HAVING count(*) + 1 >= {self.min_events} AND avg(gap) BETWEEN {self.min_gap!r} AND {self.max_gap!r} "
            f"AND stddev_pop(gap) / avg(gap) <= {self.max_cv!r} ORDER BY stddev_pop(gap) / avg(gap), eventos DESC, src_ip, dst_ip, dst_port LIMIT 100")
        out = []
        for actor, dst_ip, port, eventos, media, sd in res.rows:
            cv = float(sd) / float(media)
            out.append(Finding(
                detector=self.name, title="Conexiones periódicas hacia un destino externo",
                severity="high" if cv <= 0.05 and eventos >= 50 else "medium", entity={"src_ip": actor},
                summary=(f"{actor} se conecta a {dst_ip}:{port} {eventos} veces cada {float(media):.0f} s de media, con una variación de "
                         f"{cv:.1%}: una regularidad que el tráfico humano no tiene."),
                metrics={"eventos": eventos, "intervalo_medio_s": round(float(media), 1), "variacion": round(cv, 4), "destino": dst_ip,
                         "puerto": port}, related={"dst_ip": [dst_ip]}, mitre=("T1071",)))
        return out


@register
class BlockedThenAllowed(Detector):
    name = "blocked_then_allowed"
    applies_to = ("network",)
    description = "Mismo origen, destino y puerto bloqueado y, poco después, permitido, de forma repetida (un reintento que se cuela)."

    def __init__(self, window_s: float = 900.0, min_pairs: int = 3):
        self.window, self.min_pairs = float(window_s), int(min_pairs)

    def run(self, engine) -> list[Finding]:
        ensure_columns(engine, ["src_ip", "dst_ip", "action"])
        res = engine.query(
            f"WITH e AS (SELECT src_ip, dst_ip, dst_port, timestamp_utc, source_row, CASE WHEN {DENY} THEN 'D' WHEN {ALLOW} THEN 'A' END AS k "
            f"FROM logs WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL), "
            f"s AS (SELECT *, lag(k) OVER w AS pk, lag(timestamp_utc) OVER w AS pt FROM e WHERE k IS NOT NULL "
            f"WINDOW w AS (PARTITION BY src_ip, dst_ip, dst_port ORDER BY timestamp_utc, source_row)) "
            f"SELECT src_ip, dst_ip, dst_port, count(*) AS pares FROM s WHERE k = 'A' AND pk = 'D' "
            f"AND (epoch_ms(timestamp_utc) - epoch_ms(pt)) / 1000.0 <= {self.window!r} GROUP BY 1, 2, 3 HAVING count(*) >= {self.min_pairs} "
            f"ORDER BY pares DESC, src_ip, dst_ip, dst_port LIMIT 100")
        out = []
        for actor, dst_ip, port, pares in res.rows:
            out.append(Finding(
                detector=self.name, title="Bloqueo seguido de permiso", severity="high" if pares >= 10 else "medium" if pares >= 5 else "low",
                entity={"src_ip": actor},
                summary=(f"{actor} → {dst_ip}:{port}: {pares} veces un bloqueo fue seguido de un permiso en menos de "
                         f"{self.window / 60:.0f} minutos."),
                metrics={"pares": pares, "destino": dst_ip, "puerto": port, "ventana_s": self.window}, related={"dst_ip": [dst_ip]}))
        return out
