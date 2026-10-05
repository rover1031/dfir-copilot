"""Grupos actor-IP: identidades que operan desde pocas IPs con un volumen por IP muy superior al de sus pares."""
from __future__ import annotations

from dfir_copilot.detectors.base import (
    Detector,
    Finding,
    NotApplicable,
    ensure_columns,
    register,
)


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _components(pairs):
    """Componentes conexos del grafo bipartito actor-IP (union-find)."""
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for actor, ip in pairs:
        ra, ri = find(("actor", actor)), find(("ip", ip))
        if ra != ri:
            parent[ra] = ri
    comps: dict = {}
    for actor, ip in pairs:
        c = comps.setdefault(find(("actor", actor)), {"actors": set(), "ips": set()})
        c["actors"].add(actor)
        c["ips"].add(ip)
    return list(comps.values())


@register
class ActorIpCluster(Detector):
    name = "actor_ip_cluster"
    description = "Grupos de identidades con mucho volumen en pocas IPs; indica si el grupo es cerrado (nadie más usa esas IPs)."

    def __init__(self, actor_col: str = "user_id", k: float = 3.0, floor_pct: float = 0.05,
                 max_ips: int = 20, max_candidates: int = 40, min_actors: int = 5):
        self.actor_col, self.k, self.floor_pct = actor_col, float(k), float(floor_pct)
        self.max_ips, self.max_candidates, self.min_actors = int(max_ips), int(max_candidates), int(min_actors)

    def run(self, engine) -> list[Finding]:
        a = _q(self.actor_col)
        if self.actor_col == "src_ip":
            raise NotApplicable("el actor es la propia IP: no hay identidades que agrupar por IP")
        ensure_columns(engine, [self.actor_col, "src_ip"])
        pairs = (
            f"pairs AS (SELECT {a} AS actor, src_ip, count(*) AS n FROM logs "
            f"WHERE {a} IS NOT NULL AND src_ip IS NOT NULL GROUP BY 1, 2), "
            f"per AS (SELECT actor, count(*) AS ips, sum(n) AS peticiones, sum(n) * 1.0 / count(*) AS ratio "
            f"FROM pairs GROUP BY 1)"
        )
        st = engine.query(
            f"WITH {pairs}, st AS (SELECT median(ratio) AS med, count(*) AS n FROM per), "
            f"dev AS (SELECT median(abs(per.ratio - st.med)) AS mad FROM per CROSS JOIN st) "
            f"SELECT st.n, st.med, dev.mad FROM st CROSS JOIN dev"
        )
        n, med, mad = st.rows[0]
        if n < self.min_actors:
            raise NotApplicable(f"solo {n} actores; se necesitan al menos {self.min_actors} pares")
        scale = max(1.4826 * float(mad), self.floor_pct * float(med))
        threshold = float(med) + self.k * scale

        rows = engine.query(
            f"WITH {pairs}, "
            f"cand AS (SELECT actor FROM per WHERE ratio > {threshold!r} AND ips <= {self.max_ips} "
            f"ORDER BY ratio DESC LIMIT {self.max_candidates}), "
            f"ext AS (SELECT p.src_ip, count(DISTINCT p.actor) AS externos FROM pairs p "
            f"WHERE p.src_ip IN (SELECT src_ip FROM pairs WHERE actor IN (SELECT actor FROM cand)) "
            f"AND p.actor NOT IN (SELECT actor FROM cand) GROUP BY 1) "
            f"SELECT p.actor, p.src_ip, p.n, coalesce(e.externos, 0) AS externos "
            f"FROM pairs p JOIN cand c ON p.actor = c.actor LEFT JOIN ext e ON p.src_ip = e.src_ip "
            f"ORDER BY p.actor, p.src_ip"
        )
        if not rows.rows:
            return []
        externos = {ip: ext for _, ip, _, ext in rows.rows}
        volume = {}
        for actor, ip, cnt, _ in rows.rows:
            volume[(actor, ip)] = cnt

        findings = []
        for i, comp in enumerate(_components([(r[0], r[1]) for r in rows.rows]), start=1):
            actors, ips = sorted(comp["actors"]), sorted(comp["ips"])
            total = sum(c for (act, ip), c in volume.items() if act in comp["actors"])
            per_ip = total / len(ips)
            shared = [ip for ip in ips if externos.get(ip, 0) > 0]
            closed = not shared
            severity = "high" if closed and len(actors) >= 2 else "medium"
            kind = "operan en exclusiva" if closed else "operan (compartiendo IPs con otras identidades)"
            findings.append(
                Finding(
                    detector=self.name,
                    title="Grupo de identidades concentrado en pocas IPs",
                    severity=severity,
                    entity={"cluster": f"C{i}"},
                    summary=(
                        f"{len(actors)} identidad(es) {kind} desde {len(ips)} IP(s): "
                        f"{per_ip:.0f} peticiones por IP frente a {float(med):.0f} típico por actor."
                    ),
                    metrics={
                        "identidades": len(actors),
                        "ips": len(ips),
                        "peticiones": total,
                        "peticiones_por_ip": round(per_ip, 1),
                        "mediana_pares_por_ip": round(float(med), 1),
                        "umbral": round(threshold, 1),
                        "cerrado": closed,
                        "ips_compartidas": len(shared),
                        "actores_comparados": n,
                    },
                    related={self.actor_col: actors, "src_ip": ips},
                )
            )
        return findings
