"""Amplitud de recursos: actores que consultan muchos más recursos distintos que sus pares."""
from __future__ import annotations

from dfir_copilot.detectors.base import Detector, Finding, NotApplicable, ensure_columns, register


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


@register
class ResourceBreadth(Detector):
    applies_to = ("web", "network")
    name = "resource_breadth"
    description = (
        "Actores que acceden a muchos más recursos distintos que sus pares "
        "(patrón de enumeración / IDOR)."
    )

    def __init__(
        self,
        actor_col: str = "user_id",
        resource_col: str = "x_invoice_id",
        k: float = 3.0,
        floor_pct: float = 0.05,
        min_actors: int = 5,
    ):
        self.actor_col, self.resource_col = actor_col, resource_col
        self.k, self.floor_pct, self.min_actors = float(k), float(floor_pct), int(min_actors)

    def run(self, engine) -> list[Finding]:
        a, r = _q(self.actor_col), _q(self.resource_col)
        ensure_columns(engine, [self.actor_col, self.resource_col])
        per = (
            f"SELECT {a} AS actor, count(DISTINCT {r}) AS recursos FROM logs "
            f"WHERE {a} IS NOT NULL AND {r} IS NOT NULL GROUP BY 1"
        )
        stats = engine.query(
            f"WITH per AS ({per}), st AS (SELECT median(recursos) AS med, count(*) AS n FROM per), "
            f"dev AS (SELECT median(abs(per.recursos - st.med)) AS mad FROM per CROSS JOIN st) "
            f"SELECT st.n, st.med, dev.mad FROM st CROSS JOIN dev"
        )
        n, med, mad = stats.rows[0]
        if n < self.min_actors:
            raise NotApplicable(f"solo {n} actores; se necesitan al menos {self.min_actors} pares")
        # Escala robusta con piso: si casi todos los pares son idénticos (MAD ~ 0) evita dividir por cero.
        scale = max(1.4826 * float(mad), self.floor_pct * float(med))
        threshold = float(med) + self.k * scale

        flagged = engine.query(
            f"SELECT {a} AS actor, count(DISTINCT {r}) AS recursos, count(*) AS peticiones, "
            f"count(DISTINCT src_ip) AS ips, count(DISTINCT user_agent) AS user_agents, "
            f"round(100.0 * count(*) FILTER (WHERE status_code >= 400) / count(*), 1) AS pct_error "
            f"FROM logs WHERE {a} IS NOT NULL AND {r} IS NOT NULL "
            f"GROUP BY 1 HAVING count(DISTINCT {r}) > {threshold!r} "
            f"ORDER BY recursos DESC, actor LIMIT 100"
        )
        findings = []
        for actor, recursos, peticiones, ips, uas, pct_error in flagged.rows:
            z = (recursos - float(med)) / scale
            severity = "high" if z > 4 * self.k else "medium" if z > 2 * self.k else "low"
            findings.append(
                Finding(
                    detector=self.name,
                    title=f"Amplitud anómala de {self.resource_col}",
                    severity=severity,
                    entity={self.actor_col: actor},
                    summary=(
                        f"{actor} accedió a {recursos} {self.resource_col} distintos, "
                        f"{recursos / float(med):.2f}x la mediana de sus pares ({float(med):g})."
                    ),
                    metrics={
                        "recursos_distintos": recursos,
                        "mediana_pares": float(med),
                        "mad": float(mad),
                        "z_robusto": round(z, 2),
                        "umbral": round(threshold, 1),
                        "peticiones": peticiones,
                        "ips": ips,
                        "user_agents": uas,
                        "pct_error": float(pct_error),
                        "actores_comparados": n,
                    },
                )
            )
        return findings
