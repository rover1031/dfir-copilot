"""Rampa temporal: actores cuya actividad crece de forma anómala entre el inicio y el final del periodo."""
from __future__ import annotations

import math

from dfir_copilot.detectors.base import Detector, Finding, NotApplicable, ensure_columns, register


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


@register
class ActivityRamp(Detector):
    applies_to = ("web", "network")
    name = "activity_ramp"
    description = "Actores cuya actividad en el último tercio del periodo supera con creces la del primer tercio."

    def __init__(self, actor_col: str = "user_id", k: float = 3.0, floor_abs: float = 0.2,
                 min_total: int = 100, min_ratio: float = 3.0, min_final: int = 50, min_actors: int = 5):
        self.actor_col, self.k, self.floor_abs = actor_col, float(k), float(floor_abs)
        self.min_total, self.min_ratio, self.min_final = int(min_total), float(min_ratio), int(min_final)
        self.min_actors = int(min_actors)

    def run(self, engine) -> list[Finding]:
        a = _q(self.actor_col)
        ensure_columns(engine, [self.actor_col, "timestamp_utc"])
        days = engine.query("SELECT date_diff('day', min(timestamp_utc), max(timestamp_utc)) FROM logs").rows[0][0]
        if days < 3:
            raise NotApplicable(f"el periodo cubre {days} día(s); se necesitan al menos 3 para comparar tercios")
        base = (
            f"bounds AS (SELECT min(timestamp_utc) AS t0, max(timestamp_utc) AS t1 FROM logs), "
            f"per AS (SELECT {a} AS actor, count(*) AS total, "
            f"count(*) FILTER (WHERE timestamp_utc < b.t0 + (b.t1 - b.t0) / 3) AS tercio_inicial, "
            f"count(*) FILTER (WHERE timestamp_utc >= b.t1 - (b.t1 - b.t0) / 3) AS tercio_final "
            f"FROM logs CROSS JOIN bounds b WHERE {a} IS NOT NULL GROUP BY 1 "
            f"HAVING count(*) >= {self.min_total}), "
            f"lr AS (SELECT actor, total, tercio_inicial, tercio_final, "
            f"(tercio_final + 1.0) / (tercio_inicial + 1.0) AS ratio, "
            f"ln((tercio_final + 1.0) / (tercio_inicial + 1.0)) AS lr FROM per)"
        )
        st = engine.query(
            f"WITH {base}, st AS (SELECT median(lr) AS med, count(*) AS n FROM lr), "
            f"dev AS (SELECT median(abs(lr.lr - st.med)) AS mad FROM lr CROSS JOIN st) "
            f"SELECT st.n, st.med, dev.mad FROM st CROSS JOIN dev"
        )
        n, med, mad = st.rows[0]
        if n < self.min_actors:
            raise NotApplicable(f"solo {n} actores con volumen suficiente; se necesitan {self.min_actors}")
        scale = max(1.4826 * float(mad), self.floor_abs)
        threshold = float(med) + self.k * scale

        res = engine.query(
            f"WITH {base} SELECT actor, total, tercio_inicial, tercio_final, ratio, lr FROM lr "
            f"WHERE lr > {threshold!r} AND ratio >= {self.min_ratio!r} AND tercio_final >= {self.min_final} "
            f"ORDER BY ratio DESC, actor LIMIT 100"
        )
        peers = math.exp(float(med))
        findings = []
        for actor, total, ini, fin, ratio, lr in res.rows:
            z = (lr - float(med)) / scale
            severity = "high" if z > 4 * self.k else "medium" if z > 2 * self.k else "low"
            findings.append(
                Finding(
                    detector=self.name,
                    title="Rampa de actividad",
                    severity=severity,
                    entity={self.actor_col: actor},
                    summary=(
                        f"{actor} pasó de {ini} peticiones en el primer tercio del periodo a {fin} en el "
                        f"último ({ratio:.1f}x); sus pares cambian {peers:.2f}x."
                    ),
                    metrics={
                        "tercio_inicial": ini,
                        "tercio_final": fin,
                        "ratio": round(ratio, 2),
                        "ratio_mediano_pares": round(peers, 2),
                        "z_robusto": round(z, 2),
                        "peticiones": total,
                        "actores_comparados": n,
                    },
                )
            )
        return findings
