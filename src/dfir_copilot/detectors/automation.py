"""Clientes automatizados: actores cuyo tráfico proviene de herramientas de scraping o scripting."""
from __future__ import annotations

from dfir_copilot.detectors.base import Detector, Finding, ensure_columns, register

# Conocimiento de dominio verificable: firmas de User-Agent por familia (RE2, sin distinguir mayúsculas).
# Los crawlers que se declaran "bot" (Googlebot, etc.) quedan fuera a propósito: son legítimos.
SIGNATURES = {
    "offensive_tool": r"sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|ffuf|wfuzz|nuclei|burp",
    "scripted_client": (
        r"scrapy|crawler4j|python-requests|python-urllib|aiohttp|httpx|go-http-client|okhttp|"
        r"apache-httpclient|libwww|node-fetch|axios|curl|wget|powershell|java/"
    ),
    "api_client": r"postman|insomnia|httpie",
}


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _family_case() -> str:
    whens = " ".join(
        f"WHEN regexp_matches(user_agent, {_lit('(?i)' + rx)}) THEN {_lit(name)}"
        for name, rx in SIGNATURES.items()
    )
    return f"CASE {whens} END"


@register
class AutomationClients(Detector):
    name = "automation_clients"
    description = "Actores cuyo tráfico proviene mayoritariamente de herramientas automatizadas (por User-Agent)."

    def __init__(self, actor_col: str = "user_id", min_pct: float = 20.0, baseline_ratio: float = 0.5):
        self.actor_col, self.min_pct, self.baseline_ratio = actor_col, float(min_pct), float(baseline_ratio)

    def run(self, engine) -> list[Finding]:
        a = _q(self.actor_col)
        ensure_columns(engine, [self.actor_col, "user_agent"])
        res = engine.query(
            f"WITH ua AS (SELECT DISTINCT user_agent FROM logs WHERE user_agent IS NOT NULL), "
            f"cls AS (SELECT user_agent, {_family_case()} AS familia FROM ua) "
            f"SELECT l.{a} AS actor, count(*) AS peticiones, "
            f"count(*) FILTER (WHERE c.familia IS NOT NULL) AS automatizadas, "
            f"round(100.0 * count(*) FILTER (WHERE c.familia IS NOT NULL) / count(*), 1) AS pct_automatizado, "
            f"count(*) FILTER (WHERE c.familia = 'offensive_tool') AS ofensivas, "
            f"list_sort(list(DISTINCT l.user_agent) FILTER (WHERE c.familia IS NOT NULL)) AS herramientas, "
            f"count(DISTINCT l.src_ip) AS ips "
            f"FROM logs l LEFT JOIN cls c USING (user_agent) WHERE l.{a} IS NOT NULL "
            f"GROUP BY 1 HAVING 100.0 * count(*) FILTER (WHERE c.familia IS NOT NULL) / count(*) >= {self.min_pct!r} "
            f"ORDER BY pct_automatizado DESC, automatizadas DESC, actor LIMIT 100"
        )
        total = engine.query(f"SELECT count(DISTINCT {a}) FROM logs WHERE {a} IS NOT NULL").rows[0][0]
        if not res.rows:
            return []
        # Si la automatización es la norma (p. ej. una API consumida por scripts) deja de ser señal.
        is_baseline = len(res.rows) / total > self.baseline_ratio
        findings = []
        for actor, peticiones, auto, pct, ofensivas, herramientas, ips in res.rows:
            if is_baseline:
                severity = "info"
            elif ofensivas:
                severity = "high"
            else:
                severity = "medium" if pct >= 50 else "low"
            findings.append(
                Finding(
                    detector=self.name,
                    title="Tráfico de herramientas automatizadas",
                    severity=severity,
                    entity={self.actor_col: actor},
                    summary=(
                        f"{actor}: el {pct:g}% de sus peticiones ({auto} de {peticiones}) viene de "
                        f"clientes automatizados: {', '.join(herramientas[:5])}."
                    ),
                    metrics={
                        "pct_automatizado": float(pct),
                        "peticiones": peticiones,
                        "automatizadas": auto,
                        "ofensivas": ofensivas,
                        "herramientas": list(herramientas[:10]),
                        "ips": ips,
                        "automatizacion_es_la_norma": is_baseline,
                    },
                )
            )
        return findings
