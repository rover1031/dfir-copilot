"""Generador de datasets sintéticos con verdad conocida (ground truth) para probar detectores y agente."""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

HEADER = "timestamp,http_staus,http_host,http_uri,http_method,http_referer,http_user_agent,source_ip\n"
_BROWSERS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/87.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1 Safari/605.1",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 Firefox/84.0",
)
_TOOLS = ("Scrapy/2.3.0 (+https://scrapy.org)", "wget", "crawler4j")
_SITES = ("MeliAR", "MeliBR", "MeliCO", "MeliMX")


@dataclass(frozen=True)
class GroundTruth:
    normal_actors: tuple
    attacker_actors: tuple
    attacker_ips: tuple
    out_of_pool_invoices: int


def _row(day: date, hhmm: str, status: int, invoice: int, site: str, actor: str, ip: str, ua: str,
         referer: str = "https://mercadolibre.com/billing") -> str:
    ts = f"2020-{day.day:02d}-{day.month:02d}T{hhmm}"  # el origen usa AAAA-DD-MM
    uri = f"/invoices/search?invoice_id={invoice}&site_id={site}&authtoken=ATUSER-ID-{actor}"
    return f'{ts},{status},mercadolibre.com,{uri},GET,{referer},"{ua}",{ip}'


def make_idor_dataset(
    seed: int = 7,
    n_normal: int = 12,
    n_attackers: int = 3,
    pool_size: int = 200,
    out_of_pool: int = 150,
    normal_requests: int = 400,
    attacker_requests: int = 300,
) -> tuple[list[str], GroundTruth]:
    """Población normal que comparte un conjunto de facturas + atacantes que enumeran facturas ajenas."""
    rng = random.Random(seed)
    pool = list(range(118822000, 118822000 + pool_size))
    outside = list(range(229933000, 229933000 + out_of_pool))
    normal = tuple(f"normal{i:02d}" for i in range(n_normal))
    attackers = tuple(f"atacante{i:02d}" for i in range(n_attackers))
    normal_ips = [f"10.1.{i // 250}.{i % 250 + 1}" for i in range(40)]
    attacker_ips = ("66.6.6.1", "66.6.6.2")

    def when(weights=None):
        if weights is None:
            offset = rng.randrange(92)
        else:  # rampa: octubre, noviembre, diciembre
            month = rng.choices([0, 1, 2], weights=weights)[0]
            span = (31, 30, 31)[month]
            offset = sum((31, 30, 31)[:month]) + rng.randrange(span)
        return date(2020, 10, 1) + timedelta(days=offset), f"{rng.randrange(24):02d}:{rng.randrange(60):02d}"

    rows = []
    for actor in normal:
        for _ in range(normal_requests):
            day, hhmm = when()
            status = rng.choices([200, 304, 400, 401], weights=[70, 10, 10, 10])[0]
            rows.append(_row(day, hhmm, status, rng.choice(pool), rng.choice(_SITES), actor,
                             rng.choice(normal_ips), rng.choice(_BROWSERS)))
    for actor in attackers:
        targets = sorted(rng.sample(outside, int(0.7 * len(outside))))  # recorre ids ajenos en orden
        for inv in targets:
            day, hhmm = when((5, 25, 70))
            rows.append(_row(day, hhmm, 200, inv, rng.choice(_SITES), actor,
                             rng.choice(attacker_ips), rng.choice(_TOOLS), "google.com"))
        for _ in range(max(0, attacker_requests - len(targets))):
            day, hhmm = when((5, 25, 70))
            status = rng.choices([200, 401], weights=[68, 32])[0]
            rows.append(_row(day, hhmm, status, rng.choice(pool), rng.choice(_SITES), actor,
                             rng.choice(attacker_ips), rng.choice(_TOOLS)))
    rng.shuffle(rows)  # el log real no viene ordenado
    return rows, GroundTruth(normal, attackers, attacker_ips if n_attackers else (), out_of_pool)


def write_csv(path: str | Path, rows: list[str]) -> Path:
    path = Path(path)
    path.write_text(HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return path
