"""Geolocalización por país, LOCAL y opcional. El framework no trae base de datos (tamaño y licencia): la descargas tú y la dejas en
`<raíz de datos>/geoip/` (o indicas la ruta con DFIR_GEOIP_DB). Se admiten:

* **CSV de rangos** (el formato de DB-IP «IP to Country Lite», gratuita, CC BY 4.0): `ip_inicio,ip_fin,país` por línea, también `.csv.gz`.
* **MaxMind DB** (`.mmdb`, p. ej. DB-IP Lite o GeoLite2), si está instalada la librería `maxminddb`.

Solo IPv4 en el CSV. Las IPs privadas o reservadas no se buscan (no tienen país). Nada sale de la máquina: es una búsqueda en un archivo.
La precisión es la de la base: un país por IP es una aproximación (VPNs, nubes, proxies) y así se dice en las respuestas.
"""
from __future__ import annotations

import bisect
import functools
import gzip
import ipaddress
import os
from pathlib import Path

ATTRIBUTION = "Geolocalización: base local (p. ej. DB-IP Lite, CC BY 4.0, https://db-ip.com); un país por IP es una aproximación."


class GeoDB:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._starts: list[int] = []
        self._rows: list[tuple[int, str]] = []
        self._mmdb = None
        name = self.path.name.lower()
        if name.endswith(".mmdb"):
            import maxminddb  # opcional: pip install maxminddb

            self._mmdb = maxminddb.open_database(str(self.path))
        else:
            opener = gzip.open if name.endswith(".gz") else open
            ranges = []
            with opener(self.path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    parts = [p.strip().strip('"') for p in line.split(",")]
                    if len(parts) < 3 or ":" in parts[0]:
                        continue  # cabecera, línea rota o IPv6
                    try:
                        a, b = int(ipaddress.IPv4Address(parts[0])), int(ipaddress.IPv4Address(parts[1]))
                    except ValueError:
                        continue
                    ranges.append((a, b, parts[2].upper()))
            ranges.sort()
            self._starts = [a for a, _, _ in ranges]
            self._rows = [(b, c) for _, b, c in ranges]

    def country(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not addr.is_global:
            return "red privada"
        if self._mmdb is not None:
            rec = self._mmdb.get(ip) or {}
            c = rec.get("country") or {}
            return c.get("iso_code") or None
        if addr.version != 4:
            return None
        n = int(addr)
        i = bisect.bisect_right(self._starts, n) - 1
        if i >= 0 and n <= self._rows[i][0]:
            return self._rows[i][1]
        return None


def geo_path() -> Path | None:
    env = os.environ.get("DFIR_GEOIP_DB")
    if env:
        return Path(env) if Path(env).exists() else None
    from dfir_copilot.projects import data_root

    folder = data_root() / "geoip"
    found = sorted([*folder.glob("*.mmdb"), *folder.glob("*.csv"), *folder.glob("*.csv.gz")]) if folder.is_dir() else []
    return found[0] if found else None


@functools.lru_cache(maxsize=4)
def _load(path: str, mtime: float) -> GeoDB:
    return GeoDB(path)


def geo_db() -> GeoDB | None:
    """La base configurada (cacheada mientras el archivo no cambie) o None si no hay ninguna."""
    path = geo_path()
    return _load(str(path), path.stat().st_mtime) if path else None


__all__ = ["ATTRIBUTION", "GeoDB", "geo_db", "geo_path"]
