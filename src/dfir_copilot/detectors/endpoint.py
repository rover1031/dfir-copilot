"""Detectores para logs de endpoint (EDR). Corren solo sobre logs con `log_schema: endpoint`.

Como los de red, dan lo mismo sobre los datos reales y sobre la copia seudonimizada: el nombre del ejecutable y las señales de la línea
de comandos salen de las columnas derivadas de la copia (`<col>_base`, `<col>_flags`) o, en los datos reales, de las MISMAS expresiones
(`endpoint_sql`). Todo `ORDER BY ... LIMIT` lleva desempates.
"""
from __future__ import annotations

from dfir_copilot.detectors.base import Detector, Finding, NotApplicable, ensure_columns, register
from dfir_copilot.detectors.network import scope_sql
from dfir_copilot.endpoint_sql import basename_sql, cmd_flags_sql

# Binarios del sistema que un atacante usa para ejecutar o descargar sin traer herramientas propias (living off the land).
LOLBINS = ("powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "wscript.exe",
           "cscript.exe", "msiexec.exe", "installutil.exe", "cmd.exe")
OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "acrord32.exe", "acrobat.exe")
SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _in(values) -> str:
    return ", ".join("'" + v + "'" for v in values)


def _columns(engine) -> set[str]:
    return {r[0] for r in engine.query("DESCRIBE logs").rows}


def base_of(engine, col: str) -> str:
    """Nombre del ejecutable: `<col>_base` en la copia, o la misma expresión sobre el dato real."""
    return _q(f"{col}_base") if f"{col}_base" in _columns(engine) else basename_sql(_q(col))


def flags_of(engine, col: str = "command_line") -> str:
    return _q(f"{col}_flags") if f"{col}_flags" in _columns(engine) else cmd_flags_sql(_q(col))


@register
class LolbinNetwork(Detector):
    name = "lolbin_network"
    applies_to = ("endpoint",)
    description = "Binarios del sistema usados por atacantes (rundll32, powershell, mshta...) conectando a Internet."

    def __init__(self, min_events: int = 1):
        self.min_events = int(min_events)

    def run(self, engine) -> list[Finding]:
        ensure_columns(engine, ["host", "process_name", "dst_ip"])
        proc, dst = base_of(engine, "process_name"), scope_sql(engine, "dst_ip")
        res = engine.query(
            f"SELECT host, {proc} AS proceso, count(*) AS conexiones, count(DISTINCT dst_ip) AS destinos, "
            f"list_sort(list(DISTINCT dst_ip)) AS ips FROM logs WHERE {proc} IN ({_in(LOLBINS)}) AND {dst} = 'public' "
            f"GROUP BY 1, 2 HAVING count(*) >= {self.min_events} ORDER BY conexiones DESC, host, proceso LIMIT 100")
        return [Finding(
            detector=self.name, title="Binario del sistema conectando a Internet", severity="high" if n >= 10 else "medium",
            entity={"host": host}, summary=f"En {host}, {proceso} abrió {n} conexión(es) hacia {d} destino(s) de Internet.",
            metrics={"proceso": proceso, "conexiones": n, "destinos": d}, related={"dst_ip": list(ips)[:10]}, mitre=("T1218", "T1071"))
            for host, proceso, n, d, ips in res.rows]


@register
class SuspiciousParent(Detector):
    name = "suspicious_parent"
    applies_to = ("endpoint",)
    description = "Aplicaciones de ofimática o lectores de PDF que lanzan intérpretes de comandos o scripts (adjunto malicioso)."

    def run(self, engine) -> list[Finding]:
        ensure_columns(engine, ["host", "process_name", "parent_process"])
        proc, parent = base_of(engine, "process_name"), base_of(engine, "parent_process")
        res = engine.query(
            f"SELECT host, {parent} AS padre, {proc} AS hijo, count(*) AS veces FROM logs WHERE {parent} IN ({_in(OFFICE)}) "
            f"AND {proc} IN ({_in(SHELLS)}) GROUP BY 1, 2, 3 ORDER BY veces DESC, host, padre, hijo LIMIT 100")
        return [Finding(
            detector=self.name, title="Ofimática lanzando un intérprete", severity="high", entity={"host": host},
            summary=f"En {host}, {padre} lanzó {hijo} ({n} vez/veces): patrón típico de un adjunto o macro maliciosa.",
            metrics={"padre": padre, "hijo": hijo, "veces": n}, mitre=("T1204.002", "T1059")) for host, padre, hijo, n in res.rows]


@register
class SuspiciousCommandLine(Detector):
    name = "suspicious_cmdline"
    applies_to = ("endpoint",)
    description = "Líneas de comandos con señales de ataque: codificadas, descargas, ventana oculta, sin restricciones o proxy de scripts."

    def run(self, engine) -> list[Finding]:
        ensure_columns(engine, ["host", "process_name", "command_line"])
        proc, flags = base_of(engine, "process_name"), flags_of(engine)
        res = engine.query(
            f"SELECT host, {proc} AS proceso, {flags} AS senales, count(*) AS veces FROM logs WHERE {flags} IS NOT NULL "
            f"GROUP BY 1, 2, 3 ORDER BY veces DESC, host, proceso, senales LIMIT 100")
        out = []
        for host, proceso, senales, n in res.rows:
            grave = {"encoded", "download", "script_proxy"} & set(senales.split(","))
            out.append(Finding(
                detector=self.name, title="Línea de comandos sospechosa", severity="high" if grave else "medium", entity={"host": host},
                summary=f"En {host}, {proceso} se ejecutó {n} vez/veces con señales: {senales}.",
                metrics={"proceso": proceso, "senales": senales, "veces": n}, mitre=("T1059.001", "T1027")))
        return out


__all__ = ["LOLBINS", "LolbinNetwork", "NotApplicable", "SuspiciousCommandLine", "SuspiciousParent", "base_of", "flags_of"]
