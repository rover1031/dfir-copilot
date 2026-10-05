"""Simulador de logs de firewall con verdad conocida: el equivalente de `synthetic.make_idor_dataset` para logs de red.

Tráfico normal (DNS, web, NTP, servidores internos, algún descarte por la regla por defecto) más seis anomalías plantadas, cada una con su
verdad conocida en `FirewallTruth`:

| Anomalía                        | Qué se planta                                                                              | Detector que debe verla |
|---------------------------------|--------------------------------------------------------------------------------------------|-------------------------|
| Barrido de puertos              | un host interno recorre 10.50.9.0/24 por SSH, SMB y RDP varias noches                      | `service_fanout`        |
| Regla de bloqueo que permite    | la regla `RULE_BLOCK_MALICIOUS_IP` aparece con acción ALLOW para unos hosts                | `policy_contradiction`  |
| Administración hacia Internet   | dos hosts con RDP, SMB y SSH PERMITIDOS hacia un destino externo                           | `risky_outbound`        |
| Exfiltración                    | un host envía decenas de MB a un destino externo durante las últimas semanas               | `volume_outlier`        |
| Baliza                          | un host se conecta a un destino externo cada 600 s (±3 s) durante 30 días                  | `beaconing`             |
| Bloqueo seguido de permiso      | un host es bloqueado y, dos minutos después, permitido hacia el mismo destino, una y otra vez | `blocked_then_allowed`  |

Formatos de salida (`write_firewall`): `generic_es` (como el export de ejemplo del analista: `ip_origen`, `accion`...), `generic_en`,
`paloalto` (nombres de columna y valores de un export de tráfico de PAN-OS) y `ecs_json` (NDJSON anidado al estilo ECS). Los cuatro dicen lo
mismo: sirven para comprobar que el análisis NO depende del formato.
"""
from __future__ import annotations

import csv
import json
import random
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path

STYLES = ("generic_es", "generic_en", "paloalto", "ecs_json")
DEVICE = "FW-BORDER-COL-01"

# Destinos externos (rangos públicos de verdad: ninguno en 192.0.2/24, 198.51.100/24 ni 203.0.113/24, que la clasificación toma por reservados).
PUBLIC = ["8.8.4.4", "13.107.42.14", "52.96.108.2", "104.18.32.7", "151.101.1.69", "142.250.80.46", "172.217.14.206", "20.190.151.9",
          "23.45.12.10", "34.117.59.81", "35.186.224.25", "54.239.28.85", "99.84.130.12", "140.82.112.3", "185.199.108.153",
          "31.13.71.36", "157.240.22.35", "17.253.144.10", "104.244.42.1", "199.232.69.140", "205.251.242.103", "66.102.1.100"]
DNS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
BAD = ["185.220.101.5", "45.9.148.77", "91.219.236.10"]
USERS = ["j_doe", "e_rios", "m_perez", "a_gomez", "l_torres", "admin_local", "system_service"]


@dataclass(frozen=True)
class FirewallTruth:
    scanners: tuple
    contradiction_rule: str
    contradiction_hosts: tuple
    risky_hosts: tuple
    exfil_hosts: tuple
    exfil_dst: str
    beacon_hosts: tuple
    beacon_dst: str
    bypass_hosts: tuple
    bypass_dst: str
    rows: int


def _row(ts, src, sport, dst, dport, proto, action, sent, recv, rule, user, app=None):
    return {"ts": ts, "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport, "protocol": proto, "action": action,
            "bytes_sent": sent, "bytes_received": recv, "rule": rule, "user": user, "application": app, "device": DEVICE}


def make_firewall_dataset(seed: int = 11, days: int = 92, hosts: int = 40, events_per_host_day: int = 6,
                          start: date = date(2026, 7, 1)) -> tuple[list[dict], FirewallTruth]:
    """Devuelve (filas ordenadas por hora, verdad conocida). Con los valores por defecto, unas 22 000 filas en tres meses."""
    rng = random.Random(seed)
    ips = [f"10.50.1.{i}" for i in range(1, hosts + 1)]
    user_of = {ip: (rng.choice(USERS) if rng.random() > 0.15 else None) for ip in ips}  # ~15 % de eventos sin usuario
    rows: list[dict] = []

    def when(day: int, hour: int | None = None) -> datetime:
        h = hour if hour is not None else rng.choices(range(24), weights=[1] * 7 + [6] * 11 + [2] * 6)[0]
        return datetime.combine(start + timedelta(days=day), datetime.min.time()) + timedelta(hours=h, minutes=rng.randrange(60),
                                                                                              seconds=rng.randrange(60))

    def sent() -> int:
        return int(rng.lognormvariate(7.5, 1.2))

    def recv() -> int:
        return int(rng.lognormvariate(8.5, 1.3))

    # --- anómalos elegidos entre los hosts (no se confunden con los normales) -----------------------------------------------
    pick = list(ips)
    rng.shuffle(pick)
    scanner, risky, exfil, beacon, bypass = pick[0], pick[1:3], pick[3], pick[4], pick[5]
    contradiction = pick[6:9]

    # --- tráfico normal ---------------------------------------------------------------------------------------------------------
    for d in range(days):
        for ip in ips:
            for _ in range(rng.randint(max(1, events_per_host_day - 2), events_per_host_day + 2)):
                ts, user, sport, roll = when(d), user_of[ip], rng.randint(1024, 65535), rng.random()
                if roll < 0.33:
                    rows.append(_row(ts, ip, sport, rng.choice(DNS), 53, "UDP", "ALLOW", sent() // 8, recv() // 4, "RULE_DNS_OUT", user, "dns"))
                elif roll < 0.76:
                    port = 443 if rng.random() < 0.8 else 80
                    rows.append(_row(ts, ip, sport, rng.choice(PUBLIC), port, "TCP", "ALLOW", sent(), recv(), "RULE_ALLOW_WEB", user,
                                     "ssl" if port == 443 else "web-browsing"))
                elif roll < 0.81:
                    rows.append(_row(ts, ip, sport, rng.choice(PUBLIC), 123, "UDP", "ALLOW", 76, 76, "RULE_DNS_OUT", user, "ntp"))
                elif roll < 0.91:
                    rows.append(_row(ts, ip, sport, f"10.50.9.{rng.randint(10, 20)}", rng.choice([445, 443, 22]), "TCP", "ALLOW", sent(), recv(),
                                     "RULE_ALLOW_INTERNAL", user))
                elif roll < 0.95:
                    rows.append(_row(ts, ip, sport, rng.choice(PUBLIC), rng.randint(2000, 60000), rng.choice(["TCP", "UDP"]),
                                     rng.choice(["DROP", "DROP", "REJECT"]), 0, 0, "RULE_DEFAULT_DENY", user))
                elif roll < 0.97:
                    rows.append(_row(ts, ip, None, rng.choice(PUBLIC), None, "ICMP", "ALLOW", 64, 64, "RULE_ALLOW_WEB", user))
                elif ip not in contradiction:  # bloqueos normales de la regla de IPs maliciosas: siempre bloquean
                    rows.append(_row(ts, ip, sport, rng.choice(BAD), rng.choice([80, 443, 8080]), "TCP", "BLOCK", 0, 0,
                                     "RULE_BLOCK_MALICIOUS_IP", user))

    # --- anomalías con verdad conocida -------------------------------------------------------------------------------------------
    for d in rng.sample(range(days), k=min(3, days)):  # 1) barrido: tres noches, 10.50.9.0/24 por SSH, SMB y RDP
        for host in range(1, 255):
            for port in (22, 445, 3389):
                open_port = rng.random() < 0.04  # algún puerto abierto: la acción y la regla van siempre de acuerdo
                rows.append(_row(when(d, 2) + timedelta(seconds=rng.randrange(1800)), scanner, rng.randint(1024, 65535), f"10.50.9.{host}",
                                 port, "TCP", "ALLOW" if open_port else "DROP", 0, 0,
                                 "RULE_ALLOW_INTERNAL" if open_port else "RULE_DEFAULT_DENY", user_of[scanner]))
    for ip in contradiction:  # 2) la regla de bloqueo aparece con ALLOW
        for d in rng.sample(range(days), k=min(14, days)):
            for _ in range(rng.randint(3, 5)):
                rows.append(_row(when(d), ip, rng.randint(1024, 65535), "185.220.101.5", 443, "TCP", "ALLOW", sent(), recv(),
                                 "RULE_BLOCK_MALICIOUS_IP", user_of[ip]))
    for ip in risky:  # 3) administración permitida hacia Internet
        for d in rng.sample(range(days), k=min(20, days)):
            for _ in range(3):
                rows.append(_row(when(d), ip, rng.randint(1024, 65535), "45.9.148.77", rng.choice([3389, 445, 22]), "TCP", "ALLOW", sent(),
                                 recv(), "RULE_ALLOW_WEB", user_of[ip]))
    for d in range(max(0, days - 20), days):  # 4) exfiltración: las últimas tres semanas
        if rng.random() < 0.7:
            rows.append(_row(when(d, rng.randint(1, 5)), exfil, rng.randint(1024, 65535), "45.9.148.77", 443, "TCP", "ALLOW",
                             int(rng.uniform(8e6, 25e6)), 4000, "RULE_ALLOW_WEB", user_of[exfil], "ssl"))
    t0 = datetime.combine(start + timedelta(days=max(0, days - 30)), datetime.min.time())  # 5) baliza cada 600 s durante 30 días
    for i in range(min(30, days) * 144):
        rows.append(_row(t0 + timedelta(seconds=600 * i + rng.randint(-3, 3)), beacon, rng.randint(1024, 65535), "91.219.236.10", 8443,
                         "TCP", "ALLOW", rng.randint(200, 400), rng.randint(200, 400), "RULE_ALLOW_WEB", user_of[beacon], "ssl"))
    for d in rng.sample(range(days), k=min(12, days)):  # 6) bloqueo seguido de permiso a los dos minutos
        t = when(d)
        rows.append(_row(t, bypass, rng.randint(1024, 65535), "185.199.108.153", 8080, "TCP", "DROP", 0, 0, "RULE_DEFAULT_DENY", user_of[bypass]))
        rows.append(_row(t + timedelta(minutes=2), bypass, rng.randint(1024, 65535), "185.199.108.153", 8080, "TCP", "ALLOW", sent(), recv(),
                         "RULE_ALLOW_WEB", user_of[bypass]))

    rows.sort(key=lambda r: (r["ts"], r["src_ip"], str(r["dst_ip"]), r["dst_port"] or 0))
    truth = FirewallTruth(scanners=(scanner,), contradiction_rule="RULE_BLOCK_MALICIOUS_IP", contradiction_hosts=tuple(sorted(contradiction)),
                          risky_hosts=tuple(sorted(risky)), exfil_hosts=(exfil,), exfil_dst="45.9.148.77", beacon_hosts=(beacon,),
                          beacon_dst="91.219.236.10", bypass_hosts=(bypass,), bypass_dst="185.199.108.153", rows=len(rows))
    return rows, truth


# --- formatos ---------------------------------------------------------------------------------------------------------------

_PA_ACTION = {"ALLOW": "allow", "BLOCK": "deny", "DROP": "drop", "REJECT": "reset-both"}


def write_firewall(rows: list[dict], path: str | Path, style: str = "generic_es") -> Path:
    """Escribe `rows` en el formato `style` (ver STYLES). CSV con cabecera, salvo `ecs_json` (NDJSON anidado)."""
    if style not in STYLES:
        raise ValueError(f"Formato desconocido: {style!r} (válidos: {STYLES})")
    path = Path(path)
    ts = (lambda r: r["ts"].strftime("%Y/%m/%d %H:%M:%S")) if style == "paloalto" else (lambda r: r["ts"].strftime("%Y-%m-%d %H:%M:%S"))
    if style == "ecs_json":
        with path.open("w", encoding="utf-8") as fh:
            for r in rows:
                doc = {"@timestamp": r["ts"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "source": {"ip": r["src_ip"], "port": r["src_port"], "bytes": r["bytes_sent"]},
                       "destination": {"ip": r["dst_ip"], "port": r["dst_port"], "bytes": r["bytes_received"]},
                       "network": {"transport": r["protocol"].lower()}, "event": {"action": _PA_ACTION[r["action"]]},
                       "rule": {"name": r["rule"]}, "observer": {"name": r["device"]}}
                if r["user"]:
                    doc["user"] = {"name": r["user"]}
                fh.write(json.dumps(doc) + "\n")
        return path
    heads = {
        "generic_es": ("timestamp", "ip_origen", "src_port", "ip_destino", "dst_port", "protocolo", "accion", "bytes_sent", "bytes_received",
                       "rule_id", "user_origen", "device_name"),
        "generic_en": ("timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "action", "bytes_sent", "bytes_received",
                       "rule_name", "user", "device_name"),
        "paloalto": ("Receive Time", "Source address", "Source Port", "Destination address", "Destination Port", "IP Protocol", "Action",
                     "Bytes Sent", "Bytes Received", "Rule", "Source User", "Device Name", "Application"),
    }[style]
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(heads)
        for r in rows:
            common = [ts(r), r["src_ip"], r["src_port"] if r["src_port"] is not None else "", r["dst_ip"],
                      r["dst_port"] if r["dst_port"] is not None else ""]
            if style == "paloalto":
                w.writerow([*common, r["protocol"].lower(), _PA_ACTION[r["action"]], r["bytes_sent"], r["bytes_received"], r["rule"],
                            r["user"] or "", r["device"], r["application"] or ""])
            else:
                w.writerow([*common, r["protocol"], r["action"], r["bytes_sent"], r["bytes_received"], r["rule"], r["user"] or "", r["device"]])
    return path
