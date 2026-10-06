#!/usr/bin/env python3
"""Genera CHANGELOG.md a partir del historial de git, agrupado por día (lo más reciente arriba). Uso, desde la raíz del repositorio y donde
haya git (en WSL, no dentro del contenedor): python3 tools/changelog.py"""
from __future__ import annotations

import subprocess
import sys
from collections import OrderedDict
from pathlib import Path


def main() -> int:
    try:
        log = subprocess.run(["git", "log", "--date=short", "--pretty=format:%ad%x09%h%x09%s"], capture_output=True, text=True,
                             check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"No se pudo leer el historial de git: {exc}", file=sys.stderr)
        return 1
    days: OrderedDict[str, list[str]] = OrderedDict()
    for line in log.splitlines():
        if line.count("\t") < 2:
            continue
        day, short, subject = line.split("\t", 2)
        days.setdefault(day, []).append(f"- {subject} (`{short}`)")
    out = ["# Cambios", "", "Generado desde el historial de git con `python3 tools/changelog.py`. Lo más reciente, arriba.", ""]
    for day, items in days.items():
        out += [f"## {day}", "", *items, ""]
    Path("CHANGELOG.md").write_text("\n".join(out), encoding="utf-8")
    print(f"CHANGELOG.md: {sum(len(v) for v in days.values())} cambios en {len(days)} día(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
