#!/usr/bin/env python3
"""Aplica la entrega de documentación sobre archivos EXISTENTES (los nuevos ya vienen en el zip): usuario del contenedor configurable y
nota de contexto en el informe de ejemplo. Uso, desde la raíz del repositorio: python3 tools/aplicar_docs.py [--check]
Cada cambio exige que el texto esperado aparezca EXACTAMENTE una vez; si alguno falla no se escribe NADA. Idempotente."""
from __future__ import annotations

import sys
from pathlib import Path

EXAMPLE = Path("docs/ejemplos/informe_idor_compartible.md")
NOTE = """> **Ejemplo real generado por DFIR Co-pilot** — variante *compartible* del informe del caso de estudio
> (explotación de un IDOR en `/invoices/search`, dataset externo de tráfico de prueba sin relación con ninguna organización).
> Los valores sensibles van como alias y el diccionario de alias no se incluye; el código comprobó que no lleva ningún valor real.
> La zona horaria (`America/Santiago`) la decidió el analista sin confirmación externa, y así consta en el propio informe.

"""

CHANGES = [
    (Path("docker/Dockerfile"), "usuario del contenedor configurable (DFIR_UID)",
     "RUN useradd -m -u 1000 analyst && chown -R analyst /workspace\n",
     "ARG UID=1000\nRUN useradd -m -u ${UID} analyst && chown -R analyst /workspace\n", "ARG UID="),
    (Path("docker-compose.yml"), "DFIR_UID como argumento de construcción",
     "    build:\n      context: .\n      dockerfile: docker/Dockerfile\n",
     "    build:\n      context: .\n      dockerfile: docker/Dockerfile\n      args:\n        UID: ${DFIR_UID:-1000}\n", "DFIR_UID"),
    (EXAMPLE, "nota de contexto del informe de ejemplo", "", NOTE, "Ejemplo real generado por DFIR Co-pilot"),   # "" = al principio
]


def plan(root: Path):
    texts, changed, report, errors = {}, set(), [], []
    for rel, what, old, new, marker in CHANGES:
        path = root / rel
        if not path.is_file():
            errors.append(f"{rel}: no existe (¿estás en la raíz del repositorio?)")
            continue
        text = texts.setdefault(path, path.read_text(encoding="utf-8"))
        if marker in text:
            report.append(f"= {rel}: «{what}» ya estaba aplicado")
            continue
        if old == "":
            texts[path] = new + text
        else:
            n = text.count(old)
            if n != 1:
                errors.append(f"{rel}: «{what}»: el texto esperado aparece {n} vez/veces (debe ser 1)")
                continue
            texts[path] = text.replace(old, new, 1)
        changed.add(path)
        report.append(f"+ {rel}: {what}")
    return {p: texts[p] for p in changed}, report, errors


def main(argv) -> int:
    texts, report, errors = plan(Path.cwd())
    print("\n".join(report))
    if errors:
        print("\nNO SE APLICÓ NADA:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 2
    if "--check" in argv:
        print("\nComprobación correcta: se puede aplicar.")
        return 0
    for path, text in texts.items():
        path.write_text(text, encoding="utf-8")
    print("\nAplicado. Revisa con `git diff`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
