#!/usr/bin/env python3
"""Filtro "clean" de Git para notebooks: quita las salidas y el estado de ejecución. Solo biblioteca estándar.

Un notebook ejecutado guarda dentro del .ipynb todo lo que se imprimió (nombres de usuario, IPs, conteos…). Este filtro
se aplica en `git add`: el repositorio guarda la versión limpia y tu copia de trabajo conserva sus salidas.

Instalación (una vez por clon; `git config` no se versiona), desde la raíz del repositorio:
    git config filter.stripnb.clean "python3 tools/strip_notebook_outputs.py"
    git config filter.stripnb.smudge cat
    git config filter.stripnb.required true
y `.gitattributes` ya trae la línea `*.ipynb filter=stripnb`.

`smudge cat` es obligatorio con `required true`: al SACAR un notebook del repositorio (`git checkout`, `git archive`) Git
exige también ese lado del filtro, y sin él falla con "smudge filter stripnb failed". `cat` lo deja pasar tal cual.

Lee el notebook por la entrada estándar y escribe la versión limpia por la salida estándar. Si lo que recibe no es un
notebook válido, falla sin escribir nada: así `git add` se detiene en vez de guardar contenido sin limpiar.
"""
from __future__ import annotations

import json
import sys

# Metadatos de celda que Jupyter añade al ejecutar o al colapsar salidas (tiempos, estado de la interfaz).
CELL_METADATA_DROP = ("execution", "collapsed", "scrolled", "ExecuteTime")
# Jupyter lo reescribe en cada guardado con la versión de Python local: solo genera ruido en los diffs.
NOTEBOOK_METADATA_DROP = ("language_info",)


def strip(notebook: dict) -> dict:
    """Devuelve el mismo notebook sin salidas ni estado de ejecución (modifica el diccionario recibido)."""
    for cell in notebook.get("cells", []):
        if cell.get("cell_type") == "code":
            cell["outputs"] = []
            cell["execution_count"] = None
        metadata = cell.get("metadata")
        if isinstance(metadata, dict):
            for key in CELL_METADATA_DROP:
                metadata.pop(key, None)
    metadata = notebook.get("metadata")
    if isinstance(metadata, dict):
        for key in NOTEBOOK_METADATA_DROP:
            metadata.pop(key, None)
    return notebook


def clean_text(raw: str) -> str:
    """Texto de un .ipynb -> texto limpio, serializado igual que nbformat (claves ordenadas, sangría de 1, sin escapar
    acentos): un notebook que Jupyter acaba de guardar y no tiene salidas queda byte a byte igual. Si el archivo no
    terminaba en salto de línea tampoco se le añade."""
    notebook = json.loads(raw)
    if not isinstance(notebook, dict) or not isinstance(notebook.get("cells"), list):
        raise ValueError("no es un notebook de Jupyter (falta la lista 'cells')")
    out = json.dumps(strip(notebook), indent=1, ensure_ascii=False, sort_keys=True)
    return out + "\n" if raw.endswith("\n") else out


def main() -> int:
    raw = sys.stdin.buffer.read().decode("utf-8")
    try:
        cleaned = clean_text(raw)
    except ValueError as exc:  # JSONDecodeError también es ValueError
        sys.stderr.write(f"strip_notebook_outputs: entrada rechazada: {exc}\n")
        return 1
    sys.stdout.buffer.write(cleaned.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
