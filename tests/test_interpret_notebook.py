"""Los notebooks 11 y 12 (P1-a): lo que se guarda en Git va sin salidas, sus celdas compilan y solo importan nombres que
existen. Se comprueba lo que GUARDARÍA Git (tras el filtro), no tu copia de trabajo: ejecutar un notebook y dejar sus salidas
en tu copia es normal; el filtro las quita al hacer `git add`."""
import ast
import importlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NOTEBOOKS = [ROOT / "notebooks" / name for name in ("11_interpretacion.ipynb", "12_zona_horaria.ipynb")]
_spec = importlib.util.spec_from_file_location("strip_notebook_outputs", ROOT / "tools" / "strip_notebook_outputs.py")
_strip = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_strip)


def code_cells(path: Path) -> list[dict]:
    """Celdas de código tal como quedarían en Git (después del filtro)."""
    nb = json.loads(_strip.clean_text(path.read_text(encoding="utf-8")))
    return [c for c in nb["cells"] if c["cell_type"] == "code"]


def as_python(cell) -> str:
    lines = ("".join(cell["source"])).splitlines()
    return "\n".join(re.sub(r"^%time\s+", "", ln) for ln in lines if not ln.startswith("%") or ln.startswith("%time"))


@pytest.mark.parametrize("path", NOTEBOOKS, ids=lambda p: p.stem)
def test_lo_que_se_guarda_en_git_va_limpio_y_sus_celdas_compilan(path):
    assert path.exists()
    cells = code_cells(path)
    assert len(cells) >= 5
    for cell in cells:
        assert cell["outputs"] == [] and cell["execution_count"] is None
        ast.parse(as_python(cell))


@pytest.mark.parametrize("path", NOTEBOOKS, ids=lambda p: p.stem)
def test_los_nombres_que_importa_existen_en_el_codigo(path):
    checked = 0
    for cell in code_cells(path):
        for node in ast.walk(ast.parse(as_python(cell))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("dfir_copilot"):
                try:
                    module = importlib.import_module(node.module)
                except ModuleNotFoundError:
                    continue  # módulo ajeno a P1-a que no existe en este entorno de pruebas
                for alias in node.names:
                    assert hasattr(module, alias.name), f"{node.module} no tiene {alias.name}"
                    checked += 1
    assert checked >= 3  # el 12 importa 3 nombres; el 11, más de 10
