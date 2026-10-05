"""El notebook 11 (P1-a): compila, no trae salidas y solo importa nombres que existen."""
import ast
import importlib
import json
import re
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent.parent / "notebooks" / "11_interpretacion.ipynb"


def code_cells():
    nb = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    return [c for c in nb["cells"] if c["cell_type"] == "code"]


def as_python(cell) -> str:
    lines = ("".join(cell["source"])).splitlines()
    return "\n".join(re.sub(r"^%time\s+", "", ln) for ln in lines if not ln.startswith("%") or ln.startswith("%time"))


def test_el_notebook_esta_limpio_y_sus_celdas_compilan():
    assert NOTEBOOK.exists()
    cells = code_cells()
    assert len(cells) >= 5
    for cell in cells:
        assert cell["outputs"] == [] and cell["execution_count"] is None
        ast.parse(as_python(cell))


def test_los_nombres_que_importa_existen_en_el_codigo():
    checked = 0
    for cell in code_cells():
        for node in ast.walk(ast.parse(as_python(cell))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("dfir_copilot"):
                try:
                    module = importlib.import_module(node.module)
                except ModuleNotFoundError:
                    continue  # módulo ajeno a P1-a que no existe en este entorno de pruebas
                for alias in node.names:
                    assert hasattr(module, alias.name), f"{node.module} no tiene {alias.name}"
                    checked += 1
    assert checked >= 10
