"""El filtro de Git que limpia las salidas de los notebooks: qué quita, qué conserva y cómo se comporta dentro de Git."""
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "strip_notebook_outputs.py"
spec = importlib.util.spec_from_file_location("strip_notebook_outputs", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def notebook(with_outputs=True):
    return {
        "cells": [
            {"cell_type": "markdown", "id": "m1", "metadata": {}, "source": ["# Título con ñ y acentos\n"]},
            {"cell_type": "code", "id": "c1", "execution_count": 7 if with_outputs else None,
             "metadata": {"execution": {"iopub.execute_input": "2026-10-05T04:00:00"}, "collapsed": True, "tags": ["x"]},
             "outputs": [{"name": "stdout", "output_type": "stream", "text": ["usuario real: normal00\n"]}] if with_outputs else [],
             "source": ["print('hola')"]},
        ],
        "metadata": {"kernelspec": {"name": "python3"}, "language_info": {"version": "3.14.0"}},
        "nbformat": 4, "nbformat_minor": 5,
    }


def run_filter(text: str):
    return subprocess.run([sys.executable, str(SCRIPT)], input=text.encode("utf-8"), capture_output=True)


def test_quita_salidas_y_estado_de_ejecucion_y_conserva_el_resto():
    cleaned = json.loads(mod.clean_text(json.dumps(notebook(), indent=1)))
    code = cleaned["cells"][1]
    assert code["outputs"] == [] and code["execution_count"] is None
    assert code["metadata"] == {"tags": ["x"]}                       # solo se quitan los metadatos de ejecución
    assert code["source"] == ["print('hola')"] and code["id"] == "c1"
    assert cleaned["cells"][0]["source"] == ["# Título con ñ y acentos\n"]
    assert "language_info" not in cleaned["metadata"] and cleaned["metadata"]["kernelspec"] == {"name": "python3"}


def test_ningun_valor_de_las_salidas_sobrevive():
    assert "normal00" not in mod.clean_text(json.dumps(notebook()))


def test_es_idempotente_y_un_notebook_limpio_no_cambia_ni_un_byte():
    clean = json.dumps(notebook(with_outputs=False), indent=1, ensure_ascii=False)
    for text in (clean, clean + "\n"):
        once = mod.clean_text(text)
        assert once == mod.clean_text(once)
    fixed = json.dumps(mod.strip(notebook(with_outputs=False)), indent=1, ensure_ascii=False, sort_keys=True)
    assert mod.clean_text(fixed) == fixed and mod.clean_text(fixed + "\n") == fixed + "\n"


def test_serializa_como_jupyter_claves_ordenadas_y_acentos_sin_escapar():
    """Lo que Jupyter acaba de guardar (sin salidas) queda igual: así guardar un notebook no genera ruido en los diffs."""
    saved = json.dumps(mod.strip(notebook(with_outputs=False)), indent=1, ensure_ascii=False, sort_keys=True) + "\n"
    assert mod.clean_text(saved) == saved
    unsorted = json.dumps(notebook(with_outputs=False), indent=1)          # otro orden y \u00f1 escapada
    cleaned = mod.clean_text(unsorted)
    assert list(json.loads(cleaned)["cells"][1]) == sorted(json.loads(cleaned)["cells"][1])
    assert "ñ" in cleaned and "\\u00f1" not in cleaned


@pytest.mark.parametrize("bad", ["", "no es json", "[]", '{"cells": 3}', '{"a": 1}'])
def test_una_entrada_que_no_es_un_notebook_se_rechaza_sin_escribir_nada(bad):
    r = run_filter(bad)
    assert r.returncode == 1 and r.stdout == b"" and b"rechazada" in r.stderr


def test_como_programa_lee_stdin_y_escribe_stdout():
    r = run_filter(json.dumps(notebook()))
    assert r.returncode == 0 and json.loads(r.stdout)["cells"][1]["outputs"] == []


def test_los_notebooks_del_repositorio_se_limpian_y_el_filtro_es_estable():
    paths = sorted((ROOT / "notebooks").glob("*.ipynb"))
    assert paths
    for p in paths:
        once = mod.clean_text(p.read_text(encoding="utf-8"))
        assert once == mod.clean_text(once), p.name
        for cell in json.loads(once)["cells"]:
            if cell["cell_type"] == "code":
                assert cell["outputs"] == [] and cell["execution_count"] is None, p.name


# --- dentro de Git de verdad ---------------------------------------------------------------------------------------
pytestmark_git = pytest.mark.skipif(shutil.which("git") is None, reason="git no está instalado (p. ej. en el contenedor)")


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)


@pytest.fixture()
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    for k, v in (("user.name", "t"), ("user.email", "t@t"), ("commit.gpgsign", "false"),
                 ("filter.stripnb.clean", f"{sys.executable} {SCRIPT}"), ("filter.stripnb.required", "true")):
        git(tmp_path, "config", k, v)
    (tmp_path / ".gitattributes").write_text("*.ipynb filter=stripnb\n", encoding="utf-8")
    return tmp_path


@pytestmark_git
def test_git_guarda_la_version_limpia_y_la_copia_de_trabajo_conserva_las_salidas(repo):
    nb = repo / "a.ipynb"
    nb.write_text(json.dumps(notebook(), indent=1) + "\n", encoding="utf-8")
    assert git(repo, "add", "a.ipynb").returncode == 0
    stored = json.loads(git(repo, "show", ":a.ipynb").stdout)
    assert stored["cells"][1]["outputs"] == [] and "normal00" not in git(repo, "show", ":a.ipynb").stdout
    assert "normal00" in nb.read_text(encoding="utf-8")  # tu copia de trabajo no se toca


@pytestmark_git
def test_ejecutar_un_notebook_no_cambia_lo_que_git_guardaria(repo):
    """Ojo: `git status` puede mostrar ' M' aunque no haya nada nuevo. Git compara primero el TAMAÑO del archivo con el del
    índice y, si difiere (el notebook ejecutado pesa más), lo da por modificado sin consultar el filtro. Lo que cuenta es
    el contenido: `git diff` vacío, nada que añadir y nada que confirmar."""
    nb = repo / "a.ipynb"
    nb.write_text(json.dumps(notebook(with_outputs=False), indent=1) + "\n", encoding="utf-8")
    git(repo, "add", "-A")
    assert git(repo, "commit", "-qm", "base").returncode == 0
    nb.write_text(json.dumps(notebook(), indent=1) + "\n", encoding="utf-8")   # como si lo hubieras ejecutado y guardado
    assert git(repo, "diff").stdout == ""                                       # el contenido guardado no cambió
    git(repo, "add", "-A")
    assert git(repo, "diff", "--cached", "--quiet").returncode == 0             # no hay nada preparado
    assert git(repo, "status", "--porcelain").stdout == ""                      # tras `add` el índice ya coincide
    assert git(repo, "commit", "-qm", "nada").returncode != 0                   # y no hay nada que confirmar


@pytestmark_git
def test_un_cambio_real_en_el_codigo_si_aparece(repo):
    nb = repo / "a.ipynb"
    nb.write_text(json.dumps(notebook(with_outputs=False), indent=1) + "\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    changed = notebook()
    changed["cells"][1]["source"] = ["print('otra cosa')"]
    nb.write_text(json.dumps(changed, indent=1) + "\n", encoding="utf-8")
    assert git(repo, "status", "--porcelain").stdout.strip() == "M a.ipynb"
    assert "otra cosa" in git(repo, "diff").stdout and "normal00" not in git(repo, "diff").stdout


@pytestmark_git
def test_git_add_falla_si_el_archivo_no_es_un_notebook_valido(repo):
    (repo / "roto.ipynb").write_text("{ esto no es json", encoding="utf-8")
    r = git(repo, "add", "roto.ipynb")
    assert r.returncode != 0 and git(repo, "ls-files").stdout == ""  # required=true: no se guarda sin limpiar
