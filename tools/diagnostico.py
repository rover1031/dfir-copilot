#!/usr/bin/env python3
"""Diagnóstico de SOLO LECTURA del proyecto DFIR Co-pilot. No modifica nada salvo escribir su propio informe en reports/.

Uso (desde la raíz del repositorio, dentro del contenedor):
    python tools/diagnostico.py            # rápido (~1 min): entorno, dependencias, secretos, datos, código, Django, lint, docs
    python tools/diagnostico.py --tests    # además corre la suite completa con los tests más lentos (~8-10 min)

Nunca imprime el valor de un secreto: solo el archivo, la línea y el tipo de patrón."""
from __future__ import annotations

import argparse
import ast
import importlib
import importlib.metadata as md
import os
import platform
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path.cwd()
PKG = ROOT / "src" / "dfir_copilot"
SKIP_DIRS = {".git", "data", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", ".ruff_cache", ".ipynb_checkpoints",
             ".mypy_cache", "dist", "build"}
KEY_PACKAGES = ("django", "duckdb", "pandas", "pyarrow", "pydantic", "langchain-core", "langgraph", "langchain-anthropic", "langchain-openai",
                "anthropic", "openai", "pymupdf", "openpyxl", "xlrd", "maxminddb", "pyyaml", "pytest", "ruff", "jupyterlab")
SECRET_PATTERNS = {
    "clave Anthropic": re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    "clave OpenAI": re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}"),
    "clave AWS": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "asignación de secreto": re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"),
}

findings: list[tuple[str, str, str]] = []      # (nivel, área, texto)
out: list[str] = []


def flag(level: str, area: str, text: str) -> None:
    findings.append((level, area, text))


def h(title: str) -> None:
    out.append(f"\n## {title}\n")


def walk_files(base: Path, suffixes: tuple[str, ...] | None = None):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if suffixes is None or p.suffix in suffixes:
                yield p


def dir_size(path: Path) -> tuple[int, int]:
    total = count = 0
    for dirpath, _d, filenames in os.walk(path):
        for name in filenames:
            try:
                total += (Path(dirpath) / name).stat().st_size
                count += 1
            except OSError:
                pass
    return total, count


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def run(cmd: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, f"{type(exc).__name__}: {exc}"


# --- 1. entorno -------------------------------------------------------------------------------------------------------------
def entorno() -> None:
    h("1. Entorno")
    out.append(f"- Python {platform.python_version()} · {platform.system()} {platform.release()} · {platform.machine()}")
    out.append("\n| Paquete | Versión |\n|---|---|")
    for name in KEY_PACKAGES:
        try:
            out.append(f"| {name} | {md.version(name)} |")
        except md.PackageNotFoundError:
            out.append(f"| {name} | no instalado |")
    tess = shutil.which("tesseract")
    if tess:
        _rc, v = run([tess, "--version"])
        _rc, langs = run([tess, "--list-langs"])
        lang_list = [x.strip() for x in langs.splitlines()[1:] if x.strip()]
        out.append(f"\n- tesseract: {v.splitlines()[0] if v else '?'} · idiomas: {', '.join(lang_list)}")
        for need in ("eng", "spa"):
            if need not in lang_list:
                flag("AVISO", "entorno", f"tesseract sin el idioma {need}")
    else:
        flag("AVISO", "entorno", "tesseract no está instalado: los PDF escaneados no se podrán leer")
    out.append(f"- git en este entorno: {'sí' if shutil.which('git') else 'no (normal dentro del contenedor; revisa git desde WSL)'}")


# --- 2. dependencias declaradas frente a importadas --------------------------------------------------------------------------
def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def dependencias() -> None:
    h("2. Dependencias (pyproject.toml frente a lo que importa el código)")
    path = ROOT / "pyproject.toml"
    if not path.is_file():
        flag("FALLO", "dependencias", "no hay pyproject.toml en la raíz")
        out.append("Sin pyproject.toml.")
        return
    import tomllib

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    proj = data.get("project", {})
    declared: dict[str, str] = {}
    for req in proj.get("dependencies", []):
        declared[_norm(re.split(r"[<>=!~\[; ]", req, 1)[0])] = "base"
    for extra, reqs in proj.get("optional-dependencies", {}).items():
        for req in reqs:
            declared.setdefault(_norm(re.split(r"[<>=!~\[; ]", req, 1)[0]), f"extra «{extra}»")
    out.append(f"- Proyecto: `{proj.get('name')}` {proj.get('version', '?')} · requiere Python {proj.get('requires-python', '?')}")
    out.append(f"- Extras: {', '.join(proj.get('optional-dependencies', {})) or '—'} · scripts: "
               f"{', '.join(proj.get('scripts', {})) or '—'}")
    if not PKG.is_dir():
        return
    try:
        mod_to_dist = md.packages_distributions()
    except Exception:  # noqa: BLE001
        mod_to_dist = {}
    used: dict[str, set[str]] = {}
    for f in walk_files(PKG, (".py",)):
        try:
            tree = ast.parse(f.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError) as exc:
            flag("FALLO", "código", f"{f.relative_to(ROOT)} no se puede analizar: {exc}")
            continue
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module.split(".")[0]]
            for m in mods:
                if m != "dfir_copilot" and m not in sys.stdlib_module_names:
                    used.setdefault(m, set()).add(str(f.relative_to(ROOT)))
    out.append("\n| Módulo importado | Distribución | Declarada en | Instalada |\n|---|---|---|---|")
    for mod in sorted(used):
        dists = mod_to_dist.get(mod, [])
        dist = dists[0] if dists else mod
        where = declared.get(_norm(dist)) or declared.get(_norm(mod))
        try:
            ver = md.version(dist)
        except md.PackageNotFoundError:
            ver = "no"
        out.append(f"| {mod} | {dist} | {where or '**no declarada**'} | {ver} |")
        if not where:
            flag("AVISO", "dependencias", f"`{mod}` se importa en {len(used[mod])} archivo(s) pero `{dist}` no está en pyproject.toml "
                                          f"(p. ej. {sorted(used[mod])[0]})")
        if ver == "no" and (not where or where == "base"):
            flag("AVISO", "dependencias", f"`{dist}` se importa pero no está instalado en este entorno")
        elif ver == "no":
            out.append(f"  - `{dist}` es opcional ({where}) y no está instalado: la función que lo usa queda desactivada")


# --- 3. secretos y .gitignore -----------------------------------------------------------------------------------------------------
def secretos() -> None:
    h("3. Secretos y exclusiones")
    hits = Counter()
    for f in walk_files(ROOT):
        if f.name in (".env",) or f.suffix in (".png", ".jpg", ".pdf", ".parquet", ".duckdb", ".zip", ".gz", ".pyc", ".mmdb"):
            continue
        try:
            if f.stat().st_size > 2_000_000:
                continue
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if "FAKE" in line or "secreto-de-pruebas" in line:     # valores falsos declarados como tales en las pruebas
                continue
            for kind, rx in SECRET_PATTERNS.items():
                if rx.search(line):
                    rel = f.relative_to(ROOT)
                    hits[(str(rel), kind)] += 1
                    level = "AVISO" if ("tests" in rel.parts or "secreto-de-pruebas" in line) else "FALLO"
                    flag(level, "secretos", f"posible {kind} en {rel}:{n} (valor no mostrado)")
    out.append(f"- Coincidencias de patrones de secreto: {sum(hits.values())} (detalle en el resumen de hallazgos)")
    env, example, gi = ROOT / ".env", ROOT / ".env.example", ROOT / ".gitignore"
    out.append(f"- .env: {'existe' if env.exists() else 'no existe'} · .env.example: {'existe' if example.exists() else 'NO existe'}")
    if not example.exists():
        flag("AVISO", "entrega", "falta .env.example: quien reciba el proyecto no sabrá qué variables definir")
    if gi.is_file():
        rules = {ln.strip() for ln in gi.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}
        out.append(f"- .gitignore: {len(rules)} reglas")
        for must in (".env", "data/"):
            if not any(r.rstrip("/") == must.rstrip("/") or r.lstrip("/").rstrip("/") == must.rstrip("/") for r in rules):
                flag("FALLO" if must == ".env" else "AVISO", "secretos", f".gitignore no excluye explícitamente `{must}`")
    else:
        flag("FALLO", "secretos", "no hay .gitignore: .env y data/ podrían subirse al repositorio")


# --- 4. datos acumulados -------------------------------------------------------------------------------------------------------
def datos() -> None:
    h("4. Datos acumulados (data/ y reports/)")
    data = ROOT / "data"
    if not data.is_dir():
        out.append("Sin carpeta data/.")
        return
    out.append("| Carpeta | Archivos | Tamaño |\n|---|---|---|")
    for sub in sorted(p for p in data.iterdir() if p.is_dir()):
        size, count = dir_size(sub)
        out.append(f"| data/{sub.name} | {count} | {human(size)} |")
    projects = [p for p in (data / "projects").glob("*") if (p / "project.json").is_file()] if (data / "projects").is_dir() else []
    legacy = [p for p in (data / "cases").glob("*") if p.is_dir()] if (data / "cases").is_dir() else []
    out.append(f"\n- Análisis (proyectos): {len(projects)} · casos sueltos antiguos (data/cases): {len(legacy)}")
    if projects:
        out.append("\n| Análisis | Tamaño | Modificado |\n|---|---|---|")
        for p in sorted(projects, key=lambda p: p.stat().st_mtime, reverse=True)[:30]:
            size, _c = dir_size(p)
            out.append(f"| {p.name} | {human(size)} | {datetime.fromtimestamp(p.stat().st_mtime, UTC):%Y-%m-%d %H:%M} |")
    if len(projects) + len(legacy) > 10:
        flag("AVISO", "datos", f"{len(projects)} análisis y {len(legacy)} casos sueltos acumulados: no hay forma de eliminarlos desde la interfaz")
    rep = ROOT / "reports"
    if rep.is_dir():
        size, count = dir_size(rep)
        out.append(f"- reports/: {count} archivo(s), {human(size)}")
    big = sorted(((p.stat().st_size, p) for p in walk_files(ROOT) if p.is_file()), reverse=True)[:8]
    out.append("\n- Archivos más grandes fuera de data/: " + ", ".join(f"`{p.relative_to(ROOT)}` ({human(s)})" for s, p in big))
    for s, p in big:
        if s > 20_000_000:
            flag("AVISO", "entrega", f"{p.relative_to(ROOT)} pesa {human(s)} fuera de data/: ¿debe ir en el repositorio?")


# --- 5. código ---------------------------------------------------------------------------------------------------------------------
def codigo() -> None:
    h("5. Código")
    if not PKG.is_dir():
        out.append("Sin src/dfir_copilot.")
        return
    rows, long_funcs, prints, bare, broad, todo, nodoc = [], [], 0, 0, 0, 0, []
    for f in sorted(walk_files(PKG, (".py",))):
        text = f.read_text(encoding="utf-8")
        rel = f.relative_to(ROOT)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        lines = text.count("\n") + 1
        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        rows.append((lines, str(rel), len(funcs)))
        if not ast.get_docstring(tree) and f.name != "__init__.py":
            nodoc.append(str(rel))
        for fn in funcs:
            span = (fn.end_lineno or fn.lineno) - fn.lineno + 1
            if span > 80:
                long_funcs.append((span, f"{rel}:{fn.lineno} {fn.name}"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print" and "__main__" not in f.name:
                prints += 1
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    bare += 1
                elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    broad += 1
        todo += len(re.findall(r"\b(TODO|FIXME|XXX)\b", text))
    total = sum(r[0] for r in rows)
    out.append(f"- {len(rows)} módulos · {total:,} líneas · TODO/FIXME: {todo} · `print` fuera de __main__: {prints} · "
               f"`except:` desnudo: {bare} · `except Exception`: {broad}")
    out.append("\n**Módulos más grandes**\n\n| Líneas | Módulo | Funciones |\n|---|---|---|")
    for lines, rel, nf in sorted(rows, reverse=True)[:12]:
        out.append(f"| {lines} | {rel} | {nf} |")
        if lines > 800:
            flag("MEJORA", "código", f"{rel} tiene {lines} líneas: candidato a dividir por responsabilidades")
    if long_funcs:
        out.append("\n**Funciones de más de 80 líneas**\n")
        out.extend(f"- {span} líneas · `{where}`" for span, where in sorted(long_funcs, reverse=True)[:15])
    if bare:
        flag("AVISO", "código", f"{bare} `except:` desnudo(s): capturan también Ctrl+C y errores de sistema")
    if nodoc:
        flag("MEJORA", "documentación", f"{len(nodoc)} módulo(s) sin docstring: {', '.join(nodoc[:6])}{'…' if len(nodoc) > 6 else ''}")


def importar() -> None:
    h("6. ¿Todos los módulos importan?")
    if not PKG.is_dir():
        return
    sys.path.insert(0, str(ROOT / "src"))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dfir_copilot.web.settings")
    os.environ.setdefault("DFIR_WEB_SECRET", "diagnostico")
    try:
        import django

        django.setup()
    except Exception as exc:  # noqa: BLE001
        out.append(f"- Django no se pudo inicializar: {type(exc).__name__}: {exc}")
    failed, ok = [], 0
    for f in sorted(walk_files(PKG, (".py",))):
        if f.name == "__main__.py":
            continue
        mod = ".".join(f.relative_to(ROOT / "src").with_suffix("").parts).removesuffix(".__init__")
        try:
            importlib.import_module(mod)
            ok += 1
        except Exception as exc:  # noqa: BLE001
            failed.append(f"`{mod}`: {type(exc).__name__}: {str(exc).splitlines()[0][:160] if str(exc) else ''}")
    out.append(f"- Importan sin error: {ok} · con error: {len(failed)}")
    for line in failed:
        out.append(f"  - {line}")
        flag("FALLO", "código", f"no importa: {line}")
    _django_settings()


def _django_settings() -> None:
    try:
        from django.conf import settings as s

        if not s.configured:
            return
    except Exception:  # noqa: BLE001
        return
    h("7. Configuración de la interfaz (Django)")
    mw = list(getattr(s, "MIDDLEWARE", []))
    out.append(f"- DEBUG={s.DEBUG} · ALLOWED_HOSTS={list(s.ALLOWED_HOSTS)} · SECRET_KEY definida: {bool(getattr(s, 'SECRET_KEY', ''))}")
    out.append(f"- CSRF: {'sí' if any('CsrfViewMiddleware' in m for m in mw) else 'NO'} · X-Frame: {getattr(s, 'X_FRAME_OPTIONS', '—')} · "
               f"subida máx.: {getattr(s, 'DFIR_MAX_UPLOAD_MB', '?')} MB")
    if s.DEBUG:
        flag("AVISO", "web", "DEBUG=True: muestra trazas con rutas y valores si algo falla")
    if not any("CsrfViewMiddleware" in m for m in mw):
        flag("FALLO", "web", "sin CsrfViewMiddleware")
    if "*" in s.ALLOWED_HOSTS:
        flag("AVISO", "web", "ALLOWED_HOSTS='*'")


# --- 8. tests ------------------------------------------------------------------------------------------------------------------------
def tests(run_suite: bool) -> None:
    h("8. Pruebas")
    tdir = ROOT / "tests"
    per_file = []
    for f in sorted(tdir.glob("test_*.py")) if tdir.is_dir() else []:
        text = f.read_text(encoding="utf-8")
        per_file.append((len(re.findall(r"^\s*def test_", text, re.M)), f.name, text.count("pytest.mark.skip") + text.count("importorskip")))
    out.append(f"- {len(per_file)} archivos de prueba · {sum(n for n, _f, _s in per_file)} funciones de test (sin contar parametrizaciones)")
    out.append("\n| Tests | Archivo | skip/importorskip |\n|---|---|---|")
    out.extend(f"| {n} | {name} | {s} |" for n, name, s in sorted(per_file, reverse=True))
    if not run_suite:
        out.append("\n(Suite no ejecutada: usa `--tests` para correrla con los tiempos de los tests más lentos.)")
        return
    rc, text = run([sys.executable, "-m", "pytest", "-q", "--durations=20", "-p", "no:cacheprovider"], timeout=3600)
    tail = "\n".join(text.strip().splitlines()[-45:])
    out.append(f"\n```\n{tail}\n```")
    if rc != 0:
        flag("FALLO", "pruebas", "la suite no pasó completa: ver sección 8")


# --- 9. lint y 10. documentación ---------------------------------------------------------------------------------------------------
def lint() -> None:
    h("9. Lint (ruff)")
    ruff = shutil.which("ruff")
    if not ruff:
        out.append("ruff no está instalado en este entorno.")
        return
    rc, text = run([ruff, "check", "src", "tests", "--statistics", "--exit-zero"])
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    out.append("```\n" + ("\n".join(lines[-30:]) or "sin avisos") + "\n```")
    if lines and not any("All checks passed" in ln for ln in lines):
        flag("MEJORA", "código", f"ruff reporta avisos ({len(lines)} línea(s) de estadísticas)")


def documentacion() -> None:
    h("10. Documentación")
    for name in ("README.md", "LICENSE", "CHANGELOG.md", ".env.example", "docker-compose.yml", "docker/Dockerfile"):
        p = ROOT / name
        out.append(f"- {name}: {'sí (' + human(p.stat().st_size) + ')' if p.exists() else 'NO'}")
    if not (ROOT / "README.md").exists():
        flag("FALLO", "entrega", "falta README.md: quien reciba el proyecto no sabrá instalarlo, correrlo ni probarlo")
    docs = sorted((ROOT / "docs").glob("*.md")) if (ROOT / "docs").is_dir() else []
    out.append(f"- docs/: {', '.join(d.name for d in docs) or 'vacío'}")
    nb = sorted((ROOT / "notebooks").glob("*.ipynb")) if (ROOT / "notebooks").is_dir() else []
    out.append(f"- notebooks/: {len(nb)} cuaderno(s)")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tests", action="store_true", help="corre además la suite completa (~8-10 min)")
    args = ap.parse_args(argv)
    start = datetime.now(UTC)
    for step in (entorno, dependencias, secretos, datos, codigo, importar, lint, documentacion):
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - un paso que falla no impide el resto del diagnóstico
            flag("FALLO", "diagnóstico", f"el paso {step.__name__} falló: {type(exc).__name__}: {exc}")
    tests(args.tests)
    order = {"FALLO": 0, "AVISO": 1, "MEJORA": 2}
    counts = Counter(level for level, _a, _t in findings)
    head = [f"# Diagnóstico DFIR Co-pilot · {start:%Y-%m-%d %H:%M} UTC", "",
            f"**{counts['FALLO']} fallo(s) · {counts['AVISO']} aviso(s) · {counts['MEJORA']} mejora(s)**", "",
            "| Nivel | Área | Hallazgo |", "|---|---|---|"]
    head += [f"| {lv} | {area} | {text} |" for lv, area, text in sorted(findings, key=lambda x: (order.get(x[0], 9), x[1]))]
    report = "\n".join(head + out) + "\n"
    dest = ROOT / "reports" / f"diagnostico-{start:%Y%m%d-%H%M}.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(report, encoding="utf-8")
    print(report)
    print(f"\nInforme guardado en {dest.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
