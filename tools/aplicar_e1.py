#!/usr/bin/env python3
"""Aplica E1 (papelera + correcciones del diagnóstico) sobre archivos EXISTENTES; los nuevos ya vienen en el zip.

Uso, desde la raíz del repositorio:
    python3 tools/aplicar_e1.py --check     # solo comprueba
    python3 tools/aplicar_e1.py             # aplica

Cada cambio exige que el texto esperado aparezca EXACTAMENTE una vez; si alguno falla no se escribe NADA. Idempotente."""
from __future__ import annotations

import sys
from pathlib import Path

SRC = Path("src/dfir_copilot")

JOB = '''    def job(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            raise NotFound("Trabajo desconocido (¿se reinició el servidor?)")
        return job
'''
FORGET = '''
    def forget(self, prefix) -> int:
        """Suelta los agentes en caché de los casos bajo `prefix` (p. ej. un análisis que se mueve a la papelera)."""
        prefix = str(prefix).rstrip("/")
        with self._lock:
            keys = [k for k in self._bundles if k == prefix or k.startswith(prefix + "/")]
            for k in keys:
                self._bundles.pop(k, None)
        return len(keys)
'''
URLS_HEAD = "from django.urls import path\n\nfrom dfir_copilot.web import views\n"
URLS_DOC = '"""Rutas de la interfaz web: casos (de un proyecto o sueltos), proyectos, evidencia, incidente, documentos y papelera."""\n'
URLS_TRASH = '''
# Papelera: eliminar análisis y casos de forma recuperable
from dfir_copilot.web.trash_views import urlpatterns as _trash_urls  # noqa: E402

urlpatterns += _trash_urls
'''

# (archivo, descripción, texto esperado o None para añadir al final, texto nuevo, marca de «ya aplicado»)
CHANGES = [
    (SRC / "web/services.py", "Services.forget", JOB, JOB + FORGET, "def forget"),
    (SRC / "web/urls.py", "docstring de urls.py", URLS_HEAD, URLS_DOC + URLS_HEAD, '"""Rutas de la interfaz web'),
    (SRC / "web/urls.py", "rutas de la papelera", None, URLS_TRASH, "trash_views"),
    (Path("pyproject.toml"), "pillow y numpy en el extra pdf", 'pdf = ["pymupdf"]\n', 'pdf = ["pymupdf", "pillow", "numpy"]\n', '"pillow"'),
    (Path("pyproject.toml"), "extra geoip (opcional)", 'openai = ["langchain-openai>=1.0"]\n',
     'openai = ["langchain-openai>=1.0"]\ngeoip = ["maxminddb"]  # opcional: solo para bases GeoIP .mmdb; el CSV de DB-IP no lo necesita\n', "geoip ="),
    (SRC / "documents/pdf_reader.py", "zip con strict explícito (B905)", "zip(seps, seps[1:]) if", "zip(seps, seps[1:], strict=False) if",
     "seps[1:], strict=False"),
    (SRC / "documents/search.py", "variable de bucle sin usar (B007)", "    for i, (p, s) in enumerate(sents):\n",
     "    for i, (_p, s) in enumerate(sents):\n", "(_p, s)"),
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
        if old is None:
            texts[path] = text.rstrip("\n") + "\n" + new
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
    print("\nAplicado. Revisa con `git diff` y corre las pruebas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
