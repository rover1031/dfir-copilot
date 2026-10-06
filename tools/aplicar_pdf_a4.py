#!/usr/bin/env python3
"""Aplica PDF-a.4 sobre los archivos EXISTENTES del proyecto (los nuevos ya vienen en el zip).

Uso, desde la raíz del repositorio:
    python3 tools/aplicar_pdf_a4.py --check     # solo comprueba y dice qué haría
    python3 tools/aplicar_pdf_a4.py             # aplica

Cada cambio exige que el texto esperado aparezca EXACTAMENTE una vez. Si alguno no coincide, no se escribe NADA (ni siquiera los que sí
coincidían) y se explica cuál falló. Es idempotente: lo ya aplicado se omite. Revisa el resultado con `git diff`."""
from __future__ import annotations

import sys
from pathlib import Path

SRC = Path("src/dfir_copilot")

SUBMIT_TASK = '''
    def submit_task(self, project_id: str, case_id: str, fn) -> bool:
        """Lanza una tarea cualquiera (p. ej. el análisis de un documento PDF) con el mismo control de «en curso» y la misma cola que
        los logs: un archivo a la vez, y `running()` la ve, así que la interfaz sigue mostrando «analizando…» sin cambios."""
        key = (project_id, case_id)
        with self._lock:
            if key in self._running:
                return False
            self._running.add(key)

        def job():
            try:
                fn()
            finally:
                with self._lock:
                    self._running.discard(key)

        if self.sync:
            job()
        else:
            self._pool.submit(job)
        return True
'''

PIPELINE_ANCHOR = '''        if self.sync:
            job()
        else:
            self._pool.submit(job)
        return True
'''

START_NEW_ANCHOR = '''    sv = get_services()
    for f in project.files():
        if f.supported and project.status(f.case_id) is None and not sv.runner.running(project.id, f.case_id):
            sv.runner.submit(project, f, sv.deps)
'''
START_NEW_NEW = START_NEW_ANCHOR + '''    # PDF: los documentos también se analizan solos al entrar, en la misma cola
    from dfir_copilot.web.document_views import start_documents  # import tardío: ese módulo importa estas vistas

    start_documents(project)
'''

ROWS_ANCHOR = '''            origin = "—"
        st = project.status(f.case_id) or {}
        state = st.get("state")
'''
ROWS_NEW = '''            origin = "—"
        st = project.status(f.case_id) or {}
        if f.kind == "document":  # los documentos guardan su estado junto a sus resultados, no en status/
            from dfir_copilot.web.document_views import document_state

            st = document_state(project, f)
        state = st.get("state")
'''

URLS_APPEND = '''
# PDF: pantalla de análisis de documentos
from dfir_copilot.web.document_views import urlpatterns as _document_urls  # noqa: E402

urlpatterns += _document_urls
'''

# (archivo, descripción, texto esperado, texto nuevo, marca de «ya aplicado»)  ·  para urls.py el texto esperado es None: se añade al final
CHANGES = [
    (SRC / "pipeline.py", "PipelineRunner.submit_task", PIPELINE_ANCHOR, PIPELINE_ANCHOR + SUBMIT_TASK, "def submit_task"),
    (SRC / "web/views.py", "_start_new lanza los documentos", START_NEW_ANCHOR, START_NEW_NEW, "start_documents"),
    (SRC / "web/views.py", "_evidence_rows lee el estado de los documentos", ROWS_ANCHOR, ROWS_NEW, "document_state"),
    (SRC / "web/urls.py", "rutas de la pantalla del documento", None, URLS_APPEND, "document_views"),
]


def plan(root: Path) -> tuple[dict[Path, str], list[str], list[str]]:
    """Devuelve (solo los archivos que cambian -> su texto nuevo, informe, errores)."""
    texts: dict[Path, str] = {}
    changed: set[Path] = set()
    report, errors = [], []
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
            changed.add(path)
            report.append(f"+ {rel}: {what}")
            continue
        n = text.count(old)
        if n != 1:
            errors.append(f"{rel}: «{what}»: el texto esperado aparece {n} vez/veces (debe ser 1). No se escribió nada.")
            continue
        texts[path] = text.replace(old, new, 1)
        changed.add(path)
        report.append(f"+ {rel}: {what}")
    return {p: texts[p] for p in texts if p in changed}, report, errors


def main(argv: list[str]) -> int:
    root = Path.cwd()
    texts, report, errors = plan(root)
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
