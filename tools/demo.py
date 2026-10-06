#!/usr/bin/env python3
"""Demostración con datos SINTÉTICOS: crea dos análisis y los analiza de punta a punta, sin modelo y sin datos reales.

Uso (dentro del contenedor, desde la raíz del repositorio):
    python tools/demo.py                # crea «Demo IDOR» y «Demo incidente» si no existen
    python tools/demo.py --reiniciar    # los borra y los vuelve a crear
    python tools/demo.py --con-modelo   # además usa el modelo (requiere la clave en .env; gasta API)

Qué se crea:
* «Demo IDOR»: un log web con una explotación IDOR plantada en /invoices/search (el caso de estudio del proyecto, con verdad conocida).
* «Demo incidente»: firewall + endpoint (Falcon) del mismo entorno, con una cadena maliciosa plantada que la correlación debe unir, y un
  boletín PDF de ejemplo con IOCs ficticios (direcciones de documentación RFC 5737 y dominios .test, que no existen).
Después abre la interfaz (`python -m dfir_copilot.web --host 0.0.0.0`) en http://127.0.0.1:8000."""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

DEMO_NAMES = ("Demo IDOR", "Demo incidente")


def _bulletin_pdf(path: Path) -> Path:
    """Boletín de ejemplo, con texto seleccionable y IOCs ficticios."""
    import pymupdf

    md5 = hashlib.md5(b"dfir-copilot-demo-1").hexdigest()
    sha1 = hashlib.sha1(b"dfir-copilot-demo-2").hexdigest()
    sha256 = hashlib.sha256(b"dfir-copilot-demo-3").hexdigest()
    pages = [
        "Boletín de amenazas de ejemplo (DFIR Co-pilot, datos ficticios)\n\n"
        "Resumen: un actor obtuvo acceso inicial por una VPN sin MFA, desactivó el antivirus con un controlador vulnerable y "
        "exfiltró datos antes de cifrar los servidores. Todos los indicadores de este boletín son ficticios: las direcciones son "
        "de documentación (RFC 5737) y los dominios usan el TLD reservado .test.\n\n"
        "Recomendaciones: aplicar MFA en todos los accesos remotos, vigilar la carga de controladores vulnerables y separar las "
        "copias de seguridad de la administración ordinaria.",
        "Indicadores de compromiso\n\n"
        f"MD5 {md5}\nSHA-1 {sha1}\nSHA-256 {sha256}\n"
        "IP 203.0.113.45 (servidor de mando y control)\nIP 198.51.100.23 (exfiltración)\n"
        "URL hxxps://c2.ejemplo-malicioso[.]test/beacon\nCorreo de contacto: rescate@ejemplo-malicioso.test\n"
        "Vulnerabilidad explotada: CVE-2024-21762",
    ]
    doc = pymupdf.open()
    for text in pages:
        page = doc.new_page()
        page.insert_textbox(pymupdf.Rect(50, 50, 545, 790), text, fontsize=10)
    doc.save(str(path))
    return path


def _upload(project, path: Path) -> None:
    def chunks():
        with path.open("rb") as fh:
            while block := fh.read(1 << 20):
                yield block

    project.add_upload(path.name, chunks(), analyst="demo")


def _geo():
    try:
        from dfir_copilot.geoip import geo_db

        return geo_db()
    except Exception:  # noqa: BLE001 - sin base GeoIP la demo funciona igual
        return None


def run_demo(reset: bool = False, with_model: bool = False, log=print) -> dict:
    from dfir_copilot.documents import service as D
    from dfir_copilot.pipeline import Deps, correlate_after, default_deps, run_pipeline
    from dfir_copilot.projects import Project, ProjectError, ProjectSettings, projects_root
    from dfir_copilot.synthetic import make_idor_dataset, write_csv
    from dfir_copilot.synthetic_endpoint import make_endpoint_dataset, write_endpoint
    from dfir_copilot.synthetic_firewall import make_firewall_dataset, write_firewall

    existing = {p.name: p for p in Project.list()}
    for name in DEMO_NAMES:
        if name in existing:
            if not reset:
                raise ProjectError(f"Ya existe «{name}». Ábrelo en la interfaz o usa --reiniciar para volver a crearlo.")
            target = existing[name].dir
            if target.parent.resolve() != projects_root().resolve():
                raise ProjectError(f"«{name}» no está en la raíz de análisis: no se borra por seguridad.")
            shutil.rmtree(target)
            log(f"Borrado el análisis anterior «{name}».")

    deps = default_deps() if with_model else Deps()
    settings = ProjectSettings(language="es", analyst="demo", use_llm=with_model)
    summary: dict = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        log("Generando datos sintéticos…")
        idor_rows, _ = make_idor_dataset()
        idor = write_csv(tmp / "web_access_sintetico.csv", idor_rows)
        fw_rows, fw_truth = make_firewall_dataset(hosts=20, days=35)
        fw = write_firewall(fw_rows, tmp / "firewall_sintetico.csv", "generic_es")
        ep_rows, _ = make_endpoint_dataset(fw_rows, fw_truth)
        ep = write_endpoint(ep_rows, tmp / "endpoint_falcon_sintetico.csv", "falcon_csv")
        pdf = _bulletin_pdf(tmp / "boletin_ejemplo.pdf")
        plan = {"Demo IDOR": [idor], "Demo incidente": [fw, ep, pdf]}

        for name, files in plan.items():
            project = Project.create(name, None, settings)
            for path in files:
                _upload(project, path)
            log(f"\n«{name}» ({project.id}): {len(files)} archivo(s)")
            states = {}
            for f in project.files():
                if f.supported:
                    log(f"  analizando {f.name}…")
                    states[f.name] = (run_pipeline(project, f, deps) or {}).get("state")
                elif f.kind == "document":
                    log(f"  leyendo el documento {f.name}…")
                    states[f.name] = D.run_job(f.path, project.dir / "documents" / f.case_id, geo=_geo())
                log(f"    → {states.get(f.name)}")
            if sum(1 for f in project.files() if f.supported) >= 2:
                log("  correlacionando las fuentes…")
                correlate_after(project)
            summary[project.id] = states
    log("\nListo. Arranca la interfaz y abre http://127.0.0.1:8000 :")
    log("  python -m dfir_copilot.web --host 0.0.0.0")
    return summary


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Demostración con datos sintéticos")
    ap.add_argument("--reiniciar", action="store_true", help="borra y vuelve a crear los análisis de demostración")
    ap.add_argument("--con-modelo", action="store_true", help="usa también el modelo (requiere la clave en .env; gasta API)")
    args = ap.parse_args(argv)
    try:
        run_demo(reset=args.reiniciar, with_model=args.con_modelo)
    except Exception as exc:  # noqa: BLE001 - mensaje claro en lugar de una traza
        print(f"\nNo se pudo completar la demo: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
