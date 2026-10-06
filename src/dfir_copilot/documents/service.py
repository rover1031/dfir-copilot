"""Análisis de un documento a una carpeta de resultados (PDF-a.3). Sin web ni modelo: la interfaz solo llama a estas funciones.

`analyze_to_dir` hace el trabajo caro UNA vez (texto/OCR, IOCs, estadísticas, resumen extractivo) y deja en `out_dir`:

* `manifest.json`   origen (nombre, SHA-256, tamaño), páginas y método de lectura de cada una, avisos, fechas y, si se aportó, la huella del
                    texto de referencia. Es lo que va a la cadena de custodia.
* `extraction.json` el estado de la extracción, para poder VERIFICAR después sin repetir el OCR (`verify_document`).
* `pages.jsonl`     texto de cada página (LOCAL: es el documento; no sale de la máquina salvo los pasajes que la pregunta necesite).
* `iocs.csv`        lista de bloqueo: sin dudosos, sin IPs privadas, sin servicios conocidos y sin hashes de OCR sin verificar.
* `candidatos_ocr.csv`  hashes leídos por OCR pendientes de verificar contra una fuente de texto.
* `dudosos.csv`     lo que se parece a un IOC pero no cuadra (hash truncado o mal leído, fila partida entre páginas...).
* `resumen.json`    estadísticas, países de las IPs (si hay base GeoIP), idioma, resumen extractivo y avisos.
Las escrituras son atómicas (archivo temporal y renombrado): una interrupción no deja un resultado a medias."""
from __future__ import annotations

import csv
import hashlib
import json
import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from dfir_copilot.documents import iocs as I
from dfir_copilot.documents import pdf_reader as R
from dfir_copilot.documents import search as S

SCHEMA = 1
SUMMARY_SENTENCES = 6


class DocumentError(Exception):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _sha256(path: Path) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _atomic(path: Path, data: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    os.replace(tmp, path)


def _write_json(path: Path, obj) -> None:
    _atomic(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)


def dump_extraction(ex: I.Extraction) -> dict:
    return {"schema": SCHEMA, "pages": ex.pages, "removed_lines": ex.removed_lines,
            "iocs": [[i.kind, i.value, list(i.pages), i.count, list(i.tags)] for i in ex.iocs],
            "doubtful": [[d.page, d.reason, d.length, d.text] for d in ex.doubtful]}


def load_extraction(data: dict) -> I.Extraction:
    if data.get("schema") != SCHEMA:
        raise DocumentError(f"Formato de extracción no soportado: {data.get('schema')!r}")
    return I.Extraction(data["pages"], [I.IOC(k, v, tuple(p), c, tuple(t)) for k, v, p, c, t in data["iocs"]],
                        [I.Doubtful(p, r, n, t) for p, r, n, t in data["doubtful"]], list(data["removed_lines"]))


def _publish(out: Path, ex: I.Extraction, pages: list[str], manifest: dict, verification: dict | None, geo) -> dict:
    """Escribe todo lo derivado de la extracción. Se usa al analizar y al verificar: así las dos rutas dejan el mismo resultado."""
    _write_json(out / "extraction.json", dump_extraction(ex))
    _write_csv(out / "iocs.csv", ["tipo", "valor", "menciones", "paginas", "etiquetas"], I.priority_rows(ex))
    _write_csv(out / "candidatos_ocr.csv", ["tipo", "valor", "menciones", "paginas", "etiquetas"], I.candidate_rows(ex))
    _write_csv(out / "dudosos.csv", ["pagina", "motivo", "longitud", "texto"],
               [{"pagina": d.page, "motivo": d.reason, "longitud": d.length, "texto": d.text} for d in ex.doubtful])
    pending = len(I.candidate_rows(ex))
    notices = list(manifest.get("warnings", []))
    if pending:
        notices.append(f"{pending} hash(es) leídos por OCR sin verificar: no están en la lista de bloqueo (iocs.csv). "
                       "Aporta un texto de referencia (p. ej. la página web del boletín) para verificarlos.")
    if ex.doubtful:
        notices.append(f"{len(ex.doubtful)} elemento(s) dudosos (hash truncado o mal leído, fila partida entre páginas): ver dudosos.csv.")
    summary = {
        "estadisticas": I.summary(ex),
        "paises": [list(r) for r in I.countries(ex, geo)] if geo is not None else None,
        "paises_nota": None if geo is not None else "Sin base GeoIP local configurada: no se calcularon países.",
        "idioma": S.language_hint(pages),
        "resumen_extractivo": [[p, s] for p, s in S.key_sentences(pages, n=SUMMARY_SENTENCES)],
        "hashes_sin_verificar": pending,
        "verificacion": verification,
        "avisos": notices,
    }
    _write_json(out / "resumen.json", summary)
    _write_json(out / "manifest.json", manifest)
    return summary


def analyze_to_dir(pdf_path: str | Path, out_dir: str | Path, reference_text: str | None = None, geo=None, ocr: str = "auto",
                   dpi: int = 300) -> dict:
    """Analiza el PDF y deja los resultados en `out_dir`. Devuelve el manifest. `geo` es cualquier objeto con `.country(ip)` (GeoDB)."""
    pdf_path, out = Path(pdf_path), Path(out_dir)
    if not pdf_path.is_file():
        raise DocumentError(f"No existe el documento: {pdf_path.name}")
    out.mkdir(parents=True, exist_ok=True)
    started = _now()
    sha, size = _sha256(pdf_path)
    try:
        ex, pdf, report = R.analyze(pdf_path, reference_text=reference_text, ocr=ocr, dpi=dpi)
    except R.PdfReadError as exc:
        raise DocumentError(str(exc)) from exc
    _atomic(out / "pages.jsonl", "\n".join(json.dumps({"page": n, "method": m, "text": t}, ensure_ascii=False)
                                           for n, (t, m) in enumerate(zip(pdf.pages, pdf.methods, strict=True), start=1)) + "\n")
    manifest = {"schema": SCHEMA, "source": {"name": pdf_path.name, "sha256": sha, "bytes": size}, "pages": len(pdf.pages),
                "methods": dict(Counter(pdf.methods)), "page_methods": pdf.methods, "warnings": pdf.warnings,
                "started_utc": started, "finished_utc": _now(), "reference": None}
    if reference_text:
        manifest["reference"] = {"sha256": hashlib.sha256(reference_text.encode("utf-8")).hexdigest(), "chars": len(reference_text),
                                 "applied_utc": _now()}
    _publish(out, ex, pdf.pages, manifest, report, geo)
    return manifest


def load(out_dir: str | Path) -> dict:
    """Resultado guardado: manifest, resumen, texto de las páginas y extracción."""
    out = Path(out_dir)
    try:
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        summary = json.loads((out / "resumen.json").read_text(encoding="utf-8"))
        extraction = load_extraction(json.loads((out / "extraction.json").read_text(encoding="utf-8")))
        pages = [json.loads(line)["text"] for line in (out / "pages.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    except FileNotFoundError as exc:
        raise DocumentError(f"El análisis del documento no está completo: falta {Path(exc.filename).name}") from exc
    return {"manifest": manifest, "summary": summary, "pages": pages, "extraction": extraction}


def open_index(out_dir: str | Path) -> S.Index:
    """Índice de búsqueda sobre el texto guardado (para el chat con el documento)."""
    return S.Index(load(out_dir)["pages"])


def verify_document(out_dir: str | Path, reference_text: str, geo=None) -> dict:
    """Contrasta los hashes leídos por OCR con una fuente de texto SIN repetir el OCR. Devuelve el informe de verificación."""
    if not reference_text or not reference_text.strip():
        raise DocumentError("El texto de referencia está vacío.")
    out = Path(out_dir)
    data = load(out)
    ex, manifest = data["extraction"], data["manifest"]
    report = I.verify_hashes(ex, reference_text)
    manifest["reference"] = {"sha256": hashlib.sha256(reference_text.encode("utf-8")).hexdigest(), "chars": len(reference_text),
                             "applied_utc": _now()}
    _publish(out, ex, data["pages"], manifest, report, geo)
    return report
