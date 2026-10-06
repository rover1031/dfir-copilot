"""Lectura de PDF (PDF-a.2): inventario de páginas, OCR cuando no hay texto y recuperación de tablas de hashes por filas.

* Una página con capa de texto se lee tal cual; una página "solo imagen" (p. ej. impresa con «Microsoft Print to PDF») pasa por Tesseract.
* Una tabla de IOCs de un PDF rasterizado se lee FILA A FILA: las líneas horizontales de la tabla delimitan cada fila, el tipo (MD5, SHA-1,
  SHA-256) se lee de su celda y el hash de la suya, y las líneas en que la celda lo partió se unen. El hash solo es válido si su longitud
  coincide con la del tipo; si no, se informa como dudoso con la longitud esperada y la leída. Nada dudoso entra al CSV de bloqueo.
* Una fila sin tipo al inicio de una página es la continuación de la última fila de la página anterior.
Requiere PyMuPDF (`import pymupdf`), numpy y Pillow, y el binario `tesseract` (idiomas eng y spa) para las páginas sin texto."""
from __future__ import annotations

import io
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from dfir_copilot.documents import iocs as I

MIN_TEXT_CHARS = 40                       # menos que esto en una página = no tiene capa de texto útil
EXPECTED = {"md5": 32, "sha1": 40, "sha256": 64}
_LABEL = re.compile(r"^(md[-—–]?5|sha[-—–]?(1|l|i)|sha[-—–]?256)$", re.I)
_FIX = str.maketrans({"o": "0", "O": "0", "l": "1", "I": "1", "i": "1"})  # confusiones típicas del OCR dentro de un hash
_HEX = re.compile(r"[0-9a-f]")


class PdfReadError(Exception):
    pass


@dataclass(frozen=True)
class PageInfo:
    page: int
    text_chars: int
    images: int
    kind: str                              # "texto" | "solo_imagen" | "vacia"


@dataclass(frozen=True)
class HashRow:
    page: int
    kind: str                              # md5 | sha1 | sha256 | desconocido
    value: str
    expected: int
    status: str                            # "ok" | "longitud_invalida" | "sin_tipo" | "continuacion_incompleta"

    @property
    def length(self) -> int:
        return len(self.value)


@dataclass
class PdfRead:
    inventory: list[PageInfo]
    pages: list[str]
    methods: list[str]                     # por página: "texto" | "ocr"
    rows: list[HashRow] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _need_tesseract() -> str:
    exe = shutil.which("tesseract")
    if not exe:
        raise PdfReadError("No está instalado tesseract (paquetes tesseract-ocr, tesseract-ocr-eng y tesseract-ocr-spa).")
    return exe


def inventory(path: str | Path) -> list[PageInfo]:
    import pymupdf

    out = []
    with pymupdf.open(str(path)) as doc:
        for n, page in enumerate(doc, start=1):
            chars, images = len(page.get_text().strip()), len(page.get_images())
            out.append(PageInfo(n, chars, images, "texto" if chars >= MIN_TEXT_CHARS else ("solo_imagen" if images else "vacia")))
    return out


def _render(path: str | Path, page_no: int, dpi: int):
    import pymupdf
    from PIL import Image

    with pymupdf.open(str(path)) as doc:
        pix = doc[page_no - 1].get_pixmap(dpi=dpi)
        return Image.open(io.BytesIO(pix.tobytes("png"))).convert("L")


HEX_ALPHABET = "0123456789abcdefABCDEF"


def _ocr(img, psm: int, lang: str = "eng+spa", whitelist: str | None = None) -> str:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    cmd = [_need_tesseract(), "stdin", "stdout", "--psm", str(psm), "-l", lang]
    if whitelist:
        cmd += ["-c", f"tessedit_char_whitelist={whitelist}", "-c", "load_system_dawg=0", "-c", "load_freq_dawg=0"]
    res = subprocess.run(cmd, input=buf.getvalue(), capture_output=True, timeout=180)
    return res.stdout.decode("utf-8", "replace")


def _ocr_words(img, psm: int = 6, lang: str = "eng") -> list[dict]:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    res = subprocess.run([_need_tesseract(), "stdin", "stdout", "--psm", str(psm), "-l", lang, "tsv"], input=buf.getvalue(),
                         capture_output=True, timeout=180)
    words = []
    for line in res.stdout.decode("utf-8", "replace").splitlines()[1:]:
        c = line.split("\t")
        if len(c) >= 12 and c[11].strip():
            words.append({"left": int(c[6]), "top": int(c[7]), "w": int(c[8]), "h": int(c[9]), "text": c[11].strip()})
    return words


def _cluster(idx, gap: int = 3) -> list[int]:
    groups: list[list[int]] = []
    for v in idx:
        if groups and v - groups[-1][-1] <= gap:
            groups[-1].append(int(v))
        else:
            groups.append([int(v)])
    return [round(sum(g) / len(g)) for g in groups]


def _geometry(img) -> tuple[list[int], list[int]] | None:
    """(líneas horizontales, líneas verticales) de la tabla, por las líneas dibujadas: no depende de que el OCR lea la cabecera.
    Las horizontales son las filas oscuras de al menos la mitad del ancho; las verticales, las columnas oscuras dentro de la tabla."""
    import numpy as np

    dark = np.asarray(img) < 140
    H, W = dark.shape
    rows = np.where(dark.mean(axis=1) > 0.45)[0]
    if len(rows) < 2:
        return None
    seps = _cluster(rows)
    xs = np.where(dark[rows].any(axis=0))[0]
    x0, x1 = int(xs.min()), int(xs.max())
    y0, y1 = seps[0], seps[-1]
    if y1 - y0 < 10 or x1 - x0 < W * 0.3:
        return None
    cols = np.where(dark[y0:y1, x0:x1 + 1].mean(axis=0) > 0.6)[0] + x0
    verts = _cluster(cols)
    return (seps, verts) if len(verts) >= 3 else None


def _clean_hex(text: str) -> str:
    return "".join(_HEX.findall(text.replace(" ", "").translate(_FIX).lower()))


def _norm_kind(label: str) -> str:
    s = re.sub(r"[^a-z0-9]", "", label.lower())
    if s.startswith("md"):
        return "md5"
    if s.endswith("256"):
        return "sha256"
    return "sha1" if s.startswith("sha") else "desconocido"


def _table_pass(path: str | Path, page_nos: list[int], dpi: int, whitelist: str | None) -> list[dict]:
    """Una pasada de lectura de la tabla a una resolución. Devuelve filas en bruto: {page, kind, value, cont}."""
    rows: list[dict] = []
    pending: dict | None = None            # última fila de la página anterior, por si continúa en la siguiente
    for page_no in page_nos:
        img = _render(path, page_no, dpi)
        H = img.size[1]
        geo = _geometry(img)
        if geo is None:
            continue
        seps, verts = geo
        bands = [(a, b) for a, b in zip(seps, seps[1:]) if b - a > int(0.008 * H)]
        v0, v1, v2 = verts[0], verts[1], verts[2]          # borde izquierdo, entre Type e Indicator, entre Indicator y Description
        first = True
        for top, bottom in bands:
            cell_t = img.crop((v0 + 6, top + 4, v1 - 6, bottom - 3))
            cell_i = img.crop((v1 + 6, top + 4, v2 - 6, bottom - 3))
            label_words = [w["text"] for w in _ocr_words(cell_t, psm=7)]
            joined = "".join(label_words).strip("|")                      # Tesseract puede partir "SHA-1" en "SHA-" y "1"
            label = joined if _LABEL.match(joined) else next((w for w in label_words if _LABEL.match(w.strip("|"))), None)
            if label is None and any(w.lower() in ("type", "indicator") for w in label_words):
                continue                    # fila de cabecera
            value = _clean_hex(_ocr(cell_i, psm=6, lang="eng", whitelist=whitelist))
            if not value:
                continue
            if label is None:
                if first and pending is not None:                       # continuación de la fila anterior
                    pending["value"] += value
                    pending["cont"] = True
                else:
                    rows.append({"page": page_no, "kind": "desconocido", "value": value, "cont": False})
                first = False
                continue
            if pending is not None:
                rows.append(pending)
            pending = {"page": page_no, "kind": _norm_kind(label), "value": value, "cont": False}
            first = False
        if pending is not None and bands:
            rows.append(pending)
            pending = None
    return rows


def table_rows(path: str | Path, page_nos: list[int], dpis: tuple[int, ...] = (300, 400, 500), whitelist: str | None = HEX_ALPHABET) -> list[HashRow]:
    """Lee las tablas de hashes de las páginas indicadas, fila a fila, a varias resoluciones. Una fila solo es válida si TODAS las lecturas
    coinciden y su longitud es la de su tipo: la longitud sola no detecta un carácter mal leído (p. ej. un 0 leído como e). Si las
    lecturas difieren, la fila queda como `discrepancia_ocr` y no genera IOC. Una fila cortada por el borde de la página (sin línea de
    cierre) no se lee: la tabla se informa con huecos en lugar de inventar su final."""
    passes = [_table_pass(path, page_nos, d, whitelist) for d in dpis]
    ref = passes[len(passes) // 2]
    aligned = all(len(ps) == len(ref) for ps in passes)
    out: list[HashRow] = []
    for i, base in enumerate(ref):
        reads = [ps[i] for ps in passes] if aligned else [base]
        agree = aligned and all(r["value"] == base["value"] and r["kind"] == base["kind"] for r in reads)
        row = _finish(base)
        if not agree and row.status in ("ok", "longitud_invalida", "continuacion_incompleta"):
            row = HashRow(row.page, row.kind, row.value, row.expected, "discrepancia_ocr")
        out.append(row)
    return out


def _finish(p: dict) -> HashRow:
    if p["kind"] == "desconocido":
        return HashRow(p["page"], "desconocido", p["value"], 0, "sin_tipo")
    exp = EXPECTED.get(p["kind"], 0)
    if len(p["value"]) == exp:
        return HashRow(p["page"], p["kind"], p["value"], exp, "ok")
    return HashRow(p["page"], p["kind"], p["value"], exp, "continuacion_incompleta" if p.get("cont") else "longitud_invalida")


def read_pdf(path: str | Path, ocr: str = "auto", dpi: int = 300, lang: str = "eng+spa") -> PdfRead:
    """Texto por página (capa de texto u OCR) y filas de las tablas de hashes de las páginas sin texto. `ocr`: auto | siempre | nunca."""
    inv = inventory(path)
    pages, methods, warnings = [], [], []
    import pymupdf

    with pymupdf.open(str(path)) as doc:
        for info in inv:
            if ocr != "siempre" and info.kind == "texto":
                pages.append(doc[info.page - 1].get_text())
                methods.append("texto")
            elif ocr == "nunca":
                pages.append("")
                methods.append("sin_texto")
                warnings.append(f"Página {info.page}: sin capa de texto y el OCR está desactivado.")
            else:
                pages.append(_ocr(_render(path, info.page, dpi), psm=4, lang=lang))
                methods.append("ocr")
    image_pages = [i.page for i in inv if i.kind != "texto"] if ocr != "nunca" else []
    rows = table_rows(path, image_pages) if image_pages else []
    if image_pages:
        warnings.append(f"Páginas leídas con OCR: {image_pages}. Un hash leído por OCR solo se acepta si su longitud cuadra con su tipo.")
    return PdfRead(inv, pages, methods, rows, warnings)


def analyze(path: str | Path, reference_text: str | None = None, **kw) -> tuple[I.Extraction, PdfRead, dict | None]:
    """Documento -> IOCs. Todo hash leído por OCR sale con la etiqueta `ocr_sin_verificar` y NO entra a la lista de bloqueo hasta contrastarlo
    con una fuente de texto (`reference_text`, p. ej. la página web del boletín). Las filas que no cuadran van a dudosos."""
    pdf = read_pdf(path, **kw)
    ex = I.extract(pdf.pages)
    ocr_pages = {n for n, m in enumerate(pdf.methods, start=1) if m == "ocr"}
    table_pages = {r.page for r in pdf.rows}
    # el OCR de página completa deja fragmentos hex sueltos de la tabla: se sustituyen por el resultado fila a fila
    ex.doubtful[:] = [d for d in ex.doubtful if not (d.page in table_pages and d.reason.startswith("hex"))]
    ex.iocs[:] = [I.IOC(i.kind, i.value, i.pages, i.count, tuple(sorted({*i.tags, I.UNVERIFIED})))
                  if i.kind in I.HASH_KINDS.values() and set(i.pages) <= ocr_pages else i for i in ex.iocs]
    have = {(i.kind, i.value) for i in ex.iocs}
    for r in pdf.rows:
        if r.status == "ok":
            if (r.kind, r.value) not in have:
                ex.iocs.append(I.IOC(r.kind, r.value, (r.page,), 1, ("ocr_tabla", I.UNVERIFIED)))
                have.add((r.kind, r.value))
        else:
            why = {"longitud_invalida": "longitud distinta de la de su tipo",
                   "discrepancia_ocr": "las lecturas de OCR a distintas resoluciones no coinciden",
                   "continuacion_incompleta": "fila partida entre páginas, falta parte del hash",
                   "sin_tipo": "fila sin tipo legible"}[r.status]
            ex.doubtful.append(I.Doubtful(r.page, f"hash {r.kind}: {why} (esperada {r.expected or '?'}, leída {r.length})", r.length, r.value))
    ex.iocs.sort(key=lambda i: (I.KIND_ORDER.index(i.kind), -i.count, i.value))
    report = I.verify_hashes(ex, reference_text) if reference_text else None
    return ex, pdf, report
