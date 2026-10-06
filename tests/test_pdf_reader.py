"""PDF-a.2: inventario de páginas y lectura de una tabla de hashes de un PDF SIN capa de texto (como el de «Microsoft Print to PDF»).
El PDF raster se fabrica en el test, con valores sintéticos. Lo esencial: una página sin texto se detecta; los hashes leídos por OCR salen
como candidatos sin verificar y NO llegan a la lista de bloqueo; un hash truncado (longitud distinta de su tipo) queda como dudoso; y
contrastar con una fuente de texto los promueve."""
import hashlib
import io
import shutil

import pytest

pymupdf = pytest.importorskip("pymupdf")
PIL_Image = pytest.importorskip("PIL.Image")
from PIL import ImageDraw, ImageFont  # noqa: E402

from dfir_copilot.documents import iocs as I  # noqa: E402
from dfir_copilot.documents import pdf_reader as R  # noqa: E402

needs_tesseract = pytest.mark.skipif(shutil.which("tesseract") is None, reason="falta el binario tesseract")

MD5 = hashlib.md5(b"fila-md5").hexdigest()
SHA1 = hashlib.sha1(b"fila-sha1").hexdigest()
SHA256_TRUNC = hashlib.sha256(b"fila-sha256").hexdigest()[:59]          # como en la fuente real: truncado


def _font(size: int):
    for path in ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/usr/share/fonts/dejavu/DejaVuSansMono.ttf"):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


def _table_pdf(tmp_path, rows):
    """Una página A4 a 300 dpi con una tabla Type | Indicator | Description dibujada como imagen (sin texto en el PDF)."""
    W, H = 2480, 3508
    img = PIL_Image.new("L", (W, H), 255)
    d = ImageDraw.Draw(img)
    font = _font(40)
    x = (200, 640, 1900, 2300)
    y = 300
    d.text((x[0] + 20, y + 15), "Type", font=font, fill=0)
    d.text((x[1] + 20, y + 15), "Indicator", font=font, fill=0)
    d.text((x[2] + 20, y + 15), "Description", font=font, fill=0)
    edges = [y, y + 80]
    for kind, value, widths in rows:
        lines, pos = [], 0
        for w in widths:
            lines.append(value[pos:pos + w])
            pos += w
        top = edges[-1]
        height = 30 + 62 * len(lines)
        d.text((x[0] + 20, top + height // 2 - 24), kind, font=font, fill=0)
        for n, line in enumerate(lines):
            d.text((x[1] + 25, top + 18 + 62 * n), line, font=font, fill=0)
        d.text((x[2] + 20, top + height // 2 - 24), "threat indicator", font=font, fill=0)
        edges.append(top + height)
    for e in edges:
        d.line([(x[0], e), (x[3], e)], fill=0, width=5)
    for xv in x:
        d.line([(xv, edges[0]), (xv, edges[-1])], fill=0, width=5)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    doc = pymupdf.open()
    page = doc.new_page(width=595, height=842)
    page.insert_image(page.rect, stream=buf.getvalue())
    path = tmp_path / "boletin_raster.pdf"
    doc.save(str(path))
    return path


def test_inventario_distingue_pagina_con_texto_de_pagina_solo_imagen(tmp_path):
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 100), "Informe con texto seleccionable que supera el umbral minimo de caracteres.")
    doc.save(str(tmp_path / "texto.pdf"))
    assert [i.kind for i in R.inventory(tmp_path / "texto.pdf")] == ["texto"]
    raster = _table_pdf(tmp_path, [("MD5", MD5, (28, 4))])
    info = R.inventory(raster)[0]
    assert info.kind == "solo_imagen" and info.text_chars < R.MIN_TEXT_CHARS


def test_ocr_desactivado_avisa_en_lugar_de_inventar_texto(tmp_path):
    pdf = R.read_pdf(_table_pdf(tmp_path, [("MD5", MD5, (28, 4))]), ocr="nunca")
    assert pdf.pages == [""] and pdf.rows == [] and "OCR está desactivado" in pdf.warnings[0]


@needs_tesseract
def test_tabla_raster_candidatos_sin_verificar_truncado_dudoso_y_verificacion(tmp_path):
    path = _table_pdf(tmp_path, [("MD5", MD5, (28, 4)), ("SHA-1", SHA1, (28, 12)), ("SHA-256", SHA256_TRUNC, (28, 28, 3))])
    ex, pdf, _ = R.analyze(path)
    assert pdf.methods == ["ocr"]
    assert {r.kind: r.status for r in pdf.rows if r.kind != "sha256"} == {"md5": "ok", "sha1": "ok"}
    assert I.priority_rows(ex) == [] and {r["valor"] for r in I.candidate_rows(ex)} == {MD5, SHA1}       # nada llega a la lista de bloqueo
    assert any("sha256" in d.reason for d in ex.doubtful)                                                 # el truncado es dudoso, no IOC
    assert not any(i.kind == "sha256" for i in ex.iocs)
    rep = I.verify_hashes(ex, f"{MD5}\n{SHA1}")
    assert rep["verificados"] == 2 and {r["valor"] for r in I.priority_rows(ex)} == {MD5, SHA1}
