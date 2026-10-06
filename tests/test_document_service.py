"""PDF-a.3: análisis de un documento a una carpeta. Lo esencial: el manifest lleva la huella del PDF; la lista de bloqueo no incluye lo
privado, lo conocido ni lo no verificado; los hashes leídos por OCR quedan como candidatos y se verifican DESPUÉS sin repetir el OCR; y el
resultado guardado se puede releer y consultar."""
import csv
import hashlib
import json
import shutil

import pytest

pymupdf = pytest.importorskip("pymupdf")

from test_pdf_reader import MD5, SHA1, _table_pdf  # noqa: E402

from dfir_copilot.documents import iocs as I  # noqa: E402
from dfir_copilot.documents import pdf_reader as R  # noqa: E402
from dfir_copilot.documents import service as D  # noqa: E402

needs_tesseract = pytest.mark.skipif(shutil.which("tesseract") is None, reason="falta el binario tesseract")
SHA256 = hashlib.sha256(b"doc-sha256").hexdigest()


class FakeGeo:
    def country(self, ip):
        return {"8.8.8.8": "US", "1.1.1.1": "AU"}.get(ip)


def _text_pdf(tmp_path):
    body = (f"Threat report. The actor staged tools on evil.example.ru and 8.8.8.8, also 1.1.1.1 and internal 10.0.0.5. "
            f"Contact via https://x.com/ and https://tox.example.chat/dl. Sample hashes {MD5} and {SHA256}. "
            "Attackers disabled backup services before encryption and cleared event logs afterwards.")
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_textbox(pymupdf.Rect(40, 40, 555, 400), body, fontsize=10)
    path = tmp_path / "boletin_texto.pdf"
    doc.save(str(path))
    return path


def _rows(path):
    return list(csv.DictReader(path.open(encoding="utf-8")))


def test_analisis_de_un_pdf_con_texto_deja_todos_los_resultados(tmp_path):
    pdf = _text_pdf(tmp_path)
    out = tmp_path / "out"
    manifest = D.analyze_to_dir(pdf, out, geo=FakeGeo())
    assert manifest["source"]["sha256"] == hashlib.sha256(pdf.read_bytes()).hexdigest() and manifest["methods"] == {"texto": 1}
    for name in ("manifest.json", "extraction.json", "pages.jsonl", "iocs.csv", "candidatos_ocr.csv", "dudosos.csv", "resumen.json"):
        assert (out / name).is_file(), name
    assert not list(out.glob("*.tmp"))                                              # escrituras atómicas: no queda nada a medias
    values = {r["valor"] for r in _rows(out / "iocs.csv")}
    assert {MD5, SHA256, "8.8.8.8", "1.1.1.1", "evil.example.ru", "tox.example.chat"} <= values
    assert not values & {"10.0.0.5", "x.com", "https://x.com/"}                    # privada y servicio conocido fuera de la lista de bloqueo
    summary = json.loads((out / "resumen.json").read_text(encoding="utf-8"))
    assert dict((c, n) for c, n, _ in summary["paises"]) == {"US": 1, "AU": 1} and summary["idioma"] == "en"
    assert summary["hashes_sin_verificar"] == 0 and summary["resumen_extractivo"]


def test_sin_base_geoip_se_dice_en_lugar_de_inventar_paises(tmp_path):
    out = tmp_path / "out"
    D.analyze_to_dir(_text_pdf(tmp_path), out)
    summary = json.loads((out / "resumen.json").read_text(encoding="utf-8"))
    assert summary["paises"] is None and "GeoIP" in summary["paises_nota"]


def test_el_resultado_se_relee_y_se_consulta(tmp_path):
    out = tmp_path / "out"
    D.analyze_to_dir(_text_pdf(tmp_path), out)
    data = D.load(out)
    assert len(data["pages"]) == 1 and data["extraction"].pages == 1
    assert D.dump_extraction(D.load_extraction(D.dump_extraction(data["extraction"]))) == D.dump_extraction(data["extraction"])
    hit = D.open_index(out).search("backup services disabled encryption")[0]
    assert hit.passage.page == 1


def test_errores_claros(tmp_path):
    with pytest.raises(D.DocumentError, match="No existe"):
        D.analyze_to_dir(tmp_path / "no_existe.pdf", tmp_path / "out")
    (tmp_path / "vacio").mkdir()
    with pytest.raises(D.DocumentError, match="no está completo"):
        D.load(tmp_path / "vacio")
    with pytest.raises(D.DocumentError, match="vacío"):
        D.verify_document(tmp_path / "vacio", "  ")


def test_verificar_despues_corrige_y_actualiza_los_archivos_sin_ocr(tmp_path, monkeypatch):
    out = tmp_path / "out"
    D.analyze_to_dir(_text_pdf(tmp_path), out)
    ex = D.load(out)["extraction"]
    bad = SHA1[:20] + ("0" if SHA1[20] != "0" else "1") + SHA1[21:]                      # un hash de OCR con un carácter mal leído
    ex.iocs.append(I.IOC("sha1", bad, (1,), 1, ("ocr_tabla", I.UNVERIFIED)))
    D._atomic(out / "extraction.json", json.dumps(D.dump_extraction(ex)))
    monkeypatch.setattr(R, "_ocr", lambda *a, **k: (_ for _ in ()).throw(AssertionError("verificar no debe repetir el OCR")))
    report = D.verify_document(out, f"fuente de texto\n{SHA1}\n")
    assert report["corregidos"] == [(bad, SHA1)] and report["sin_confirmar"] == 0
    assert SHA1 in {r["valor"] for r in _rows(out / "iocs.csv")} and _rows(out / "candidatos_ocr.csv") == []
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["reference"]["sha256"] == hashlib.sha256(f"fuente de texto\n{SHA1}\n".encode()).hexdigest()
    assert json.loads((out / "resumen.json").read_text(encoding="utf-8"))["hashes_sin_verificar"] == 0


@needs_tesseract
def test_pdf_raster_deja_candidatos_y_se_verifica_despues_sin_repetir_el_ocr(tmp_path, monkeypatch):
    out = tmp_path / "out"
    manifest = D.analyze_to_dir(_table_pdf(tmp_path, [("MD5", MD5, (28, 4)), ("SHA-1", SHA1, (28, 12))]), out)
    assert manifest["methods"] == {"ocr": 1}
    assert not any(r["tipo"] in ("md5", "sha1") for r in _rows(out / "iocs.csv"))               # nada sin verificar en la lista de bloqueo
    assert {r["valor"] for r in _rows(out / "candidatos_ocr.csv")} == {MD5, SHA1}
    summary = json.loads((out / "resumen.json").read_text(encoding="utf-8"))
    assert summary["hashes_sin_verificar"] == 2 and any("sin verificar" in a for a in summary["avisos"])
    monkeypatch.setattr(R, "_ocr", lambda *a, **k: (_ for _ in ()).throw(AssertionError("sin OCR")))
    monkeypatch.setattr(R, "_ocr_words", lambda *a, **k: (_ for _ in ()).throw(AssertionError("sin OCR")))
    D.verify_document(out, f"{MD5}\n{SHA1}")
    assert {r["valor"] for r in _rows(out / "iocs.csv")} == {MD5, SHA1} and _rows(out / "candidatos_ocr.csv") == []


# --- PDF-a.4: estado y trabajo en segundo plano ------------------------------------------------------------------

def test_run_job_deja_el_estado_final(tmp_path):
    out = tmp_path / "doc"
    assert D.read_state(out) == {} and D.run_job(_text_pdf(tmp_path), out) == "done"
    assert D.read_state(out)["state"] == "done" and (out / "manifest.json").is_file()


def test_run_job_con_pdf_danado_queda_failed_con_motivo_y_no_propaga(tmp_path):
    bad = tmp_path / "roto.pdf"
    bad.write_bytes(b"esto no es un pdf")
    out = tmp_path / "doc"
    assert D.run_job(bad, out) == "failed"
    st = D.read_state(out)
    assert st["state"] == "failed" and st["error"]
    assert D.run_job(tmp_path / "no_existe.pdf", tmp_path / "otro") == "failed"


def test_estado_danado_se_informa_en_lugar_de_romper(tmp_path):
    (tmp_path / "doc").mkdir()
    (tmp_path / "doc" / D.STATE_FILE).write_text("{no es json", encoding="utf-8")
    assert D.read_state(tmp_path / "doc")["state"] == "failed"


@needs_tesseract
def test_pdf_raster_termina_en_needs_attention_y_verificar_lo_deja_en_done(tmp_path):
    out = tmp_path / "doc"
    assert D.run_job(_table_pdf(tmp_path, [("MD5", MD5, (28, 4)), ("SHA-1", SHA1, (28, 12))]), out) == "needs_attention"
    D.verify_document(out, f"{MD5}\n{SHA1}")
    assert D.read_state(out)["state"] == "done"
