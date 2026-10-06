"""PDF-a.1: IOCs desde texto. Lo esencial: solo entra lo que tiene la forma correcta; lo dudoso se separa y no llega al CSV de bloqueo;
los hashes partidos por una celda de tabla se reconstruyen (incluida una continuación de 1 carácter); la cabecera/pie repetidos no cuentan
como IOC; y los servicios conocidos se etiquetan en lugar de esconderse. Los valores son sintéticos (hashlib), no IOCs reales."""
import csv
import hashlib

from dfir_copilot.documents import iocs as I

MD5 = hashlib.md5(b"a").hexdigest()
SHA1 = hashlib.sha1(b"a").hexdigest()
SHA256 = hashlib.sha256(b"a").hexdigest()


def kinds(ex, kind):
    return {i.value: i for i in ex.iocs if i.kind == kind}


def test_hashes_validos_por_longitud_y_normalizados_a_minusculas():
    ex = I.extract([f"md5 {MD5.upper()} sha1 {SHA1} sha256 {SHA256}"])
    assert set(kinds(ex, "md5")) == {MD5} and set(kinds(ex, "sha1")) == {SHA1} and set(kinds(ex, "sha256")) == {SHA256}


def test_hex_de_longitud_invalida_va_a_dudosos_y_no_es_ioc():
    ex = I.extract([f"posible {MD5}0 y fragmento {SHA256[:28]}"])
    assert not any(i.kind in ("md5", "sha1", "sha256") for i in ex.iocs)
    assert sorted(d.length for d in ex.doubtful) == [28, 33]


def test_un_numero_largo_no_es_un_hash():
    assert I.extract(["1" * 32 + " " + "2" * 40]).iocs == []


def test_hash_partido_en_celda_se_reconstruye():
    page = "\n".join(["MD5", MD5[:28], MD5[28:], "Descripcion", "SHA-256", SHA256[:28], SHA256[28:56], SHA256[56:], "Descripcion"])
    ex = I.extract([page])
    assert set(kinds(ex, "md5")) == {MD5} and set(kinds(ex, "sha256")) == {SHA256} and ex.doubtful == []


def test_continuacion_de_un_solo_caracter():
    page = "\n".join(["SHA-1", SHA1[:39], SHA1[39:], "Descripcion"])
    assert set(kinds(I.extract([page]), "sha1")) == {SHA1}


def test_fragmento_que_no_cuadra_no_se_une_y_queda_dudoso():
    page = "\n".join(["SHA-1", SHA1[:28], SHA1[28:35], "Descripcion"])  # faltan 5 caracteres
    ex = I.extract([page])
    assert not kinds(ex, "sha1") and [d.length for d in ex.doubtful] == [28]


def test_ips_publicas_privadas_y_formas_invalidas():
    ex = I.extract(["C2 8.8.8.8 y 10.0.0.5; version v1.2.3.4; 999.1.1.1; 01.2.3.4; fin 1.1.1.1."])
    ips = kinds(ex, "ip")
    assert set(ips) == {"8.8.8.8", "10.0.0.5", "1.1.1.1"}
    assert "no_publica" in ips["10.0.0.5"].tags and "no_publica" not in ips["8.8.8.8"].tags
    assert I.summary(ex)["ips_publicas"] == 2


def test_ofuscacion_url_y_dominio():
    ex = I.extract(["ver hxxps://evil[.]example[.]ru/a.php y correo soc(at)evil[.]ru"])
    assert "https://evil.example.ru/a.php" in kinds(ex, "url")
    assert "evil.example.ru" in kinds(ex, "domain")
    assert "soc@evil.ru" in kinds(ex, "email") and "evil.ru" not in kinds(ex, "domain")  # el dominio del correo no cuenta aparte


def test_nombres_de_archivo_no_son_dominios():
    ex = I.extract(["powershell.exe lanzo Setup.dll y readme.txt y script.ps1 y a.php"])
    assert kinds(ex, "domain") == {}


def test_onion_valido_e_invalido():
    name = "abcdefghijklmnopqrstuvwxyz234567" + "abcdefghijklmnopqrstuvwx"  # 56 caracteres base32
    ex = I.extract([f"blog http://{name}.onion/ y roto abcdefghij.onion"])
    assert set(kinds(ex, "onion")) == {f"{name}.onion"}
    assert [d.length for d in ex.doubtful] == [10]


def test_cve():
    assert set(kinds(I.extract(["explotan cve-2024-21762 y CVE-2023-27997"]), "cve")) == {"CVE-2024-21762", "CVE-2023-27997"}


def test_cabecera_y_pie_repetidos_no_son_iocs():
    pages = [f"6/10/26 titulo del articulo\ncuerpo {n} evil{n}.ru\nhttps://sitio-editor.com/nota/\n{n}/6" for n in range(1, 7)]
    ex = I.extract(pages)
    assert "sitio-editor.com" not in kinds(ex, "domain")
    assert {f"evil{n}.ru" for n in range(1, 7)} <= set(kinds(ex, "domain"))
    assert any("sitio-editor.com" in line for line in ex.removed_lines)


def test_una_linea_de_hash_nunca_se_quita_por_repetida():
    pages = [f"cabecera comun larga\n{SHA256}" for _ in range(4)]
    ex = I.extract(pages)
    assert kinds(ex, "sha256")[SHA256].count == 4 and kinds(ex, "sha256")[SHA256].pages == (1, 2, 3, 4)


def test_servicio_conocido_se_etiqueta_no_se_esconde_y_no_va_al_csv(tmp_path):
    text = f"contacto https://x.com/ y https://tor.example.ru/dl y {MD5} y 8.8.8.8 y 10.0.0.5 y {SHA256[:30]}"
    ex = I.extract([text])
    assert "servicio_conocido" in kinds(ex, "domain")["x.com"].tags and "servicio_conocido" in kinds(ex, "url")["https://x.com/"].tags
    path = I.write_csv(ex, tmp_path / "out" / "iocs.csv")
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    values = {r["valor"] for r in rows}
    assert {MD5, "8.8.8.8", "tor.example.ru", "https://tor.example.ru/dl"} <= values
    assert not values & {"x.com", "https://x.com/", "10.0.0.5", SHA256[:30]}


def test_estadisticas_y_paises_con_base_local():
    class Geo:
        def country(self, ip):
            return {"1.1.1.1": "AU", "8.8.8.8": "US", "9.9.9.9": "US"}.get(ip)

    ex = I.extract(["8.8.8.8 8.8.8.8 1.1.1.1", "9.9.9.9 8.8.8.8 7.7.7.7"])
    assert I.countries(ex, Geo()) == [("US", 2, 4), ("AU", 1, 1), ("desconocido", 1, 1)]
    s = I.summary(ex)
    assert s["unicos_por_tipo"] == {"ip": 4} and s["menciones_totales"] == 6 and s["top_por_menciones"][0] == ("ip", "8.8.8.8", 3)
    assert s["iocs_por_pagina"] == {1: 2, 2: 3}


def test_sin_iocs_se_dice_explicitamente():
    s = I.summary(I.extract(["texto sin indicadores"]))
    assert s["unicos_por_tipo"] == {} and s["ips_publicas"] == 0 and s["menciones_totales"] == 0


def test_lineas_que_solo_difieren_en_digitos_de_un_ioc_no_se_tratan_como_pie():
    pages = [f"indicador de red: 45.33.1.{n}" for n in range(1, 7)]
    ex = I.extract(pages)
    assert ex.removed_lines == [] and len(kinds(ex, "ip")) == 6


def test_el_host_de_una_url_es_dominio_aunque_su_tld_no_este_en_la_lista():
    ex = I.extract(["descarga https://tox.example.chat/download.html y http://203.0.113.9/x y https://usuario@host.example.chat:8443/a"])
    assert {"tox.example.chat", "host.example.chat"} <= set(kinds(ex, "domain"))
    assert "203.0.113.9" not in kinds(ex, "domain")


# --- PDF-a.2: candidatos de OCR y verificación contra una fuente de texto -----------------------------------------

def _ocr_extraction():
    bad_sha1 = SHA1[:20] + ("0" if SHA1[20] != "0" else "1") + SHA1[21:]            # un carácter mal leído
    return I.Extraction(
        1,
        [I.IOC("md5", MD5, (1,), 1, ("ocr_tabla", I.UNVERIFIED)), I.IOC("sha1", bad_sha1, (1,), 1, ("ocr_tabla", I.UNVERIFIED))],
        [I.Doubtful(1, "hash sha256: longitud distinta de la de su tipo (esperada 64, leída 63)", 63, SHA256[:-1])],
    )


def test_los_candidatos_de_ocr_no_entran_a_la_lista_de_bloqueo():
    ex = _ocr_extraction()
    assert I.priority_rows(ex) == [] and len(I.candidate_rows(ex)) == 2


def test_verificar_contra_una_fuente_confirma_corrige_y_registra():
    ex = _ocr_extraction()
    rep = I.verify_hashes(ex, f"fuente:\n{MD5}\n{SHA1}\n{SHA256}\n")
    assert rep["verificados"] == 1 and len(rep["corregidos"]) == 2 and rep["sin_confirmar"] == 0
    assert {r["valor"] for r in I.priority_rows(ex)} == {MD5, SHA1, SHA256}
    assert ex.doubtful == []
    assert {i.value: i.tags for i in ex.iocs}[SHA1] == ("corregido_con_fuente", "ocr_tabla")


def test_si_dos_hashes_de_la_fuente_son_igual_de_parecidos_no_se_corrige():
    base = SHA1[:20] + "0" + SHA1[21:]
    a, b = SHA1[:20] + "1" + SHA1[21:], SHA1[:20] + "2" + SHA1[21:]               # a y b están a la misma distancia de `base`
    ex = I.Extraction(1, [I.IOC("sha1", base, (1,), 1, (I.UNVERIFIED,))])
    rep = I.verify_hashes(ex, f"{a}\n{b}")
    assert rep["sin_confirmar"] == 1 and [i.value for i in ex.iocs if i.kind == "sha1"] == []


def test_la_fuente_dice_que_hashes_faltan_en_el_documento():
    ex = I.Extraction(1, [I.IOC("md5", MD5, (1,), 1, (I.UNVERIFIED,))])
    rep = I.verify_hashes(ex, f"{MD5}\n{SHA1}")
    assert rep["en_la_fuente_y_no_en_el_documento"] == [SHA1]
