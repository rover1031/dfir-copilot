"""PDF-b.1: consultar un documento sin dárselo entero al modelo. Lo esencial: la búsqueda devuelve el pasaje correcto con su página; una cita
inventada o puesta en otra página se rechaza; el resumen extractivo es determinista y cita páginas; y lo que saldría hacia el modelo queda
registrado y acotado."""
import pytest

from dfir_copilot.documents import search as S

PAGES = [
    "The operation moves from access to full network encryption at striking speed.\n\n"
    "Initial access appears to come from exposed firewall management interfaces, unpatched devices, or stolen VPN credentials.",
    "Attackers used vulnerable drivers to terminate antivirus and endpoint detection processes before encryption.\n\n"
    "Backup services were then disabled, often immediately before encryption. Event logs were also cleared.",
    "Contact the group at hxxps://tox.example.chat/download and check evil.example.ru or 203.0.113.9 for staging.",
]


def test_la_busqueda_devuelve_el_pasaje_correcto_con_su_pagina():
    idx = S.Index(PAGES)
    top = idx.search("how did they get initial access VPN credentials", k=3)
    assert top and top[0].passage.page == 1 and "VPN credentials" in top[0].passage.text
    assert idx.search("backup services disabled")[0].passage.page == 2


def test_un_ioc_se_busca_entero():
    idx = S.Index(PAGES)
    assert idx.search("203.0.113.9")[0].passage.page == 3 and idx.search("evil.example.ru")[0].passage.page == 3


def test_sin_coincidencias_no_inventa_nada():
    assert S.Index(PAGES).search("zzzz qqqq") == []


def test_la_consulta_debe_estar_en_el_idioma_del_documento():
    idx = S.Index(PAGES)
    assert S.language_hint(PAGES) == "en"
    assert idx.search("desactivan las copias de seguridad") == []          # misma idea, otro idioma: la búsqueda léxica no la une
    assert S.language_hint(["El informe describe cómo los atacantes desactivan las copias de seguridad de la empresa."]) == "es"


def test_verificar_cita():
    assert S.verify_quote(PAGES, 2, "Backup services were then DISABLED, often immediately before encryption")
    assert not S.verify_quote(PAGES, 1, "Backup services were then disabled, often immediately before encryption")   # página equivocada
    assert not S.verify_quote(PAGES, 2, "They deleted all the shadow copies with vssadmin")                         # inventada
    assert not S.verify_quote(PAGES, 2, "Backup")                                                                    # demasiado corta
    assert not S.verify_quote(PAGES, 9, "Backup services were then disabled")                                        # página inexistente


def test_pagina_inexistente_da_error_claro():
    with pytest.raises(IndexError, match="3 páginas"):
        S.Index(PAGES).page(7)


def test_resumen_extractivo_determinista_con_paginas():
    long_pages = PAGES + ["Encryption of backup services was a deliberate step. Attackers cleared event logs before encryption started."]
    a, b = S.key_sentences(long_pages, n=3), S.key_sentences(long_pages, n=3)
    assert a == b and 1 <= len(a) <= 3
    assert all(isinstance(p, int) and 1 <= p <= 4 and s for p, s in a)
    assert [p for p, _ in a] == sorted(p for p, _ in a)                      # en el orden del documento


def test_lo_que_sale_hacia_el_modelo_se_registra_y_se_acota():
    idx = S.Index(PAGES * 4)
    hits = idx.search("encryption backup", k=6)
    text, out = S.prepare_for_model(hits, max_chars=500)
    assert out.chars == len(text) <= 500 and text.startswith("[p.") and set(out.pages) <= set(range(1, 13))
    assert len(out.sha256) == 64
    text2, out2 = S.prepare_for_model(hits, max_chars=500)
    assert (text, out) == (text2, out2)                                       # determinista
    assert S.prepare_for_model([], 500)[0] == ""


def test_pasajes_largos_se_parten_y_cortos_se_unen():
    short = "uno.\n\ndos.\n\ntres."
    assert len(S.split_passages([short])) == 1
    big = " ".join(f"Frase numero {i} del documento largo." for i in range(120))
    parts = S.split_passages([big])
    assert len(parts) > 1 and all(len(p.text) <= 1100 for p in parts)


def test_la_cabecera_y_el_pie_repetidos_no_son_pasajes_ni_resumen():
    pages = [f"6/10/26 Titulo del articulo en cada pagina\nCuerpo {n}: attackers disabled backup services before encryption and cleared logs.\n"
             f"https://sitio-editor.com/nota/ {n}/6" for n in range(1, 7)]
    idx = S.Index(pages)
    assert not any("sitio-editor" in p.text or "Titulo del articulo" in p.text for p in idx.passages)
    assert not any("sitio-editor" in s or "Titulo del articulo" in s for _, s in S.key_sentences(pages, n=6, min_chars=20))
    assert S.verify_quote(pages, 3, "https://sitio-editor.com/nota/ 3/6")          # la cita se verifica contra el texto original
