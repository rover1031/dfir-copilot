"""Consultar un documento sin dárselo entero al modelo (PDF-b.1). Funciones puras, sin red ni modelo.

* `Index`: pasajes del documento y búsqueda BM25. Devuelve pasajes con su página; el agente cita páginas, no inventa.
* `verify_quote`: comprueba que una cita del modelo existe de verdad en la página que dice (insensible a mayúsculas, acentos y espacios).
* `key_sentences`: resumen EXTRACTIVO (frases centrales del documento, en su orden y con su página), sin modelo.
* `prepare_for_model`: arma el texto que saldría hacia el modelo y deja constancia de qué páginas y cuántos caracteres son. Por defecto solo
  salen los pasajes que la pregunta necesita, nunca el documento completo.
* `language_hint`: idioma probable del documento. La búsqueda es léxica: el agente debe formular la consulta en el idioma del DOCUMENTO
  (un boletín en inglés no responde a una consulta en español).
"""
from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

from dfir_copilot.documents.iocs import strip_repeated

_STOP_EN = frozenset(["the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "by", "from", "at", "as", "is", "are", "was", "were", "be", "been", "it", "its", "this", "that", "these", "those", "not", "no", "but", "if", "then", "than", "which", "who", "whom", "their", "they", "them", "we", "you", "he", "she", "his", "her", "our", "your", "has", "have", "had", "do", "does", "did", "can", "could", "would", "should", "will", "may", "might", "also", "into", "over", "under", "between", "about", "after", "before", "such"])
_STOP_ES = frozenset(["el", "la", "los", "las", "un", "una", "unos", "unas", "y", "o", "de", "del", "al", "en", "con", "por", "para", "como", "es", "son", "fue", "fueron", "ser", "se", "su", "sus", "lo", "le", "les", "que", "qué", "cual", "cuál", "quien", "no", "pero", "si", "sí", "más", "menos", "muy", "también", "entre", "sobre", "tras", "desde", "hasta", "este", "esta", "estos", "estas", "ese", "esa", "eso", "esto", "hay", "ha", "han", "he", "había", "puede", "pueden", "donde", "cuando", "cómo", "cuánto"])
_STOP = _STOP_EN | _STOP_ES
_TOKEN = re.compile(r"[a-z0-9]+(?:[._:-][a-z0-9]+)*")
_SENT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9¿¡\"“])")


def _plain(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii").lower()


def tokens(text: str) -> list[str]:
    """Palabras sin acentos ni palabras vacías. Un dominio, una IP o un hash se conservan enteros y además se parten (dominio y partes)."""
    out = []
    for tok in _TOKEN.findall(_plain(text)):
        if "." in tok or "-" in tok or "_" in tok or ":" in tok:
            out.append(tok)
            out += [p for p in re.split(r"[._:-]", tok) if len(p) >= 3 and p not in _STOP]
        elif len(tok) >= 2 and tok not in _STOP:
            out.append(tok)
    return out


def language_hint(pages: list[str]) -> str:
    words = _TOKEN.findall(_plain(" ".join(pages)))
    en, es = sum(w in _STOP_EN for w in words), sum(w in _STOP_ES for w in words)
    return "en" if en > es else ("es" if es > en else "desconocido")


@dataclass(frozen=True)
class Passage:
    page: int
    index: int
    text: str


@dataclass(frozen=True)
class Hit:
    passage: Passage
    score: float


@dataclass(frozen=True)
class Outgoing:
    """Lo que saldría hacia el modelo: páginas, caracteres y huella del texto (el texto en sí queda en el ledger local)."""
    pages: tuple[int, ...]
    chars: int
    sha256: str


def split_passages(pages: list[str], min_chars: int = 200, max_chars: int = 1100) -> list[Passage]:
    out: list[Passage] = []
    for n, text in enumerate(pages, start=1):
        blocks = [" ".join(b.split()) for b in re.split(r"\n\s*\n", text) if b.strip()]
        merged: list[str] = []
        for b in blocks:
            if merged and len(merged[-1]) < min_chars:
                merged[-1] += " " + b
            else:
                merged.append(b)
        for b in merged:
            while len(b) > max_chars:
                cut = max(b.rfind(". ", 0, max_chars), b.rfind(" ", 0, max_chars))
                cut = cut + 1 if cut > max_chars // 2 else max_chars
                out.append(Passage(n, len(out), b[:cut].strip()))
                b = b[cut:].strip()
            if b:
                out.append(Passage(n, len(out), b))
    return out


class Index:
    def __init__(self, pages: list[str]):
        self.pages = list(pages)                                   # texto original: las citas se verifican contra él
        self.passages = split_passages(strip_repeated(pages)[0])   # sin cabecera/pie repetidos: no son contenido
        self._tf = [Counter(tokens(p.text)) for p in self.passages]
        self._len = [sum(c.values()) for c in self._tf]
        self._avg = (sum(self._len) / len(self._len)) if self._len else 0.0
        self._df: Counter = Counter()
        for c in self._tf:
            self._df.update(c.keys())

    def search(self, query: str, k: int = 5, k1: float = 1.5, b: float = 0.75) -> list[Hit]:
        q = list(dict.fromkeys(tokens(query)))
        n = len(self.passages)
        scored = []
        for i, tf in enumerate(self._tf):
            s = 0.0
            for t in q:
                f = tf.get(t, 0)
                if f:
                    idf = math.log(1 + (n - self._df[t] + 0.5) / (self._df[t] + 0.5))
                    s += idf * f * (k1 + 1) / (f + k1 * (1 - b + b * self._len[i] / (self._avg or 1)))
            if s > 0:
                scored.append(Hit(self.passages[i], round(s, 4)))
        scored.sort(key=lambda h: (-h.score, h.passage.page, h.passage.index))
        return scored[:k]

    def page(self, number: int) -> str:
        if not 1 <= number <= len(self.pages):
            raise IndexError(f"El documento tiene {len(self.pages)} páginas; no existe la {number}.")
        return self.pages[number - 1]


def _norm_quote(text: str) -> str:
    return " ".join(re.sub(r"\W+", " ", _plain(text)).split())


def verify_quote(pages: list[str], page: int, quote: str, min_chars: int = 12) -> bool:
    """¿La cita aparece de verdad en esa página? Una cita demasiado corta no prueba nada y se rechaza."""
    q = _norm_quote(quote)
    return len(q) >= min_chars and 1 <= page <= len(pages) and q in _norm_quote(pages[page - 1])


def key_sentences(pages: list[str], n: int = 5, min_chars: int = 40, max_chars: int = 400) -> list[tuple[int, str]]:
    """Resumen extractivo: las `n` frases más centrales (las que más repiten los términos frecuentes del documento), en su orden."""
    sents = []
    for p, text in enumerate(strip_repeated(pages)[0], start=1):
        for s in _SENT.split(" ".join(text.split())):
            if min_chars <= len(s) <= max_chars and not re.fullmatch(r"[\W\d_]*", s):
                sents.append((p, s.strip()))
    doc = Counter(t for _, s in sents for t in set(tokens(s)))
    scored = []
    for i, (_p, s) in enumerate(sents):
        toks = set(tokens(s))
        if toks:
            scored.append((sum(doc[t] - 1 for t in toks) / math.sqrt(len(toks)), i))
    top = sorted(sorted(scored, key=lambda x: (-x[0], x[1]))[:n], key=lambda x: x[1])
    return [sents[i] for _, i in top]


def prepare_for_model(hits: list[Hit], max_chars: int = 6000) -> tuple[str, Outgoing]:
    """Texto con los pasajes (cada uno marcado con su página) que saldrían hacia el modelo, y su registro. Se corta en `max_chars`."""
    parts, used, pages = [], 0, []
    for h in hits:
        block = f"[p.{h.passage.page}] {h.passage.text}"
        if used + len(block) > max_chars:
            break
        parts.append(block)
        used += len(block)
        pages.append(h.passage.page)
    text = "\n\n".join(parts)
    return text, Outgoing(tuple(sorted(set(pages))), len(text), hashlib.sha256(text.encode("utf-8")).hexdigest())
