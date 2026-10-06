"""IOCs desde texto: extracción DETERMINISTA, sin modelo (PDF-a.1).

Entrada: el texto de un documento, una cadena por página. Salida: IOCs con sus páginas y menciones, más lo que NO se pudo dar por válido.

Principios:
* Un IOC solo se acepta si tiene la forma correcta (hash de 32/40/64 hex, IPv4 válida, dominio con TLD conocido, .onion de 16/56 caracteres).
  Lo que se le parece pero no cuadra (un hash con un carácter de más, un fragmento partido) va a `doubtful`: nunca entra al CSV de bloqueo.
* Se deshace la ofuscación habitual (hxxp, [.], (dot), [at]) y se unen los hashes que una celda de tabla partió en varias líneas.
* Las líneas que se repiten en casi todas las páginas (cabecera, pie, "1/6") se quitan antes de extraer: el dominio del sitio que publica el
  boletín no es un IOC. Se informa de qué se quitó.
* Los servicios legítimos conocidos (x.com, torproject.org...) NO se descartan: se etiquetan `servicio_conocido` y quedan fuera del CSV de
  bloqueo. La decisión de bloquear sigue siendo del analista.
Límites conocidos: solo IPv4 (IPv6 queda para otra entrega) y un hash partido entre dos páginas se marca como dudoso, no se une.
"""
from __future__ import annotations

import csv
import ipaddress
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

HASH_KINDS = {32: "md5", 40: "sha1", 64: "sha256"}
KIND_ORDER = ("sha256", "sha1", "md5", "ip", "url", "domain", "onion", "email", "cve")

# TLD aceptados: genéricos y países habituales. No incluye los que chocan con extensiones de archivo (.sh .py .pl .rs .md .ps .zip .mov).
TLDS = frozenset(
    ["com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "co", "xyz", "top", "site", "online", "shop", "club", "app", "dev", "cloud", "tech", "store", "live", "icu", "vip", "work", "link", "click", "ac", "ae", "ar", "at", "au", "be", "bg", "br", "by", "ca", "ch", "cl", "cn", "cz", "de", "dk", "do", "ec", "ee", "es", "eu", "fi", "fr", "gb", "gr", "hk", "hr", "hu", "id", "ie", "il", "in", "ir", "is", "it", "jp", "kr", "kz", "lt", "lu", "lv", "mx", "my", "nl", "no", "nz", "pa", "pe", "ph", "pk", "pt", "ro", "ru", "se", "sg", "si", "sk", "th", "tr", "tw", "ua", "uk", "us", "uy", "ve", "vn", "za", "cc", "tv", "me", "gg", "ly", "to", "ws", "su", "pw", "tk", "ml", "ga", "cf", "gq", "cx", "la"])

KNOWN_SERVICES = frozenset(
    ["x.com", "twitter.com", "torproject.org", "google.com", "microsoft.com", "github.com", "youtube.com", "facebook.com", "linkedin.com", "wikipedia.org", "mitre.org", "virustotal.com", "cisa.gov", "nist.gov", "sophos.com", "fortinet.com", "crowdstrike.com", "paloaltonetworks.com"])

_REFANG = (
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\s*:\s*//\s*\]"), "://"),
    (re.compile(r"[\[({]\s*(?:\.|dot)\s*[\])}]", re.I), "."),
    (re.compile(r"[\[({]\s*(?:@|at)\s*[\])}]", re.I), "@"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
)
_HEXLINE = re.compile(r"[0-9a-fA-F]+")
_HASH = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_HEXRUN = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{20,}(?![0-9A-Za-z])")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_URL = re.compile(r"(?:https?|ftp)://[^\s<>\"'`\])]+", re.I)
_DOMAIN = re.compile(r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-])")
_ONION = re.compile(r"(?<![\w.-])([a-z2-7]{10,56})\.onion(?![\w-])", re.I)
_EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?![\w-])")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


@dataclass(frozen=True)
class IOC:
    kind: str
    value: str
    pages: tuple[int, ...]
    count: int
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Doubtful:
    page: int
    reason: str
    length: int
    text: str


@dataclass
class Extraction:
    pages: int
    iocs: list[IOC] = field(default_factory=list)
    doubtful: list[Doubtful] = field(default_factory=list)
    removed_lines: list[str] = field(default_factory=list)


def refang(text: str) -> str:
    for rx, rep in _REFANG:
        text = rx.sub(rep, text)
    return text


def strip_repeated(pages: list[str], min_pages: int = 3, ratio: float = 0.5) -> tuple[list[str], list[str]]:
    """Quita las líneas que se repiten en al menos la mitad de las páginas (cabecera, pie, numeración). Nunca quita una línea que sea
    solo hexadecimal: eso podría ser un hash. Devuelve (páginas limpias, líneas quitadas)."""
    if len(pages) < min_pages:
        return list(pages), []

    def norm(line: str) -> str:
        # solo el contador de página ("1/6", "2 de 6") se considera variable: otros dígitos pueden ser parte de un IOC
        return re.sub(r"\b\d{1,4}\s*(?:/|de|of)\s*\d{1,4}\b", "#/#", line.strip().lower())

    seen: Counter = Counter()
    for page in pages:
        seen.update({norm(ln) for ln in page.splitlines() if len(ln.strip()) >= 6 and not _HEXLINE.fullmatch(ln.strip())})
    threshold = max(min_pages, math.ceil(ratio * len(pages)))
    repeated = {k for k, n in seen.items() if n >= threshold}
    removed: dict[str, None] = {}
    clean = []
    for page in pages:
        keep = []
        for ln in page.splitlines():
            if len(ln.strip()) >= 6 and not _HEXLINE.fullmatch(ln.strip()) and norm(ln) in repeated:
                removed.setdefault(ln.strip())
            else:
                keep.append(ln)
        clean.append("\n".join(keep))
    return clean, list(removed)


def join_wrapped_hashes(text: str) -> str:
    """Une un hash que una celda de tabla partió en 2-4 líneas (la continuación puede ser de 1 carácter). Solo une si el total es 32, 40 o
    64 y la primera línea tiene al menos 20 caracteres; si no, deja las líneas como están y el escáner las marcará como dudosas."""
    lines = text.split("\n")
    out, i = [], 0
    while i < len(lines):
        first = lines[i].strip()
        if _HEXLINE.fullmatch(first) and len(first) >= 20 and len(first) not in HASH_KINDS:
            acc, j = "", i
            while j < len(lines) and j - i < 4 and _HEXLINE.fullmatch(lines[j].strip()):
                acc += lines[j].strip()
                j += 1
                nxt = lines[j].strip() if j < len(lines) else ""
                if len(acc) in HASH_KINDS and not (_HEXLINE.fullmatch(nxt) and len(nxt) < 20):
                    break
                if len(acc) > 64:
                    break
            if len(acc) in HASH_KINDS and j - i >= 2:
                out.append(acc)
                i = j
                continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def _valid_ipv4(text: str) -> ipaddress.IPv4Address | None:
    parts = text.split(".")
    if len(parts) != 4 or any((len(p) > 1 and p.startswith("0")) or int(p) > 255 for p in parts):
        return None
    return ipaddress.IPv4Address(text)


def _is_service(domain: str, known: frozenset[str]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in known)


def _scan_page(page_no: int, text: str, acc: dict, doubtful: list, known: frozenset[str]) -> None:
    def add(kind: str, value: str, *tags: str) -> None:
        slot = acc[(kind, value)]
        slot["pages"].add(page_no)
        slot["count"] += 1
        slot["tags"].update(tags)

    hash_spans = []
    for m in _HASH.finditer(text):
        h = m.group(0)
        if not re.search(r"[a-fA-F]", h):
            continue  # solo dígitos: un número, no un hash
        add(HASH_KINDS[len(h)], h.lower())
        hash_spans.append(m.span())
    for m in _HEXRUN.finditer(text):
        run = m.group(0)
        if len(run) in HASH_KINDS or not re.search(r"[a-fA-F]", run) or any(s <= m.start() < e for s, e in hash_spans):
            continue
        doubtful.append(Doubtful(page_no, "hex de longitud no válida (¿hash incompleto o mal leído?)", len(run), run.lower()))

    for m in _IPV4.finditer(text):
        ip = _valid_ipv4(m.group(0))
        if ip is not None:
            add("ip", str(ip), *(() if ip.is_global else ("no_publica",)))

    for m in _URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?")
        if "://" in url and len(url) > 8:
            add("url", url)
            host = re.match(r"[a-z]+://(?:[^/@?#]*@)?([^/:?#]+)", url, re.I)
            host = host.group(1).lower() if host else ""
            # el host de una URL es un dominio sea cual sea su TLD (la lista de TLD solo hace falta para texto suelto)
            if "." in host and not host.endswith(".onion") and _valid_ipv4(host) is None and re.fullmatch(r"[a-z0-9.-]+", host):
                add("domain", host, *(("servicio_conocido",) if _is_service(host, known) else ()))

    for m in _ONION.finditer(text):
        name = m.group(1).lower()
        if len(name) in (16, 56):
            add("onion", f"{name}.onion")
        else:
            doubtful.append(Doubtful(page_no, ".onion con longitud no válida (v2=16, v3=56)", len(name), f"{name}.onion"))

    for m in _EMAIL.finditer(text):
        tld = m.group(0).rsplit(".", 1)[1].lower()
        if tld in TLDS:
            add("email", m.group(0).lower())

    for m in _DOMAIN.finditer(text):
        dom = m.group(0).lower()
        if dom.rsplit(".", 1)[1] in TLDS and not dom.endswith(".onion"):
            add("domain", dom, *(("servicio_conocido",) if _is_service(dom, known) else ()))

    for m in _CVE.finditer(text):
        add("cve", m.group(0).upper())


def extract(pages: list[str], known_services: frozenset[str] = KNOWN_SERVICES) -> Extraction:
    """`pages[i]` es el texto de la página i+1."""
    clean, removed = strip_repeated(pages)
    acc: dict = defaultdict(lambda: {"pages": set(), "count": 0, "tags": set()})
    doubtful: list[Doubtful] = []
    for n, raw in enumerate(clean, start=1):
        _scan_page(n, join_wrapped_hashes(refang(raw)), acc, doubtful, known_services)
    # una URL con host conocido hereda la etiqueta del servicio
    for (kind, value), slot in acc.items():
        if kind == "url":
            host = re.sub(r"^[a-z]+://", "", value, flags=re.I).split("/")[0].split(":")[0].lower()
            if _is_service(host, known_services):
                slot["tags"].add("servicio_conocido")
    iocs = [IOC(k, v, tuple(sorted(s["pages"])), s["count"], tuple(sorted(s["tags"]))) for (k, v), s in acc.items()]
    iocs.sort(key=lambda i: (KIND_ORDER.index(i.kind), -i.count, i.value))
    return Extraction(len(pages), iocs, doubtful, removed)


def summary(ex: Extraction, top: int = 10) -> dict:
    """Estadísticas del documento. Todo sale del código; el modelo no interviene."""
    by_kind = Counter(i.kind for i in ex.iocs)
    per_page: Counter = Counter()
    for i in ex.iocs:
        per_page.update(i.pages)
    ranked = sorted(ex.iocs, key=lambda i: (-i.count, KIND_ORDER.index(i.kind), i.value))[:top]
    return {
        "paginas": ex.pages,
        "unicos_por_tipo": {k: by_kind[k] for k in KIND_ORDER if by_kind[k]},
        "menciones_totales": sum(i.count for i in ex.iocs),
        "ips_publicas": sum(1 for i in ex.iocs if i.kind == "ip" and "no_publica" not in i.tags),
        "iocs_por_pagina": {p: per_page[p] for p in sorted(per_page)},
        "top_por_menciones": [(i.kind, i.value, i.count) for i in ranked],
        "dudosos": len(ex.doubtful),
        "lineas_repetidas_quitadas": len(ex.removed_lines),
    }


def countries(ex: Extraction, geo) -> list[tuple[str, int, int]]:
    """País de las IPs públicas con una base local (`geo.country(ip)`, p. ej. GeoDB). Devuelve [(país, IPs únicas, menciones)] de mayor a
    menor. Un país por IP es una aproximación (VPN, nubes, proxies)."""
    ips: Counter = Counter()
    mentions: Counter = Counter()
    for i in ex.iocs:
        if i.kind == "ip" and "no_publica" not in i.tags:
            country = geo.country(i.value) or "desconocido"
            ips[country] += 1
            mentions[country] += i.count
    return sorted(((c, ips[c], mentions[c]) for c in ips), key=lambda r: (-r[1], -r[2], r[0]))


UNVERIFIED = "ocr_sin_verificar"           # leído por OCR y sin contrastar con una fuente de texto: puede tener un carácter mal leído
_EXCLUDED_FROM_BLOCKLIST = {"no_publica", "servicio_conocido", UNVERIFIED}


def _rows(iocs: list[IOC]) -> list[dict]:
    return [{"tipo": i.kind, "valor": i.value, "menciones": i.count, "paginas": ",".join(map(str, i.pages)), "etiquetas": ",".join(i.tags)}
            for i in sorted(iocs, key=lambda i: (-i.count, KIND_ORDER.index(i.kind), i.value))]


def priority_rows(ex: Extraction) -> list[dict]:
    """IOCs listos para una watchlist o lista de bloqueo: sin dudosos, sin IPs no públicas, sin servicios conocidos y sin candidatos de OCR
    sin verificar (un hash con un carácter mal leído no coincide con nada y da una falsa sensación de cobertura)."""
    return _rows([i for i in ex.iocs if not _EXCLUDED_FROM_BLOCKLIST & set(i.tags)])


def candidate_rows(ex: Extraction) -> list[dict]:
    """Hashes leídos por OCR que faltan por verificar contra una fuente de texto."""
    return _rows([i for i in ex.iocs if UNVERIFIED in i.tags])


def write_csv(ex: Extraction, path: str | Path, candidates: bool = False) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["tipo", "valor", "menciones", "paginas", "etiquetas"])
        w.writeheader()
        w.writerows(candidate_rows(ex) if candidates else priority_rows(ex))
    return path


def _distance(a: str, b: str, limit: int) -> int:
    """Distancia de edición con tope: devuelve limit+1 si es mayor."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def verify_hashes(ex: Extraction, reference_text: str, max_distance: int = 3) -> dict:
    """Contrasta los hashes leídos por OCR (candidatos y filas dudosas de tabla) con una fuente de texto que aporta el analista.
    Coincidencia exacta -> `verificado_con_fuente`. Diferencia de hasta `max_distance` caracteres con UN solo hash de la fuente ->
    se corrige al valor de la fuente (`corregido_con_fuente`) y queda registrado. Devuelve el informe; modifica `ex`."""
    ref = {m.group(0).lower() for m in _HASH.finditer(join_wrapped_hashes(refang(reference_text))) if re.search(r"[a-fA-F]", m.group(0))}
    verified, corrected, unmatched = [], [], []

    def resolve(value: str) -> tuple[str, str] | None:
        if value in ref:
            return value, "verificado_con_fuente"
        near = sorted((_distance(value, r, max_distance), r) for r in ref)
        near = [(d, r) for d, r in near if d <= max_distance]
        if near and (len(near) == 1 or near[0][0] < near[1][0]):
            return near[0][1], "corregido_con_fuente"
        return None

    def promote(value: str, pages: tuple[int, ...], count: int, extra: tuple[str, ...]) -> None:
        got = resolve(value)
        if got is None:
            unmatched.append(value)
            return
        fixed, tag = got
        (verified if fixed == value else corrected).append(fixed if fixed == value else (value, fixed))
        ex.iocs.append(IOC(HASH_KINDS[len(fixed)], fixed, pages, count, tuple(sorted({*extra, tag}))))

    keep = []
    for i in ex.iocs:
        if i.kind in HASH_KINDS.values() and UNVERIFIED in i.tags:
            promote(i.value, i.pages, i.count, tuple(t for t in i.tags if t != UNVERIFIED))
        else:
            keep.append(i)
    ex.iocs[:] = keep
    rest = []
    for d in ex.doubtful:
        if d.reason.startswith("hash ") and resolve(d.text) is not None:
            promote(d.text, (d.page,), 1, ("ocr_tabla",))
        else:
            rest.append(d)
    ex.doubtful[:] = rest
    have = {i.value for i in ex.iocs}
    ex.iocs.sort(key=lambda i: (KIND_ORDER.index(i.kind), -i.count, i.value))
    return {"verificados": len(verified), "corregidos": corrected, "sin_confirmar": len(unmatched),
            "en_la_fuente_y_no_en_el_documento": sorted(ref - have)}
