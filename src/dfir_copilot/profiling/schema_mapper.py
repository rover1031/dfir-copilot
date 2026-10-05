"""Mapeador bilingüe de esquemas: propone qué campo de la fuente corresponde a cada campo canónico.

Combina dos evidencias independientes, ambas calculadas en local:
  1. El NOMBRE del campo, normalizado y comparado con el diccionario de alias en inglés y español (aliases.yaml).
  2. El CONTENIDO del campo (tipos semánticos detectados por DuckDB): confirma un alias, lo desmiente, o propone
     un mapeo cuando el nombre no dice nada (p. ej. la columna con el error tipográfico `http_staus`).
El resultado es una PROPUESTA: lo ambiguo se marca para que lo resuelva el LLM o el analista.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ALIASES_FILE = Path(__file__).with_name("aliases.yaml")
STRONG, LEAF, TOKENS, WEAK, SEMANTIC = 1.0, 0.9, 0.75, 0.7, 0.55
MIN_SCORE, AMBIGUITY_MARGIN = 0.5, 0.1
# Contenido demasiado común para proponer un mapeo por sí solo fuera de un log web (un puerto 443 "parece" un código
# HTTP; una ruta Linux "parece" una URL; "falcon.process" "parece" un dominio).
GENERIC_SEMANTICS = {"http_status", "domain", "uri_path"}
# Desempate entre tipos de log con igual puntuación: del más específico al más genérico.
SPECIFICITY = ("edr", "dns", "firewall", "web", "proxy", "auth")

# Por tipo de log: campos típicos y, entre ellos, los DISTINTIVOS (sin al menos uno, el tipo no aplica).
LOG_SIGNATURES = {
    "web": {"fields": ("http_method", "status_code", "uri", "user_agent", "referer"),
            "key": ("http_method", "status_code", "user_agent")},
    "proxy": {"fields": ("uri", "host", "action", "user_id", "bytes_out", "src_ip"), "key": ("action",)},
    "firewall": {"fields": ("src_ip", "dst_ip", "dst_port", "protocol", "action", "src_port"),
                 "key": ("dst_port", "protocol", "dst_ip")},
    "auth": {"fields": ("user_id", "action", "src_ip", "event_type", "host"), "key": ("event_type", "action")},
    "dns": {"fields": ("dns_query", "src_ip"), "key": ("dns_query",)},
    "edr": {"fields": ("process_name", "command_line", "parent_process", "file_hash", "host", "process_id"),
            "key": ("process_name", "command_line", "parent_process", "file_hash")},
}


def normalize_name(name: str) -> str:
    """'Dirección IP' -> 'direccion_ip', 'sourceIPAddress' -> 'source_ip_address', '@timestamp' -> 'timestamp'."""
    s = unicodedata.normalize("NFKD", str(name))
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    s = re.sub(r"[^a-z0-9]+", "_", s.lower())
    return s.strip("_")


@dataclass(frozen=True)
class FieldInfo:
    path: str
    kind: str = "varchar"
    semantics: dict = field(default_factory=dict)  # tipo semántico -> % de valores que lo cumplen
    timestamp_pct: float = 0.0  # mejor tasa de interpretación como fecha (0-100)


@dataclass(frozen=True)
class FieldMatch:
    canonical: str
    field: str
    score: float
    method: str  # alias | alias_leaf | tokens | weak_alias | semantic
    evidence: tuple = ()
    rank: int = 0  # preferencia del alias (orden en aliases.yaml): desempata coincidencias con igual puntuación


@dataclass
class MappingProposal:
    matches: dict
    ambiguous: list
    unmapped: list


class SchemaMapper:
    def __init__(self, aliases_path: str | Path | None = None, extra: dict | None = None):
        data = yaml.safe_load(Path(aliases_path or ALIASES_FILE).read_text(encoding="utf-8"))
        for canonical, spec in (extra or {}).items():  # ampliación sin tocar el YAML del proyecto
            base = data.setdefault(canonical, {"domain": "common", "aliases": []})
            base["aliases"] = list(base.get("aliases", [])) + list(spec.get("aliases", []))
            base["weak_aliases"] = list(base.get("weak_aliases", [])) + list(spec.get("weak_aliases", []))
        self.canon = {}
        for canonical, spec in data.items():
            strong = [normalize_name(canonical)] + [normalize_name(a) for a in spec.get("aliases", [])]
            weak = [normalize_name(a) for a in spec.get("weak_aliases", [])]
            rank: dict[str, int] = {}
            for i, alias in enumerate(strong + weak):
                rank.setdefault(alias, i)  # el primero en la lista es el preferido
            self.canon[canonical] = {
                "domain": spec.get("domain", "common"),
                "description": spec.get("description", {}),
                "semantics": set(spec.get("semantics", [])),
                "strong": set(strong), "weak": set(weak), "rank": rank,
                "token_aliases": [a.split("_") for a in strong if a.count("_") >= 1],
            }
        self._order = {c: i for i, c in enumerate(self.canon)}

    def domain(self, canonical: str) -> str:
        return self.canon[canonical]["domain"]

    # --- puntuación de un campo contra cada canónico ------------------------------------------------------------
    @staticmethod
    def _contains(seq: list, sub: list) -> bool:
        return any(seq[i:i + len(sub)] == sub for i in range(len(seq) - len(sub) + 1))

    def candidates(self, f: FieldInfo, allow_generic: bool = True) -> list[FieldMatch]:
        full = normalize_name(f.path)
        leaf = normalize_name(f.path.split(".")[-1])
        tokens = full.split("_")
        dominant = {s for s, p in f.semantics.items() if p >= 80}
        present = {s for s, p in f.semantics.items() if p >= 50}
        if f.timestamp_pct >= 90:
            dominant.add("timestamp")
            present.add("timestamp")
        out = []
        for canonical, spec in self.canon.items():
            score, method, evidence, rank = 0.0, None, [], 10_000
            if full in spec["strong"]:
                score, method, rank = STRONG, "alias", spec["rank"][full]
                evidence.append(f"alias:{full}")
            elif leaf != full and leaf in spec["strong"]:
                score, method, rank = LEAF, "alias_leaf", spec["rank"][leaf]
                evidence.append(f"alias:{leaf}")
            elif any(self._contains(tokens, a) for a in spec["token_aliases"]):
                # el alias completo aparece SEGUIDO dentro del nombre: ip_origen_cliente sí; session_process_id no
                score, method = TOKENS, "tokens"
                evidence.append("tokens")
            elif full in spec["weak"]:
                score, method, rank = WEAK, "weak_alias", spec["rank"][full]
                evidence.append(f"weak_alias:{full}")
            if method and spec["semantics"]:
                if spec["semantics"] & dominant:
                    score += 0.15
                    evidence.append("semantics:" + ",".join(sorted(spec["semantics"] & dominant)))
                elif present and not spec["semantics"] & present:
                    score -= 0.4
                    evidence.append("semantics_mismatch:" + ",".join(sorted(present)))
            if not method and spec["semantics"]:
                strong_sem = ({s for s, p in f.semantics.items() if p >= 90}
                              | ({"timestamp"} if f.timestamp_pct >= 90 else set())) & spec["semantics"]
                if not allow_generic:
                    strong_sem -= GENERIC_SEMANTICS
                if strong_sem:  # el nombre no dice nada, pero el contenido sí
                    score, method = SEMANTIC, "semantic"
                    evidence.append("semantics_only:" + ",".join(sorted(strong_sem)))
            if method and score >= MIN_SCORE:
                out.append(FieldMatch(canonical, f.path, round(min(score, 1.0), 2), method, tuple(evidence), rank))
        return out

    # --- asignación global ---------------------------------------------------------------------------------
    def propose(self, fields: list[FieldInfo]) -> MappingProposal:
        # Pasada 1 sin semántica genérica; si el log resulta ser web/proxy, pasada 2 con ella.
        proposal = self._assign([m for f in fields for m in self.candidates(f, allow_generic=False)], fields)
        hints = self.log_type_hints(proposal)
        if hints and hints[0]["type"] in ("web", "proxy"):
            proposal = self._assign([m for f in fields for m in self.candidates(f, allow_generic=True)], fields)
        return proposal

    def _assign(self, cands: list[FieldMatch], fields: list[FieldInfo]) -> MappingProposal:
        cands.sort(key=lambda m: (-m.score, m.rank, self._order[m.canonical], m.field))
        matches, used = {}, set()
        for m in cands:
            if m.canonical in matches or m.field in used:
                continue
            matches[m.canonical] = m
            used.add(m.field)
        ambiguous = []
        for canonical, chosen in matches.items():
            rivals = sorted({m.field: m.score for m in cands if m.canonical == canonical and m.field != chosen.field
                             and m.score >= chosen.score - AMBIGUITY_MARGIN}.items())
            if rivals:
                ambiguous.append({"canonical": canonical,
                                  "candidates": [{"field": chosen.field, "score": chosen.score}]
                                  + [{"field": f, "score": s} for f, s in rivals]})
        unmapped = sorted(f.path for f in fields if f.path not in used)
        ordered = {c: matches[c] for c in sorted(matches, key=lambda c: self._order[c])}
        return MappingProposal(ordered, ambiguous, unmapped)

    def log_type_hints(self, proposal: MappingProposal, top: int = 3) -> list[dict]:
        present = set(proposal.matches)
        hints = []
        for log_type, sig in LOG_SIGNATURES.items():
            if not any(k in present for k in sig["key"]):
                continue
            hit = [c for c in sig["fields"] if c in present]
            keys = [k for k in sig["key"] if k in present]
            # mitad cobertura de campos típicos, mitad cobertura de campos distintivos
            score = round(0.5 * len(hit) / len(sig["fields"]) + 0.5 * len(keys) / len(sig["key"]), 2)
            if score >= 0.2:
                hints.append({"type": log_type, "score": score, "evidence": hit})
        hints.sort(key=lambda h: (-h["score"], SPECIFICITY.index(h["type"])))
        return hints[:top]
