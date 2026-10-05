"""Qué ve el modelo: columnas disponibles y mensaje de usuario con el Data Profile (P1-a).

Regla de privacidad: del Inspector solo salen metadatos de esquema de cada columna derivada (nombre, tipo, rol, parámetro
de origen, cobertura y cardinalidad). NUNCA la regex, los ejemplos (aunque estén enmascarados) ni el texto libre de la
decisión, que podría arrastrar valores.
"""
from __future__ import annotations

import json
from collections.abc import Iterable

from dfir_copilot.interpret.validation import EXTRA_COLUMNS, columns_from_profile, profile_vocabulary
from dfir_copilot.profiling.data_profile import DataProfile
from dfir_copilot.schema import CANONICAL_FIELDS, CANONICAL_NAMES


def columns_for(profile: DataProfile, derived: Iterable = ()) -> dict[str, str]:
    """Columnas del dataset ingerido (nombre -> tipo): las del perfil más las derivadas del Inspector.

    El Inspector puede derivar una columna CANÓNICA (p. ej. `user_id` desde un parámetro de la URL): el perfil no la mapea
    porque no existe como campo del archivo, pero sí estará en el Parquet. Esas se añaden con su tipo canónico.
    """
    derived = list(derived)
    names = [d.name for d in derived]
    if len(set(names)) != len(names):
        raise ValueError(f"Columnas derivadas repetidas: {sorted({n for n in names if names.count(n) > 1})}")
    canonical_derived = {d.name for d in derived if d.name in CANONICAL_NAMES}
    extras = {d.name: d.type for d in derived if d.name not in CANONICAL_NAMES}
    columns = columns_from_profile(profile, extras)
    if not canonical_derived:
        return columns
    canonical_dtype = {f.name: f.dtype for f in CANONICAL_FIELDS} | {n: dt for n, (dt, _) in EXTRA_COLUMNS.items()}
    ordered = {n: canonical_dtype[n] for n in canonical_dtype if n in columns or n in canonical_derived}
    ordered.update({name: dtype for name, dtype in columns.items() if name not in ordered})
    return ordered


def _describe_columns(columns: dict[str, str], derived: Iterable) -> str:
    canon = {f.name: f.description for f in CANONICAL_FIELDS} | {n: d for n, (_, d) in EXTRA_COLUMNS.items()}
    by_name = {d.name: d for d in derived}
    lines = []
    for name, dtype in columns.items():
        d = by_name.get(name)
        if d is None:
            lines.append(f"{name} {dtype} - {canon.get(name, '')}".rstrip(" -"))
        else:
            what = f"derived from URL parameter '{d.key}'" + (" (canonical column)" if name in canon else "")
            lines.append(f"{name} {dtype} - {what}; role={d.role}; present in {d.hit_pct}% of rows; "
                         f"{d.distinct} distinct values")
    return "\n".join(lines)


def build_user_message(profile: DataProfile, derived: Iterable, columns: dict[str, str], lang: str) -> str:
    if lang not in ("es", "en"):
        raise ValueError(f"Idioma no soportado: {lang!r} (usa 'es' o 'en')")
    derived = list(derived)
    return (
        f"<lang>{lang}</lang>\n"
        f"<canonical_names>{', '.join(sorted(profile_vocabulary()))}</canonical_names>\n"
        f"<columns>\n{_describe_columns(columns, derived)}\n</columns>\n"
        f"<data_profile>\n{profile.to_llm_json()}\n</data_profile>"
    )


# Caracteres por token, medido en una llamada real (claude-sonnet-5-5, perfil de 8 campos): 12 326 caracteres entre sistema,
# usuario y esquema JSON dieron 5 956 tokens de entrada. Es una estimación gruesa (el texto en español y el JSON tokenizan peor
# que el inglés corriente); sirve para ver el orden de magnitud antes de enviar, no para facturar.
CHARS_PER_TOKEN = 2.1


def estimate_tokens(*parts: str | dict) -> int:
    """Tokens de entrada aproximados de lo que se enviaría (los diccionarios se cuentan como el JSON compacto)."""
    chars = sum(len(p if isinstance(p, str) else json.dumps(p, ensure_ascii=False, separators=(",", ":"))) for p in parts)
    return round(chars / CHARS_PER_TOKEN)
