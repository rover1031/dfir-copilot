"""Qué ve el modelo: columnas disponibles y mensaje de usuario con el Data Profile (P1-a).

Regla de privacidad: del Inspector solo salen metadatos de esquema de cada columna derivada (nombre, tipo, rol, parámetro
de origen, cobertura y cardinalidad). NUNCA la regex, los ejemplos (aunque estén enmascarados) ni el texto libre de la
decisión, que podría arrastrar valores.
"""
from __future__ import annotations

from collections.abc import Iterable

from dfir_copilot.interpret.validation import columns_from_profile
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
    ordered = {f.name: f.dtype for f in CANONICAL_FIELDS if f.name in columns or f.name in canonical_derived}
    ordered.update({name: dtype for name, dtype in columns.items() if name in extras})
    return ordered


def _describe_columns(columns: dict[str, str], derived: Iterable) -> str:
    canon = {f.name: f.description for f in CANONICAL_FIELDS}
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
        f"<columns>\n{_describe_columns(columns, derived)}\n</columns>\n"
        f"<data_profile>\n{profile.to_llm_json()}\n</data_profile>"
    )
