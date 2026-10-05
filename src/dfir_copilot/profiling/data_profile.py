"""Contrato del "Data Profile": el ÚNICO artefacto que viaja al LLM en la fase de razonamiento.

Claves estables en inglés (contrato de máquina); textos para personas en el idioma pedido (`lang`).
Se valida con pydantic y expone su JSON Schema para documentar el contrato y validarlo en otros servicios.
"""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, Field

PROFILE_VERSION = "1.0"
LLM_TASKS = ("classify_log_type", "confirm_field_mapping", "propose_investigation_queries")


class _M(BaseModel):
    model_config = {"extra": "forbid"}


class Privacy(_M):
    mode: Literal["strict"] = "strict"
    raw_values_included: Literal[False] = False
    notes: list[str]


class Source(_M):
    file_name: str  # solo el nombre: la ruta completa puede revelar usuarios o carpetas internas
    sha256: str | None
    size_bytes: int
    format: Literal["csv", "tsv", "json", "parquet"]
    compression: str | None = None
    encoding: str | None = None
    delimiter: str | None = None
    has_header: bool | None = None


class Dataset(_M):
    row_count: int
    field_count: int
    profiled_fields: int
    sample_rows: int
    nested: bool


class Ratio(_M):
    name: str
    pct: float


class FieldProfile(_M):
    path: str
    type: str
    null_pct: float
    distinct_approx: int | None = None
    length: dict | None = None  # {"min", "max", "avg"} para texto
    numeric_pct: float | None = None
    semantics: list[Ratio] = Field(default_factory=list)
    shapes: list[Ratio] = Field(default_factory=list)  # forma abstracta: letras->a, dígitos->9
    url_param_keys: list[str] = Field(default_factory=list)  # solo NOMBRES de parámetros, nunca valores
    enum_values: list[str] | None = None  # solo si TODOS pertenecen al vocabulario técnico seguro
    pii: list[str] = Field(default_factory=list)
    secret_in_values_pct: float = 0.0
    timestamp_format: str | None = None
    timestamp_pct: float | None = None
    mapped_to: str | None = None
    mapping_score: float | None = None


class TimestampCandidate(_M):
    field: str
    format: str
    parse_pct_sample: float
    parse_pct_full: float | None = None
    min_utc: str | None = None
    max_utc: str | None = None
    timezone_in_data: bool | None = None
    alternatives: list[Ratio] = Field(default_factory=list)


class MappingEntry(_M):
    canonical: str
    field: str
    score: float
    method: str
    evidence: list[str]


class LogTypeHint(_M):
    type: str
    label: str
    score: float
    evidence: list[str]


class Warning_(_M):
    code: str
    field: str | None = None
    message: str


class DataProfile(_M):
    profile_version: Literal["1.0"] = PROFILE_VERSION
    lang: Literal["es", "en"]
    generated_at_utc: str
    privacy: Privacy
    source: Source
    dataset: Dataset
    fields: list[FieldProfile]
    timestamp: TimestampCandidate | None = None
    mapping: list[MappingEntry]
    ambiguous: list[dict] = Field(default_factory=list)
    unmapped_fields: list[str] = Field(default_factory=list)
    log_type_hints: list[LogTypeHint]
    warnings: list[Warning_]
    llm_tasks: list[str] = Field(default_factory=lambda: list(LLM_TASKS))

    def to_llm_json(self) -> str:
        """Serialización compacta para la API (sin nulos)."""
        return json.dumps(self.model_dump(exclude_none=True), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def json_schema(cls) -> dict:
        return cls.model_json_schema()
