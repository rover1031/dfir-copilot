"""`interpret_profile`: una llamada al modelo con el Data Profile y revisión de lo que devuelve (P1-a)."""
from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from pydantic import ValidationError

from dfir_copilot.interpret.context import build_user_message, columns_for
from dfir_copilot.interpret.prompts import PROMPT_VERSION, SYSTEM_PROMPT
from dfir_copilot.interpret.schemas import ProfileInterpretation, wire_schema
from dfir_copilot.interpret.structured import StructuredLLM
from dfir_copilot.interpret.validation import ReviewedInterpretation, SqlSandbox, review_interpretation
from dfir_copilot.profiling.data_profile import DataProfile


@dataclass(frozen=True)
class InterpretationResult:
    reviewed: ReviewedInterpretation | None  # None si la respuesta no se pudo usar
    error: Literal["parse_error", "schema_violation"] | None
    error_detail: str | None
    usage: dict | None
    elapsed_ms: int
    columns: dict
    prompt_version: str

    @property
    def ok(self) -> bool:
        return self.reviewed is not None


def interpret_profile(
    llm: StructuredLLM,
    profile: DataProfile,
    *,
    derived: Iterable = (),
    lang: str | None = None,
    sandbox: SqlSandbox | None = None,
) -> InterpretationResult:
    """Envía el perfil (y los metadatos de las derivadas del Inspector) y devuelve la interpretación ya revisada.

    No reintenta ni corrige nada por su cuenta: si la respuesta no es utilizable, lo dice con `error`. Los fallos de red o de
    autenticación del proveedor se propagan tal cual.
    """
    derived = list(derived)
    lang = lang or profile.lang
    columns = columns_for(profile, derived)
    user = build_user_message(profile, derived, columns, lang)
    t0 = time.perf_counter()
    reply = llm.invoke(SYSTEM_PROMPT, user, wire_schema())
    elapsed = int((time.perf_counter() - t0) * 1000)

    def failed(code, detail):
        return InterpretationResult(None, code, detail, reply.usage, elapsed, columns, PROMPT_VERSION)

    if reply.data is None:
        return failed("parse_error", reply.parse_error or "respuesta vacía")
    try:
        raw = ProfileInterpretation.model_validate(reply.data)
    except ValidationError as exc:
        first = exc.errors()[0]
        return failed("schema_violation", f"{exc.error_count()} error(es); el primero en {'.'.join(map(str, first['loc']))}: {first['msg']}")
    reviewed = review_interpretation(raw, profile, columns, sandbox=sandbox)
    return InterpretationResult(reviewed, None, None, reply.usage, elapsed, columns, PROMPT_VERSION)
