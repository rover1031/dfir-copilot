"""Contrato de la salida del LLM en la fase de interpretación del perfil (P1-a).

El modelo recibe SOLO el Data Profile y devuelve un `ProfileInterpretation`. Claves y códigos en inglés (contrato de
máquina); los textos para personas (`hypothesis`, `reason`, `question`...) vienen en el idioma pedido.

Este módulo solo describe la FORMA. Que lo propuesto sea cierto (columnas que existen, SQL que compila, campos que están
en el perfil) lo decide `validation.py`: el modelo propone, el código dispone.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints

# Tope de lo que se acepta del modelo. No son límites del esquema (que haría fallar TODA la respuesta por un elemento
# de más), sino de `review_interpretation`, que descarta el exceso y lo deja anotado.
MAX_QUERIES = 8
MAX_QUESTIONS = 5
MAX_SQL_CHARS = 4000

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{2,39}$")]
Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=600)]
Sql = Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=MAX_SQL_CHARS)]


class _M(BaseModel):
    model_config = {"extra": "forbid"}


class LogClassification(_M):
    log_type: Slug  # p. ej. web_access, authentication, edr_process, firewall, cloud_audit, unknown
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    evidence_fields: list[str] = Field(default_factory=list, max_length=12)  # rutas de campo del perfil
    rationale: Text


class MappingReview(_M):
    """Opinión del modelo sobre una entrada del mapeo canónico propuesto por el perfilador."""

    action: Literal["confirm", "reject", "change", "add"]
    canonical: str  # nombre canónico (schema.CANONICAL_NAMES)
    field: str  # ruta de campo del perfil: el campo confirmado, rechazado, nuevo destino, o el que faltaba mapear
    reason: Text


class ProposedQuery(_M):
    """Una hipótesis de investigación con la consulta que la contrasta. `refuted_if` es obligatoria: sin una condición
    que la refute no es una hipótesis, es una anécdota."""

    id: Slug
    hypothesis: Text
    sql: Sql  # un único SELECT sobre la vista `logs`
    expected_if_true: Text
    refuted_if: Text
    priority: Literal["high", "medium", "low"]


class AnalystQuestion(_M):
    """Lo que el esquema no puede responder y solo el analista sabe (zona horaria, qué cuentas están autorizadas...)."""

    question: Text
    why_it_matters: Text


class ProfileInterpretation(_M):
    classification: LogClassification
    mapping_review: list[MappingReview] = Field(default_factory=list)
    proposed_queries: list[ProposedQuery] = Field(default_factory=list)
    analyst_questions: list[AnalystQuestion] = Field(default_factory=list)


# Palabras clave de JSON Schema que la salida estructurada de la API puede no admitir. No se envían al modelo: el rango, el
# largo y el patrón se comprueban igualmente al validar con pydantic, y lo que no cumpla se rechaza con un código claro.
_UNSUPPORTED_KEYWORDS = frozenset({
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
    "minLength", "maxLength", "pattern", "minItems", "maxItems", "uniqueItems", "format", "default", "title",
})


def wire_schema() -> dict:
    """JSON Schema de `ProfileInterpretation` para enviar a la API: misma forma, sin restricciones de valor."""
    schema = ProfileInterpretation.model_json_schema()
    # `properties` contiene NOMBRES de campo: si un campo se llamara como una palabra clave, no debe borrarse.
    def walk(node):
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if k == "properties" and isinstance(v, dict):
                    out[k] = {name: walk(sub) for name, sub in v.items()}
                elif k in _UNSUPPORTED_KEYWORDS:
                    continue
                else:
                    out[k] = walk(v)
            return out
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node
    wire = walk(schema)
    wire["title"] = "ProfileInterpretation"  # LangChain exige un título en la raíz de un esquema en forma de diccionario
    return wire
