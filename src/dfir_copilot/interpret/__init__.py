"""Interpretación del Data Profile con un LLM (P1-a): contrato de salida, validación de lo que el modelo propone y llamada."""
from dfir_copilot.interpret.context import build_user_message, columns_for
from dfir_copilot.interpret.interpret import InterpretationResult, interpret_profile
from dfir_copilot.interpret.prompts import PROMPT_VERSION, SYSTEM_PROMPT
from dfir_copilot.interpret.schemas import (
    MAX_QUERIES,
    MAX_QUESTIONS,
    AnalystQuestion,
    LogClassification,
    MappingReview,
    ProfileInterpretation,
    ProposedQuery,
    wire_schema,
)
from dfir_copilot.interpret.structured import LangChainStructured, StructuredLLM, StructuredReply
from dfir_copilot.interpret.validation import (
    Discard,
    ReviewedInterpretation,
    SqlCheck,
    SqlSandbox,
    columns_from_profile,
    review_interpretation,
)

__all__ = [
    "MAX_QUERIES", "MAX_QUESTIONS", "PROMPT_VERSION", "SYSTEM_PROMPT", "AnalystQuestion", "Discard", "InterpretationResult",
    "LangChainStructured", "LogClassification", "MappingReview", "ProfileInterpretation", "ProposedQuery",
    "ReviewedInterpretation", "SqlCheck", "SqlSandbox", "StructuredLLM", "StructuredReply", "build_user_message",
    "columns_for", "columns_from_profile", "interpret_profile", "review_interpretation", "wire_schema",
]
