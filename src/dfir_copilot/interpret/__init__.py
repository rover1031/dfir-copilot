"""Interpretación del Data Profile con un LLM (P1-a): contrato de salida, validación de lo que el modelo propone y llamada."""
from dfir_copilot.interpret.context import CHARS_PER_TOKEN, build_user_message, columns_for, estimate_tokens
from dfir_copilot.interpret.execute import QueryRun, run_accepted_queries, summarize_runs
from dfir_copilot.interpret.interpret import InterpretationResult, interpret_profile
from dfir_copilot.interpret.prompts import PROMPT_VERSION, SYSTEM_PROMPT
from dfir_copilot.interpret.render import render_interpretation, result_to_dict
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
    EXTRA_COLUMNS,
    TABLE_COLUMNS,
    Discard,
    ReviewedInterpretation,
    SqlCheck,
    SqlSandbox,
    columns_from_profile,
    profile_vocabulary,
    review_interpretation,
)

__all__ = [
    "CHARS_PER_TOKEN", "EXTRA_COLUMNS", "MAX_QUERIES", "MAX_QUESTIONS", "TABLE_COLUMNS", "PROMPT_VERSION", "SYSTEM_PROMPT", "AnalystQuestion", "Discard", "InterpretationResult",
    "LangChainStructured", "LogClassification", "MappingReview", "ProfileInterpretation", "ProposedQuery",
    "ReviewedInterpretation", "SqlCheck", "SqlSandbox", "StructuredLLM", "StructuredReply", "build_user_message",
    "QueryRun", "columns_for", "columns_from_profile", "estimate_tokens", "profile_vocabulary", "interpret_profile", "render_interpretation", "result_to_dict",
    "review_interpretation", "run_accepted_queries", "summarize_runs", "wire_schema",
]
