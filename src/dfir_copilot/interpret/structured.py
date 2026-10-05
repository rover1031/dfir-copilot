"""Frontera con el proveedor de LLM: una llamada con salida estructurada, sin acoplar `interpret` a LangChain.

`StructuredLLM` es la interfaz mínima (se sustituye por un modelo simulado en los tests). `LangChainStructured` la
implementa sobre cualquier chat model de LangChain, es decir, sobre lo que devuelve tu `make_llm`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class StructuredReply:
    data: dict | None  # JSON que devolvió el modelo, ya como diccionario; None si no se pudo leer
    usage: dict | None  # tokens de entrada/salida, tal como los informa el proveedor
    parse_error: str | None = None


class StructuredLLM(Protocol):
    def invoke(self, system: str, user: str, schema: dict) -> StructuredReply: ...


class LangChainStructured:
    """Adaptador sobre un chat model de LangChain.

    Se usa `json_schema` y no la llamada forzada a herramienta: con `claude-sonnet-5-5` esta última no está soportada. El
    esquema viaja como diccionario y se valida después con pydantic, para no depender de qué restricciones acepta la API.
    """

    def __init__(self, chat_model, *, method: str = "json_schema"):
        self._model = chat_model
        self._method = method

    def invoke(self, system: str, user: str, schema: dict) -> StructuredReply:
        from langchain_core.messages import HumanMessage, SystemMessage

        runnable = self._model.with_structured_output(schema, include_raw=True, method=self._method)
        out = runnable.invoke([SystemMessage(content=system), HumanMessage(content=user)])
        raw, parsed, error = out.get("raw"), out.get("parsed"), out.get("parsing_error")
        usage = dict(getattr(raw, "usage_metadata", None) or {}) or None
        if error is not None or not isinstance(parsed, dict):
            detail = f"{type(error).__name__}: {str(error)[:200]}" if error is not None else "la respuesta no es un objeto JSON"
            return StructuredReply(None, usage, detail)
        return StructuredReply(parsed, usage)
