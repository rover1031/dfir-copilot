"""Fábrica de modelos de lenguaje: el proveedor se elige por configuración (.env), no por código.

Los paquetes de cada proveedor se importan solo cuando se usan, así que tener un proveedor sin
configurar no cuesta nada ni exige claves.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5"}  # OpenAI no tiene valor por defecto: se pide explícito
SUPPORTED = ("anthropic", "openai")


class LLMConfigError(Exception):
    """Configuración del modelo incompleta o inválida."""


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "anthropic"
    model: str | None = None
    temperature: float | None = None  # claude-sonnet-5-5 rechaza valores distintos del predeterminado
    max_tokens: int = 8192
    timeout_s: float = 60.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> LLMConfig:
        env = os.environ if env is None else env
        raw_temp = env.get("LLM_TEMPERATURE", "").strip().lower()
        try:
            temperature = None if raw_temp in ("", "none") else float(raw_temp)
            max_tokens = int(env.get("LLM_MAX_TOKENS", "8192"))
            timeout_s = float(env.get("LLM_TIMEOUT_S", "60"))
        except ValueError as exc:
            raise LLMConfigError(f"Valor numérico inválido en la configuración del modelo: {exc}") from exc
        return cls(
            provider=env.get("LLM_PROVIDER", "anthropic").strip().lower(),
            model=(env.get("LLM_MODEL") or "").strip() or None,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout_s=timeout_s,
        )

    @property
    def resolved_model(self) -> str | None:
        return self.model or DEFAULT_MODELS.get(self.provider)


def mask_secret(value: str | None) -> str:
    """Muestra solo los últimos 4 caracteres de una clave."""
    if not value:
        return "(no definida)"
    return f"…{value[-4:]}" if len(value) > 8 else "****"


def make_llm(config: LLMConfig | None = None, env: Mapping[str, str] | None = None):
    """Devuelve un chat model de LangChain para el proveedor configurado."""
    env = os.environ if env is None else env
    cfg = config or LLMConfig.from_env(env)
    if cfg.provider not in SUPPORTED:
        raise LLMConfigError(f"Proveedor no soportado: {cfg.provider!r}. Usa uno de {SUPPORTED}")
    common = {"max_tokens": cfg.max_tokens, "timeout": cfg.timeout_s}
    if cfg.temperature is not None:
        common["temperature"] = cfg.temperature

    if cfg.provider == "anthropic":
        key = env.get("ANTHROPIC_API_KEY")
        if not key:
            raise LLMConfigError("Falta ANTHROPIC_API_KEY en el archivo .env (y recrear el contenedor)")
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model=cfg.resolved_model, api_key=key, **common)

    # --- OpenAI: listo para usar, solo hay que configurar LLM_PROVIDER=openai ---
    key = env.get("OPENAI_API_KEY")
    if not key:
        raise LLMConfigError("Falta OPENAI_API_KEY en el archivo .env (y recrear el contenedor)")
    if not cfg.resolved_model:
        raise LLMConfigError("Con OpenAI debes indicar LLM_MODEL (no hay modelo por defecto)")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise LLMConfigError("Falta el paquete de OpenAI: instala el extra con `pip install -e '.[openai]'`") from exc
    return ChatOpenAI(model=cfg.resolved_model, api_key=key, **common)
