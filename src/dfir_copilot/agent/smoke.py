"""Prueba de humo del modelo: `python -m dfir_copilot.agent.smoke`. Hace UNA llamada mínima y no imprime claves."""
from __future__ import annotations

import os
import sys
import time

from dfir_copilot.agent.llm import LLMConfig, LLMConfigError, make_llm, mask_secret


def _text(content) -> str:
    if isinstance(content, str):
        return content
    return "".join(b.get("text", "") for b in content if isinstance(b, dict))


def main() -> int:
    try:
        cfg = LLMConfig.from_env()
        llm = make_llm(cfg)
    except LLMConfigError as exc:
        print(f"Configuración incompleta: {exc}")
        return 2
    key_var = "ANTHROPIC_API_KEY" if cfg.provider == "anthropic" else "OPENAI_API_KEY"
    print(f"proveedor={cfg.provider} | modelo={cfg.resolved_model} | clave={mask_secret(os.environ.get(key_var))}")
    t0 = time.perf_counter()
    try:
        reply = llm.invoke("Responde únicamente con la palabra: listo")
    except Exception as exc:  # noqa: BLE001 - se muestra el tipo y un resumen, nunca la clave
        print(f"La llamada falló ({type(exc).__name__}): {str(exc)[:300]}")
        return 1
    print(f"respuesta: {_text(reply.content).strip()!r} | {int((time.perf_counter() - t0) * 1000)} ms")
    print(f"tokens: {getattr(reply, 'usage_metadata', None)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
