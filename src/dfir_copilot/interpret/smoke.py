"""Llamada real de la interpretación: `python -m dfir_copilot.interpret.smoke RUTA [opciones]`.

Perfila el archivo en local (Inspector), arma el mensaje y, tras confirmarlo, hace UNA llamada al modelo configurado.
Lo único que sale de tu máquina es el Data Profile y los metadatos de las columnas derivadas (nombres, tipos, estadísticas):
ningún valor de ningún log. `--dry-run` muestra exactamente ese contenido y termina sin llamar a nadie.

Códigos de salida: 0 correcto | 1 falló la llamada | 2 configuración o entrada inválida | 3 respuesta inutilizable.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import replace
from pathlib import Path

from dfir_copilot.agent.llm import LLMConfig, LLMConfigError, make_llm, mask_secret
from dfir_copilot.interpret.context import build_user_message, columns_for, estimate_tokens
from dfir_copilot.interpret.interpret import interpret_profile
from dfir_copilot.interpret.prompts import PROMPT_VERSION, SYSTEM_PROMPT
from dfir_copilot.interpret.render import render_interpretation, result_to_dict
from dfir_copilot.interpret.schemas import wire_schema
from dfir_copilot.interpret.structured import LangChainStructured

_YES = {"s", "si", "sí", "y", "yes"}
DEFAULT_TIMEOUT_S = 180.0


def _default_llm_factory(cfg: LLMConfig):
    return LangChainStructured(make_llm(cfg))


def _default_inspector(path, lang):
    from dfir_copilot.profiling.inspector import inspect_source

    return inspect_source(path, lang=lang)


def main(argv=None, *, inspector=None, llm_factory=None, input_fn=input) -> int:
    ap = argparse.ArgumentParser(prog="python -m dfir_copilot.interpret.smoke", description=__doc__.split("\n\n")[0])
    ap.add_argument("path", help="archivo de logs (CSV, TSV, JSON/NDJSON o Parquet)")
    ap.add_argument("--lang", choices=("es", "en"), default="es")
    ap.add_argument("--dry-run", action="store_true", help="muestra lo que se enviaría y termina, sin llamar al modelo")
    ap.add_argument("--yes", action="store_true", help="no pedir confirmación antes de enviar")
    ap.add_argument("--timeout", type=float, default=None, help="segundos de espera de la API (por defecto, el mayor entre LLM_TIMEOUT_S y 180)")
    ap.add_argument("--save", metavar="ARCHIVO.json", help="guarda el resultado (sin el perfil enviado)")
    args = ap.parse_args(argv)

    print(f"Perfilando en local: {Path(args.path).name} ...")
    try:
        draft = (inspector or _default_inspector)(args.path, args.lang)
        profile = getattr(draft, "profile", None)
        if profile is None:
            print(f"El Inspector no produjo un perfil (estado: {getattr(draft, 'status', 'desconocido')}).")
            return 2
        derived = list(draft.derived)
        columns = columns_for(profile, derived)
        user = build_user_message(profile, derived, columns, args.lang)
    except (OSError, ValueError) as exc:
        print(f"No se pudo preparar el mensaje ({type(exc).__name__}): {str(exc)[:300]}")
        return 2

    approx = estimate_tokens(SYSTEM_PROMPT, user, wire_schema())
    print(f"filas: {profile.dataset.row_count:,} | campos: {profile.dataset.field_count} | derivadas: {len(derived)} | "
          f"columnas consultables: {len(columns)}")
    print(f"Se enviaría: prompt de sistema {len(SYSTEM_PROMPT):,} caracteres + mensaje {len(user):,} caracteres "
          f"+ esquema de respuesta (unos {approx:,} tokens de entrada, estimación gruesa) | versión del prompt {PROMPT_VERSION}")
    if args.dry_run:
        print("\n===== PROMPT DE SISTEMA =====\n" + SYSTEM_PROMPT + "\n===== MENSAJE DE USUARIO =====\n" + user)
        return 0

    try:
        cfg = LLMConfig.from_env()
        # Esta llamada genera una respuesta larga (en la prueba real, 5 446 tokens y 53 s): con 60 s habría estado al límite.
        cfg = replace(cfg, timeout_s=args.timeout or max(cfg.timeout_s, DEFAULT_TIMEOUT_S))
        llm = (llm_factory or _default_llm_factory)(cfg)
    except LLMConfigError as exc:
        print(f"Configuración incompleta: {exc}")
        return 2
    key_var = "ANTHROPIC_API_KEY" if cfg.provider == "anthropic" else "OPENAI_API_KEY"
    print(f"proveedor={cfg.provider} | modelo={cfg.resolved_model} | clave={mask_secret(os.environ.get(key_var))} | "
          f"espera máx. {cfg.timeout_s:.0f} s")
    if not args.yes and input_fn("Se enviará ese contenido al proveedor. ¿Continuar? [s/N] ").strip().lower() not in _YES:
        print("Cancelado: no se envió nada.")
        return 0

    try:
        result = interpret_profile(llm, profile, derived=derived, lang=args.lang)
    except Exception as exc:  # noqa: BLE001 - se muestra el tipo y un resumen, nunca la clave
        print(f"La llamada falló ({type(exc).__name__}): {str(exc)[:300]}")
        return 1
    print("\n" + render_interpretation(result, args.lang))
    if args.save:
        out = Path(args.save)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result_to_dict(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\nGuardado en {out}")
    return 0 if result.ok else 3


if __name__ == "__main__":
    sys.exit(main())
