"""Privacidad hacia el LLM: copia seudonimizada del dataset y diccionario de alias que nunca sale de la máquina."""
from dfir_copilot.privacy.context import privacy_context
from dfir_copilot.privacy.parity import detector_parity
from dfir_copilot.privacy.pseudonymize import (
    POLICY_VERSION,
    AmbiguousText,
    PrivacyError,
    PrivacyPolicy,
    Pseudonymizer,
    TextResult,
    build_pseudonymized,
)

__all__ = ["POLICY_VERSION", "AmbiguousText", "PrivacyError", "PrivacyPolicy", "Pseudonymizer", "TextResult",
           "build_pseudonymized", "detector_parity", "privacy_context"]
