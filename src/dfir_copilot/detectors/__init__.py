"""Detectores como plugins. Importar este paquete registra los detectores disponibles."""
from dfir_copilot.detectors import breadth  # noqa: F401  (registra ResourceBreadth)
from dfir_copilot.detectors.base import (  # noqa: F401
    Detector,
    DetectorRun,
    Finding,
    NotApplicable,
    available,
    register,
    run_detectors,
)
