"""Detectores como plugins. Importar este paquete registra los detectores disponibles."""
from dfir_copilot.detectors import automation, breadth, cluster, ramp  # noqa: F401  (registran detectores)
from dfir_copilot.detectors.base import (  # noqa: F401
    Detector,
    DetectorRun,
    Finding,
    NotApplicable,
    available,
    register,
    run_detectors,
)
from dfir_copilot.detectors.correlate import CaseCandidate, correlate  # noqa: F401
