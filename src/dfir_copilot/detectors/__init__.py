"""Detectores como plugins. Importar este paquete registra los detectores disponibles."""
from dfir_copilot.detectors import (  # noqa: F401  (registran detectores)
    automation,
    breadth,
    cluster,
    endpoint,
    network,
    ramp,
)
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
