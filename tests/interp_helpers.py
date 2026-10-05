"""Apoyo común de los tests de interpretación (P1-a): perfil sintético, derivadas, respuesta del modelo y modelo simulado."""
import json
from dataclasses import dataclass
from pathlib import Path

from dfir_copilot.interpret import StructuredReply
from dfir_copilot.profiling.data_profile import DataProfile

# Vocabulario del PERFILADOR (claves de aliases.yaml), no el de la tabla: `timestamp` y `uri`, no `timestamp_utc` y `endpoint`.
MAPPED = {"timestamp": "ts", "src_ip": "ip", "uri": "path", "status_code": "code", "user_id": "uid"}


def make_profile(mapped=None, with_timestamp=True) -> DataProfile:
    mapped = MAPPED if mapped is None else mapped
    fields = [{"path": p, "type": "VARCHAR", "null_pct": 0.0} for p in ("ts", "ip", "path", "code", "uid", "extra")]
    return DataProfile.model_validate({
        "lang": "es", "generated_at_utc": "2026-10-05T00:00:00Z",
        "privacy": {"notes": ["x"]},
        "source": {"file_name": "t.csv", "sha256": None, "size_bytes": 1, "format": "csv"},
        "dataset": {"row_count": 10, "field_count": 6, "profiled_fields": 6, "sample_rows": 10, "nested": False},
        "fields": fields,
        "timestamp": {"field": "ts", "format": "%Y", "parse_pct_sample": 100.0} if with_timestamp else None,
        "mapping": [{"canonical": c, "field": f, "score": 1.0, "method": "alias", "evidence": []} for c, f in mapped.items()],
        "log_type_hints": [], "warnings": [],
    })


@dataclass
class Derived:
    """Misma forma que `profiling.inspector.DerivedProposal`."""

    name: str
    regex: str
    type: str
    role: str
    reason: str
    key: str
    hit_pct: float
    distinct: int
    examples: tuple = ()


USER = Derived("user_id", "REGEX-SECRETA-1", "VARCHAR", "canonical", "RAZON-LIBRE-1", "authtoken", 100.0, 35, ("an*******",))
INVOICE = Derived("x_invoice_id", "REGEX-SECRETA-2", "VARCHAR", "resource", "RAZON-LIBRE-2", "invoice_id", 99.9, 5025, ("11*****",))

GOOD = {
    "classification": {"log_type": "web_access", "confidence": 0.9, "evidence_fields": ["path", "code"], "rationale": "r"},
    "mapping_review": [{"action": "confirm", "canonical": "uri", "field": "path", "reason": "r"}],
    "proposed_queries": [{
        "id": "facturas_por_usuario", "hypothesis": "h", "priority": "high", "expected_if_true": "e", "refuted_if": "r",
        "sql": "SELECT user_id, count(DISTINCT x_invoice_id) AS n FROM logs GROUP BY 1 ORDER BY n DESC LIMIT 20",
    }],
    "analyst_questions": [{"question": "¿Qué zona horaria?", "why_it_matters": "w"}],
}


class Scripted:
    """Modelo simulado: devuelve respuestas preparadas y recuerda con qué se le llamó."""

    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def invoke(self, system, user, schema):
        self.calls.append((system, user, schema))
        return self.replies.pop(0)


def ok(data=None, usage=None):
    return StructuredReply(GOOD if data is None else data, usage or {"input_tokens": 1200, "output_tokens": 400, "total_tokens": 1600})


FIXTURES = Path(__file__).parent / "fixtures"


def real_profile() -> DataProfile:
    """El Data Profile REAL de three_months.csv (solo metadatos de esquema), tal como se envió en la primera llamada."""
    return DataProfile.model_validate(json.loads((FIXTURES / "three_months_profile.json").read_text(encoding="utf-8")))


# Las 4 derivadas que el Inspector propuso sobre three_months.csv (sin regex ni ejemplos: no los necesitan los tests).
REAL_DERIVED = [
    Derived("user_id", "r", "VARCHAR", "identity", "t", "authtoken", 100.0, 35),
    Derived("x_authtoken_type", "r", "VARCHAR", "credential_type", "t", "authtoken", 100.0, 2),
    Derived("x_invoice_id", "r", "BIGINT", "resource", "t", "invoice_id", 100.0, 11074),
    Derived("x_site_id", "r", "VARCHAR", "dimension", "t", "site_id", 100.0, 4),
]
