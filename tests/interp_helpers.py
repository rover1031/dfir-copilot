"""Apoyo común de los tests de interpretación (P1-a): un Data Profile sintético y mínimo."""
from dfir_copilot.profiling.data_profile import DataProfile

MAPPED = {"timestamp_utc": "ts", "src_ip": "ip", "endpoint": "path", "status_code": "code", "user_id": "uid"}


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
