"""Fase local del análisis: lectura multi-formato, perfilado con DuckDB y mapeo bilingüe de esquemas."""
from dfir_copilot.profiling.data_profile import DataProfile  # noqa: F401
from dfir_copilot.profiling.log_profiler import LogProfiler  # noqa: F401
from dfir_copilot.profiling.readers import SourceError, detect_format  # noqa: F401
from dfir_copilot.profiling.schema_mapper import SchemaMapper, normalize_name  # noqa: F401
