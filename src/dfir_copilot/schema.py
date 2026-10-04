"""Esquema canónico: el contrato común que toda fuente de logs debe cumplir.

Las columnas específicas de una fuente (p. ej. invoice_id) viven fuera de este
esquema, con prefijo `x_`, y se declaran en el mapping YAML de esa fuente.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    name: str
    dtype: str  # tipo de DuckDB
    description: str


CANONICAL_FIELDS: tuple[Field, ...] = (
    Field("source_row", "BIGINT", "Nº de fila en el archivo original (trazabilidad)"),
    Field("timestamp_utc", "TIMESTAMPTZ", "Instante del evento, normalizado a UTC"),
    Field("src_ip", "VARCHAR", "IP de origen de la petición"),
    Field("user_id", "VARCHAR", "Identidad del actor, si la fuente la expone"),
    Field("session_id", "VARCHAR", "Identificador de sesión, si existe"),
    Field("http_method", "VARCHAR", "Método HTTP"),
    Field("host", "VARCHAR", "Host o dominio solicitado"),
    Field("endpoint", "VARCHAR", "Ruta sin query string"),
    Field("query_string", "VARCHAR", "Parámetros de la URL, sin el '?'"),
    Field("status_code", "SMALLINT", "Código de respuesta HTTP"),
    Field("user_agent", "VARCHAR", "User-Agent (controlado por el cliente: no confiable)"),
    Field("referer", "VARCHAR", "Cabecera Referer"),
    Field("bytes_out", "BIGINT", "Bytes enviados en la respuesta, si existe"),
)

CANONICAL_NAMES: tuple[str, ...] = tuple(f.name for f in CANONICAL_FIELDS)
