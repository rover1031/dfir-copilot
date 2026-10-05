"""Perfilado genérico sobre el esquema canónico (independiente del proveedor de logs)."""
from __future__ import annotations

from dfir_copilot.engine.query_engine import QueryEngine, QueryResult

_BUCKETS = ("hour", "day", "week", "month")
_ENTITY_COLS = ("src_ip", "user_id", "session_id", "endpoint", "user_agent", "host")


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class LogProfiler:
    """Consultas de perfilado listas para usar; todas pasan por el QueryEngine (auditadas)."""

    def __init__(self, engine: QueryEngine):
        self.engine = engine
        self.columns: dict[str, str] = {
            row[0]: row[1] for row in engine.query("DESCRIBE logs").rows
        }

    # --- validación: nada que llegue al SQL sin pasar por aquí -------------------
    def _dim(self, name: str) -> str:
        if name not in self.columns:
            raise ValueError(f"Dimensión desconocida: {name!r}. Disponibles: {sorted(self.columns)}")
        return _q(name)

    def _where(self, filters: dict | None) -> str:
        if not filters:
            return ""
        parts = []
        for col, val in filters.items():
            c = self._dim(col)
            if val is None:
                parts.append(f"{c} IS NULL")
            elif isinstance(val, bool) or not isinstance(val, (str, int)):
                raise ValueError(f"Valor de filtro no soportado para {col!r}: {val!r}")
            else:
                parts.append(f"CAST({c} AS VARCHAR) = {_lit(str(val))}")
        return " WHERE " + " AND ".join(parts)

    @staticmethod
    def _limit(n: int) -> int:
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 1000:
            raise ValueError("n debe ser un entero entre 1 y 1000")
        return n

    # --- perfiles ---------------------------------------------------------------
    def overview(self) -> QueryResult:
        """Volumen, rango temporal y cardinalidad de las entidades principales."""
        distinct = ", ".join(
            f"count(DISTINCT {_q(c)}) AS {_q(c + '_distintos')}"
            for c in _ENTITY_COLS
            if c in self.columns
        )
        return self.engine.query(
            f"SELECT count(*) AS filas, min(timestamp_utc) AS desde, "
            f"max(timestamp_utc) AS hasta, {distinct} FROM logs"
        )

    def top(self, dimension: str, n: int = 10, filters: dict | None = None) -> QueryResult:
        """Top N valores de una dimensión, con su peso relativo."""
        d, n = self._dim(dimension), self._limit(n)
        return self.engine.query(
            f"SELECT {d} AS valor, count(*) AS peticiones, "
            f"round(100.0 * count(*) / sum(count(*)) OVER (), 2) AS pct "
            f"FROM logs{self._where(filters)} GROUP BY 1 ORDER BY peticiones DESC, valor LIMIT {n}"
        )

    def status_by(self, dimension: str, n: int = 20, filters: dict | None = None) -> QueryResult:
        """Distribución de clases de respuesta (2xx/3xx/4xx/5xx) por entidad."""
        d, n = self._dim(dimension), self._limit(n)
        return self.engine.query(
            f"SELECT {d} AS valor, count(*) AS peticiones, "
            f"count(*) FILTER (WHERE status_code // 100 = 2) AS s2xx, "
            f"count(*) FILTER (WHERE status_code // 100 = 3) AS s3xx, "
            f"count(*) FILTER (WHERE status_code // 100 = 4) AS s4xx, "
            f"count(*) FILTER (WHERE status_code // 100 = 5) AS s5xx, "
            f"round(100.0 * count(*) FILTER (WHERE status_code >= 400) / count(*), 1) AS pct_error "
            f"FROM logs{self._where(filters)} GROUP BY 1 ORDER BY peticiones DESC, valor LIMIT {n}"
        )

    def activity(self, entity: str = "src_ip", n: int = 20, min_requests: int = 1) -> QueryResult:
        """Resumen de comportamiento por entidad (IP, usuario, sesión...)."""
        e, n = self._dim(entity), self._limit(n)
        if isinstance(min_requests, bool) or not isinstance(min_requests, int) or min_requests < 1:
            raise ValueError("min_requests debe ser un entero >= 1")
        return self.engine.query(
            f"SELECT {e} AS entidad, count(*) AS peticiones, "
            f"count(DISTINCT endpoint) AS endpoints, count(DISTINCT src_ip) AS ips, "
            f"count(DISTINCT user_id) AS usuarios, count(DISTINCT user_agent) AS user_agents, "
            f"min(timestamp_utc) AS primera, max(timestamp_utc) AS ultima, "
            f"round(100.0 * count(*) FILTER (WHERE status_code >= 400) / count(*), 1) AS pct_error "
            f"FROM logs GROUP BY 1 HAVING count(*) >= {min_requests} "
            f"ORDER BY peticiones DESC, entidad LIMIT {n}"
        )

    def timeline(self, bucket: str = "day", filters: dict | None = None) -> QueryResult:
        """Serie temporal de peticiones (el motor devuelve como máximo `max_rows` periodos)."""
        if bucket not in _BUCKETS:
            raise ValueError(f"bucket debe ser uno de {_BUCKETS}")
        # Con zona declarada, días, semanas y meses se cortan en la medianoche DEL CLIENTE (columna periodo_local); sin ella,
        # en la de UTC (periodo). El nombre de la columna dice cuál es, para que nadie lea una como la otra.
        col, label = ("timestamp_local", "periodo_local") if "timestamp_local" in self.columns else ("timestamp_utc", "periodo")
        return self.engine.query(
            f"SELECT date_trunc('{bucket}', {col}) AS {label}, count(*) AS peticiones "
            f"FROM logs{self._where(filters)} GROUP BY 1 ORDER BY 1"
        )
