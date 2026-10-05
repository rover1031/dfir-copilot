"""Motor de consultas forenses: solo lectura, una sentencia SELECT, con límites."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from dfir_copilot.ingest.ingestor import local_timezone, sha256_file


class QueryRejected(ValueError):
    """La consulta no cumple la política de seguridad."""


class QueryTimeout(TimeoutError):
    """La consulta superó el tiempo máximo permitido."""


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def result_digest(columns, rows) -> str:
    """Huella del RESULTADO de una consulta, insensible al orden de las filas.

    Sin ORDER BY, DuckDB puede devolver las mismas filas en otro orden entre ejecuciones; por eso se ordenan las filas
    serializadas antes de hacer el hash. Los flotantes se redondean a 9 cifras significativas: sumar en paralelo puede
    cambiar los últimos dígitos sin que el resultado haya cambiado de verdad.
    """
    def norm(v):
        return format(v, ".9g") if isinstance(v, float) else v

    lines = sorted(json.dumps([norm(v) for v in r], ensure_ascii=False, default=str, separators=(",", ":"))
                   for r in rows)
    payload = "\x1f".join(columns) + "\n" + "\n".join(lines)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class QueryResult:
    sql: str
    columns: tuple[str, ...]
    rows: list
    row_count: int
    truncated: bool
    elapsed_ms: int
    executed_at_utc: str
    dataset_sha256: str

    def df(self):
        import pandas as pd

        return pd.DataFrame(self.rows, columns=list(self.columns))


class QueryEngine:
    """Conexión DuckDB endurecida sobre un Parquet canónico, expuesto como la vista `logs`."""

    VIEW = "logs"

    def __init__(
        self,
        parquet_path: str | Path,
        *,
        memory_limit: str = "2GB",
        max_rows: int = 1000,
        timeout_s: float = 30.0,
        verify: bool = True,
    ):
        self.parquet = Path(parquet_path).resolve()
        if not self.parquet.exists():
            raise FileNotFoundError(self.parquet)
        manifest_path = self.parquet.with_suffix(".manifest.json")
        self.manifest = (
            json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
        )
        self.verified = bool(verify)
        self.parquet_sha256: str | None = None  # hash real del Parquet; solo se calcula si se verifica
        if verify:
            if self.manifest is None:
                raise ValueError(f"Falta el manifiesto para verificar: {manifest_path}")
            self.parquet_sha256 = sha256_file(self.parquet)
            if self.parquet_sha256 != self.manifest["output"]["sha256"]:
                raise ValueError("El hash del Parquet no coincide con el manifiesto: dataset alterado")
        self.dataset_sha256 = self.manifest["input"]["sha256"] if self.manifest else "no-verificado"
        # Hora local del cliente, solo si alguien declaró la zona (ver `ingestor.local_timezone`). No cambia el Parquet ni
        # su hash: es una columna calculada en la vista, así que un caso ya sellado la obtiene sin reingerir.
        self.local_timezone = local_timezone((self.manifest or {}).get("timezone"))
        self.max_rows = max_rows
        self.timeout_s = timeout_s
        self.history: list[dict] = []
        self._con = self._open(memory_limit)

    def _open(self, memory_limit: str) -> duckdb.DuckDBPyConnection:
        tmp = self.parquet.parent / ".duckdb_tmp"
        con = duckdb.connect(":memory:")
        con.execute("SET TimeZone = 'UTC'")
        con.execute(f"SET memory_limit = {_lit(memory_limit)}")
        con.execute(f"SET temp_directory = {_lit(str(tmp))}")
        con.execute("SET max_temp_directory_size = '10GB'")
        local = (f", timezone({_lit(self.local_timezone)}, timestamp_utc) AS timestamp_local"
                 if self.local_timezone else "")
        con.execute(
            f"CREATE VIEW {self.VIEW} AS SELECT *{local} FROM read_parquet({_lit(str(self.parquet))})"
        )
        # Bloqueo: sin acceso a archivos ni red salvo el Parquet, y configuración inmutable.
        con.execute(f"SET allowed_paths = [{_lit(str(self.parquet))}]")
        con.execute("SET enable_external_access = false")
        con.execute("SET autoinstall_known_extensions = false")
        con.execute("SET autoload_known_extensions = false")
        con.execute("SET lock_configuration = true")
        return con

    def _validate(self, sql: str) -> str:
        text = sql.strip().rstrip(";").strip()
        if not text:
            raise QueryRejected("Consulta vacía")
        try:
            stmts = self._con.extract_statements(text)
        except duckdb.Error as exc:
            raise QueryRejected(f"SQL no interpretable: {exc}") from exc
        if len(stmts) != 1:
            raise QueryRejected("Se permite exactamente una sentencia por llamada")
        if stmts[0].type != duckdb.StatementType.SELECT:
            raise QueryRejected(f"Solo se permite SELECT; recibido: {stmts[0].type.name}")
        return text

    def _record(self, sql, status, started, t0, rows=0, truncated=False, error=None, limit=None,
                result_sha256=None):
        self.history.append(
            {
                "executed_at_utc": started,
                "sql": sql,
                "status": status,
                "rows": rows,
                "truncated": truncated,
                "elapsed_ms": int((time.perf_counter() - t0) * 1000),
                "error": error,
                "dataset_sha256": self.dataset_sha256,
                "limit": limit,  # tope de filas con el que se ejecutó: el replay debe usar el mismo
                "result_sha256": result_sha256,  # huella del resultado (None si hubo error)
            }
        )

    def _wrap(self, text: str, limit: int) -> str:
        """Aplica el tope de filas y devuelve los TIMESTAMPTZ como texto ISO (UTC).

        Evita depender de pytz al leer timestamps desde Python y entrega valores
        serializables a JSON, que es lo que consumirán las tools del agente.
        """
        base = f"SELECT * FROM ({text}) AS q"
        described = self._con.execute(f"DESCRIBE {base}").fetchall()
        # TIMESTAMP (sin zona, p. ej. timestamp_local) también como texto: valores serializables y sin ambigüedad de zona
        tz_cols = [name for name, dtype, *_ in described if dtype in ("TIMESTAMP WITH TIME ZONE", "TIMESTAMP")]
        replace = ""
        if tz_cols:
            items = ", ".join(
                'CAST("{0}" AS VARCHAR) AS "{0}"'.format(c.replace('"', '""')) for c in tz_cols
            )
            replace = f" REPLACE ({items})"
        return f"SELECT *{replace} FROM ({text}) AS q LIMIT {limit + 1}"

    def query(self, sql: str, *, max_rows: int | None = None) -> QueryResult:
        limit = min(max_rows, self.max_rows) if max_rows else self.max_rows
        started = datetime.now(UTC).isoformat(timespec="seconds")
        t0 = time.perf_counter()
        try:
            text = self._validate(sql)
            timer = threading.Timer(self.timeout_s, self._con.interrupt)
            timer.start()
            try:
                cur = self._con.execute(self._wrap(text, limit))
                columns = tuple(d[0] for d in cur.description)
                fetched = cur.fetchall()
            finally:
                timer.cancel()
        except QueryRejected as exc:
            self._record(sql, "rejected", started, t0, error=str(exc))
            raise
        except duckdb.ParserException as exc:
            self._record(sql, "rejected", started, t0, error=str(exc))
            raise QueryRejected(f"SQL no admitido como subconsulta: {exc}") from exc
        except duckdb.InterruptException:
            self._record(sql, "timeout", started, t0, error=f"> {self.timeout_s}s")
            raise QueryTimeout(f"La consulta superó {self.timeout_s}s y fue cancelada") from None
        except duckdb.Error as exc:
            self._record(sql, "error", started, t0, error=str(exc))
            raise
        truncated = len(fetched) > limit
        rows = fetched[:limit]
        self._record(sql, "ok", started, t0, rows=len(rows), truncated=truncated, limit=limit,
                     result_sha256=result_digest(columns, rows))
        return QueryResult(
            sql=text,
            columns=columns,
            rows=rows,
            row_count=len(rows),
            truncated=truncated,
            elapsed_ms=self.history[-1]["elapsed_ms"],
            executed_at_utc=started,
            dataset_sha256=self.dataset_sha256,
        )
