"""Ledger de evidencia: registro append-only con cadena de hashes (detecta ediciones silenciosas)."""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

try:  # bloqueo de archivo: evita que dos kernels abiertos sobre el mismo caso bifurquen la cadena
    import fcntl
except ImportError:  # pragma: no cover - solo Windows nativo; el proyecto corre en Linux (Docker)
    fcntl = None

LEDGER_VERSION = 1
GENESIS = "0" * 64
NOTE_STATUSES = (None, "confirmed", "refuted", "inconclusive")
_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class DatasetMismatch(Exception):
    """El ledger pertenece a otro dataset (distinto hash de entrada)."""


class LedgerCorrupt(Exception):
    """La cadena de hashes del ledger no es válida."""


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    head_hash: str
    error: str = ""


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False, default=str)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def query_id(record: dict) -> str:
    return "q-" + _sha(_canon(record))[:12]


def finding_id(finding, dataset_sha256: str) -> str:
    """Identificador determinista: re-ejecutar un detector sobre el mismo dataset da el mismo id."""
    key = {"d": finding.detector, "e": finding.entity, "s": finding.summary, "ds": dataset_sha256}
    return "f-" + _sha(_canon(key))[:12]


def candidate_id(case, dataset_sha256: str) -> str:
    """Identificador determinista de un caso candidato (mismo cálculo que usa record_cases)."""
    fids = sorted({finding_id(f, dataset_sha256) for f in case.findings})
    return "c-" + _sha(_canon({"e": case.entity, "d": list(case.detectors), "f": fids}))[:12]


class Ledger:
    """Bitácora de un caso. Úsala con `Ledger.open(...)`.

    Varias instancias (p. ej. dos notebooks) pueden escribir en el mismo caso: cada escritura toma un bloqueo
    de archivo y relee lo que otro haya añadido antes de enlazar su entrada a la cadena.
    """

    def __init__(self, path: str | Path, dataset_sha256: str):
        self.path = Path(path)
        self.dataset_sha256 = dataset_sha256
        self._entries: list[dict] = []
        self._size = 0
        if self.path.exists():
            result = self.verify()
            if not result.ok:
                raise LedgerCorrupt(f"{self.path}: {result.error}")
            self._load()
        else:
            self._reindex()

    # --- sincronización con el disco ----------------------------------------------------------
    def _disk_size(self) -> int:
        return self.path.stat().st_size if self.path.exists() else 0

    def _load(self) -> None:
        text = self.path.read_text(encoding="utf-8") if self.path.exists() else ""
        self._entries = [json.loads(line) for line in text.splitlines() if line.strip()]
        self._size = len(text.encode("utf-8"))
        self._reindex()

    def _reindex(self) -> None:
        e = self._entries
        self._queries = {x["data"]["query_id"] for x in e if x["type"] == "query"}
        self._findings = {x["data"]["finding_id"] for x in e if x["type"] == "finding"}
        self._candidates = {x["data"]["candidate_id"] for x in e if x["type"] == "case_candidate"}
        self._hypotheses = {x["data"]["hypothesis_id"] for x in e if x["type"] == "hypothesis"}

    def _sync(self) -> None:
        """Si otra instancia escribió, recarga lo que añadió."""
        if self._disk_size() != self._size:
            self._load()

    def refresh(self) -> None:
        """Fuerza la relectura desde disco (útil para ver lo que escribió otro notebook)."""
        self._load()

    # --- apertura -------------------------------------------------------------------------
    @classmethod
    def open(cls, case_id: str, engine, analyst: str | None = None,
             root: str | Path = "/workspace/data/ledger") -> Ledger:
        if not _CASE_ID.match(case_id):
            raise ValueError("case_id solo admite letras, números, '.', '_' y '-' (máx. 64)")
        if engine.manifest is None:
            raise ValueError("El ledger exige un dataset con manifiesto (ingestado con ingest_csv)")
        path = Path(root) / f"{case_id}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        ledger = cls(path, engine.dataset_sha256)
        if ledger._entries:
            recorded = ledger._entries[0]["data"]["dataset"]["input_sha256"]
            if recorded != engine.dataset_sha256:
                raise DatasetMismatch(f"El caso {case_id} se abrió con otro dataset ({recorded[:12]}…)")
        else:
            m = engine.manifest
            ledger.append("case_opened", {
                "case_id": case_id,
                "analyst": analyst,
                "ledger_version": LEDGER_VERSION,
                "duckdb_version": m.get("duckdb_version"),
                "dataset": {
                    "input_path": m["input"]["path"], "input_sha256": m["input"]["sha256"],
                    "input_rows": m["input"]["rows"], "parquet_sha256": m["output"]["sha256"],
                    "mapping_sha256": m["mapping"]["sha256"],
                    "timezone_assumed": m["timezone"]["assumed"],
                    "timezone_verified": m["timezone"]["verified"],
                    "time_range_utc": m["time_range_utc"],
                },
                "ingest_warnings": m.get("warnings", []),
            })
        return ledger

    # --- escritura ------------------------------------------------------------------------
    def append(self, type_: str, data: dict) -> dict:
        with open(self.path, "a", encoding="utf-8") as fh:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                self._sync()  # dentro del bloqueo: nadie más puede escribir entre la lectura y la escritura
                entry = {
                    "seq": len(self._entries) + 1,
                    "ts_utc": datetime.now(UTC).isoformat(timespec="seconds"),
                    "type": type_,
                    "data": data,
                    "prev_hash": self._entries[-1]["hash"] if self._entries else GENESIS,
                }
                entry["hash"] = _sha(_canon(entry))
                line = _canon(entry)
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
                stored = json.loads(line)
                self._entries.append(stored)
                self._size += len((line + "\n").encode("utf-8"))
                if type_ == "hypothesis":
                    self._hypotheses.add(data["hypothesis_id"])
                return stored
            finally:
                if fcntl:
                    fcntl.flock(fh, fcntl.LOCK_UN)

    def record_queries(self, queries) -> int:
        """Registra consultas (cualquier estado: las rechazadas también son auditoría). Devuelve cuántas son nuevas."""
        self._sync()
        new = 0
        for q in queries:
            qid = query_id(q)
            if qid not in self._queries:
                self.append("query", {"query_id": qid, **q})
                self._queries.add(qid)
                new += 1
        return new

    def record_runs(self, runs) -> dict:
        """Registra consultas, hallazgos y ejecuciones de detectores. Los hallazgos ya vistos no se duplican."""
        self._sync()
        counts = {"queries": 0, "findings": 0, "runs": 0}
        for run in runs:
            counts["queries"] += self.record_queries(run.queries)
            qids = [query_id(q) for q in run.queries]
            fids = []
            for f in run.findings:
                fid = finding_id(f, self.dataset_sha256)
                fids.append(fid)
                if fid in self._findings:
                    continue
                self.append("finding", {
                    "finding_id": fid, "detector": f.detector, "title": f.title, "severity": f.severity,
                    "entity": f.entity, "summary": f.summary, "metrics": f.metrics,
                    "related": f.related, "mitre": list(f.mitre),
                    "query_ids": [query_id(q) for q in f.evidence],
                })
                self._findings.add(fid)
                counts["findings"] += 1
            self.append("detector_run", {"detector": run.name, "status": run.status, "reason": run.reason,
                                         "query_ids": qids, "finding_ids": fids})
            counts["runs"] += 1
        return counts

    def record_cases(self, cases) -> int:
        """Registra los casos candidatos de `correlate()`. Exige que sus hallazgos ya estén en el ledger."""
        self._sync()
        new = 0
        for c in cases:
            fids = sorted({finding_id(f, self.dataset_sha256) for f in c.findings})
            missing = [f for f in fids if f not in self._findings]
            if missing:
                raise KeyError(f"Hallazgos sin registrar: {missing}. Llama antes a record_runs().")
            cid = candidate_id(c, self.dataset_sha256)
            if cid in self._candidates:
                continue
            self.append("case_candidate", {"candidate_id": cid, "entity": c.entity, "signals": c.signals,
                                           "detectors": list(c.detectors), "severity": c.severity,
                                           "finding_ids": fids})
            self._candidates.add(cid)
            new += 1
        return new

    def note(self, text: str, refs=(), status: str | None = None, analyst: str | None = None) -> dict:
        """Decisión o comentario del analista, enlazado a consultas, hallazgos o casos existentes."""
        if not text or not text.strip():
            raise ValueError("La nota no puede estar vacía")
        if status not in NOTE_STATUSES:
            raise ValueError(f"status debe ser uno de {NOTE_STATUSES}")
        known = self.known_refs()
        unknown = [r for r in refs if r not in known]
        if unknown:
            raise KeyError(f"Referencias desconocidas: {unknown}")
        return self.append("note", {"text": text.strip(), "refs": list(refs), "status": status,
                                    "analyst": analyst})

    # --- lectura y verificación ----------------------------------------------------------
    def known_refs(self) -> set[str]:
        """Identificadores citables como evidencia o referencia: consultas, hallazgos, casos e hipótesis."""
        self._sync()
        return self._queries | self._findings | self._candidates | self._hypotheses

    @property
    def head_hash(self) -> str:
        self._sync()
        return self._entries[-1]["hash"] if self._entries else GENESIS

    def entries(self, type_: str | None = None) -> list[dict]:
        self._sync()
        return [e for e in self._entries if type_ is None or e["type"] == type_]

    def summary(self) -> dict:
        self._sync()
        counts = Counter(e["type"] for e in self._entries)
        return {"path": str(self.path), "entries": len(self._entries), "head_hash": self.head_hash,
                "dataset_sha256": self.dataset_sha256, "counts": dict(counts)}

    def verify(self) -> VerifyResult:
        """Relee el archivo desde disco y recalcula toda la cadena."""
        prev, n = GENESIS, 0
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line_no, line in enumerate(fh, start=1):
                    entry = json.loads(line)
                    claimed = entry.pop("hash", None)
                    if entry.get("seq") != n + 1:
                        return VerifyResult(False, n, prev, f"línea {line_no}: seq {entry.get('seq')} (esperado {n + 1})")
                    if entry.get("prev_hash") != prev:
                        return VerifyResult(False, n, prev, f"línea {line_no}: prev_hash no enlaza con la entrada anterior")
                    if _sha(_canon(entry)) != claimed:
                        return VerifyResult(False, n, prev, f"línea {line_no}: el hash no coincide con el contenido")
                    prev, n = claimed, n + 1
        except (OSError, json.JSONDecodeError) as exc:
            return VerifyResult(False, n, prev, f"no se pudo leer el ledger: {exc}")
        return VerifyResult(True, n, prev)

    def replay(self, engine, record: bool = True) -> list[dict]:
        """Re-ejecuta las consultas registradas y compara el número de filas devueltas.

        Las re-ejecuciones son verificaciones, no análisis nuevo: no se añaden al historial del motor y el
        resultado queda como UNA entrada `replay` en el ledger (en vez de duplicar cada consulta).
        """
        if engine.dataset_sha256 != self.dataset_sha256:
            raise DatasetMismatch("El motor usa un dataset distinto al del ledger")
        mark = len(engine.history)
        results = []
        for e in self.entries("query"):
            d = e["data"]
            if d["status"] != "ok":
                continue
            try:
                rows = engine.query(d["sql"]).row_count
                results.append({"query_id": d["query_id"], "recorded_rows": d["rows"],
                                "replayed_rows": rows, "match": rows == d["rows"]})
            except Exception as exc:  # noqa: BLE001 - se reporta, no se oculta
                results.append({"query_id": d["query_id"], "recorded_rows": d["rows"],
                                "replayed_rows": None, "match": False, "error": f"{type(exc).__name__}: {exc}"})
        del engine.history[mark:]
        if record:
            self.append("replay", {"queries": len(results), "matches": sum(r["match"] for r in results),
                                   "mismatches": [r["query_id"] for r in results if not r["match"]]})
        return results
