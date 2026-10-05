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

from dfir_copilot.i18n import t
from dfir_copilot.ingest.ingestor import sha256_file

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


class MappingMismatch(DatasetMismatch):
    """El mapping con el que se ingirió el dataset no es el que abrió el caso (las columnas derivadas pueden diferir)."""


class ParquetMismatch(DatasetMismatch):
    """El Parquet no es el que abrió el caso: se re-ingirió o se alteró."""


class CopyMismatch(DatasetMismatch):
    """La copia seudonimizada no es la que registró el ledger (otra política, otro Parquet de origen o un hash distinto)."""


class CopyNotRegistered(Exception):
    """Una consulta corrió sobre una copia seudonimizada que el ledger no conoce: regístrala antes con `record_copy()`."""


class LedgerCorrupt(Exception):
    """La cadena de hashes del ledger no es válida."""


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    entries: int
    head_hash: str
    error: str = ""


def verify_file(path: str | Path) -> VerifyResult:
    """Recalcula la cadena de hashes de un archivo de ledger sin abrirlo como `Ledger` (no lanza si está corrupto)."""
    prev, n = GENESIS, 0
    try:
        with open(path, encoding="utf-8") as fh:
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
        self._copies = {x["data"]["copy_id"]: x["data"] for x in e if x["type"] == "data_copy"}

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
        if getattr(engine, "copy_kind", "real") != "real":
            raise ValueError("El ledger se abre con el motor de los datos REALES (es el que lo ata al dataset sellado). La copia "
                             "seudonimizada se registra aparte: `ledger.record_copy(engine_seudonimizado)`.")
        path = Path(root) / f"{case_id}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        ledger = cls(path, engine.dataset_sha256)
        if ledger._entries:
            recorded = ledger._entries[0]["data"]["dataset"]["input_sha256"]
            if recorded != engine.dataset_sha256:
                raise DatasetMismatch(f"El caso {case_id} se abrió con otro dataset ({recorded[:12]}…)")
            ledger._assert_bound(engine, case_id)
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
                    # procedencia (in_data | declared | default) y quién/cuándo; .get: manifiestos anteriores no los tienen
                    "timezone_source": m["timezone"].get("source"),
                    "timezone_note": m["timezone"].get("note"),
                    "time_range_utc": m["time_range_utc"],
                },
                "ingest_warnings": m.get("warnings", []),
            })
        return ledger

    def _assert_bound(self, engine, case_id: str) -> None:
        """El mismo CSV puede dar otro Parquet si cambia el mapping (p. ej. la zona horaria: 00:04 pasa a 05:04).

        Por eso no basta con comparar el hash de entrada: se exige que el mapping y el Parquet sean los que abrieron
        el caso. Los ledgers anteriores a esta comprobación no guardaban alguno de los dos y se aceptan como antes.
        """
        recorded = self._entries[0]["data"]["dataset"]
        manifest = engine.manifest or {}
        mapping_now = manifest.get("mapping", {}).get("sha256")
        if recorded.get("mapping_sha256") and mapping_now and recorded["mapping_sha256"] != mapping_now:
            raise MappingMismatch(t("integrity.err.mapping", case_id=case_id,
                                    recorded=recorded["mapping_sha256"][:12], current=mapping_now[:12]))
        parquet_now = getattr(engine, "parquet_sha256", None) or sha256_file(engine.parquet)
        if recorded.get("parquet_sha256") and recorded["parquet_sha256"] != parquet_now:
            raise ParquetMismatch(t("integrity.err.parquet", case_id=case_id,
                                    recorded=recorded["parquet_sha256"][:12], current=parquet_now[:12]))

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
                elif type_ == "data_copy":
                    self._copies[data["copy_id"]] = data
                return stored
            finally:
                if fcntl:
                    fcntl.flock(fh, fcntl.LOCK_UN)

    def record_copy(self, engine) -> bool:
        """Registra la copia seudonimizada sobre la que se consultará: política, tratamientos, hash del Parquet, del diccionario
        (nunca su contenido) y del Parquet real del que sale. Es idempotente. Devuelve True si escribió.

        Las copias reales no se registran: `case_opened` ya las identifica, y toda consulta anterior a P1-b.2b (sin sello de
        copia) se considera hecha sobre ellas.
        """
        if getattr(engine, "copy_kind", "real") == "real":
            return False
        if not engine.verified:
            raise ValueError("Una copia seudonimizada solo se registra si su Parquet se verificó contra el manifiesto")
        self._sync()
        if engine.copy_id in self._copies:
            return False
        m = engine.manifest
        if m["input"]["sha256"] != self.dataset_sha256:
            raise DatasetMismatch(f"La copia {engine.copy_id} sale de otro archivo de origen que el de este ledger")
        source = m["source_parquet"]["sha256"]
        bound = self._entries[0]["data"]["dataset"].get("parquet_sha256") if self._entries else None
        if bound and source != bound:
            raise CopyMismatch(f"La copia {engine.copy_id} se construyó desde otro Parquet ({source[:12]}…) que el que abrió el "
                               f"caso ({bound[:12]}…): se re-ingirió o se alteró después de seudonimizar")
        self.append("data_copy", {
            "copy_id": engine.copy_id, "kind": "pseudonymized", "parquet_sha256": engine.parquet_sha256,
            "source_parquet_sha256": source, "policy": m.get("policy"), "treatments": m.get("treatments"),
            "aliases_sha256": (m.get("aliases") or {}).get("sha256"), "rows": m["output"]["rows"]})
        return True

    def copies(self) -> dict[str, dict]:
        """Copias seudonimizadas registradas (id -> detalle)."""
        self._sync()
        return dict(self._copies)

    def record_queries(self, queries) -> int:
        """Registra consultas (cualquier estado: las rechazadas también son auditoría). Devuelve cuántas son nuevas."""
        self._sync()
        queries = list(queries)
        unknown = sorted({q["copy"] for q in queries if str(q.get("copy", "")).startswith("pseudonymized:")
                          and q["copy"] not in self._copies})
        if unknown:  # antes de escribir nada: o entran todas o ninguna
            raise CopyNotRegistered(f"Consultas sobre copias sin registrar: {unknown}. Llama antes a record_copy(engine).")
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

    def record_roles(self, roles) -> bool:
        """Registra qué columnas se trataron como actor y recurso (cambian lo que significan los hallazgos).

        Solo escribe si difieren de la última decisión registrada: ejecutar detectores diez veces deja una entrada.
        """
        self._sync()
        data = roles.as_record()
        last = next((e for e in reversed(self._entries) if e["type"] == "roles"), None)
        if last and last["data"] == data:
            return False
        self.append("roles", data)
        return True

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
        return verify_file(self.path)

    def replay(self, engine, record: bool = True) -> list[dict]:
        """Re-ejecuta las consultas registradas y compara el número de filas devueltas (y la huella del resultado).

        `engine` es un motor o una lista de motores. Cada consulta se re-ejecuta sobre el motor de LA COPIA en la que corrió
        (campo `copy` del registro): una consulta del agente sobre la copia seudonimizada solo tiene sentido sobre esa misma
        copia, porque `U-0003` no existe en los datos reales. Las consultas sin sello (anteriores a P1-b.2b) corrieron sobre los
        datos reales. Si falta el motor de alguna copia, esas consultas NO se verifican: salen con `skipped=True` y `match=False`
        (no verificada no es lo mismo que alterada, por eso no cuentan como `mismatches` en la entrada del ledger).

        Las re-ejecuciones son verificaciones, no análisis nuevo: no se añaden al historial del motor y el
        resultado queda como UNA entrada `replay` en el ledger (en vez de duplicar cada consulta).
        """
        engines = list(engine) if isinstance(engine, (list, tuple, set)) else [engine]
        if not engines:
            raise ValueError("replay necesita al menos un motor")
        self._sync()
        for e in engines:
            if e.dataset_sha256 != self.dataset_sha256:
                raise DatasetMismatch("El motor usa un dataset distinto al del ledger")
            if e.copy_kind == "pseudonymized" and e.copy_id not in self._copies:
                raise CopyMismatch(f"La copia {e.copy_id} no está registrada en este ledger: otra política o un Parquet "
                                   f"reconstruido; sus alias no son los que vio el modelo")
        by_copy = {e.copy_id: e for e in engines}
        real = next((e for e in engines if e.copy_kind == "real"), None)
        marks = {id(e): len(e.history) for e in engines}
        results = []
        for entry in self.entries("query"):
            d = entry["data"]
            if d["status"] != "ok":
                continue
            copy = d.get("copy") or "real"  # sin sello: consulta anterior a P1-b.2b, siempre sobre los datos reales
            target = real if copy.startswith("real") else by_copy.get(copy)
            base = {"query_id": d["query_id"], "copy": copy, "recorded_rows": d["rows"]}
            if target is None:
                results.append({**base, "replayed_rows": None, "hash_match": None, "match": False, "skipped": True,
                                "error": f"sin motor para la copia {copy}"})
                continue
            try:
                res = target.query(d["sql"], max_rows=d.get("limit"))  # mismo tope que en la ejecución original
                rows = res.row_count
                recorded_hash = d.get("result_sha256")
                # Con truncamiento, un LIMIT sin ORDER BY puede elegir otras filas: solo se compara el recuento.
                comparable = recorded_hash is not None and not d.get("truncated") and not res.truncated
                hash_match = (target.history[-1]["result_sha256"] == recorded_hash) if comparable else None
                results.append({**base, "replayed_rows": rows, "hash_match": hash_match,
                                "match": rows == d["rows"] and hash_match is not False})
            except Exception as exc:  # noqa: BLE001 - se reporta, no se oculta
                results.append({**base, "replayed_rows": None, "hash_match": None, "match": False,
                                "error": f"{type(exc).__name__}: {exc}"})
        for e in engines:
            del e.history[marks[id(e)]:]
        if record:
            by = {}
            for r in results:
                c = by.setdefault(r["copy"], {"queries": 0, "matches": 0})
                c["queries"] += 1
                c["matches"] += bool(r["match"])
            self.append("replay", {"queries": len(results), "matches": sum(r["match"] for r in results),
                                   "mismatches": [r["query_id"] for r in results if not r["match"] and not r.get("skipped")],
                                   "skipped": [r["query_id"] for r in results if r.get("skipped")],
                                   "by_copy": by,
                                   "hash_checked": sum(r["hash_match"] is not None for r in results),
                                   "hash_mismatches": [r["query_id"] for r in results if r["hash_match"] is False]})
        return results
