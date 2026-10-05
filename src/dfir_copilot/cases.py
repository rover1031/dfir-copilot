"""Espacio por caso: `data/cases/<caso>/{raw,processed,ledger}` + `mapping.yaml` + `case.json`.

Un caso = un dataset. Cada caso tiene su propia carpeta, así que dos casos con archivos del mismo nombre no pueden
pisarse el Parquet, y el mapping aprobado se COPIA dentro del caso: es inmutable y se verifica contra los hashes que
registran el manifiesto y el ledger. Una vez abierto el ledger, el dataset queda sellado.
"""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.evidence.ledger import _CASE_ID, Ledger, verify_file
from dfir_copilot.i18n import resolve_lang, t
from dfir_copilot.ingest.ingestor import MAPPINGS_DIR, ingest_file, sha256_file

DEFAULT_ROOT = "/workspace/data/cases"
CASE_VERSION = 1


class CaseError(Exception):
    """Error del espacio por caso (no existe, ya existe, mal identificado)."""


class CaseLocked(CaseError):
    """El caso ya tiene un ledger abierto: su dataset está sellado."""


@dataclass(frozen=True)
class Check:
    key: str
    ok: bool | None  # None = no aplicable todavía
    detail: str


@dataclass(frozen=True)
class IntegrityReport:
    case_id: str
    checks: tuple

    @property
    def ok(self) -> bool:
        return all(c.ok is not False for c in self.checks)

    def render(self, lang: str | None = None) -> str:
        lines = []
        for c in self.checks:
            mark = {True: "OK ", False: "XX ", None: "-- "}[c.ok]
            lines.append(f"{mark}{t('integrity.check.' + c.key, lang)}: {c.detail}")
        return "\n".join(lines)


def _valid_id(case_id: str) -> str:
    if not _CASE_ID.match(case_id or ""):
        raise CaseError(t("case.err.bad_id", case_id=case_id))
    return case_id


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)  # escritura atómica: nunca queda un case.json a medias


class CaseWorkspace:
    """Carpeta de un caso. Créala con `create()` o ábrela con `open()`."""

    def __init__(self, root: str | Path, case_id: str, lang: str | None = None):
        self.case_id = _valid_id(case_id)
        self.lang = resolve_lang(lang)
        self.dir = Path(root) / case_id
        self.raw_dir, self.processed_dir, self.ledger_dir = (self.dir / n for n in ("raw", "processed", "ledger"))
        self.mapping_path = self.dir / "mapping.yaml"
        self.meta_path = self.dir / "case.json"

    # --- ciclo de vida -----------------------------------------------------------------------------------------
    @classmethod
    def create(cls, case_id: str, root: str | Path = DEFAULT_ROOT, analyst: str | None = None,
               lang: str | None = None) -> CaseWorkspace:
        ws = cls(root, case_id, lang)
        if ws.dir.exists():
            raise CaseError(t("case.err.exists", ws.lang, case_id=case_id, path=ws.dir))
        for d in (ws.raw_dir, ws.processed_dir, ws.ledger_dir):
            d.mkdir(parents=True)
        _write_json(ws.meta_path, {"case_version": CASE_VERSION, "case_id": case_id, "analyst": analyst,
                                   "lang": ws.lang, "created_at_utc": datetime.now(UTC).isoformat(timespec="seconds"),
                                   "dataset": None})
        return ws

    @classmethod
    def open(cls, case_id: str, root: str | Path = DEFAULT_ROOT, lang: str | None = None) -> CaseWorkspace:
        ws = cls(root, case_id, lang)
        if not ws.meta_path.exists():
            raise CaseError(t("case.err.not_found", ws.lang, case_id=case_id, root=root))
        return ws

    @classmethod
    def open_or_create(cls, case_id: str, root: str | Path = DEFAULT_ROOT, analyst: str | None = None,
                       lang: str | None = None) -> CaseWorkspace:
        """Abre el caso si existe y lo crea si no: un notebook puede re-ejecutarse sin tocar celdas.

        Una carpeta a medias (sin case.json) no se reutiliza en silencio: es un estado que debe mirar el analista.
        """
        ws = cls(root, case_id, lang)
        if ws.meta_path.exists():
            return cls.open(case_id, root, lang)
        if ws.dir.exists():
            raise CaseError(t("case.err.incomplete", ws.lang, path=ws.dir))
        return cls.create(case_id, root, analyst, lang)

    @staticmethod
    def list_cases(root: str | Path = DEFAULT_ROOT) -> list[dict]:
        out = []
        for meta in sorted(Path(root).glob("*/case.json")) if Path(root).exists() else []:
            data = json.loads(meta.read_text(encoding="utf-8"))
            out.append({"case_id": data["case_id"], "analyst": data.get("analyst"),
                        "created_at_utc": data.get("created_at_utc"), "ingested": bool(data.get("dataset"))})
        return out

    @property
    def meta(self) -> dict:
        return json.loads(self.meta_path.read_text(encoding="utf-8"))

    @property
    def ledger_path(self) -> Path:
        return self.ledger_dir / f"{self.case_id}.jsonl"

    @property
    def sealed(self) -> bool:
        """Con un ledger abierto, el dataset ya respalda hallazgos: no puede cambiar."""
        return self.ledger_path.exists() and self.ledger_path.stat().st_size > 0

    # --- datos -------------------------------------------------------------------------------------------------
    def add_raw(self, path: str | Path, link: bool = False) -> Path:
        """Guarda el archivo original en raw/ (copia verificada por hash, o enlace simbólico para archivos enormes).

        La copia queda de solo lectura. Si ya existe otra con el mismo nombre y distinto contenido, se rechaza.
        """
        src = Path(path).resolve()
        dest = self.raw_dir / src.name
        if dest.exists() or dest.is_symlink():
            old, new = sha256_file(dest), sha256_file(src)
            if old != new:
                raise CaseError(t("case.err.raw_changed", self.lang, name=src.name, old=old[:12], new=new[:12]))
            return dest
        if link:
            dest.symlink_to(src)
        else:
            shutil.copy2(src, dest)
            if sha256_file(dest) != sha256_file(src):  # la copia debe ser idéntica bit a bit
                dest.unlink()
                raise CaseError(f"copy failed verification: {src.name}")
            dest.chmod(0o444)
        return dest

    def ingest(self, path: str | Path, mapping: str | Path, memory_limit: str = "2GB") -> dict:
        """Normaliza un archivo (CSV, TSV, JSON/NDJSON, Parquet; también .gz) al espacio del caso. `mapping` es un nombre del paquete (p. ej. `web_access_meli`) o la
        ruta a un YAML aprobado; en ambos casos se copia a `mapping.yaml` dentro del caso."""
        if self.sealed:
            raise CaseLocked(t("case.err.locked", self.lang, case_id=self.case_id))
        candidate = Path(str(mapping))
        source_file = candidate if candidate.suffix in (".yaml", ".yml") and candidate.exists() \
            else MAPPINGS_DIR / f"{mapping}.yaml"
        if not source_file.exists():
            raise FileNotFoundError(source_file)
        shutil.copyfile(source_file, self.mapping_path)
        manifest = ingest_file(path, source=source_file.stem, out_dir=self.processed_dir, memory_limit=memory_limit,
                               mapping_path=self.mapping_path, overwrite=True)  # el caso no está sellado: se puede rehacer
        meta = self.meta
        meta["dataset"] = {"parquet": Path(manifest["output"]["path"]).name,
                           "input_sha256": manifest["input"]["sha256"], "mapping_sha256": manifest["mapping"]["sha256"],
                           "parquet_sha256": manifest["output"]["sha256"], "rows": manifest["output"]["rows"],
                           "ingested_at_utc": manifest["ingested_at_utc"]}
        _write_json(self.meta_path, meta)
        return manifest

    def _dataset(self) -> dict:
        dataset = self.meta.get("dataset")
        if not dataset:
            raise CaseError(t("case.err.no_dataset", self.lang, case_id=self.case_id))
        return dataset

    def engine(self, **kwargs) -> QueryEngine:
        return QueryEngine(self.processed_dir / self._dataset()["parquet"], **kwargs)

    def pseudonymized(self, policy=None, **engine_kwargs):
        """(motor, diccionario) sobre la copia seudonimizada del dataset del caso; la crea la primera vez.

        Es lo que debe consultar todo lo que vea el LLM. El diccionario (alias -> valor real) se queda en `processed/`.
        """
        from dfir_copilot.privacy import PrivacyPolicy, Pseudonymizer, build_pseudonymized

        policy = policy or PrivacyPolicy()
        dataset = self._dataset()
        parquet = self.processed_dir / dataset["parquet"]
        stem = parquet.name.removesuffix(".parquet")
        manifest_path = self.processed_dir / f"{stem}.pseudo-{policy.fingerprint()}.manifest.json"
        pseudo = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else None
        if pseudo is None or pseudo["source_parquet"]["sha256"] != dataset["parquet_sha256"]:
            real = json.loads(parquet.with_suffix(".manifest.json").read_text(encoding="utf-8"))
            pseudo = build_pseudonymized(parquet, real, self.processed_dir, policy)
        engine = QueryEngine(pseudo["output"]["path"], **engine_kwargs)  # verifica el hash del Parquet seudonimizado
        return engine, Pseudonymizer(pseudo)

    @property
    def agent_dir(self) -> Path:
        return self.dir / "agent"

    def checkpointer(self):
        """Guardado en disco de la conversación del agente: `build_agent(..., checkpointer=ws.checkpointer())`.

        Una aprobación pendiente o una conversación en curso sobreviven a reiniciar el kernel. Vive en `agent/threads.json`,
        fuera de `raw/`, `processed/` y `ledger/`: no forma parte de lo que sella el caso."""
        from dfir_copilot.agent.persist import FileCheckpointer

        return FileCheckpointer(self.agent_dir / "threads.json")

    def ledger(self, engine: QueryEngine | None = None, analyst: str | None = None) -> Ledger:
        engine = engine or self.engine()
        return Ledger.open(self.case_id, engine, analyst=analyst or self.meta.get("analyst"), root=self.ledger_dir)

    # --- verificación completa ----------------------------------------------------------------------------------
    def verify(self) -> IntegrityReport:
        """Comprueba toda la cadena de custodia sin lanzar excepciones: devuelve un informe con cada comprobación."""
        lang = self.lang
        checks: list[Check] = []

        def add(key, ok, detail=None):
            checks.append(Check(key, ok, detail if detail is not None else t("integrity.detail.ok", lang)))

        def compare(key, expected, actual):
            add(key, expected == actual, None if expected == actual else
                t("integrity.detail.mismatch", lang, expected=str(expected)[:12], actual=str(actual)[:12]))

        dataset = self.meta.get("dataset")
        if not dataset:
            add("dataset", None, t("case.err.no_dataset", lang, case_id=self.case_id))
            return IntegrityReport(self.case_id, tuple(checks))
        parquet = self.processed_dir / dataset["parquet"]
        manifest_path = parquet.with_suffix(".manifest.json")
        if not parquet.exists() or not manifest_path.exists():
            add("dataset", False, t("integrity.detail.missing", lang))
            return IntegrityReport(self.case_id, tuple(checks))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        parquet_now = sha256_file(parquet)
        compare("parquet_manifest", manifest["output"]["sha256"], parquet_now)
        if self.mapping_path.exists():
            mapping_now = sha256_file(self.mapping_path)
            compare("mapping_manifest", manifest["mapping"]["sha256"], mapping_now)
        else:
            mapping_now = manifest["mapping"]["sha256"]
            add("mapping_manifest", False, t("integrity.detail.missing", lang))
        raw = self.raw_dir / Path(manifest["input"]["path"]).name
        if raw.exists() or raw.is_symlink():
            compare("raw", manifest["input"]["sha256"], sha256_file(raw))

        if self.ledger_path.exists():
            chain = verify_file(self.ledger_path)
            add("ledger_chain", chain.ok, None if chain.ok else chain.error)
            if chain.ok:
                first = json.loads(self.ledger_path.read_text(encoding="utf-8").splitlines()[0])
                recorded = first["data"]["dataset"]
                compare("parquet_ledger", recorded.get("parquet_sha256"), parquet_now)
                compare("mapping_ledger", recorded.get("mapping_sha256"), mapping_now)
        else:
            add("ledger_chain", None, t("integrity.detail.not_recorded", lang))
        return IntegrityReport(self.case_id, tuple(checks))
