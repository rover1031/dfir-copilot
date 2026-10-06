"""Proyectos: una carpeta con los archivos a analizar. Un proyecto crea UN CASO POR ARCHIVO (un caso = un dataset).

```
<projects_root>/<proyecto>/
├── project.json     nombre, ticket, descripción, modo, carpeta de origen, ajustes (idioma, zona horaria, modelo, tope de tokens)
├── evidencia/       (modo "evidence") los archivos del análisis: subidos o traídos del servidor, copiados o enlazados
├── custodia.jsonl   (modo "evidence") cadena de custodia: qué entró, de dónde, quién, cuándo y con qué SHA-256, encadenada por hash
├── cases/           los casos (CaseWorkspace): raw/, processed/, ledger/ ... uno por archivo
└── status/          estado del análisis automático de cada archivo (`<caso>.json`)
```

Dos modos:
* **evidence** (el del asistente "Nuevo análisis"): cada análisis tiene su propia carpeta `evidencia/`. Los archivos entran subidos desde el
  navegador o elegidos de una carpeta del servidor, y quedan registrados en la custodia. Un Excel se convierte en un CSV por hoja (derivado,
  también registrado). Un PDF se guarda como evidencia, pero no es un log y no se analiza como tal.
* **folder** (el anterior): el proyecto vincula una carpeta del servidor y analiza lo que haya en ella.

Toda ruta del servidor debe estar DENTRO de la raíz de datos: la interfaz no debe poder leer cualquier carpeta de la máquina.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from dfir_copilot.cases import CaseWorkspace
from dfir_copilot.ingest.excel import EXCEL_SUFFIXES, ExcelError, excel_to_csv
from dfir_copilot.ingest.text_logs import TEXT_SUFFIXES, TextLogError, text_to_csv

try:  # bloqueo de la custodia entre hilos y procesos (en Windows sin WSL no existe: se escribe sin bloqueo)
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

DEFAULT_DATA_ROOT = "/workspace/data"
SUPPORTED_SUFFIXES = (".csv", ".tsv", ".json", ".ndjson", ".jsonl", ".parquet")
DOCUMENT_SUFFIXES = (".pdf",)
LANGUAGES = ("es", "en")
EVIDENCE_DIR = "evidencia"
CUSTODY_FILE = "custodia.jsonl"
_GENESIS = "0" * 64
_CHUNK = 1 << 20
_PROJECT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


class ProjectError(Exception):
    """Proyecto inexistente, duplicado o con una ruta no permitida."""


def slugify(text: str, limit: int = 40) -> str:
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_text.lower()).strip("-")
    return slug[:limit].strip("-")


def data_root() -> Path:
    return Path(os.environ.get("DFIR_DATA_ROOT", DEFAULT_DATA_ROOT))


def inbox_root() -> Path:
    """Carpeta de entrada: lo único que la interfaz ofrece para elegir archivos del servidor (no las carpetas internas)."""
    root = Path(os.environ.get("DFIR_INBOX_ROOT", str(data_root() / "inbox")))
    with contextlib.suppress(OSError):  # sin permiso para crearla: se informa al navegarla
        root.mkdir(parents=True, exist_ok=True)
    return root


def projects_root() -> Path:
    return Path(os.environ.get("DFIR_PROJECTS_ROOT", str(data_root() / "projects")))


@dataclass(frozen=True)
class ProjectSettings:
    language: str = "es"
    timezone: str | None = None        # IANA, p. ej. America/Santiago; None = nadie la declaró (se asume UTC, sin verificar)
    analyst: str | None = None
    use_llm: bool = True               # etapas con modelo (interpretación y triaje). Sin esto el análisis es 100 % local
    max_tokens: int = 210_000          # tope por pregunta del agente
    max_tokens_case: int | None = None  # tope acumulado por caso (opcional)
    max_tokens_incident: int | None = None  # tope acumulado de TODO el análisis (todas sus fuentes), opcional

    def __post_init__(self):
        if self.language not in LANGUAGES:
            raise ProjectError(f"Idioma no soportado: {self.language!r} (usa {LANGUAGES})")
        for name in ("max_tokens", "max_tokens_case", "max_tokens_incident"):
            v = getattr(self, name)
            if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 1):
                raise ProjectError(f"{name} debe ser un entero positivo")
        if self.timezone:
            from dfir_copilot.ingest.ingestor import check_timezone

            try:
                check_timezone(self.timezone)
            except ValueError as exc:
                raise ProjectError(str(exc)) from exc


@dataclass(frozen=True)
class SourceFile:
    name: str
    path: Path
    size: int
    case_id: str
    supported: bool
    reason: str | None = None
    kind: str = "log"  # log | excel (se analiza por sus hojas derivadas) | document (PDF: evidencia, no log) | other


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def _stem(name: str) -> str:
    lower = name.lower()
    if lower.endswith(".gz"):
        name = name[:-3]
    return Path(name).stem


def _supported(name: str) -> bool:
    lower = name.lower()
    if lower.endswith(".gz"):
        lower = lower[:-3]
    return lower.endswith(SUPPORTED_SUFFIXES)


def file_kind(name: str) -> str:
    lower = name.lower()
    if _supported(name):
        return "log"
    if lower.endswith(EXCEL_SUFFIXES):
        return "excel"
    if lower.endswith(DOCUMENT_SUFFIXES):
        return "document"
    if lower.endswith(TEXT_SUFFIXES):
        return "text"
    return "other"


def accepted(name: str) -> bool:
    """¿Se puede añadir como evidencia? Logs, Excel y PDF."""
    return file_kind(name) != "other"


def safe_name(filename: str) -> str:
    """Nombre de archivo seguro: sin rutas (ni / ni \\), solo ASCII imprimible, sin puntos iniciales."""
    base = re.split(r"[\\/]", filename or "")[-1]
    base = unicodedata.normalize("NFKD", base).encode("ascii", "ignore").decode("ascii")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._-") or "archivo"
    return base[-120:]


def _split_name(name: str) -> tuple[str, str]:
    lower = name.lower()
    if lower.endswith(".gz") and "." in name[:-3]:
        stem, ext = name[:-3].rsplit(".", 1)
        return stem, f".{ext}.gz"
    return (name.rsplit(".", 1)[0], "." + name.rsplit(".", 1)[1]) if "." in name else (name, "")


def sha256_path(path: Path) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _reason(kind: str, mode: str) -> str | None:
    if kind == "excel":
        return ("Excel: sus hojas se analizan como CSV derivados" if mode == "evidence"
                else "Excel: añádelo desde «Nuevo análisis» para convertir sus hojas")
    if kind == "document":
        return "documento (no es un log): guardado como evidencia"
    if kind == "text":
        return ("log de texto: se analiza por sus CSV derivados (Palo Alto o Nginx/Apache)" if mode == "evidence"
                else "log de texto: añádelo desde «Nuevo análisis» para convertirlo")
    return None if kind == "log" else "formato no soportado"


class Project:
    def __init__(self, root: Path, project_id: str):
        self.id = project_id
        self.dir = Path(root) / project_id
        self.meta_path = self.dir / "project.json"
        self.cases_dir = self.dir / "cases"
        self.status_dir = self.dir / "status"

    # --- ciclo de vida ----------------------------------------------------------------------------------------
    @classmethod
    def create(cls, name: str, source_dir: str | Path | None = None, settings: ProjectSettings | None = None,
               root: str | Path | None = None, base: str | Path | None = None, ticket: str | None = None,
               description: str | None = None) -> Project:
        """Sin `source_dir`: análisis con carpeta de evidencia propia (modo "evidence"). Con él: vincula esa carpeta (modo "folder").
        `base`: raíz bajo la que debe estar `source_dir` (por defecto la raíz de datos)."""
        name = (name or "").strip()
        project_id = slugify(name)
        if not name or not _PROJECT_ID.match(project_id):
            raise ProjectError("El nombre del análisis debe tener al menos una letra o un número")
        source = cls.check_source_dir(source_dir, base) if source_dir is not None and str(source_dir).strip() else None
        project = cls(Path(root) if root else projects_root(), project_id)
        if project.dir.exists():
            raise ProjectError(f"Ya existe un análisis con el identificador '{project_id}'")
        settings = settings or ProjectSettings()
        project.cases_dir.mkdir(parents=True)
        project.status_dir.mkdir(parents=True)
        if source is None:
            source = project.dir / EVIDENCE_DIR
            source.mkdir()
        _atomic_write(project.meta_path, {
            "project_version": 3, "shared_dictionary": source_dir is None or not str(source_dir).strip(),
            "id": project_id, "name": name, "mode": "evidence" if source_dir is None or not str(source_dir).strip()
            else "folder", "source_dir": str(source), "ticket": (ticket or "").strip()[:80] or None,
            "description": (description or "").strip()[:2000] or None, "settings": asdict(settings),
            "created_at_utc": datetime.now(UTC).isoformat(timespec="seconds")})
        return project

    @staticmethod
    def check_source_dir(source_dir: str | Path, base: str | Path | None = None) -> Path:
        base_path = Path(base) if base else data_root()
        try:
            source = Path(source_dir).expanduser().resolve()
            allowed = base_path.resolve()
        except (OSError, RuntimeError) as exc:
            raise ProjectError(f"Ruta no válida: {exc}") from exc
        if not source.is_relative_to(allowed):
            raise ProjectError(f"La carpeta debe estar dentro de {allowed} (la interfaz no lee otras rutas de la máquina)")
        if not source.is_dir():
            raise ProjectError(f"No existe la carpeta {source}")
        return source

    @classmethod
    def open(cls, project_id: str, root: str | Path | None = None) -> Project:
        if not _PROJECT_ID.match(project_id or ""):
            raise ProjectError(f"Identificador de proyecto no válido: {project_id!r}")
        project = cls(Path(root) if root else projects_root(), project_id)
        if not project.meta_path.exists():
            raise ProjectError(f"No existe el proyecto '{project_id}'")
        return project

    @staticmethod
    def list(root: str | Path | None = None) -> list[Project]:
        base = Path(root) if root else projects_root()
        found = sorted(p.parent.name for p in base.glob("*/project.json")) if base.exists() else []
        return [Project(base, pid) for pid in found]

    # --- datos --------------------------------------------------------------------------------------------------
    @property
    def meta(self) -> dict:
        return json.loads(self.meta_path.read_text(encoding="utf-8"))

    @property
    def name(self) -> str:
        return self.meta["name"]

    @property
    def source_dir(self) -> Path:
        return Path(self.meta["source_dir"])

    @property
    def mode(self) -> str:
        return self.meta.get("mode", "folder")

    @property
    def ticket(self) -> str | None:
        return self.meta.get("ticket")

    @property
    def description(self) -> str | None:
        return self.meta.get("description")

    @property
    def settings(self) -> ProjectSettings:
        return ProjectSettings(**self.meta["settings"])

    def files(self) -> list[SourceFile]:
        """Archivos de la carpeta de origen (no recursivo), con el id de caso que les corresponde."""
        if not self.source_dir.is_dir():
            return []
        entries = sorted((p for p in self.source_dir.iterdir()
                          if p.is_file() and not p.name.startswith(".") and not p.name.endswith(".partial")),
                         key=lambda p: p.name.lower())
        base_ids = [f"{self.id[:28]}--{slugify(_stem(p.name), 28) or 'archivo'}" for p in entries]
        out = []
        for p, base in zip(entries, base_ids, strict=True):
            case_id = base if base_ids.count(base) == 1 else f"{base}-{hashlib.sha1(p.name.encode()).hexdigest()[:6]}"
            kind = file_kind(p.name)
            out.append(SourceFile(p.name, p, p.stat().st_size, case_id, kind == "log", _reason(kind, self.mode), kind))
        return out

    def file(self, case_id: str) -> SourceFile:
        for f in self.files():
            if f.case_id == case_id:
                return f
        raise ProjectError(f"El proyecto no tiene ningún archivo para el caso '{case_id}'")

    @property
    def dictionary_path(self) -> Path | None:
        """Diccionario de alias compartido por las fuentes de este análisis (solo análisis nuevos: `shared_dictionary` en project.json)."""
        return self.dir / "diccionario.duckdb" if self.meta.get("shared_dictionary") else None

    def workspace(self, case_id: str, create: bool = False) -> CaseWorkspace:
        s = self.settings
        if create:
            ws = CaseWorkspace.open_or_create(case_id, root=self.cases_dir, analyst=s.analyst, lang=s.language)
            marker = ws.dir / "shared_dictionary.txt"
            if self.dictionary_path and not marker.exists():
                marker.write_text(str(self.dictionary_path), encoding="utf-8")
            return ws
        return CaseWorkspace.open(case_id, root=self.cases_dir, lang=s.language)

    # --- evidencia y custodia (modo "evidence") ----------------------------------------------------------------------
    @property
    def custody_path(self) -> Path:
        return self.dir / CUSTODY_FILE

    def _require_evidence(self) -> None:
        if self.mode != "evidence":
            raise ProjectError("Este análisis vincula una carpeta del servidor: para añadir archivos crea uno con «Nuevo análisis»")

    def _unique(self, name: str) -> Path:
        stem, ext = _split_name(name)
        candidate, i = self.source_dir / name, 2
        while candidate.exists() or candidate.is_symlink() or candidate.with_name(candidate.name + ".partial").exists():
            candidate, i = self.source_dir / f"{stem}-{i}{ext}", i + 1
        return candidate

    def _write(self, target: Path, chunks: Iterable[bytes], max_bytes: int | None) -> tuple[str, int]:
        partial = target.with_name(target.name + ".partial")
        h, size = hashlib.sha256(), 0
        try:
            with open(partial, "xb") as fh:
                for chunk in chunks:
                    size += len(chunk)
                    if max_bytes is not None and size > max_bytes:
                        raise ProjectError(f"El archivo supera el límite de {max_bytes // (1 << 20):,} MB")
                    h.update(chunk)
                    fh.write(chunk)
            os.replace(partial, target)
        finally:
            partial.unlink(missing_ok=True)
        return h.hexdigest(), size

    def _custody(self, action: str, **data) -> dict:
        with open(self.custody_path, "a+", encoding="utf-8") as fh:
            if fcntl:
                fcntl.flock(fh, fcntl.LOCK_EX)
            fh.seek(0)
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
            prev = json.loads(lines[-1]) if lines else None
            entry = {"seq": len(lines) + 1, "at_utc": datetime.now(UTC).isoformat(timespec="seconds"), "action": action, **data,
                     "prev_hash": prev["hash"] if prev else _GENESIS}
            entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
            fh.seek(0, os.SEEK_END)
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def custody(self) -> list[dict]:
        if not self.custody_path.exists():
            return []
        return [json.loads(ln) for ln in self.custody_path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def verify_custody(self) -> dict:
        """Comprueba la cadena (nadie editó la custodia) y que cada archivo registrado sigue teniendo el mismo SHA-256."""
        problems, prev = [], _GENESIS
        records = self.custody()
        for e in records:
            body = {k: v for k, v in e.items() if k != "hash"}
            if e.get("prev_hash") != prev or hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")
                                                            ).hexdigest() != e.get("hash"):
                problems.append(f"registro {e.get('seq')}: la cadena de custodia no cuadra (¿editada a mano?)")
            prev = e.get("hash")
        current = {}
        for e in records:
            if e["action"] in ("added", "derived"):
                current[e["file"]] = e["sha256"]
        for name, sha in sorted(current.items()):
            path = self.source_dir / name
            if not path.exists():
                problems.append(f"{name}: el archivo ya no está en la evidencia")
            elif sha256_path(path)[0] != sha:
                problems.append(f"{name}: el contenido cambió desde que entró (SHA-256 distinto)")
        return {"ok": not problems, "records": len(records), "files": len(current), "problems": problems}

    def _admit(self, target: Path, sha: str, size: int, analyst: str | None, **origin) -> list[dict]:
        out = [self._custody("added", file=target.name, sha256=sha, bytes=size, kind=file_kind(target.name), analyst=analyst, **origin)]
        if file_kind(target.name) == "text":
            stem = _split_name(target.name)[0]
            try:
                parts = text_to_csv(target, lambda label: self._unique(f"{stem}__{label}.csv"))
            except TextLogError as exc:
                out.append(self._custody("derivation_failed", file=target.name, error=str(exc)[:300], analyst=analyst))
                return out
            for part in parts:
                d_sha, d_size = sha256_path(part["path"])
                out.append(self._custody("derived", file=part["path"].name, sha256=d_sha, bytes=d_size, kind="log", analyst=analyst,
                                         derived_from={"file": target.name, "sha256": sha}, format=part["format"], rows=part["rows"],
                                         skipped=part["skipped"]))
            return out
        if file_kind(target.name) == "excel":
            stem = _split_name(target.name)[0]
            try:
                sheets = excel_to_csv(target, lambda sheet: self._unique(f"{stem}__{slugify(sheet, 40) or 'hoja'}.csv"))
            except ExcelError as exc:
                out.append(self._custody("derivation_failed", file=target.name, error=str(exc)[:300], analyst=analyst))
                return out
            for sh in sheets:
                d_sha, d_size = sha256_path(sh["path"])
                out.append(self._custody("derived", file=sh["path"].name, sha256=d_sha, bytes=d_size, kind="log", analyst=analyst,
                                         derived_from={"file": target.name, "sha256": sha}, sheet=sh["sheet"], rows=sh["rows"]))
        return out

    def add_upload(self, filename: str, chunks: Iterable[bytes], analyst: str | None = None,
                   max_bytes: int | None = None) -> list[dict]:
        """Añade un archivo subido desde el navegador. Devuelve los registros de custodia (el archivo y, si es Excel, sus hojas)."""
        self._require_evidence()
        name = safe_name(filename)
        if not accepted(name):
            raise ProjectError(f"Tipo de archivo no admitido: {name} (se admiten logs CSV, TSV, JSON, NDJSON, Parquet y de texto "
                               ".log/.txt, Excel y PDF)")
        target = self._unique(name)
        sha, size = self._write(target, chunks, max_bytes)
        return self._admit(target, sha, size, analyst, origin="upload", origin_name=(filename or "")[:300], mode="copy")

    def add_from_server(self, path: str | Path, mode: str = "copy", analyst: str | None = None,
                        base: str | Path | None = None) -> list[dict]:
        """Añade un archivo que ya está en el servidor, dentro de la raíz de datos: copiado (lo normal) o enlazado (archivos enormes)."""
        self._require_evidence()
        if mode not in ("copy", "link"):
            raise ProjectError("El modo debe ser 'copy' o 'link'")
        allowed = (Path(base) if base else data_root()).resolve()
        try:
            src = Path(path).expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            raise ProjectError(f"Ruta no válida: {exc}") from exc
        if not src.is_relative_to(allowed):
            raise ProjectError(f"El archivo debe estar dentro de {allowed}")
        if src.is_relative_to(self.dir.resolve()):
            raise ProjectError("Ese archivo ya pertenece a este análisis")
        if not src.is_file():
            raise ProjectError(f"No existe el archivo {src}")
        name = safe_name(src.name)
        if not accepted(name):
            raise ProjectError(f"Tipo de archivo no admitido: {name}")
        target = self._unique(name)
        if mode == "copy":
            def chunks():
                with open(src, "rb") as fh:
                    while chunk := fh.read(_CHUNK):
                        yield chunk
            sha, size = self._write(target, chunks(), None)
        else:
            sha, size = sha256_path(src)
            target.symlink_to(src)
        return self._admit(target, sha, size, analyst, origin="server", origin_path=str(src), mode=mode)

    # --- estado del análisis automático ------------------------------------------------------------------------
    def status_path(self, case_id: str) -> Path:
        return self.status_dir / f"{case_id}.json"

    def status(self, case_id: str) -> dict | None:
        path = self.status_path(case_id)
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def save_status(self, case_id: str, data: dict) -> None:
        _atomic_write(self.status_path(case_id), data)


@dataclass(frozen=True)
class CaseRef:
    """Un caso visible en la interfaz: de un proyecto o suelto (los de `data/cases`, anteriores a los proyectos)."""

    case_id: str
    project_id: str | None = None
    extra: dict = field(default_factory=dict)


def browse(rel: str = "", base: str | Path | None = None) -> dict:
    """Contenido de una carpeta dentro de la raíz de datos, para elegir archivos desde la interfaz. `rel` es relativa a la raíz.
    No sale de la raíz (ni con `..` ni con enlaces) y no muestra la carpeta interna de proyectos."""
    root = (Path(base) if base else data_root()).resolve()
    try:
        here = (root / (rel or "")).resolve()
    except (OSError, RuntimeError) as exc:
        raise ProjectError(f"Ruta no válida: {exc}") from exc
    if not here.is_relative_to(root):
        raise ProjectError(f"Solo se puede navegar dentro de {root}")
    if not here.is_dir():
        raise ProjectError(f"No existe la carpeta {here}")
    hidden = {projects_root().resolve()}
    dirs, files = [], []
    for p in sorted(here.iterdir(), key=lambda x: x.name.lower()):
        if p.name.startswith("."):
            continue
        try:
            real = p.resolve()
        except (OSError, RuntimeError):
            continue
        if not real.is_relative_to(root) or real in hidden:
            continue
        if p.is_dir():
            dirs.append({"name": p.name, "rel": str(real.relative_to(root))})
        elif p.is_file():
            files.append({"name": p.name, "rel": str(real.relative_to(root)), "size": p.stat().st_size, "kind": file_kind(p.name)})
    parent = None if here == root else ("" if here.parent == root else str(here.parent.relative_to(root)))
    return {"root": str(root), "path": str(here), "rel": "" if here == root else str(here.relative_to(root)), "parent": parent,
            "dirs": dirs, "files": files}
