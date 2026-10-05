"""Proyectos: una carpeta con los archivos a analizar. Un proyecto crea UN CASO POR ARCHIVO (un caso = un dataset).

```
<projects_root>/<proyecto>/
├── project.json     nombre, carpeta de origen, ajustes (idioma, zona horaria, modelo, tope de tokens)
├── cases/           los casos (CaseWorkspace): raw/, processed/, ledger/ ... uno por archivo
└── status/          estado del análisis automático de cada archivo (`<caso>.json`)
```

La carpeta de origen debe estar DENTRO de la raíz de datos: la interfaz web deja escribir una ruta y no debe poder leer cualquier
carpeta de la máquina. Los archivos no se copian: el caso enlaza al original (`add_raw(link=True)`), que ya queda verificado por hash.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from dfir_copilot.cases import CaseWorkspace

DEFAULT_DATA_ROOT = "/workspace/data"
SUPPORTED_SUFFIXES = (".csv", ".tsv", ".json", ".ndjson", ".jsonl", ".parquet")
LANGUAGES = ("es", "en")
_PROJECT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


class ProjectError(Exception):
    """Proyecto inexistente, duplicado o con una ruta no permitida."""


def slugify(text: str, limit: int = 40) -> str:
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_text.lower()).strip("-")
    return slug[:limit].strip("-")


def data_root() -> Path:
    return Path(os.environ.get("DFIR_DATA_ROOT", DEFAULT_DATA_ROOT))


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

    def __post_init__(self):
        if self.language not in LANGUAGES:
            raise ProjectError(f"Idioma no soportado: {self.language!r} (usa {LANGUAGES})")
        for name in ("max_tokens", "max_tokens_case"):
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


class Project:
    def __init__(self, root: Path, project_id: str):
        self.id = project_id
        self.dir = Path(root) / project_id
        self.meta_path = self.dir / "project.json"
        self.cases_dir = self.dir / "cases"
        self.status_dir = self.dir / "status"

    # --- ciclo de vida ----------------------------------------------------------------------------------------
    @classmethod
    def create(cls, name: str, source_dir: str | Path, settings: ProjectSettings | None = None,
               root: str | Path | None = None, base: str | Path | None = None) -> Project:
        """`base`: raíz bajo la que debe estar `source_dir` (por defecto la raíz de datos)."""
        name = (name or "").strip()
        project_id = slugify(name)
        if not name or not _PROJECT_ID.match(project_id):
            raise ProjectError("El nombre del proyecto debe tener al menos una letra o un número")
        source = cls.check_source_dir(source_dir, base)
        project = cls(Path(root) if root else projects_root(), project_id)
        if project.dir.exists():
            raise ProjectError(f"Ya existe el proyecto '{project_id}'")
        settings = settings or ProjectSettings()
        project.cases_dir.mkdir(parents=True)
        project.status_dir.mkdir(parents=True)
        _atomic_write(project.meta_path, {"project_version": 1, "id": project_id, "name": name, "source_dir": str(source),
                                          "settings": asdict(settings), "created_at_utc": datetime.now(UTC).isoformat(timespec="seconds")})
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
    def settings(self) -> ProjectSettings:
        return ProjectSettings(**self.meta["settings"])

    def files(self) -> list[SourceFile]:
        """Archivos de la carpeta de origen (no recursivo), con el id de caso que les corresponde."""
        if not self.source_dir.is_dir():
            return []
        entries = sorted((p for p in self.source_dir.iterdir() if p.is_file() and not p.name.startswith(".")),
                         key=lambda p: p.name.lower())
        base_ids = [f"{self.id[:28]}--{slugify(_stem(p.name), 28) or 'archivo'}" for p in entries]
        out = []
        for p, base in zip(entries, base_ids, strict=True):
            case_id = base if base_ids.count(base) == 1 else f"{base}-{hashlib.sha1(p.name.encode()).hexdigest()[:6]}"
            ok = _supported(p.name)
            out.append(SourceFile(p.name, p, p.stat().st_size, case_id, ok, None if ok else "formato no soportado"))
        return out

    def file(self, case_id: str) -> SourceFile:
        for f in self.files():
            if f.case_id == case_id:
                return f
        raise ProjectError(f"El proyecto no tiene ningún archivo para el caso '{case_id}'")

    def workspace(self, case_id: str, create: bool = False) -> CaseWorkspace:
        s = self.settings
        if create:
            return CaseWorkspace.open_or_create(case_id, root=self.cases_dir, analyst=s.analyst, lang=s.language)
        return CaseWorkspace.open(case_id, root=self.cases_dir, lang=s.language)

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
