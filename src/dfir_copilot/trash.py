"""Papelera de análisis y casos: eliminar sin perder la trazabilidad.

En DFIR un análisis lleva evidencia y su cadena de custodia, así que «eliminar» se hace en dos pasos:
1. **Mover a la papelera** (recuperable): el análisis desaparece de la lista y se puede restaurar tal cual.
2. **Eliminar definitivamente** desde la papelera (o vaciarla).

Cada paso queda en un **registro de eliminaciones** propio, encadenado por hashes como la custodia, porque la custodia del análisis se va con
él: quién, cuándo, qué archivos y con qué SHA-256, y el último hash de su custodia. Así queda constancia de que hubo evidencia y de que se
eliminó, aunque ya no exista.

Reglas:
* Un análisis que vincula una carpeta del servidor (modo «folder») se elimina SIN tocar esa carpeta: solo se mueven los datos del análisis.
* No se elimina nada mientras se está analizando.
* Los informes exportados de sus casos (`reports/<caso>/`) viajan con el análisis y vuelven al restaurarlo.
* Restaurar nunca sobrescribe: si ya existe un análisis con ese identificador, se rechaza.
* Todo es un `rename` dentro de la raíz de datos: no se copia evidencia ni se duplica espacio."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REGISTRY = "registro.jsonl"
CARD = "ficha.json"
CONTENT = "contenido"
REPORTS = "reportes"
_GENESIS = "0" * 64
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
_ITEM = re.compile(r"^\d{8}T\d{6}Z--(proyecto|caso)--[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
VACIAR = "VACIAR"


class TrashError(Exception):
    pass


@dataclass(frozen=True)
class Roots:
    trash: Path
    projects: Path
    cases: Path
    reports: Path


def _now() -> datetime:
    return datetime.now(UTC)


def _size(path: Path) -> int:
    total = 0
    for dirpath, _d, files in os.walk(path):
        for name in files:
            try:
                total += (Path(dirpath) / name).stat().st_size
            except OSError:
                pass
    return total


def _check_id(value: str, what: str) -> str:
    if not _ID.match(value or "") or value in (".", ".."):
        raise TrashError(f"Identificador de {what} no válido: {value!r}")
    return value


def _check_item(item_id: str) -> str:
    if not _ITEM.match(item_id or ""):
        raise TrashError(f"Elemento de la papelera no válido: {item_id!r}")
    return item_id


# --- registro encadenado ------------------------------------------------------------------------------------------------------------
def _record(roots: Roots, action: str, **data) -> dict:
    roots.trash.mkdir(parents=True, exist_ok=True)
    path = roots.trash / REGISTRY
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()] if path.exists() else []
    prev = json.loads(lines[-1])["hash"] if lines else _GENESIS
    entry = {"seq": len(lines) + 1, "at_utc": _now().isoformat(timespec="seconds"), "action": action, **data, "prev_hash": prev}
    entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def registry(roots: Roots) -> list[dict]:
    path = roots.trash / REGISTRY
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()] if path.exists() else []


def verify_registry(roots: Roots) -> dict:
    """¿Alguien editó el registro de eliminaciones? Misma comprobación que la cadena de custodia."""
    problems, prev = [], _GENESIS
    entries = registry(roots)
    for e in entries:
        body = {k: v for k, v in e.items() if k != "hash"}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
        if e.get("prev_hash") != prev or digest != e.get("hash"):
            problems.append(f"registro {e.get('seq')}: la cadena no cuadra (¿editado a mano?)")
        prev = e.get("hash")
    return {"ok": not problems, "records": len(entries), "problems": problems}


# --- mover a la papelera ------------------------------------------------------------------------------------------------------------
def _custody_summary(project) -> tuple[list[dict], str | None, int]:
    try:
        records = project.custody()
    except Exception:  # noqa: BLE001 - una custodia ilegible no impide eliminar; se anota
        return [], None, 0
    current: dict[str, str] = {}
    for e in records:
        if e.get("action") in ("added", "derived") and e.get("file"):
            current[e["file"]] = e.get("sha256")
    return [{"file": f, "sha256": s} for f, s in sorted(current.items())], (records[-1].get("hash") if records else None), len(records)


def _move_reports(roots: Roots, case_ids: list[str], item: Path) -> list[str]:
    moved = []
    for cid in case_ids:
        src = roots.reports / cid
        if cid and _ID.match(cid) and src.is_dir():
            (item / REPORTS).mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(item / REPORTS / cid))
            moved.append(cid)
    return moved


def _new_item(roots: Roots, kind: str, ident: str) -> Path:
    item = roots.trash / f"{_now():%Y%m%dT%H%M%SZ}--{kind}--{ident}"
    n = 1
    while item.exists():                               # dos eliminaciones en el mismo segundo
        n += 1
        item = roots.trash / f"{_now():%Y%m%dT%H%M%SZ}--{kind}--{ident}-{n}"
    item.mkdir(parents=True)
    return item


def trash_project(project, roots: Roots, by: str | None = None, running: bool = False) -> dict:
    """Mueve un análisis a la papelera. `running`: hay algo analizándose en él (entonces se rechaza)."""
    _check_id(project.id, "análisis")
    if running:
        raise TrashError("Hay archivos de este análisis analizándose: espera a que terminen antes de eliminarlo.")
    src = Path(project.dir)
    if not src.is_dir() or src.parent.resolve() != roots.projects.resolve():
        raise TrashError("El análisis no está en la raíz de análisis: no se elimina por seguridad.")
    files, head, n_custody = _custody_summary(project)
    case_ids = [f.case_id for f in project.files()]
    mode = getattr(project, "mode", "evidence")
    card = {"kind": "proyecto", "id": project.id, "name": getattr(project, "name", project.id), "mode": mode,
            "source_dir_kept": str(project.source_dir) if mode == "folder" else None, "by": by,
            "moved_at_utc": _now().isoformat(timespec="seconds"), "bytes": _size(src), "files": files,
            "custody_records": n_custody, "custody_head": head}
    item = _new_item(roots, "proyecto", project.id)
    shutil.move(str(src), str(item / CONTENT))
    card["reports"] = _move_reports(roots, case_ids, item)
    (item / CARD).write_text(json.dumps(card, ensure_ascii=False, indent=2), encoding="utf-8")
    _record(roots, "moved_to_trash", item=item.name, kind="proyecto", id=project.id, by=by, files=files, custody_head=head,
            bytes=card["bytes"], source_dir_kept=card["source_dir_kept"])
    return {**card, "item": item.name}


def trash_case(case_id: str, roots: Roots, by: str | None = None) -> dict:
    """Mueve un caso suelto antiguo (`data/cases/<caso>`) a la papelera."""
    _check_id(case_id, "caso")
    src = roots.cases / case_id
    if not src.is_dir():
        raise TrashError(f"No existe el caso '{case_id}'")
    card = {"kind": "caso", "id": case_id, "name": case_id, "mode": "caso", "source_dir_kept": None, "by": by,
            "moved_at_utc": _now().isoformat(timespec="seconds"), "bytes": _size(src), "files": [], "custody_records": 0,
            "custody_head": None}
    item = _new_item(roots, "caso", case_id)
    shutil.move(str(src), str(item / CONTENT))
    card["reports"] = _move_reports(roots, [case_id], item)
    (item / CARD).write_text(json.dumps(card, ensure_ascii=False, indent=2), encoding="utf-8")
    _record(roots, "moved_to_trash", item=item.name, kind="caso", id=case_id, by=by, files=[], custody_head=None, bytes=card["bytes"],
            source_dir_kept=None)
    return {**card, "item": item.name}


# --- papelera: listar, restaurar, eliminar definitivamente ---------------------------------------------------------------------------
def items(roots: Roots) -> list[dict]:
    out = []
    if not roots.trash.is_dir():
        return out
    for d in roots.trash.iterdir():
        if d.is_dir() and _ITEM.match(d.name) and (d / CARD).is_file():
            try:
                out.append({**json.loads((d / CARD).read_text(encoding="utf-8")), "item": d.name})
            except json.JSONDecodeError:
                out.append({"item": d.name, "kind": "?", "id": d.name, "name": d.name, "bytes": _size(d), "damaged": True})
    return sorted(out, key=lambda c: c["item"], reverse=True)


def restore(item_id: str, roots: Roots, by: str | None = None) -> dict:
    item = roots.trash / _check_item(item_id)
    if not (item / CARD).is_file():
        raise TrashError("Ese elemento ya no está en la papelera.")
    card = json.loads((item / CARD).read_text(encoding="utf-8"))
    ident = _check_id(card["id"], "análisis")
    target = (roots.projects if card["kind"] == "proyecto" else roots.cases) / ident
    if target.exists():
        raise TrashError(f"Ya existe un {'análisis' if card['kind'] == 'proyecto' else 'caso'} con el identificador '{ident}': "
                         "renómbralo o elimínalo antes de restaurar este.")
    for cid in card.get("reports", []):
        if (roots.reports / cid).exists():
            raise TrashError(f"Ya existen informes en reports/{cid}: muévelos antes de restaurar.")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(item / CONTENT), str(target))
    for cid in card.get("reports", []):
        roots.reports.mkdir(parents=True, exist_ok=True)
        shutil.move(str(item / REPORTS / cid), str(roots.reports / cid))
    shutil.rmtree(item)
    _record(roots, "restored", item=item_id, kind=card["kind"], id=ident, by=by)
    return card


def purge(item_id: str, roots: Roots, by: str | None = None, confirmation: str = "") -> dict:
    """Elimina DEFINITIVAMENTE un elemento de la papelera. Exige escribir su identificador."""
    item = roots.trash / _check_item(item_id)
    if not item.is_dir():
        raise TrashError("Ese elemento ya no está en la papelera.")
    card = json.loads((item / CARD).read_text(encoding="utf-8")) if (item / CARD).is_file() else {"id": item_id, "kind": "?", "files": []}
    if confirmation.strip() != card["id"]:
        raise TrashError(f"Para eliminar definitivamente escribe exactamente el identificador: {card['id']}")
    shutil.rmtree(item)
    _record(roots, "purged", item=item_id, kind=card.get("kind"), id=card["id"], by=by, files=card.get("files", []),
            custody_head=card.get("custody_head"))
    return card


def purge_all(roots: Roots, by: str | None = None, confirmation: str = "") -> int:
    if confirmation.strip() != VACIAR:
        raise TrashError(f"Para vaciar la papelera escribe {VACIAR}.")
    n = 0
    for c in items(roots):
        purge(c["item"], roots, by=by, confirmation=c["id"])
        n += 1
    return n
