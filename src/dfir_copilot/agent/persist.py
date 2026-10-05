"""Conversación del agente persistente en disco (P1-c).

Hasta ahora el hilo del agente vivía en memoria: al reiniciar el kernel se perdía, incluso una aprobación pendiente. Aquí se guarda
en `data/cases/<caso>/agent/threads.json`, junto al caso.

Decisiones:
* Sin dependencias nuevas: extiende `InMemorySaver` de LangGraph (que ya guarda todo como bytes serializados) y vuelca su contenido.
* JSON y no `pickle`: un archivo `pickle` dentro de la carpeta del caso ejecutaría código al cargarse si alguien lo altera.
* Se COMPACTA al terminar cada pregunta: el guardado en memoria conserva todos los puntos intermedios y el estado completo en cada
  uno, así que sin compactar el archivo crecería rápido (y se reescribe entero en cada paso). Se queda el último punto de cada hilo
  con lo que necesita, también cuando hay una aprobación pendiente. No se pierde nada de lo que importa: la evidencia vive en el
  ledger; esto es solo la conversación con el modelo.
* Cada hilo guarda con qué prompt de sistema y con qué copia de datos se creó. Un hilo no se reanuda con otro prompt (la API
  rechaza los bloques de razonamiento firmados contra el prefijo anterior) ni con otra copia (los alias no serían los mismos).
"""
from __future__ import annotations

import base64
import json
import os
import threading
from collections import defaultdict
from pathlib import Path

from langgraph.checkpoint.memory import InMemorySaver

FORMAT_VERSION = 1


class ThreadStale(Exception):
    """El hilo guardado se creó con otro prompt de sistema u otra copia de datos: no se puede reanudar."""


class CheckpointFileError(Exception):
    """El archivo del hilo no se puede leer o no es compatible con la versión de LangGraph instalada."""


def _b(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


class FileCheckpointer(InMemorySaver):
    """`InMemorySaver` que se vuelca a un archivo JSON tras cada cambio y se recarga al abrirse."""

    def __init__(self, path: str | Path, **kwargs):
        super().__init__(**kwargs)
        for attr in ("storage", "writes", "blobs"):  # estructura interna de LangGraph: si cambia, se avisa en vez de corromper
            if not hasattr(self, attr):
                raise CheckpointFileError(f"Esta versión de LangGraph no es compatible con el guardado en disco (falta {attr})")
        self.path = Path(path)
        self._lock = threading.RLock()
        self._meta: dict[str, dict] = {}
        if self.path.exists():
            self._load()

    # --- metadatos por hilo ---------------------------------------------------------------------------------
    def get_meta(self, thread_id: str) -> dict | None:
        return self._meta.get(thread_id)

    def set_meta(self, thread_id: str, **fields) -> None:
        with self._lock:
            self._meta[thread_id] = {**self._meta.get(thread_id, {}), **fields}
            self._flush()

    def threads(self) -> list[str]:
        return sorted({*self.storage, *self._meta})

    # --- mutaciones: se guardan siempre ------------------------------------------------------------------------
    def put(self, *args, **kwargs):
        with self._lock:
            out = super().put(*args, **kwargs)
            self._flush()
            return out

    def put_writes(self, *args, **kwargs):
        with self._lock:
            super().put_writes(*args, **kwargs)
            self._flush()

    def delete_thread(self, thread_id: str) -> None:
        with self._lock:
            super().delete_thread(thread_id)
            self._meta.pop(thread_id, None)
            self._flush()

    # --- compactar ----------------------------------------------------------------------------------------------
    def compact(self, thread_id: str) -> None:
        """Deja solo el último punto de cada espacio de nombres del hilo, con sus escrituras pendientes y los datos que usa."""
        with self._lock:
            for ns, checkpoints in list(self.storage.get(thread_id, {}).items()):
                if len(checkpoints) <= 1:
                    continue
                keep = max(checkpoints)  # los ids de punto de control son ordenables en el tiempo
                versions = self.serde.loads_typed(checkpoints[keep][0]).get("channel_versions", {})
                for cid in [c for c in checkpoints if c != keep]:
                    del checkpoints[cid]
                    self.writes.pop((thread_id, ns, cid), None)
                needed = {(thread_id, ns, ch, ver) for ch, ver in versions.items()}
                for key in [k for k in self.blobs if k[0] == thread_id and k[1] == ns and k not in needed]:
                    del self.blobs[key]
            self._flush()

    # --- volcado y carga ------------------------------------------------------------------------------------------
    def _flush(self) -> None:
        data = {
            "format": FORMAT_VERSION,
            "meta": self._meta,
            "storage": [[t, ns, cid, [[a[0], _b(a[1])], [m[0], _b(m[1])], parent]]
                        for t, by_ns in self.storage.items() for ns, cps in by_ns.items()
                        for cid, (a, m, parent) in cps.items()],
            "writes": [[t, ns, cid, task, idx, [w[0], w[1], [w[2][0], _b(w[2][1])], w[3]]]
                       for (t, ns, cid), ws in self.writes.items() for (task, idx), w in ws.items()],
            "blobs": [[t, ns, ch, ver, [v[0], _b(v[1])]] for (t, ns, ch, ver), v in self.blobs.items()],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)  # escritura atómica: nunca queda un archivo a medias

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("format") != FORMAT_VERSION:
                raise CheckpointFileError(f"Formato {data.get('format')!r} desconocido (se esperaba {FORMAT_VERSION})")
            self._meta = dict(data.get("meta", {}))
            storage: defaultdict = defaultdict(lambda: defaultdict(dict))
            for t, ns, cid, (a, m, parent) in data["storage"]:
                storage[t][ns][cid] = ((a[0], _unb(a[1])), (m[0], _unb(m[1])), parent)
            writes: defaultdict = defaultdict(dict)
            for t, ns, cid, task, idx, (wtask, channel, (wtype, wval), path) in data["writes"]:
                writes[(t, ns, cid)][(task, idx)] = (wtask, channel, (wtype, _unb(wval)), path)
            blobs = {(t, ns, ch, ver): (v[0], _unb(v[1])) for t, ns, ch, ver, v in data["blobs"]}
        except CheckpointFileError:
            raise
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise CheckpointFileError(f"No se pudo leer {self.path}: {type(exc).__name__}: {exc}. "
                                      f"Muévelo o bórralo para empezar un hilo nuevo (el ledger no se toca).") from exc
        self.storage.update(storage)
        self.writes.update(writes)
        self.blobs.update(blobs)
