"""Registro de hipótesis con estado, persistido en el ledger. El agente propone; el analista decide."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

STATUSES = ("propuesta", "en_prueba", "confirmada", "refutada")
FINAL = ("confirmada", "refutada")


class HypothesisError(Exception):
    """Operación inválida sobre una hipótesis. El mensaje se devuelve al agente para que se corrija."""


def hypothesis_id(statement: str) -> str:
    """Identificador determinista: la misma hipótesis (ignorando espacios y mayúsculas) tiene el mismo id."""
    norm = re.sub(r"\s+", " ", statement.strip().lower())
    return "h-" + hashlib.sha256(norm.encode("utf-8")).hexdigest()[:8]


@dataclass(frozen=True)
class DecisionRequest:
    hypothesis_id: str
    to: str
    evidence_refs: tuple
    rationale: str


class HypothesisBook:
    """Ciclo de vida: propuesta -> en_prueba -> confirmada | refutada.

    El paso a confirmada/refutada solo se aplica con la decisión de un analista (`decide`).
    El estado se reconstruye desde el ledger, así que sobrevive a reinicios del kernel.
    """

    def __init__(self, ledger):
        self.ledger = ledger
        self._items: dict[str, dict] = {}
        for entry in ledger.entries():
            d = entry["data"]
            if entry["type"] == "hypothesis":
                self._items[d["hypothesis_id"]] = {**d, "status": "propuesta", "evidence_refs": [], "history": []}
            elif entry["type"] == "hypothesis_update" and d["hypothesis_id"] in self._items:
                self._apply(self._items[d["hypothesis_id"]], d)

    @staticmethod
    def _apply(item: dict, update: dict) -> None:
        item["history"].append({k: update.get(k) for k in ("from", "to", "decision", "decided_by", "note")})
        if update["decision"] in ("auto", "approved"):
            item["status"] = update["to"]
            item["evidence_refs"] = sorted(set(item["evidence_refs"]) | set(update.get("evidence_refs", [])))

    def all(self) -> list[dict]:
        return list(self._items.values())

    def get(self, hid: str) -> dict:
        if hid not in self._items:
            raise HypothesisError(f"hipótesis desconocida: {hid}. Conocidas: {list(self._items)}")
        return self._items[hid]

    def propose(self, statement: str, rationale: str = "", test_plan: str = "",
                proposed_by: str = "agent", copy: str | None = None) -> tuple[dict, bool]:
        """`copy`: identidad de la copia de datos sobre la que se formula (`engine.copy_id`). El texto de una hipótesis puede
        llevar valores de ESA copia; el agente solo se lo muestra de vuelta al modelo si sigue consultando la misma."""
        statement = " ".join(statement.split())
        if not 10 <= len(statement) <= 500:
            raise HypothesisError("La hipótesis debe tener entre 10 y 500 caracteres")
        hid = hypothesis_id(statement)
        if hid in self._items:
            return self._items[hid], False
        data = {"hypothesis_id": hid, "statement": statement, "rationale": rationale.strip(),
                "test_plan": test_plan.strip(), "proposed_by": proposed_by}
        if copy:
            data["copy"] = copy
        self.ledger.append("hypothesis", data)
        self._items[hid] = {**data, "status": "propuesta", "evidence_refs": [], "history": []}
        return self._items[hid], True

    def start_testing(self, hid: str) -> dict:
        item = self.get(hid)
        if item["status"] in FINAL:
            raise HypothesisError(f"{hid} ya está {item['status']}; no se reabre")
        if item["status"] == "en_prueba":
            return item
        update = {"hypothesis_id": hid, "from": item["status"], "to": "en_prueba", "requested_by": "agent",
                  "decided_by": None, "decision": "auto", "rationale": "", "note": "", "evidence_refs": []}
        self.ledger.append("hypothesis_update", update)
        self._apply(item, update)
        return item

    def request_decision(self, hid: str, to: str, evidence_refs, rationale: str) -> DecisionRequest:
        """Valida una petición de cierre. No cambia el estado: hace falta la decisión del analista."""
        item = self.get(hid)
        if to not in FINAL:
            raise HypothesisError(f"el estado solicitado debe ser uno de {FINAL}")
        if item["status"] != "en_prueba":
            raise HypothesisError(
                f"{hid} está '{item['status']}'. Solo se puede cerrar una hipótesis 'en_prueba': "
                f"márcala primero con status='en_prueba'.")
        refs = tuple(dict.fromkeys(evidence_refs))
        if not refs:
            raise HypothesisError("Falta evidencia: indica evidence_refs con identificadores reales (q-…, f-…, c-…)")
        unknown = [r for r in refs if r not in self.ledger.known_refs() or r == hid]
        if unknown:
            raise HypothesisError(f"Referencias que no existen en el ledger: {unknown}. "
                                  "Usa solo ids devueltos por las herramientas.")
        if not rationale or not rationale.strip():
            raise HypothesisError("Falta la justificación (rationale)")
        return DecisionRequest(hid, to, refs, rationale.strip())

    def decide(self, request: DecisionRequest, approve: bool, analyst: str, note: str = "") -> dict:
        item = self.get(request.hypothesis_id)
        if item["status"] in FINAL:
            raise HypothesisError(f"{request.hypothesis_id} ya está {item['status']}")
        update = {"hypothesis_id": request.hypothesis_id, "from": item["status"],
                  "to": request.to if approve else item["status"], "requested_by": "agent",
                  "decided_by": analyst, "decision": "approved" if approve else "rejected",
                  "rationale": request.rationale, "note": note, "evidence_refs": list(request.evidence_refs)}
        self.ledger.append("hypothesis_update", update)
        self._apply(item, update)
        return item
