"""Registro de hipótesis con estado, persistido en el ledger. El agente propone; el analista decide."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

STATUSES = ("propuesta", "en_prueba", "confirmada", "refutada", "retirada")
FINAL = ("confirmada", "refutada")   # decisiones del analista sobre la evidencia
CLOSED = (*FINAL, "retirada")        # ya no admiten pruebas ni peticiones; "retirada" = el analista la descarta o la reemplaza


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
    refutation_checks: tuple = ()  # solo al confirmar: ({"ref", "would_refute_if", "observed"}, …)


MIN_CHECK_TEXT = 10


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
                self._items[d["hypothesis_id"]] = {**d, "seq": entry["seq"], "status": "propuesta", "evidence_refs": [],
                                                   "history": []}
            elif entry["type"] == "hypothesis_update" and d["hypothesis_id"] in self._items:
                self._apply(self._items[d["hypothesis_id"]], d)

    @staticmethod
    def _apply(item: dict, update: dict) -> None:
        item["history"].append({k: update.get(k) for k in ("from", "to", "decision", "decided_by", "note")})
        if update["decision"] in ("auto", "approved"):
            item["status"] = update["to"]
            if update.get("superseded_by"):
                item["superseded_by"] = update["superseded_by"]
            if update.get("refutation_checks"):
                item["refutation_checks"] = list(update["refutation_checks"])
            item["evidence_refs"] = sorted(set(item["evidence_refs"]) | set(update.get("evidence_refs", [])))

    def all(self) -> list[dict]:
        return list(self._items.values())

    def get(self, hid: str) -> dict:
        if hid not in self._items:
            raise HypothesisError(f"hipótesis desconocida: {hid}. Conocidas: {list(self._items)}")
        return self._items[hid]

    def propose(self, statement: str, rationale: str = "", test_plan: str = "",
                proposed_by: str = "agent", copy: str | None = None,
                falsifier: str | None = None) -> tuple[dict, bool]:
        """`copy`: identidad de la copia de datos sobre la que se formula (`engine.copy_id`). El texto de una hipótesis puede
        llevar valores de ESA copia; el agente solo se lo muestra de vuelta al modelo si sigue consultando la misma.

        `falsifier`: qué resultado en los datos la REFUTARÍA, fijado antes de probarla. Es opcional aquí (hipótesis anteriores,
        o propuestas por el analista) pero el agente está obligado a darlo (ver `ProposeArgs`)."""
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
        if falsifier and falsifier.strip():
            data["falsifier"] = " ".join(falsifier.split())[:500]
        stored = self.ledger.append("hypothesis", data)
        self._items[hid] = {**data, "seq": stored["seq"], "status": "propuesta", "evidence_refs": [], "history": []}
        return self._items[hid], True

    def start_testing(self, hid: str) -> dict:
        item = self.get(hid)
        if item["status"] in CLOSED:
            raise HypothesisError(f"{hid} ya está {item['status']}; no se reabre")
        if item["status"] == "en_prueba":
            return item
        update = {"hypothesis_id": hid, "from": item["status"], "to": "en_prueba", "requested_by": "agent",
                  "decided_by": None, "decision": "auto", "rationale": "", "note": "", "evidence_refs": []}
        self.ledger.append("hypothesis_update", update)
        self._apply(item, update)
        return item

    def request_decision(self, hid: str, to: str, evidence_refs, rationale: str,
                         refutation_checks=()) -> DecisionRequest:
        """Valida una petición de cierre. No cambia el estado: hace falta la decisión del analista.

        Confirmar exige `refutation_checks`: al menos un intento real de refutar la hipótesis (ver `_validate_checks`)."""
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
        checks = self._validate_checks(item, refutation_checks) if to == "confirmada" else ()
        return DecisionRequest(hid, to, refs, rationale.strip(), checks)

    def _validate_checks(self, item: dict, checks) -> tuple:
        """Un intento de refutación cuenta si es una consulta que se ejecutó con éxito DESPUÉS de proponer la hipótesis.

        Lo que se comprueba es objetivo (existe, salió bien, es posterior). Que de verdad buscara refutarla no se puede verificar
        por código: por eso el analista ve la consulta, qué la habría refutado y qué se observó antes de aprobar."""
        if not checks:
            raise HypothesisError(
                "Para confirmar falta un intento de refutación (refutation_checks): una consulta posterior a proponer la "
                "hipótesis que buscaba refutarla. Indica ref (q-…), would_refute_if y observed. Si no puedes diseñar una "
                "prueba que pueda fallar, no la confirmes.")
        ok = {e["data"]["query_id"]: e["seq"] for e in self.ledger.entries("query") if e["data"].get("status") == "ok"}
        out, problems = [], []
        for c in checks:
            ref, would, seen = c.get("ref", ""), " ".join(str(c.get("would_refute_if", "")).split()), \
                " ".join(str(c.get("observed", "")).split())
            if ref not in ok:
                problems.append(f"{ref}: no es una consulta ejecutada con éxito; usa un id q-… devuelto por las herramientas")
            elif ok[ref] <= item["seq"]:
                problems.append(f"{ref}: se ejecutó ANTES de proponer la hipótesis; un intento de refutación debe ser posterior")
            elif len(would) < MIN_CHECK_TEXT or len(seen) < MIN_CHECK_TEXT:
                problems.append(f"{ref}: describe qué resultado la habría refutado (would_refute_if) y qué observaste (observed)")
            else:
                out.append({"ref": ref, "would_refute_if": would, "observed": seen})
        if problems:
            raise HypothesisError("Intentos de refutación no válidos: " + "; ".join(problems))
        return tuple({c["ref"]: c for c in out}.values())  # una vez por consulta

    def decide(self, request: DecisionRequest, approve: bool, analyst: str, note: str = "") -> dict:
        item = self.get(request.hypothesis_id)
        if item["status"] in CLOSED:
            raise HypothesisError(f"{request.hypothesis_id} ya está {item['status']}")
        update = {"hypothesis_id": request.hypothesis_id, "from": item["status"],
                  "to": request.to if approve else item["status"], "requested_by": "agent",
                  "decided_by": analyst, "decision": "approved" if approve else "rejected",
                  "rationale": request.rationale, "note": note, "evidence_refs": list(request.evidence_refs)}
        if request.refutation_checks:
            update["refutation_checks"] = [dict(c) for c in request.refutation_checks]
        self.ledger.append("hypothesis_update", update)
        self._apply(item, update)
        return item

    def retire(self, hid: str, analyst: str, reason: str, superseded_by: str | None = None) -> dict:
        """El analista descarta una hipótesis (duplicada, reemplazada por otra mejor formulada, fuera de alcance).

        No es una decisión sobre la evidencia: una hipótesis ya confirmada o refutada no se retira, y la retirada tampoco se
        revierte. Queda en el ledger con quién, por qué y, si la hay, qué hipótesis la reemplaza."""
        item = self.get(hid)
        if item["status"] == "retirada":
            return item
        if item["status"] in FINAL:
            raise HypothesisError(f"{hid} ya está {item['status']} por decisión sobre la evidencia; no se retira")
        if not reason or not reason.strip():
            raise HypothesisError("Falta el motivo de la retirada")
        if superseded_by is not None:
            if superseded_by == hid:
                raise HypothesisError("Una hipótesis no puede reemplazarse a sí misma")
            self.get(superseded_by)  # debe existir
        update = {"hypothesis_id": hid, "from": item["status"], "to": "retirada", "requested_by": "analyst",
                  "decided_by": analyst, "decision": "approved", "rationale": reason.strip(), "note": reason.strip(),
                  "evidence_refs": []}
        if superseded_by:
            update["superseded_by"] = superseded_by
        self.ledger.append("hypothesis_update", update)
        self._apply(item, update)
        return item
