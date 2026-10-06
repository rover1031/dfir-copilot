"""Estado de la zona horaria de un caso y su confirmación por el analista.

Al ingerir, la zona queda "declarada, sin verificar" si nadie la confirmó. Confirmarla después NO cambia ningún dato (las horas ya se
convirtieron con esa zona): solo deja constancia en el ledger de quién la confirmó, cuándo y con qué base. La base importa en forense:
no es lo mismo que la confirme el dueño del export que la decida el analista sin confirmación externa, y el informe lo dice tal cual.

Para cambiar a OTRA zona hay que reingestar (las horas cambiarían): eso no se hace aquí.
"""
from __future__ import annotations

BASES = {
    "analyst_decision": "decisión del analista, sin confirmación externa",
    "export_owner": "confirmada por el dueño del export",
}


class TimezoneError(ValueError):
    """Confirmación imposible: zona distinta de la aplicada, zona que viene en el dato o base desconocida."""


def _confirmations(ledger) -> list[dict]:
    return [{**e["data"], "ts_utc": e["ts_utc"]} for e in ledger.entries("timezone_confirmation")]


def timezone_state(ledger, manifest: dict) -> dict:
    """{assumed, source, state, confirmation}. `state`: in_data | verified | export_owner | analyst_decision | default | unverified."""
    tz = (manifest or {}).get("timezone", {})
    conf = _confirmations(ledger)
    last = conf[-1] if conf else None
    if tz.get("source") == "in_data":
        state = "in_data"
    elif tz.get("verified"):
        state = "verified"
    elif last:
        state = last["basis"]
    else:
        state = "default" if tz.get("source") == "default" else "unverified"
    return {"assumed": tz.get("assumed"), "source": tz.get("source"), "state": state, "confirmation": last}


def confirm_timezone(ledger, manifest: dict, timezone: str, basis: str, analyst: str | None, note: str | None = None) -> dict:
    """Registra la confirmación en el ledger. Solo se puede confirmar la zona con la que se ingirió."""
    if basis not in BASES:
        raise TimezoneError(f"Base desconocida: {basis!r} (válidas: {', '.join(BASES)})")
    tz = (manifest or {}).get("timezone", {})
    if tz.get("source") == "in_data":
        raise TimezoneError("Las horas traen su propia zona en el dato: no hace falta confirmarla")
    assumed = tz.get("assumed")
    if (timezone or "").strip() != assumed:
        raise TimezoneError(f"El caso se ingirió con {assumed}; para usar {timezone} hay que reingestar (las horas cambiarían)")
    if tz.get("applied") is False:
        raise TimezoneError("La zona declarada no se aplicó al ingerir: no se puede confirmar sin reingestar")
    data = {"timezone": assumed, "basis": basis, "basis_text": BASES[basis], "confirmed_by": (analyst or "").strip()[:80] or None,
            "note": (note or "").strip()[:500] or None}
    ledger.append("timezone_confirmation", data)
    return data


__all__ = ["BASES", "TimezoneError", "confirm_timezone", "timezone_state"]
