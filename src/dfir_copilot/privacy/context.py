"""Qué debe saber el modelo sobre la copia que consulta (P1-b.2b).

Sin esto el modelo interpreta mal lo que ve: tomaría `x_invoice_id = 0` por una factura real, buscaría IPs privadas con
`src_ip LIKE '10.%'` (no devuelve nada y parecería "no hay") o intentaría deducir identidades. El texto se genera del
manifiesto de la copia, así que describe exactamente los tratamientos aplicados (incluidas las excepciones por caso) y es
ESTÁTICO durante un hilo: depende solo de la copia, nunca del trabajo en curso (invariante de prefijo del agente).
"""
from __future__ import annotations

from dfir_copilot.privacy.pseudonymize import PrivacyPolicy


def _active_treatments(manifest: dict) -> dict[str, str]:
    """Columna -> tratamiento, sin las columnas vacías (no hay nada que describir de ellas)."""
    rows = (manifest.get("output") or {}).get("rows")
    empty = {c for c, n in (manifest.get("null_counts") or {}).items() if rows and n == rows}
    return {c: k for c, k in (manifest.get("treatments") or {}).items() if c not in empty}


def privacy_context(manifest: dict) -> str:
    """Bloque de texto para el prompt de sistema. Cadena vacía si el manifiesto no es de una copia seudonimizada."""
    if manifest.get("kind") != "pseudonymized":
        return ""
    treatments = _active_treatments(manifest)
    policy_record = manifest.get("policy") or {}
    policy = PrivacyPolicy(overrides=policy_record.get("overrides") or {})

    def prefix(col: str) -> str:
        return policy.treatment(col, "VARCHAR")[1] or ""

    by_kind: dict[str, list[str]] = {}
    for col, kind in treatments.items():
        by_kind.setdefault(kind, []).append(col)
    lines = [f"\nCOPIA SEUDONIMIZADA (política {policy_record.get('version', '?')}): lo que ves NO son los valores reales"]
    aliased = [f"{c}→{prefix(c)}-0001…" for c in by_kind.get("alias", [])]
    ips = by_kind.get("ip", [])
    if aliased or ips:
        shown = aliased + [f"{c}→{prefix(c)}-0001…" for c in ips]
        lines.append("- Alias estables, numerados por orden de primera aparición: " + ", ".join(shown) + ". Agrupan, cuentan y "
                     "cruzan igual que los valores reales. No intentes deducir el valor real; repórtalos con su alias (el "
                     "analista los revela en local). Enumera los alias uno a uno: no los abrevies con rangos como "
                     "'U-0032 a U-0035', porque al revelarlos se leería como un rango de valores reales y no lo es.")
    for c in ips:
        lines.append(f"- {c}_scope (public, private, loopback, link_local, shared, reserved, invalid) y {c}_net (alias de la "
                     f"/24 o /64) conservan la señal de red. Para clasificar direcciones usa esas columnas: un patrón como "
                     f"'10.%' sobre {c} no devuelve nada porque la columna ya es un alias.")
    if by_kind.get("shift"):
        lines.append("- Columnas desplazadas (valor menos el mínimo de la columna): " + ", ".join(by_kind["shift"]) + ". "
                     "Las diferencias y el orden son exactos (un barrido secuencial se ve igual), pero el valor absoluto NO "
                     "es el real: no lo cites como identificador.")
    hidden = []
    if "mask_values" in by_kind:
        hidden.append(", ".join(by_kind["mask_values"]) + ": nombres de parámetro sin valores (a=*&b=*)")
    if "mask_ids" in by_kind:
        hidden.append(", ".join(by_kind["mask_ids"]) + ": segmentos con aspecto de identificador como {id}")
    if "scrub" in by_kind:
        hidden.append(", ".join(by_kind["scrub"]) + ": sin IPs, correos ni tokens ({ip}, {email}, {token})")
    if hidden:
        lines.append("- Valores ocultos: " + "; ".join(hidden) + ".")
    if by_kind.get("keep"):
        lines.append("- Sin cambios: " + ", ".join(by_kind["keep"]) + ".")
    return "\n".join(lines) + "\n"
