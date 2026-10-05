"""Etiquetas del informe en español e inglés. Un solo lugar: cada clave tiene sus dos textos, así no puede faltar uno."""
from __future__ import annotations

# clave -> (es, en). Los marcadores {…} se rellenan con str.format.
_L: dict[str, tuple[str, str]] = {
    "title": ("Informe forense", "Forensic report"),
    "variant.interno": ("INTERNO", "INTERNAL"),
    "variant.compartible": ("COMPARTIBLE", "SHAREABLE"),
    "variant.note.interno": ("Contiene valores reales y el diccionario de alias. No compartir fuera del equipo de respuesta.",
                             "Contains real values and the alias dictionary. Do not share outside the response team."),
    "variant.note.compartible": ("Los valores sensibles van seudonimizados (alias) y el diccionario de alias NO se incluye. Se comprobó "
                                 "que ningún valor real conocido aparece en el documento.",
                                 "Sensitive values are pseudonymized (aliases) and the alias dictionary is NOT included. It was checked "
                                 "that no known real value appears in the document."),
    # portada
    "s0": ("Portada", "Cover"),
    "case": ("Caso", "Case"), "file": ("Archivo analizado", "Analyzed file"), "input_sha": ("SHA-256 del archivo", "File SHA-256"),
    "analyst": ("Analista", "Analyst"), "language": ("Idioma", "Language"), "variant": ("Variante", "Variant"),
    "framework": ("Versión del framework", "Framework version"), "integrity": ("Integridad de la cadena de custodia", "Chain-of-custody integrity"),
    "integrity.ok": ("verificada: sin discrepancias", "verified: no discrepancies"),
    "integrity.fail": ("FALLA: revisar el anexo A antes de usar este informe", "FAILED: review annex A before using this report"),
    "head_hash": ("Último hash del ledger", "Ledger head hash"), "ledger_entries": ("Entradas del ledger", "Ledger entries"),
    # secciones
    "s1": ("Resumen", "Summary"), "s2": ("Datos y supuestos", "Data and assumptions"),
    "s3": ("Qué vio el modelo", "What the model saw"), "s4": ("Hallazgos", "Findings"),
    "s5": ("Línea de tiempo (calculada por código)", "Timeline (computed by code)"),
    "s6": ("Hipótesis no concluyentes y líneas abiertas", "Inconclusive hypotheses and open lines"),
    "s7": ("Limitaciones", "Limitations"), "s8": ("Recomendaciones y próximos pasos", "Recommendations and next steps"),
    "annex.a": ("Anexo A · Cadena de custodia", "Annex A · Chain of custody"),
    "annex.b": ("Anexo B · Registro de consultas", "Annex B · Query log"),
    "annex.c": ("Anexo C · Métricas del proceso", "Annex C · Process metrics"),
    "annex.d": ("Anexo D · Salida del asistente (sin verificar)", "Annex D · Assistant output (unverified)"),
    "annex.e": ("Anexo E · Diccionario de alias", "Annex E · Alias dictionary"),
    # resumen
    "sum.none": ("Ninguna hipótesis ha sido confirmada por el analista.", "No hypothesis has been confirmed by the analyst."),
    "sum.confirmed": ("Hipótesis confirmadas por el analista", "Hypotheses confirmed by the analyst"),
    "sum.by_state": ("Hipótesis por estado", "Hypotheses by state"),
    "sum.detectors": ("Hallazgos de los detectores: {n} (alta: {high}, media: {medium}, baja/info: {low}).",
                      "Detector findings: {n} (high: {high}, medium: {medium}, low/info: {low})."),
    "sum.decision": ("Decisión de {who} el {when}", "Decision by {who} on {when}"),
    "sum.limit": ("Límite señalado por el analista", "Limit noted by the analyst"),
    # datos
    "d.rows": ("Filas", "Rows"), "d.range_utc": ("Rango temporal (UTC)", "Time range (UTC)"),
    "d.timezone": ("Zona horaria de las horas del archivo", "Time zone of the file's times"),
    "d.tz.unverified": ("declarada, SIN verificar con el dueño del export", "declared, NOT verified with the export owner"),
    "d.tz.verified": ("verificada con el dueño del export", "verified with the export owner"),
    "d.tz.default": ("no declarada: se asumió UTC (sin verificar)", "not declared: UTC assumed (unverified)"),
    "d.tz.in_data": ("viene en el propio dato", "carried by the data itself"),
    "d.date_format": ("Formato de fecha del mapping", "Mapping date format"),
    "d.roles": ("Roles de análisis", "Analysis roles"), "d.actor": ("actor (quién actúa)", "actor (who acts)"),
    "d.resource": ("recurso (sobre qué actúa)", "resource (what is acted on)"),
    "d.empty": ("Columnas sin datos en este archivo", "Columns without data in this file"),
    "d.mapping_sha": ("SHA-256 del mapping", "Mapping SHA-256"), "d.warnings": ("Avisos de la ingesta", "Ingest warnings"),
    "d.none": ("ninguna", "none"),
    # modelo
    "m.policy": ("Política de seudonimización", "Pseudonymization policy"), "m.copy": ("Copia que consultó el modelo", "Copy the model queried"),
    "m.treatments": ("Tratamiento por columna", "Treatment per column"), "m.column": ("Columna", "Column"),
    "m.treatment": ("Tratamiento", "Treatment"), "m.model": ("Modelo(s) usados", "Model(s) used"),
    "m.turns": ("Turnos del agente", "Agent turns"), "m.tokens": ("Tokens gastados en el caso", "Tokens spent on the case"),
    "m.p1a": ("Interpretación del perfil (P1-a)", "Profile interpretation (P1-a)"),
    "m.p1a.text": ("El modelo recibió únicamente metadatos del perfil del archivo (nombres de campo, tipos, estadísticas), nunca filas.",
                   "The model received only file-profile metadata (field names, types, statistics), never rows."),
    "m.none": ("El modelo no se usó en este caso.", "The model was not used in this case."),
    "m.rule": ("Regla: el modelo no ve el archivo completo ni valores reales; consulta una copia seudonimizada a través de herramientas "
               "de solo lectura y todo queda en el ledger.",
               "Rule: the model never sees the whole file or real values; it queries a pseudonymized copy through read-only tools and "
               "everything is recorded in the ledger."),
    # hallazgos
    "f.detectors": ("Hallazgos de los detectores (código)", "Detector findings (code)"),
    "f.severity": ("Severidad", "Severity"), "f.detector": ("Detector", "Detector"), "f.entity": ("Entidad", "Entity"),
    "f.summary": ("Resumen", "Summary"), "f.more": ("… y {n} más (ver el ledger)", "… and {n} more (see the ledger)"),
    "f.hypotheses": ("Hipótesis decididas por el analista", "Hypotheses decided by the analyst"),
    "f.statement": ("Enunciado", "Statement"), "f.state": ("Estado", "State"), "f.falsifier": ("Criterio de refutación (fijado al proponerla)",
                                                                                                  "Refutation criterion (set when proposed)"),
    "f.no_falsifier": ("(sin criterio: formulada antes de existir este requisito)", "(no criterion: formulated before this requirement existed)"),
    "f.attempts": ("Intentos de refutación", "Refutation attempts"), "f.would": ("La habría refutado si", "Would have refuted it if"),
    "f.observed": ("Observado", "Observed"), "f.evidence": ("Evidencia citada", "Cited evidence"),
    "f.decision": ("Decisión del analista", "Analyst decision"), "f.none": ("No hay hipótesis decididas todavía.", "No hypotheses decided yet."),
    "f.real_query": ("consulta sobre datos reales: no incluida en la versión compartible",
                     "query on real data: not included in the shareable version"),
    "f.no_text": ("[texto no incluido en la versión compartible: se formuló sobre datos reales]",
                  "[text not included in the shareable version: formulated on real data]"),
    "f.rows": ("filas", "rows"),
    "f.excluded": ("{n} hallazgo(s) calculados sobre datos reales no se incluyen en la versión compartible.",
                   "{n} finding(s) computed on real data are not included in the shareable version."),
    # tiempo
    "t.global": ("Peticiones por semana", "Requests per week"), "t.period": ("Semana", "Week"), "t.requests": ("Peticiones", "Requests"),
    "t.entities": ("Entidades señaladas por los detectores", "Entities flagged by the detectors"),
    "t.first": ("Primer periodo", "First period"), "t.last": ("Último periodo", "Last period"), "t.peak": ("Pico", "Peak"),
    "t.total": ("Total", "Total"), "t.caveat": ("Los cortes de día y semana usan {zone}; esa zona no está verificada.",
                                                  "Day and week boundaries use {zone}; that zone is not verified."),
    "t.caveat.utc": ("Los cortes de día y semana usan UTC.", "Day and week boundaries use UTC."),
    "t.none": ("Sin serie temporal disponible.", "No time series available."),
    # abiertas
    "o.none": ("No hay hipótesis abiertas.", "No open hypotheses."), "o.retired": ("Retiradas por el analista", "Retired by the analyst"),
    "o.superseded": ("reemplazada por {h}", "superseded by {h}"), "o.reason": ("Motivo", "Reason"),
    # limitaciones
    "l.tz": ("La zona horaria de las horas del archivo NO está verificada. Los resultados que dependen de la hora del día, de los fines "
             "de semana o de los límites de día pueden desplazarse; los conteos, los conjuntos de identificadores y de IPs no dependen de ella.",
             "The time zone of the file's times is NOT verified. Results that depend on time of day, weekends or day boundaries may shift; "
             "counts and sets of identifiers or IPs do not depend on it."),
    "l.empty": ("Sin datos en {cols}: no se puede afirmar nada que dependa de ellas (por ejemplo volumen transferido).",
                "No data in {cols}: nothing that depends on them can be claimed (for example transferred volume)."),
    "l.status": ("Un código de respuesta 200 no prueba que se haya devuelto contenido.",
                 "A 200 response code does not prove that content was returned."),
    "l.shift": ("En la copia seudonimizada los valores absolutos de {cols} están desplazados: las diferencias y el orden son exactos, "
                "el número en sí no es el real.",
                "In the pseudonymized copy the absolute values of {cols} are shifted: differences and order are exact, the number itself is not real."),
    "l.model": ("Las conclusiones del modelo se apoyan en una copia seudonimizada; las hipótesis solo cuentan como confirmadas cuando las "
                "aprueba el analista.",
                "The model's conclusions rest on a pseudonymized copy; hypotheses count as confirmed only when the analyst approves them."),
    "l.replay": ("Consultas que no se pudieron verificar con el replay: {n}. Ver el anexo B.",
                 "Queries that could not be verified by replay: {n}. See annex B."),
    "l.notes": ("Notas del analista", "Analyst notes"), "l.note_state": ("Valoración", "Assessment"),
    # recomendaciones
    "r.none": ("(El analista no añadió recomendaciones en esta exportación.)", "(The analyst added no recommendations in this export.)"),
    # anexos
    "a.dataset": ("Archivo de entrada", "Input file"), "a.parquet": ("Parquet normalizado", "Normalized Parquet"),
    "a.copy": ("Copia seudonimizada", "Pseudonymized copy"), "a.dict": ("Diccionario de alias (solo hash)", "Alias dictionary (hash only)"),
    "a.checks": ("Comprobaciones de integridad", "Integrity checks"),
    "a.sign": ("Entregado por: ____________________  Fecha: ____________  Firma: ____________\n\n"
               "Recibido por: ____________________  Fecha: ____________  Firma: ____________",
               "Delivered by: ____________________  Date: ____________  Signature: ____________\n\n"
               "Received by: ____________________  Date: ____________  Signature: ____________"),
    "b.query": ("Consulta", "Query"), "b.copy": ("Copia", "Copy"), "b.state": ("Verificación", "Verification"),
    "b.sql": ("SQL", "SQL"), "b.cap": ("Solo se listan las primeras {n} consultas; el ledger las tiene todas.",
                                        "Only the first {n} queries are listed; the ledger has them all."),
    "b.ok": ("coincide", "matches"), "b.skipped": ("sin motor (no verificada)", "no engine (not verified)"),
    "b.drift": ("deriva de esquema", "schema drift"), "b.nondet": ("no determinista", "non-deterministic"),
    "b.mismatch": ("NO coincide", "MISMATCH"), "b.unverified": ("sin verificar", "unverified"),
    "b.excluded": ("{n} consulta(s) sobre datos reales no se incluyen en la versión compartible.",
                   "{n} query(ies) on real data are not included in the shareable version."),
    "c.questions": ("Preguntas al agente", "Questions to the agent"), "c.cuts": ("Respuestas cortadas por presupuesto", "Answers cut by budget"),
    "c.approved": ("Aprobaciones del analista", "Analyst approvals"), "c.rejected": ("Rechazos del analista", "Analyst rejections"),
    "c.queries": ("Consultas registradas", "Recorded queries"), "c.findings": ("Hallazgos de detectores", "Detector findings"),
    "c.span": ("Duración registrada (primer a último evento)", "Recorded span (first to last event)"),
    "c.attempts": ("Intentos de refutación por hipótesis confirmada", "Refutation attempts per confirmed hypothesis"),
    "c.redactions": ("Credenciales redactadas en el documento", "Credentials redacted in the document"),
    "metric": ("Métrica", "Metric"), "value": ("Valor", "Value"),
    "d.warn": ("Texto generado por el modelo. No es evidencia: los hechos están en las consultas citadas.",
               "Text generated by the model. It is not evidence: the facts are in the cited queries."),
    "d.empty_out": ("El modelo no generó respuestas en este caso.", "The model produced no answers in this case."),
    "e.text": ("Alias que aparecen en este informe y su valor real. Es la clave para revertir la seudonimización: protégela.",
               "Aliases that appear in this report and their real value. This is the key to reverse pseudonymization: protect it."),
    "e.alias": ("Alias", "Alias"), "e.real": ("Valor real", "Real value"), "e.none": ("No aparece ningún alias.", "No alias appears."),
    "footer": ("Generado por DFIR Co-pilot", "Generated by DFIR Co-pilot"), "footer.hash": ("SHA-256 del contenido", "Content SHA-256"),
    "footer.when": ("Generado el", "Generated on"),
}


def t(key: str, lang: str = "es", **kw) -> str:
    """Texto de `key` en `lang` ('es' o 'en'). Falla ruidosamente si la clave no existe: un informe no debe salir con huecos."""
    es, en = _L[key]
    text = en if lang == "en" else es
    return text.format(**kw) if kw else text


def keys() -> set[str]:
    return set(_L)
