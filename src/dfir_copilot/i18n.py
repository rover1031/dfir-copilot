"""Textos bilingües (es/en) del sistema (nivel de paquete: lo usan perfilado, ledger y espacio por caso).

Convención del proyecto: las CLAVES de los objetos JSON (Data Profile, ledger, herramientas) son un contrato estable y
van en inglés; el TEXTO dirigido a personas (avisos, explicaciones, informes) se traduce con `t()`. Así un pipeline
nunca se rompe por el idioma y cada analista lee en el suyo.
"""
from __future__ import annotations

import os
import string

SUPPORTED = ("es", "en")

_MESSAGES: dict[str, dict[str, str]] = {
    # --- privacidad ---------------------------------------------------------------------------------------------
    "privacy.strict": {
        "es": "Modo estricto: el perfil no contiene valores crudos del log; solo estadísticas, formas abstractas "
              "(letras→a, dígitos→9) y nombres de campos o parámetros.",
        "en": "Strict mode: the profile contains no raw log values; only statistics, abstract shapes "
              "(letters→a, digits→9) and field or parameter names.",
    },
    "privacy.enums": {
        "es": "Solo se listan valores de campos categóricos cuando todos pertenecen a un vocabulario técnico cerrado "
              "(métodos HTTP, códigos de estado, acciones como allow/deny).",
        "en": "Categorical values are listed only when all of them belong to a closed technical vocabulary "
              "(HTTP methods, status codes, actions such as allow/deny).",
    },
    # --- errores ---------------------------------------------------------------------------------------------------
    "err.unsupported_format": {
        "es": "Formato no soportado: '{ext}'. Formatos admitidos: CSV, TSV, JSON/NDJSON y Parquet (también .gz).",
        "en": "Unsupported format: '{ext}'. Supported: CSV, TSV, JSON/NDJSON and Parquet (also .gz).",
    },
    "err.unreadable": {
        "es": "No se pudo leer '{file}' como {fmt}: {error}",
        "en": "Could not read '{file}' as {fmt}: {error}",
    },
    "err.not_found": {"es": "No existe el archivo: {file}", "en": "File not found: {file}"},
    # --- avisos de calidad -----------------------------------------------------------------------------------------
    "warn.encoding_fallback": {
        "es": "El archivo no es UTF-8 válido; se leyó como {encoding} (típico de exportaciones de Excel en español).",
        "en": "The file is not valid UTF-8; it was read as {encoding} (typical of Spanish-locale Excel exports).",
    },
    "warn.schema_retry": {
        "es": "El esquema JSON varía a lo largo del archivo; se infirió leyendo el archivo completo.",
        "en": "The JSON schema varies across the file; it was inferred by reading the whole file.",
    },
    "warn.empty": {"es": "El archivo no contiene registros.", "en": "The file contains no records."},
    "warn.no_timestamp": {
        "es": "No se encontró ningún campo de fecha interpretable: la línea de tiempo no será posible sin ayuda.",
        "en": "No parseable date field was found: a timeline will not be possible without help.",
    },
    "warn.timestamp_ambiguous": {
        "es": "Fecha ambigua en '{field}': '{a}' y '{b}' interpretan los datos con resultados distintos. "
              "Confirma si el día va antes o después del mes.",
        "en": "Ambiguous date in '{field}': '{a}' and '{b}' both parse the data with different results. "
              "Confirm whether the day comes before or after the month.",
    },
    "warn.timestamp_rejected_alt": {
        "es": "En '{field}' se descartó '{fmt}': solo interpreta el {pct}% de los valores (indicio de orden día/mes "
              "distinto al esperado).",
        "en": "In '{field}', '{fmt}' was rejected: it only parses {pct}% of the values (hint of a day/month order "
              "different from expected).",
    },
    "warn.timestamp_partial": {
        "es": "Solo el {pct}% de '{field}' se interpreta con '{fmt}' en el archivo completo.",
        "en": "Only {pct}% of '{field}' parses with '{fmt}' across the whole file.",
    },
    "warn.timestamp_no_year": {
        "es": "'{field}' no incluye el año (formato tipo syslog): habrá que indicarlo al ingerir.",
        "en": "'{field}' has no year (syslog-like format): it must be supplied at ingestion.",
    },
    "warn.timezone_unknown": {
        "es": "'{field}' no indica zona horaria: se asumirá UTC hasta que se verifique.",
        "en": "'{field}' carries no time zone: UTC will be assumed until verified.",
    },
    "warn.secret_in_values": {
        "es": "'{field}' contiene credenciales o tokens dentro de sus valores (p. ej. parámetros: {keys}). "
              "Trátalos como expuestos.",
        "en": "'{field}' carries credentials or tokens inside its values (e.g. parameters: {keys}). "
              "Treat them as exposed.",
    },
    "warn.secret_field": {
        "es": "El nombre de '{field}' sugiere secretos (token, contraseña, clave).",
        "en": "The name of '{field}' suggests secrets (token, password, key).",
    },
    "warn.pii": {"es": "'{field}' contiene datos personales: {kinds}.", "en": "'{field}' contains personal data: {kinds}."},
    "warn.all_null": {"es": "'{field}' está vacío en todos los registros.", "en": "'{field}' is empty in every record."},
    "warn.high_nulls": {"es": "'{field}' está vacío en el {pct}% de los registros.",
                        "en": "'{field}' is empty in {pct}% of the records."},
    "warn.constant": {"es": "'{field}' tiene un único valor en todo el archivo.",
                      "en": "'{field}' holds a single value across the whole file."},
    "warn.fields_truncated": {
        "es": "Se perfilaron {kept} de {total} campos para respetar el límite de tamaño del perfil.",
        "en": "{kept} of {total} fields were profiled to respect the profile size limit.",
    },
    "warn.mapping_ambiguous": {
        "es": "Ambigüedad: '{canonical}' podría corresponder a {fields}.",
        "en": "Ambiguity: '{canonical}' could correspond to {fields}.",
    },
    "warn.request_line": {
        "es": "'{field}' contiene la línea completa de la petición HTTP (método, ruta y protocolo juntos): "
              "habrá que separarla al ingerir.",
        "en": "'{field}' holds the full HTTP request line (method, path and protocol together): "
              "it must be split at ingestion.",
    },
    "warn.constant.many": {"es": "{count} campos tienen un único valor en todo el archivo: {fields}.",
                           "en": "{count} fields hold a single value across the whole file: {fields}."},
    "warn.high_nulls.many": {
        "es": "{count} campos están vacíos en la mayoría de los registros (normal si cada tipo de evento trae campos "
              "distintos): {fields}.",
        "en": "{count} fields are empty in most records (normal when each event type carries different fields): "
              "{fields}.",
    },
    "warn.all_null.many": {"es": "{count} campos están vacíos en todos los registros: {fields}.",
                           "en": "{count} fields are empty in every record: {fields}."},
    "warn.pii.many": {"es": "{count} campos contienen datos personales: {fields}.",
                      "en": "{count} fields contain personal data: {fields}."},
    "warn.profile_trimmed": {
        "es": "El perfil se recortó para no superar {limit} KB: {omitted} campos sin mapear se listan solo por su "
              "nombre en 'unmapped_fields'.",
        "en": "The profile was trimmed to stay under {limit} KB: {omitted} unmapped fields are listed by name only "
              "in 'unmapped_fields'.",
    },
    # --- integridad y espacio por caso (P0-B2) -----------------------------------------------------------------
    "case.err.bad_id": {
        "es": "case_id solo admite letras, números, '.', '_' y '-' (máx. 64): {case_id!r}",
        "en": "case_id only allows letters, digits, '.', '_' and '-' (max 64): {case_id!r}",
    },
    "case.err.exists": {"es": "El caso '{case_id}' ya existe en {path}.", "en": "Case '{case_id}' already exists at {path}."},
    "case.err.not_found": {"es": "No existe el caso '{case_id}' en {root}.", "en": "Case '{case_id}' not found under {root}."},
    "case.err.locked": {
        "es": "El caso '{case_id}' ya tiene un ledger abierto: su dataset está sellado. Para ingerir otro archivo u otro "
              "mapping crea un caso nuevo (un caso = un dataset).",
        "en": "Case '{case_id}' already has an open ledger: its dataset is sealed. To ingest another file or mapping, "
              "create a new case (one case = one dataset).",
    },
    "case.err.no_dataset": {"es": "El caso '{case_id}' aún no tiene dataset ingerido.",
                            "en": "Case '{case_id}' has no ingested dataset yet."},
    "case.err.raw_changed": {
        "es": "'{name}' ya existe en raw/ con contenido distinto (sha256 {old}… frente a {new}…).",
        "en": "'{name}' already exists in raw/ with different content (sha256 {old}… vs {new}…).",
    },
    "integrity.err.mapping": {
        "es": "El mapping de este dataset cambió respecto al que abrió el caso {case_id} (sha256 {recorded}… frente a "
              "{current}…): las columnas derivadas podrían ser distintas. Abre un caso nuevo.",
        "en": "This dataset's mapping differs from the one that opened case {case_id} (sha256 {recorded}… vs "
              "{current}…): derived columns may differ. Open a new case.",
    },
    "integrity.err.parquet": {
        "es": "El Parquet de este dataset no es el que abrió el caso {case_id} (sha256 {recorded}… frente a "
              "{current}…): se re-ingirió o se alteró. Abre un caso nuevo.",
        "en": "This dataset's Parquet is not the one that opened case {case_id} (sha256 {recorded}… vs "
              "{current}…): it was re-ingested or altered. Open a new case.",
    },
    "integrity.check.ledger_chain": {"es": "Cadena de hashes del ledger", "en": "Ledger hash chain"},
    "integrity.check.parquet_manifest": {"es": "Parquet coincide con el manifiesto", "en": "Parquet matches the manifest"},
    "integrity.check.parquet_ledger": {"es": "Parquet coincide con lo registrado en el ledger",
                                       "en": "Parquet matches what the ledger recorded"},
    "integrity.check.mapping_manifest": {"es": "Mapping del caso coincide con el manifiesto",
                                         "en": "Case mapping matches the manifest"},
    "integrity.check.mapping_ledger": {"es": "Mapping coincide con lo registrado en el ledger",
                                       "en": "Mapping matches what the ledger recorded"},
    "integrity.check.raw": {"es": "Archivo original en raw/ coincide con el manifiesto",
                            "en": "Original file in raw/ matches the manifest"},
    "integrity.check.dataset": {"es": "Dataset ingerido", "en": "Ingested dataset"},
    "integrity.detail.missing": {"es": "no encontrado", "en": "not found"},
    "integrity.detail.not_recorded": {"es": "el ledger aún no existe", "en": "the ledger does not exist yet"},
    "integrity.detail.mismatch": {"es": "esperado {expected}…, actual {actual}…", "en": "expected {expected}…, actual {actual}…"},
    "integrity.detail.ok": {"es": "correcto", "en": "ok"},
    "roles.note.actor_from_mapping": {"es": "actor '{col}' declarado en el mapping.", "en": "actor '{col}' declared in the mapping."},
    "roles.note.resource_from_mapping": {"es": "recurso '{col}' declarado en el mapping.",
                                         "en": "resource '{col}' declared in the mapping."},
    "roles.note.actor_user": {"es": "actor inferido: '{col}' (la fuente expone identidad).",
                              "en": "actor inferred: '{col}' (the source exposes identity)."},
    "roles.note.actor_ip": {"es": "actor inferido: 'src_ip' (la fuente no expone identidad; se analiza por IP).",
                            "en": "actor inferred: 'src_ip' (the source exposes no identity; analysis is per IP)."},
    "roles.note.resource_inferred": {"es": "recurso inferido: '{col}' (la columna derivada con más valores distintos).",
                                     "en": "resource inferred: '{col}' (the derived column with the most distinct values)."},
    "roles.note.resource_endpoint": {"es": "recurso inferido: 'endpoint' (no hay columnas derivadas con datos).",
                                     "en": "resource inferred: 'endpoint' (no derived column carries data)."},
    "roles.note.override": {"es": "{role} fijado manualmente a '{col}'.", "en": "{role} set manually to '{col}'."},
    "roles.err.unknown_column": {"es": "El rol {role} apunta a la columna '{col}', que no existe en el dataset.",
                                 "en": "Role {role} points to column '{col}', which does not exist in the dataset."},
    "roles.err.no_data": {"es": "El rol {role} apunta a '{col}', que no tiene datos en este dataset.",
                          "en": "Role {role} points to '{col}', which has no data in this dataset."},
    "ingest.err.collision": {
        "es": "{out} ya contiene el resultado de OTRO archivo (sha256 {old}… frente a {new}…). Usa una carpeta de salida "
              "distinta (un espacio por caso) o pasa overwrite=True si de verdad quieres reemplazarlo.",
        "en": "{out} already holds the result of ANOTHER file (sha256 {old}… vs {new}…). Use a different output folder "
              "(one workspace per case) or pass overwrite=True if you really mean to replace it.",
    },
    "ingest.err.bad_roles": {
        "es": "roles inválido: {detail}", "en": "invalid roles: {detail}",
    },
    "ingest.err.tz_unknown": {
        "es": "Zona horaria desconocida: {tz!r}. Usa un nombre IANA exacto (p. ej. America/Santiago, America/Bogota, UTC).{hint}",
        "en": "Unknown time zone: {tz!r}. Use an exact IANA name (e.g. America/Santiago, America/Bogota, UTC).{hint}",
    },
    "ingest.err.tz_hint": {"es": " ¿Quisiste decir: {options}?", "en": " Did you mean: {options}?"},
    "ingest.err.tz_fixed": {
        "es": "{tz!r} es un desfase fijo sin cambios de horario{sign}. Usa la zona de la región (p. ej. America/New_York "
              "en vez de EST). Si el sistema que generó el log usa de verdad un desfase fijo, añade "
              "timezone_fixed_offset: true en el mapping.",
        "en": "{tz!r} is a fixed offset with no daylight-saving changes{sign}. Use the region's zone (e.g. America/New_York "
              "instead of EST). If the system that produced the log truly uses a fixed offset, add "
              "timezone_fixed_offset: true to the mapping.",
    },
    "ingest.err.tz_sign": {"es": " y su signo va al revés: {tz} es UTC{offset}", "en": " and its sign is inverted: {tz} is UTC{offset}"},
    "ingest.err.ts_keys": {
        "es": "Clave desconocida en timestamp: {keys}. Válidas: {valid}.",
        "en": "Unknown key in timestamp: {keys}. Valid: {valid}.",
    },
    "ingest.err.ts_type": {"es": "timestamp.{name} debe ser: {expected}.", "en": "timestamp.{name} must be: {expected}."},
    "ingest.err.tz_source": {
        "es": "timestamp.timezone_source = {source!r} no cuadra: {reason}",
        "en": "timestamp.timezone_source = {source!r} does not fit: {reason}",
    },
    "ingest.err.tz_source_in_data": {
        "es": "el formato {fmt!r} no trae zona en el dato (para eso: iso8601 con timezone_in_data, %z, epoch_s/epoch_ms o native).",
        "en": "format {fmt!r} carries no zone in the value (for that: iso8601 with timezone_in_data, %z, epoch_s/epoch_ms or native).",
    },
    "ingest.err.tz_source_declared": {
        "es": "el formato {fmt!r} ya trae la zona en cada valor, así que una zona declarada no se aplicaría. Quita timezone_source o usa in_data.",
        "en": "format {fmt!r} already carries the zone in each value, so a declared zone would not be applied. Drop timezone_source or use in_data.",
    },
    "ingest.err.tz_source_default": {
        "es": "'default' significa que nadie declaró la zona, así que debe ser UTC y no estar verificada.",
        "en": "'default' means nobody declared the zone, so it must be UTC and unverified.",
    },
    "ingest.warn.tz_unverified": {
        "es": "Zona horaria NO verificada: se asumió {tz}",
        "en": "Time zone NOT verified: {tz} was assumed",
    },
    "ingest.warn.tz_ignored": {
        "es": "La zona declarada {tz} no se aplica: el formato {fmt!r} ya trae su propia zona y las horas se toman del dato.",
        "en": "The declared zone {tz} is not applied: format {fmt!r} carries its own zone and times are taken from the value.",
    },
    "ingest.warn.dst_ambiguous": {
        "es": "{rows} filas tienen una hora local que ocurre dos veces por el cambio de horario en {tz} (retroceso del reloj): "
              "se interpretaron como la segunda ocurrencia. Su orden respecto a eventos de esa misma hora no es fiable.",
        "en": "{rows} rows have a local time that occurs twice due to the daylight-saving change in {tz} (clocks going back): "
              "they were read as the second occurrence. Their order relative to events in that same hour is unreliable.",
    },
    "ingest.warn.dst_nonexistent": {
        "es": "{rows} filas tienen una hora local que no existe en {tz} (el reloj se adelantó): se desplazaron al convertir "
              "a UTC. Revisa esas filas: el log puede estar en otra zona o el reloj del sistema mal configurado.",
        "en": "{rows} rows have a local time that does not exist in {tz} (clocks jumped forward): they were shifted when "
              "converting to UTC. Check those rows: the log may be in another zone or the system clock misconfigured.",
    },
    "ingest.warn.derived_empty": {
        "es": "La columna derivada '{name}' quedó vacía en todas las filas: revisa su regex o su campo de origen.",
        "en": "Derived column '{name}' is empty in every row: check its regex or its source field.",
    },
    # --- Inspector (borrador de mapping) ------------------------------------------------------------------------
    "inspector.status.ready": {"es": "LISTO PARA REVISAR", "en": "READY FOR REVIEW"},
    "inspector.status.needs_review": {"es": "REQUIERE DECISIONES ANTES DE INGERIR", "en": "NEEDS DECISIONS BEFORE INGESTION"},
    "inspector.status.unsupported": {"es": "NO SE PUEDE INGERIR (todavía)", "en": "CANNOT BE INGESTED (yet)"},
    "inspector.description": {"es": "Borrador del Inspector para {file} (tipo de log detectado: {type})",
                              "en": "Inspector draft for {file} (detected log type: {type})"},
    "inspector.yaml.header": {
        "es": "Borrador generado por el Inspector. REVÍSALO antes de usarlo: nada de esto está aprobado todavía.",
        "en": "Draft generated by the Inspector. REVIEW it before use: none of this is approved yet.",
    },
    "inspector.yaml.pending": {"es": "Decisiones pendientes", "en": "Pending decisions"},
    "inspector.yaml.tz_unverified": {"es": "sin verificar: confirma la zona horaria del export con su dueño",
                                     "en": "unverified: confirm the export's time zone with its owner"},
    "inspector.yaml.roles": {"es": "propuesta: confirma quién actúa y sobre qué", "en": "proposal: confirm who acts and on what"},
    "inspector.yaml.hits": {"es": "{hit}% de filas con valor, {distinct} distintos", "en": "{hit}% of rows have a value, {distinct} distinct"},
    "inspector.yaml.examples": {"es": "ejemplos enmascarados", "en": "masked examples"},
    "inspector.render.mapping": {"es": "CAMPOS", "en": "FIELDS"},
    "inspector.render.derived": {"es": "COLUMNAS DERIVADAS DE LA URL", "en": "COLUMNS DERIVED FROM THE URL"},
    "inspector.render.decisions": {"es": "DECISIONES", "en": "DECISIONS"},
    "inspector.render.none": {"es": "(ninguna)", "en": "(none)"},
    "inspector.render.level.required": {"es": "OBLIGATORIA", "en": "REQUIRED"},
    "inspector.render.level.review": {"es": "revisar", "en": "review"},
    "decision.timezone_unverified": {
        "es": "'{field}' no trae zona horaria: el borrador asume {tz} SIN verificar. Pregunta al dueño del export; "
              "si es otra zona, cambia timezone en el mapping antes de ingerir.",
        "en": "'{field}' carries no time zone: the draft assumes {tz} UNVERIFIED. Ask the export's owner; "
              "if it is another zone, change timezone in the mapping before ingesting.",
    },
    "decision.timezone_declared": {
        "es": "'{field}' no trae zona horaria: se usará {tz}, declarada por el analista y SIN verificar. Cuando el dueño del "
              "export la confirme, pon timezone_verified: true y anota en timezone_note quién la confirmó y cuándo.",
        "en": "'{field}' carries no time zone: {tz} will be used, declared by the analyst and UNVERIFIED. When the export's "
              "owner confirms it, set timezone_verified: true and record in timezone_note who confirmed it and when.",
    },
    "decision.timezone_ignored": {
        "es": "Declaraste {tz}, pero '{field}' ya trae la zona en cada valor: se usa la del dato y tu declaración no se aplica.",
        "en": "You declared {tz}, but '{field}' already carries the zone in each value: the value's zone is used and your "
              "declaration is not applied.",
    },
    "decision.mapping_ambiguous": {
        "es": "'{canonical}' podría venir de: {fields}. El borrador usa '{chosen}'; confirma cuál es.",
        "en": "'{canonical}' could come from: {fields}. The draft uses '{chosen}'; confirm which one it is.",
    },
    "decision.unsupported_log_type": {
        "es": "El archivo parece de tipo '{type}' y todavía no hay un esquema canónico para él (hoy solo logs web: "
              "necesita fecha y URL o línea de petición). No se puede generar un mapping ingerible.",
        "en": "The file looks like type '{type}' and there is no canonical schema for it yet (today only web logs: "
              "it needs a date and a URL or request line). An ingestible mapping cannot be generated.",
    },
    "decision.missing_timestamp": {"es": "No se encontró un campo de fecha interpretable.", "en": "No parseable date field was found."},
    "decision.missing_uri": {"es": "No se encontró un campo de URL ni de línea de petición HTTP.",
                             "en": "No URL or HTTP request-line field was found."},
    "decision.unsupported_fields": {
        "es": "Campos reconocidos que el esquema canónico actual no incluye (no se ingieren): {fields}.",
        "en": "Recognised fields the current canonical schema does not include (not ingested): {fields}.",
    },
    "decision.credential_in_url": {
        "es": "El parámetro '{param}' de la URL parece una credencial y el borrador extrae datos de él. "
              "Trátalo como expuesto en el log.",
        "en": "URL parameter '{param}' looks like a credential and the draft extracts data from it. "
              "Treat it as exposed in the log.",
    },
    "decision.derived_identity": {
        "es": "'{name}' se extrae de '{param}' (valores con estructura prefijo+identificador). Confirma que es el actor "
              "que quieres analizar.",
        "en": "'{name}' is extracted from '{param}' (values shaped prefix+identifier). Confirm it is the actor "
              "you want to analyse.",
    },
    "decision.header_missing": {
        "es": "El CSV no parece tener fila de encabezado: el mapping usa nombres de columna y no funcionará.",
        "en": "The CSV does not seem to have a header row: the mapping uses column names and will not work.",
    },
    "decision.invalid_draft": {"es": "El borrador no pasa la validación del ingestor: {error}",
                               "en": "The draft fails the ingestor's validation: {error}"},
    "derived.reason.identity": {"es": "identidad (prefijo + identificador)", "en": "identity (prefix + identifier)"},
    "derived.reason.credential_type": {"es": "tipo de credencial (el prefijo)", "en": "credential type (the prefix)"},
    "derived.reason.resource": {"es": "recurso candidato (numérico, muchos valores distintos)",
                                "en": "candidate resource (numeric, many distinct values)"},
    "derived.reason.dimension": {"es": "dimensión (pocos valores distintos)", "en": "dimension (few distinct values)"},
    "derived.reason.other": {"es": "parámetro de texto", "en": "text parameter"},
    "derived.reason.canonical": {"es": "coincide con un campo canónico por su nombre", "en": "matches a canonical field by name"},
    "case.err.incomplete": {
        "es": "La carpeta {path} existe pero no es un caso completo (falta case.json): revísala o bórrala a mano.",
        "en": "Folder {path} exists but is not a complete case (case.json is missing): inspect or delete it by hand.",
    },
    "decision.derived_gap": {
        "es": "'{name}' no extrae valor en {rows} filas ({pct}% de las que traen '{param}='): formato distinto al esperado "
              "o prefijo nuevo. Revisa esas filas antes de confiar en la columna.",
        "en": "'{name}' extracts no value in {rows} rows ({pct}% of those carrying '{param}='): unexpected format "
              "or a new prefix. Inspect those rows before trusting the column.",
    },
    # --- tipos de log ----------------------------------------------------------------------------------------------
    "log_type.web": {"es": "Acceso web / API", "en": "Web / API access"},
    "log_type.proxy": {"es": "Proxy web", "en": "Web proxy"},
    "log_type.firewall": {"es": "Firewall / flujo de red", "en": "Firewall / network flow"},
    "log_type.auth": {"es": "Autenticación / inicio de sesión", "en": "Authentication / logon"},
    "log_type.dns": {"es": "DNS", "en": "DNS"},
    "log_type.edr": {"es": "Telemetría de endpoint (EDR)", "en": "Endpoint telemetry (EDR)"},
    "log_type.unknown": {"es": "Desconocido", "en": "Unknown"},
}


def default_lang() -> str:
    lang = os.environ.get("DFIR_LANG", "es").strip().lower()[:2]
    return lang if lang in SUPPORTED else "es"


def resolve_lang(lang: str | None) -> str:
    value = (lang or default_lang()).strip().lower()[:2]
    if value not in SUPPORTED:
        raise ValueError(f"Idioma no soportado / unsupported language: {lang!r}. Usa {SUPPORTED}")
    return value


def t(key: str, lang: str | None = None, **kwargs) -> str:
    """Traduce `key` al idioma pedido y rellena sus marcadores."""
    entry = _MESSAGES.get(key)
    if entry is None:
        raise KeyError(f"mensaje sin definir: {key}")
    return entry[resolve_lang(lang)].format(**kwargs)


def placeholders(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name}


def catalog() -> dict[str, dict[str, str]]:
    return {k: dict(v) for k, v in _MESSAGES.items()}
