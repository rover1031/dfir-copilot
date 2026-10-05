# DFIR Co-pilot · Arquitectura y Fase P0 (ingesta, perfilado y parseo agnóstico)

> Documento vivo del repositorio. Idioma: español; los identificadores de código y las claves JSON van en inglés
> (ver «Convención bilingüe»).

## 1. Principios

| Principio | Qué significa en el código |
|---|---|
| **Local-first** | Todo el perfilado ocurre en DuckDB, en el equipo del analista. Los archivos se recorren en streaming: 1 GB / 4,5 M filas se perfilan con ~0,2 GB de RAM. |
| **Regla de oro de privacidad** | Al LLM solo viaja el *Data Profile*: estadísticas, formas abstractas y nombres. Nunca valores crudos. Hay un test que lo verifica y falla si se rompe. |
| **Determinismo y trazabilidad** | Muestra reproducible (`REPEATABLE`), salidas ordenadas y el SHA-256 del archivo dentro del perfil: un perfil identifica exactamente qué archivo describe. |
| **Conocimiento en configuración** | Los alias de campos viven en `aliases.yaml` y se amplían sin tocar código. |
| **El LLM propone, el analista decide** | El perfil incluye propuesta de mapeo, ambigüedades y avisos; nada se aplica sin revisión. |

## 2. Análisis en dos fases

```
            ┌──────────────────────── FASE LOCAL (DuckDB, sin red) ────────────────────────┐
 archivo ──►│ readers ──► esquema ──► pasada completa ──► muestra ──► mapeo ──► verificación │──► Data Profile (≈6 KB)
 CSV/TSV/   │ formato,    aplanado     nulos, cardinal.   semántica,  bilingüe   fecha sobre  │        │
 JSON/      │ codific.,   de JSON      longitudes,        formas,     nombre +   el archivo   │        │
 NDJSON/    │ dialecto    anidado      rangos             fechas      contenido  completo     │        │
 Parquet    └──────────────────────────────────────────────────────────────────────────────┘        ▼
 (.gz)                                                                         ┌──── FASE LLM (API) ────┐
                                                                               │ clasificar el tipo de  │
                                                                               │ log, confirmar mapeo,  │
                                                                               │ proponer consultas     │
                                                                               └───────────┬────────────┘
                                                                                           ▼
                                                     el analista aprueba ──► ingesta canónica (Parquet + manifiesto)
                                                                         ──► motor seguro, detectores, agente, ledger
```

Las consultas que proponga el LLM se escriben contra la vista canónica `logs` (después de la ingesta) y se
ejecutan en el motor seguro de solo lectura. El LLM nunca obtiene acceso a archivos.

## 3. Módulos (`src/dfir_copilot/profiling/`)

| Módulo | Responsabilidad |
|---|---|
| `readers.py` | Detecta formato y compresión (extensión o bytes mágicos), codificación (UTF-8 → Latin-1) y dialecto CSV (`sniff_csv`). Lee JSON con `read_json_auto(format='auto')` (líneas o arreglo) sin inferir `MAP` opacos. |
| `semantics.py` | Patrones RE2 (IP, email, URL, línea de petición HTTP, hashes, SID, JWT…), candidatos de fecha (ISO 8601, `strptime`, meses en español, epoch s/ms) y vocabulario técnico seguro. |
| `schema_mapper.py` | `normalize_name` y `SchemaMapper`: nombre (alias fuertes, hoja de ruta anidada, tokens, alias débiles) + contenido (confirma, desmiente o propone). Marca ambigüedades y da pistas del tipo de log. |
| `aliases.yaml` | Diccionario bilingüe: 26 campos canónicos (web, red, DNS, autenticación, endpoint) con alias en inglés y español, incluidos nombres de ECS, Sysmon, CloudTrail e IIS. |
| `data_profile.py` | Contrato pydantic del Data Profile (`DataProfile`), su JSON Schema y la serialización compacta para la API. |
| `log_profiler.py` | Orquesta las fases locales y emite el perfil y sus avisos en el idioma pedido. |
| `i18n.py` | Catálogo bilingüe con prueba de coherencia (mismas variables en ambos idiomas). |

> Nota de nombres: `dfir_copilot.engine.profiler.LogProfiler` es el perfilador **analítico** sobre datos ya
> normalizados; `dfir_copilot.profiling.LogProfiler` es el perfilador de **archivos crudos** de esta fase. Se
> unificará el nombre del primero (`CanonicalProfiler`) cuando se toque el motor.

## 4. Mapeo bilingüe

1. **Normalización:** minúsculas, sin acentos, camelCase → snake_case, separadores → `_`.
   `Dirección IP` → `direccion_ip`; `sourceIPAddress` → `source_ip_address`; `@timestamp` → `timestamp`;
   `process.parent.name` → `process_parent_name`.
2. **Puntuación por nombre:** alias fuerte 1,0 · último segmento de una ruta anidada 0,9 · tokens contenidos 0,75 ·
   alias débil (`ip`, `estado`, `fecha`) 0,7.
3. **Ajuste por contenido:** +0,15 si los valores confirman el tipo esperado; −0,4 si lo contradicen. Si el nombre
   no dice nada pero el contenido es inequívoco (≥ 90 %), se propone por contenido (0,55). Así `http_staus`, con
   error tipográfico, se mapea a `status_code`.
4. **Asignación:** voraz y determinista; cada campo se asigna una vez. Si otro candidato queda a ≤ 0,1, se marca
   como ambiguo (p. ej. `client_ip` frente a `x_forwarded_for`).

## 5. Contrato del Data Profile

Esquema completo: `docs/data_profile.schema.json`. Ejemplo (dataset sintético): `docs/ejemplo_data_profile.json`.

| Bloque | Contenido |
|---|---|
| `privacy` | Modo `strict`, `raw_values_included: false` y la explicación en el idioma pedido. |
| `source` | Nombre del archivo (no la ruta), SHA-256, tamaño, formato, compresión, codificación, separador. |
| `dataset` | Filas, campos totales y perfilados, filas de muestra, si hay estructuras anidadas. |
| `fields[]` | Por campo: tipo, % nulos, cardinalidad aproximada, longitudes, % numérico, tipos semánticos, formas abstractas, **nombres** de parámetros de URL, valores categóricos seguros, datos personales, % con secretos, formato de fecha, campo canónico asignado. |
| `timestamp` | Campo y formato elegidos, tasa de interpretación en muestra y **en el archivo completo**, rango UTC, si los datos traen zona horaria, alternativas descartadas. |
| `mapping[]`, `ambiguous[]`, `unmapped_fields[]` | Propuesta de mapeo con método y evidencia. |
| `log_type_hints[]` | Tipos de log candidatos con puntuación, etiqueta traducida y campos que lo sustentan. |
| `warnings[]` | Código estable (inglés) + mensaje traducido. |
| `llm_tasks[]` | Lo que se espera del LLM en la fase siguiente. |

## 6. Privacidad: qué sale y qué no

| Sale al LLM | Nunca sale |
|---|---|
| Nombres de campos y de parámetros de URL | Valores de cualquier campo |
| Formas abstractas (`a/9.9`, `9.9.9.9`) | IPs, usuarios, emails, comandos, rutas, hashes, tokens |
| Valores de vocabulario técnico cerrado (GET, 200, allow) | Valores categóricos fuera de ese vocabulario |
| Rangos de fechas y estadísticas | La ruta del archivo |

Límites conocidos: una forma abstracta conserva la puntuación y la longitud aproximada; los nombres de campos y
de parámetros pueden ser descriptivos. Ambos son metadatos de esquema, no registros.

## 7. Convención bilingüe

* Claves JSON, códigos de aviso y nombres canónicos: **inglés** (contrato estable, nunca cambia con el idioma).
* Textos para personas (avisos, etiquetas, informes): **es/en** vía `i18n.t()`; idioma por parámetro o `DFIR_LANG`.
* Entrada: los nombres de campo se reconocen en ambos idiomas (alias) y los meses en español se interpretan en fechas.

## 8. Cómo ampliar

* **Nuevo alias:** añadirlo en `aliases.yaml` (o en tiempo de ejecución con `SchemaMapper(extra=...)`).
* **Nuevo formato de fecha:** añadirlo a `STRPTIME_FORMATS` (y a `DAY_MONTH_PAIRS` si puede confundir día y mes).
* **Nuevo tipo semántico:** patrón RE2 en `SEMANTIC_PATTERNS`; si es dato personal, añadirlo a `_PII`.

## 9. Pendiente de P0 (bloque B) y siguientes fases

1. **Ingestor multi-formato** usando `readers` y rutas anidadas (`process.parent.name`), y con mapping generado a
   partir de la propuesta aprobada.
2. **Espacio por caso** (`data/cases/<caso>/raw|processed|ledger`) para que dos casos no compartan archivos.
3. **Integridad:** el ledger compara hash de mapping y de Parquet al abrirse; hash de resultado por consulta.
4. **Roles para detectores** leídos del mapping (actor = usuario o, si no hay, IP).
5. **Fase LLM:** herramienta del agente que recibe el Data Profile y devuelve clasificación, mapeo y consultas.
6. **Prompts y reporte bilingües** (P1/P2).

## 10. Rendimiento medido

CSV de 1,02 GB y 4.478.619 filas, 1 núcleo de CPU: **11,1 s** (incluye SHA-256), memoria máxima **0,18 GB**,
perfil de **6,4 KB**.
