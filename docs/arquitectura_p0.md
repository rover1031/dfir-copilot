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
4. **Asignación:** voraz y determinista; cada campo se asigna una vez. Con igual puntuación gana el alias que
   aparece **antes** en `aliases.yaml` (por eso el orden importa: `user_name` antes que `uid`, SHA-256 antes que MD5).
   Si otro candidato queda a ≤ 0,1, se marca como ambiguo (p. ej. `client_ip` frente a `x_forwarded_for`).
5. **Contenido genérico en dos pasadas:** códigos HTTP, dominios y rutas que empiezan por `/` son demasiado comunes
   para proponer un mapeo por sí solos (un puerto 443 «parece» un código HTTP). Solo se usan si una primera pasada
   ya identificó el log como web o proxy.
6. **Tokens contiguos:** `ip_origen_cliente` contiene `ip_origen`; `session_process_id` **no** contiene `session_id`.

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

### Presupuesto de tamaño y avisos

* El perfil no supera `max_profile_bytes` (24 KB por defecto, ≈ 6 000 tokens). Si se pasa, se recorta en este orden:
  menos detalle en campos sin mapear → sin formas → fuera los campos sin mapear menos informativos (sus nombres
  siguen en `unmapped_fields`) → sin formas en todo el perfil. Los campos mapeados nunca se eliminan.
  `dataset.fields_in_payload` y el aviso `warn.profile_trimmed` dicen cuánto se recortó.
* Los avisos repetidos (valor constante, vacíos, datos personales) se agrupan en uno por tipo. «Valor constante»
  solo se avisa con 50 registros o más.

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

## 9. Plan por fases

| Fase | Contenido | Estado |
|---|---|---|
| **P0** | Generalización e integridad: perfilado local multi-formato y mapeo bilingüe (A), espacio por caso, integridad ledger/dataset, huella de resultados y roles (B2), Inspector e ingestor multi-formato (B1) | Hecho (§12, §13) |
| **P1-a** | Fase LLM: una llamada que recibe solo el Data Profile y devuelve clasificación del log, confirmación del mapeo y consultas SQL propuestas (validadas con pydantic y ejecutadas en el motor seguro); zona horaria declarada por caso | Hecho |
| **P1-b** | Agente. b.1 filtro de notebooks, perfilado canónico y resumen por rol · b.2 copia seudonimizada (`priv-1`) y agente, toolkit, ledger y replay sobre ella (`privacidad.md`) · b.3a texto del analista traducido a alias · b.3b falsabilidad (`falsabilidad.md`) · b.3c tope de tokens por pregunta y por caso, notas del analista visibles en cada pregunta, retirar hipótesis (`presupuesto_y_notas.md`) | Hecho |
| **P1-c** | Conversación persistente en disco (`ws.checkpointer()`): una aprobación pendiente o una conversación en curso sobreviven a reiniciar el kernel; un hilo no se reanuda con otro prompt u otra copia de datos. Reproducibilidad: aviso en `run_query` y `nondeterministic` en el replay (`persistencia_y_reproducibilidad.md`) | Hecho |
| **P2** | Entrega. **Hecho:** informe forense Markdown bilingüe generado desde el ledger, en variante interna y compartible, con botón *Exportar* (`informe.md`); proyectos (una carpeta = un caso por archivo) con análisis automático al crearlos e interfaz web Django + HTMX (`interfaz_web.md`). **Pendiente:** README, CLI (`dfir ingest`, `dfir ask`), prompt del agente en inglés y PDF. `nbstripout`: resuelto con `tools/strip_notebook_outputs.py` | Parcial |
| **P3** | Ampliación: logs no web (autenticación, EDR, firewall) con esquema canónico propio, Excel, GeoIP offline, inteligencia en PDF | **Firewall hecho** (ver `docs/firewall.md`); pendientes autenticación, EDR, Excel, GeoIP y PDF |

**Transversal (fuera de P1–P3)**

| Tema | Prioridad | Estado |
|---|---|---|
| Política de exposición de datos y seudonimización hacia el LLM | Alta | Hecho (P1-b.2/b.3a). Falta la aprobación de seguridad y legal de la política (Ley 1581 de 2012 si hay datos personales hacia un proveedor externo) |
| Evaluación y métricas: casos con respuesta conocida, precisión y recall de detectores, tokens por investigación, tiempo hasta el triaje frente a la línea base manual | Alta | Pendiente (los datos ya salen del ledger) |
| Esquema canónico para EDR y autenticación (ECS u OCSF en lugar de ampliar los 13 campos web) | Alta | Pendiente; afecta a P1 y se ejecuta en P3 |
| Detectores genéricos (primera vez visto, cambios de ritmo, valores raros, MITRE) y líneas de tiempo multi-fuente | Media-alta | Pendiente |
| Integridad forense más allá de la cadena de hashes: anclar el `head_hash` fuera de la máquina, copias fuera de WSL, plantilla de cadena de custodia, redacción de credenciales en reportes | Media | Pendiente |
| Ingeniería de entrega: repositorio remoto, CI (`ruff` y `pytest`), lockfile, pre-commit, contenedor sin root, versionado y ADR | Media | Pendiente (repositorio remoto en manos del analista) |
| Integración con el ecosistema: ingesta desde Falcon NG-SIEM/LogScale, salida como consultas de LogScale o reglas Sigma, exportar el ledger al gestor de casos | Media | Pendiente |
| Interfaz web local de un solo analista (Django y HTMX) | — | Hecha (P2). Pendiente: autenticación y multi-analista |
| Después: multi-analista, modelo local para datos que no puedan salir | Baja | Pendiente |

La fase LLM es P1, no P0: P0 termina en el perfil, el mapeo y el borrador de mapping, que ya es lo que se enviaría al modelo.

## 10. Lecciones del primer archivo real (exportación de Falcon / LogScale)

108 claves planas con prefijos `#`/`@` y puntos literales, 8 eventos de tipos distintos. Encontró seis fallos que
los datos sintéticos no tocaban: perfil de 47 KB (no había presupuesto), 81 avisos de ruido, mapeos falsos por
contenido genérico (`RPort`→`status_code`, `FilePath`→`uri`), coincidencia por tokens demasiado permisiva
(`SessionProcessId`→`session_id`), empates resueltos alfabéticamente (`UID` sobre `UserName`) y un tipo de log
elegido por orden alfabético. Tras corregirlos: 23,6 KB, 8 avisos, mapeo correcto y clasificación EDR. Hay tests de
regresión con un fixture sintético de la misma estructura; los datos reales no entran en el repositorio.

## 11. Rendimiento medido

CSV de 1,02 GB y 4.478.619 filas, 1 núcleo de CPU: **11,1 s** (incluye SHA-256), memoria máxima **0,18 GB**,
perfil de **6,4 KB**.

## 12. P0-B2 · Espacio por caso, integridad y roles

### 12.1 Estructura de un caso

```
data/cases/<caso>/
├── raw/          original (copia de solo lectura verificada por hash, o enlace simbólico si es enorme)
├── processed/    Parquet canónico + manifiesto + .duckdb_tmp
├── ledger/       <caso>.jsonl (append-only, cadena de hashes)
├── mapping.yaml  copia del mapping APROBADO (inmutable: se verifica contra los hashes)
└── case.json     metadatos: analista, idioma, hashes del dataset
```

`CaseWorkspace.create / open / list_cases / add_raw / ingest / engine / ledger / verify`. **Un caso = un dataset:**
al abrirse el ledger el dataset queda sellado (`CaseLocked`); otro archivo u otro mapping exige un caso nuevo.

### 12.2 Los dos agujeros de integridad y cómo se cierran

| Agujero | Antes | Ahora |
|---|---|---|
| Re-ingerir el mismo CSV con otro mapping (p. ej. otra zona horaria: 00:04 → 05:04) | `Ledger.open` lo aceptaba en silencio; `replay` solo comparaba el nº de filas | `MappingMismatch` / `ParquetMismatch` al abrir; el replay compara además el **contenido** del resultado |
| Dos casos con un archivo del mismo nombre en la misma carpeta de salida | El segundo sobrescribía el Parquet del primero | Carpeta propia por caso + `OutputCollision` en el ingestor si el hash de entrada difiere (`overwrite=True` para forzar) |

`Ledger.open` exige ahora que el **mapping** y el **Parquet** coincidan con los registrados en `case_opened`. El Parquet
se compara con su hash real, no solo con el del manifiesto (un manifiesto copiado no basta). Los ledgers anteriores,
que no guardaban alguno de los dos hashes, se siguen abriendo.

### 12.3 Huella de resultado en el replay

Cada consulta registra `limit` (tope de filas con que se ejecutó) y `result_sha256`. El replay ejecuta con el mismo
tope y compara la huella. La huella es **insensible al orden de filas** (sin `ORDER BY`, DuckDB puede devolver las mismas
filas en otro orden) y redondea flotantes a 9 cifras significativas. Si la consulta estaba truncada, un `LIMIT` sin
`ORDER BY` puede elegir otras filas: solo se compara el recuento y `hash_match` queda en `None`. Las consultas anteriores
sin huella también dan `None`, no un falso positivo.

### 12.4 Verificación completa (`CaseWorkspace.verify()`)

Seis comprobaciones, sin lanzar excepciones: cadena del ledger · Parquet = manifiesto · Parquet = ledger · mapping =
manifiesto · mapping = ledger · original en `raw/` = manifiesto. Cada una sale OK / XX / «--» (no aplicable aún) y se
puede imprimir en español o inglés.

### 12.5 Roles: actor y recurso

Los detectores ya no suponen `user_id` y `x_invoice_id`. El mapping declara:

```yaml
roles:
  actor: user_id
  resource: x_invoice_id
```

Prioridad: **override manual > mapping > inferencia**. La inferencia usa los datos: actor = `user_id` si tiene datos, si no
`src_ip`; recurso = la columna derivada `x_*` con más valores distintos, o `endpoint` si no hay ninguna. Con actor = IP,
`actor_ip_cluster` se declara no aplicable (agrupar IPs por IP no tiene sentido). La decisión se registra en el ledger
como entrada `roles`, una sola vez mientras no cambie, porque cambia lo que significa cada hallazgo.
`describe_dataset` informa de los roles al agente (no cambia el prompt de sistema ni las herramientas, así que no rompe
la regla del prefijo estable).

### 12.6 Compatibilidad

Se verificó con un manifiesto sin la clave `roles`, un ledger con el `case_opened` del formato anterior y consultas
sin `limit` ni `result_sha256`: reabre, el replay funciona, los roles se infieren y los detectores dan los mismos
resultados. Una entrada nueva de tipo `roles` se añade al ledger la primera vez que se ejecutan los detectores (la
cadena sigue válida, pero el `head_hash` avanza: guarda el anterior como punto de control).

### 12.7 Límites conocidos

* El espacio por caso envuelve el ingestor actual, que solo lee CSV. El ingestor multi-formato (P0-B1) se enchufará
  en `CaseWorkspace.ingest` sin cambiar la API.
* `verify()` calcula el SHA-256 del original en `raw/`: con 1 GB son unos segundos.
* La inferencia de roles es una heurística. Un mapping debe declararlos; la inferencia existe para datasets anteriores.
* `mapping.yaml` del caso es inmutable por convención y por verificación, no por permisos del sistema de archivos.

## 13. P0-B1 · Inspector e ingestor multi-formato

### 13.1 Flujo

```
archivo ──► LogProfiler ──► Data Profile ─┐
   │                                       ├─► Inspector ──► BORRADOR (YAML + decisiones) ──► analista revisa ──► mapping aprobado
   └─► análisis LOCAL de valores de la URL ┘                                                                          │
        (ejemplos enmascarados)                                                           CaseWorkspace.ingest ◄───────┘
```

El Inspector **propone**; no ingiere ni modifica el archivo. El borrador es un YAML con comentarios y una lista de
decisiones pendientes; el archivo que el analista deja guardado es el mapping aprobado, que `CaseWorkspace.ingest` copia
al caso. Por qué hace falta un análisis aparte del Data Profile: para proponer `user_id` a partir de
`authtoken=ATUSER-ID-<x>` hay que ver la forma de los valores, y el perfil no los lleva por diseño. Ese análisis ocurre
en una conexión DuckDB restringida a ese archivo y lo único que se muestra son estadísticas y ejemplos enmascarados
(`an*******`).

### 13.2 Qué propone el Inspector

| Elemento | Cómo |
|---|---|
| Campos canónicos | El mapeo bilingüe del perfil, filtrado a los que el esquema sabe ingerir; el resto se informa («no se ingieren») |
| Línea de petición | Si el campo de URL contiene `GET /ruta HTTP/1.1`, usa `request_line` y el ingestor separa método y ruta |
| Fecha | Formato, zona y verificación a partir del perfil; `native`, `epoch_s`, `epoch_ms`, `iso8601` o `strptime` |
| Derivadas | Por cada parámetro de la URL: **numérico** con muchos valores → recurso (`BIGINT`); pocos valores → dimensión; **prefijo+id** (`ATUSER-ID-ana`, `user:ana`) → tipo de credencial + identidad; nombre de campo canónico (`username=`) → ese campo |
| Roles | `actor` = `user_id` si existe, si no `src_ip`; `resource` = la derivada numérica con más valores distintos |

Reglas para no inventar: una identidad exige que el valor se repita entre peticiones (un token único por fila no es un
actor); parámetros presentes en menos del 5 % de las filas se ignoran; el tope es de 12 parámetros.

**La muestra decide qué proponer; el archivo completo mide qué tan bien.** Una muestra de 20 000 filas puede no contener
un prefijo raro (p. ej. `TEST`, el 0,1 % de las filas): la regex lo dejaría fuera y esas cuentas quedarían con `user_id`
vacío sin ningún aviso. Por eso, tras proponer, el Inspector hace dos pasadas por el archivo completo:

1. **Descubre los prefijos** de los parámetros compuestos en todo el archivo (hasta 10; más de 10 no es un vocabulario).
2. **Mide cada derivada**: % de filas con valor, valores distintos (exactos hasta 1 000, aproximados por encima) y
   cuántas filas traen el parámetro pero la regex no extrae nada → decisión `derived_coverage_gap` con el recuento exacto.
   Un token malformado o un prefijo nuevo se ve ahí, no se pierde.

### 13.3 Decisiones

Cada una lleva un código estable (inglés) y un nivel. **required** bloquea el estado `ready`; **review** no, pero queda
escrita en el YAML.

| Código | Nivel | Cuándo |
|---|---|---|
| `date_order_ambiguous` | required | Día-mes y mes-día interpretan el 95 % o más de los datos con resultados distintos |
| `header_missing` | required | El CSV no parece tener encabezado |
| `invalid_draft` | required | El borrador no pasa la validación del ingestor |
| `missing_timestamp`, `missing_uri`, `unsupported_log_type` | required | El archivo no se puede ingerir (estado `unsupported`) |
| `timezone_unverified` | review | La fecha no trae zona horaria |
| `mapping_ambiguous` | review | Dos columnas compiten por el mismo campo |
| `derived_identity`, `credential_in_url` | review | Se extrae una identidad de un parámetro; credencial expuesta en el log |
| `derived_coverage_gap` | review | Hay filas con el parámetro de las que la regex no extrae valor (formato inesperado o prefijo nuevo) |
| `unsupported_fields` | review | Campos reconocidos que el esquema no incluye |

### 13.4 Ingestor multi-formato

`ingest_file` (con `ingest_csv` como alias histórico) lee CSV, TSV, JSON/NDJSON, arreglos JSON y Parquet, comprimidos o
no, con la misma lectura que el perfilador. Novedades del mapping:

* `format`: `auto`, `csv`, `tsv`, `json`, `parquet`.
* Rutas anidadas: `http.request.method` resuelve tanto una estructura `http → request → method` como una clave plana con
  puntos (LogScale). Una columna inexistente falla con sugerencia.
* `timestamp.format`: `native` (columna ya tipada), `epoch_s`, `epoch_ms`, `iso8601` (+ `timezone_in_data`), o
  `strptime`; meses en español (`ene`, `abr`, `ago`, `dic`) y `%z`.
* `request_line`: separa método y ruta; no se combina con `uri` ni `http_method`.
* `derived.from` puede ser una columna base (`query_string`) o cualquier ruta del origen.
* Aviso si una derivada queda vacía en todas las filas (regex o campo de origen erróneos).
* El manifiesto registra formato, compresión y codificación; el Parquet no arrastra la extensión de origen
  (`export.ndjson.gz` → `export.parquet`).
* Un JSON cuyo tipo cambia después de la muestra de inferencia se reintenta leyendo el archivo completo.

**Compatibilidad:** con el mismo CSV y el mismo mapping, el Parquet resultante es idéntico byte a byte al de B2.

### 13.5 Límites conocidos

* **Solo logs web.** El esquema canónico tiene 13 campos web. La telemetría de EDR, firewall o autenticación se
  reconoce y se perfila; si es de firewall se ingiere con el esquema de red (`docs/firewall.md`); si es de otro tipo (autenticación, EDR, DNS),
  el Inspector la declara `unsupported`: necesita su propio esquema (pendiente P3).
* **Qué se propone sale de una muestra** (20 000 filas por defecto, reproducible): un parámetro presente solo en filas
  que la muestra no contiene no se propone. Los prefijos y la cobertura sí se verifican en el archivo completo.
* **Prefijo+id solo con separadores conocidos:** `-ID-`, `_ID_`, `:` y `|`.
* **El JSON tipado pierde la zona:** DuckDB convierte una fecha ISO a `TIMESTAMP` sin zona; el Inspector lo marca
  `timezone_unverified`.
* **La hora sigue siendo una decisión humana.** Ningún código puede saber en qué zona exportó el sistema de origen.
* **Tiempo:** unos 35 s sobre un CSV de 1 GB y 4,5 M de filas en un solo núcleo (perfil + muestra + dos pasadas
  completas), 0,2 GB de RAM; la ingesta tarda unos 30 s y usa hasta el límite de memoria configurado (2 GB).

## 14. Higiene del repositorio: notebooks sin salidas

Un notebook ejecutado guarda dentro del `.ipynb` todo lo que se imprimió (usuarios, IPs, conteos). `tools/strip_notebook_outputs.py`
es un filtro *clean* de Git, solo con la biblioteca estándar: en `git add` quita `outputs`, `execution_count` y los
metadatos de ejecución; tu copia de trabajo conserva sus salidas. Se activa una vez por clon (`git config` no se versiona):

```bash
git config filter.stripnb.clean "python3 tools/strip_notebook_outputs.py"
git config filter.stripnb.smudge cat
git config filter.stripnb.required true
```

* `required = true`: si el archivo no es un notebook válido, `git add` falla en vez de guardarlo sin limpiar.
* `smudge = cat` es **obligatorio** con `required`: al sacar un notebook del repositorio (`git checkout`, `git archive`) Git
  exige ese lado del filtro y sin él falla con `smudge filter stripnb failed` (`git archive` deja un zip roto). `cat` deja
  pasar el notebook tal cual. Faltaba en la primera versión de estas instrucciones (corregido en P1-b.1).
* Serializa igual que Jupyter (claves ordenadas, sangría de 1, acentos sin escapar): un notebook recién guardado y sin
  salidas queda byte a byte igual, así que guardar no genera ruido en los diffs. Los notebooks del repositorio se
  entregan ya normalizados, con `id` fijo en cada celda.
* **Limitación de Git:** `git status` puede mostrar ` M` en un notebook ejecutado aunque no haya nada nuevo, porque Git
  compara primero el tamaño con el del índice y solo consulta el filtro si el tamaño coincide. Para ver qué cambió de
  verdad usa `git diff`; tras `git add -A`, un notebook sin cambios reales desaparece de `git status`.
* No reescribe commits anteriores: si ya se guardaron salidas, hay que corregir el historial antes del primer `push`.
