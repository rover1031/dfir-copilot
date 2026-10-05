# P1-a: interpretación del perfil con un LLM

Una sola llamada al modelo que recibe el **Data Profile** y devuelve una interpretación estructurada. Sin bucle de agente
ni herramientas: ocurre antes de que exista el caso. El modelo **propone**; el código **dispone**.

## Flujo

```
archivo --(local)--> Inspector --> Data Profile + metadatos de derivadas
                                        |
                          build_user_message  (+ SYSTEM_PROMPT constante)
                                        |
                                 LangChainStructured  --> modelo (json_schema)
                                        |
                          ProfileInterpretation (pydantic)
                                        |
                          review_interpretation  --> SqlSandbox (gemelo vacío)
                                        |
                       aceptado  |  descartado con código y motivo
```

## Qué sale de tu máquina

| Sale | No sale nunca |
|---|---|
| Nombres de campos y de parámetros de URL | Valores de cualquier campo |
| Formas abstractas, estadísticas, rangos | Regex de las derivadas del Inspector |
| De cada derivada: nombre, tipo, rol, parámetro de origen, cobertura, cardinalidad | Ejemplos (aunque estén enmascarados) y texto libre de las decisiones |

`python -m dfir_copilot.interpret.smoke RUTA --dry-run` imprime exactamente ese contenido y termina sin llamar a nadie.

## Dos vocabularios: perfilador y tabla

El perfilador nombra lo que ve **en el archivo** (las claves de `aliases.yaml`: `timestamp`, `uri`, `dst_ip`...). La tabla ingerida
usa el esquema canónico (`schema.py`: `timestamp_utc`, `endpoint`, `query_string`...). Casi todos coinciden; estos no:

| Nombre del perfilador | Columnas de la tabla |
|---|---|
| `timestamp` | `timestamp_utc` (normalizada a UTC) y `timestamp_raw` (texto original) |
| `uri` | `endpoint` y `query_string` |

* `TABLE_COLUMNS` (en `validation.py`) es la única tabla de traducción; el prompt de sistema se genera desde ella.
* El modelo escribe **SQL con nombres de la tabla** (`<columns>`) y **opina del mapeo con nombres del perfilador** (`<canonical_names>`).
* `columns_from_profile` solo expone las columnas que el perfil mapea. El Parquet real trae *todas* las canónicas (`session_id` y
  `bytes_out` van vacías si el log no las aporta); consultarlas devolvería un vacío silencioso, así que fallan en la validación.
* Una columna canónica que el Inspector **deriva** (p. ej. `user_id` desde `authtoken`) cuenta como mapeada.
* Regresión: `tests/fixtures/three_months_profile.json` es el Data Profile real del primer caso (solo metadatos de esquema).

## Contrato de salida (`schemas.py`)

* `classification`: `log_type`, `confidence` (0-1), `evidence_fields` (rutas del perfil), `rationale`.
* `mapping_review`: `confirm | reject | change | add` sobre el mapeo canónico, con motivo.
* `proposed_queries`: `id`, `hypothesis`, `sql`, `expected_if_true`, **`refuted_if` (obligatoria)**, `priority`.
* `analyst_questions`: lo que el esquema no puede responder.

Claves y códigos en inglés (contrato de máquina); los textos para personas, en el idioma pedido.

## Validación (`validation.py`)

| Código | Significado |
|---|---|
| `policy_rejected` | No es un único SELECT, o la política del motor lo bloquea |
| `sql_error` | No compila contra el esquema: columna inexistente, tipo, acceso a archivos |
| `no_logs_reference` | La consulta no lee la vista `logs` |
| `timeout` | Superó el tiempo del sandbox |
| `duplicate_id` / `over_limit` | Identificador repetido / más de 8 consultas o 5 preguntas |
| `unknown_field`, `unknown_canonical`, `not_in_profile_mapping`, `not_mapped_yet`, `already_mapped` | Opinión de mapeo o evidencia que no se sostiene contra el perfil (`canonical` se compara con el vocabulario del perfilador) |

Límite: sobre una tabla vacía no se detectan errores que dependen de los valores. `execute.run_accepted_queries` ejecuta lo
aceptado sobre los datos reales, en local, y `summarize_runs` cuenta cuántas **aceptadas fallaron con datos reales**.

## Decisiones de diseño

* **`json_schema`, no llamada forzada a herramienta**: con `claude-sonnet-5-5` esta última no está soportada. El esquema que
  viaja (`wire_schema()`) conserva la forma sin restricciones de valor; rango, largo y patrón se validan con pydantic.
* **Prompt de sistema constante** (`PROMPT_VERSION`): lo variable (idioma, perfil) va en el mensaje de usuario, así el prefijo es
  idéntico entre llamadas. Cualquier cambio de texto sube `PROMPT_VERSION`.
* **Datos no confiables**: nombres de campo y de parámetros pueden estar controlados por un atacante; el prompt los trata como
  datos, nunca como instrucciones.
* **Sin reintentos ni correcciones silenciosas**: una respuesta inutilizable se informa (`parse_error`, `schema_violation`) con los
  tokens consumidos; los fallos de red o de autenticación se propagan.

## Versión del prompt

`PROMPT_VERSION` identifica el texto de `SYSTEM_PROMPT`. Un test compara la huella del texto con la registrada para esa versión:
si cambias el prompt, el test falla hasta que subas la versión y registres la huella nueva. Así dos resultados con la misma versión
se hicieron siempre con el mismo prompt.

| Versión | Cambio |
|---|---|
| `p1a-1` | Primera llamada real |
| `p1a-2` | Vocabulario de mapeo (`<canonical_names>`) y traducción perfilador→tabla |

## Tokens y espera

* `estimate_tokens` usa 2,1 caracteres por token, medido en una llamada real (12 326 caracteres de sistema, usuario y esquema =
  5 956 tokens de entrada). Es una estimación gruesa; el esquema de respuesta cuenta como entrada.
* La respuesta es larga (5 446 tokens y 53 s en la prueba real): la espera por defecto es la mayor entre `LLM_TIMEOUT_S` y 180 s.

## Métricas para medir la mejora (se guardan en cada resultado)

Tokens de entrada y salida, tiempo, consultas aceptadas vs. descartadas por código, y consultas aceptadas que fallan con datos
reales. Comparar entre versiones de `PROMPT_VERSION` indica si un cambio de prompt mejora o empeora.

## Uso

```bash
python -m dfir_copilot.interpret.smoke /workspace/data/raw/three_months.csv --dry-run          # ver qué se enviaría
python -m dfir_copilot.interpret.smoke /workspace/data/raw/three_months.csv \
    --save /workspace/data/interpretaciones/three_months_p1a.json                              # llamada real
```

Códigos de salida: 0 correcto, 1 falló la llamada, 2 configuración o entrada inválida, 3 respuesta inutilizable.
