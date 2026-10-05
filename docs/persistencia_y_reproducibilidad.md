# Conversación persistente y reproducibilidad (P1-c)

## Conversación en disco

```python
agent = build_agent(engine, ledger, make_llm(), checkpointer=ws.checkpointer())   # sin checkpointer: en memoria, como antes
agent.threads()    # [{"thread_id", "created_at", "continuable", "pending"}, …]
```

Hasta ahora el hilo del agente vivía en memoria: al reiniciar el kernel se perdía, también una aprobación pendiente. Con
`ws.checkpointer()` queda en `data/cases/<caso>/agent/threads.json`, fuera de `raw/`, `processed/` y `ledger/` (no forma parte de lo que
sella el caso; `ws.verify()` no cambia).

* **Qué sobrevive.** La conversación con el modelo (mensajes, resultados de herramientas) y una aprobación pendiente: tras reiniciar,
  `agent.pending()` devuelve la petición y `agent.resolve(...)` continúa donde se quedó. Las hipótesis, las notas, el presupuesto y el
  ledger ya persistían (salen del ledger).
* **Un hilo no se reanuda con otro prompt ni con otra copia.** Cada hilo guarda con qué prompt de sistema y con qué copia de datos se
  creó. Con otro prompt la API rechaza los bloques de razonamiento firmados contra el prefijo anterior (el fallo real que motivó el
  invariante de prefijo); con otra copia los alias no serían los mismos. `ask()` y `resume()` lanzan `ThreadStale` sin enviar ni
  registrar nada; `agent.reset(thread_id)` descarta el hilo (el ledger, las hipótesis y las notas se conservan). Cualquier cambio en
  `SYSTEM_PROMPT` o en el contexto del caso invalida los hilos guardados: es lo esperable al actualizar el framework.
* **Los tokens no se cuentan dos veces tras reiniciar.** Lo ya contabilizado de un hilo con aprobación pendiente se recupera del ledger.
* **JSON, no `pickle`.** Un `pickle` dentro de la carpeta del caso ejecutaría código al cargarse si alguien lo altera. El archivo es JSON
  plano; si está dañado o es de otra versión, `CheckpointFileError` dice cómo seguir (moverlo; el ledger no se toca).
* **Se compacta.** LangGraph conserva todos los puntos intermedios con el estado completo en cada uno: sin compactar, el archivo crecería
  muy rápido y se reescribe entero en cada paso. Al terminar cada pregunta se queda el último punto del hilo, también con una aprobación
  pendiente. La evidencia vive en el ledger; esto es solo la conversación.
* **Sin dependencias nuevas.** Extiende `InMemorySaver` de LangGraph. Si una versión futura cambia su estructura interna, se avisa al abrir
  (`CheckpointFileError`) y los tests de reinicio lo detectan.
* **Privacidad.** Lo guardado es lo que ya vio el modelo (alias con la copia). Con `allow_real=True` incluye valores reales: es local.

## Reproducibilidad de las consultas

Una consulta con `LIMIT` y un `ORDER BY` con empates en el corte (p. ej. `GROUP BY 1 ORDER BY 2 DESC LIMIT 8` con 11 valores empatados
en el octavo puesto) devuelve **otras filas en cada ejecución**. Medido con DuckDB: 8 resultados distintos en 10 ejecuciones; con
`ORDER BY 2 DESC, 1` (orden total), 1. No hay alteración de datos, pero esa consulta no se puede verificar con el replay.

* **Al ejecutarla.** `run_query` ejecuta dos veces las consultas que contienen `LIMIT`; si difieren, la respuesta lleva
  `reproducible: false` y la instrucción de añadir desempates. El control no queda como consulta aparte en el ledger y se puede apagar
  con `ToolLimits(check_reproducible=False)`. Coste: una ejecución más solo en consultas con `LIMIT`.
* **En el prompt.** Regla 6: con `LIMIT`, orden total con desempates.
* **En el replay.** Si una consulta devuelve las mismas filas con otro contenido, se vuelve a ejecutar dos veces: si ELLA MISMA no da
  siempre lo mismo, sale con `nondeterministic=True` y va en `nondeterministic` de la entrada `replay`, aparte de `mismatches`. Una
  consulta estable cuyo resultado no coincide con el registrado sigue siendo un `mismatch`.

Los cuatro estados de una consulta en el replay quedan así: **coincide**, **`skipped`** (falta el motor de su copia),
**`schema_drift`** (un `DESCRIBE` cambió porque cambió la vista) y **`nondeterministic`** (no reproducible por sí misma);
`mismatches` queda reservado a lo que de verdad no coincide.
