# Presupuesto de tokens, notas del analista y retirar hipótesis (P1-b.3c)

## Tope de tokens

```python
agent = build_agent(engine, ledger, llm)                                  # 210 000 tokens por pregunta
agent = build_agent(engine, ledger, llm, max_tokens=150_000, max_tokens_case=1_000_000)
agent.budget()    # {"per_question": …, "case_limit": …, "case_used": …, "case_left": …}
```

* **Qué cuenta.** Los tokens totales de **todas** las llamadas al modelo de una pregunta (entrada y salida de cada paso), no solo la
  respuesta: en cada paso el contexto se vuelve a enviar, así que el gasto crece más rápido que el número de pasos. Una pregunta con
  aprobación incluye su reanudación. En las investigaciones reales de este caso salieron 78 059 y 95 370.
* **Cómo corta.** Al llegar al **85 %** del tope (178 500 con el valor por defecto) la siguiente llamada lleva el aviso "presupuesto
  de tokens casi agotado, no uses más herramientas" y sus llamadas a herramientas se descartan: el modelo responde con lo reunido e
  indica qué quedó sin comprobar. No se corta al 100 % porque esa respuesta final es otra llamada y también cuesta. El prompt de
  sistema y las herramientas no cambian (invariante de prefijo).
* **Quién cortó.** `r.cut_by` es `"tokens"`, `"steps"` (el límite de pasos de siempre) o `None`; también queda en `agent_turn.cut_by`.
* **Tope por caso (opcional).** `max_tokens_case` se calcula desde el ledger, así que sobrevive a reiniciar el kernel y a crear otro
  agente sobre el mismo caso. Al alcanzarlo, `ask()` lanza `TokenBudgetExceeded` **antes** de enviar nada ni escribir nada.
* **Sin doble cuenta.** Cada `agent_turn` registra `tokens_delta` (lo nuevo de ese turno): una pregunta con aprobación son dos
  turnos pero un solo gasto. Los turnos anteriores a P1-b.3c no lo tienen y cuentan por su valor si terminaron (`done`).

## Notas del analista visibles en cada pregunta

```python
agent.preview("El grupo U-0032 …")                         # qué se escribiría, sin escribir nada
agent.note("Aprobada solo en lo observable en los logs …", refs=["h-aa79d3ab"], status="confirmed")
```

* La nota pasa por el traductor a alias (como las preguntas), queda en el ledger con el **sello de la copia** y el modelo la ve al
  inicio de cada pregunta, junto con el estado de las hipótesis, como contexto que tú fijaste: ni evidencia ni instrucciones.
* Se muestran las últimas **10**. `status` es tu valoración (`None`, `confirmed`, `refuted`, `inconclusive`).
* Una nota escrita con `ledger.note()` directo no se muestra al modelo (puede llevar valores reales): el briefing solo indica
  cuántas hay (`notas_no_mostradas`). Con una nota ambigua, `AmbiguousText` y no se escribe nada.

## Retirar hipótesis

```python
agent.retire("h-7a1d7576", "Reemplazada por una versión con criterio de refutación", superseded_by="h-aa79d3ab")
```

Una hipótesis duplicada o reemplazada pasa a `retirada`: no admite pruebas ni peticiones y en el briefing el modelo solo ve su id y
quién la reemplaza. No es una decisión sobre la evidencia, así que una hipótesis ya `confirmada` o `refutada` no se retira. Queda en
el ledger con quién, por qué (traducido a alias) y qué la reemplaza.

## Replay y deriva de esquema

Una consulta `DESCRIBE` que ya no coincide sale con `schema_drift=True`: lo que cambió es el esquema de la **vista** del motor (por
ejemplo, `timestamp_local` aparece al declarar la zona horaria), no los datos. Va en `schema_drift` de la entrada `replay`, aparte de
`mismatches`, que sigue reservado a resultados de datos que no coinciden. `match` queda en `False`: no es idéntica, pero tampoco está
alterada. Conviene dejar una nota en el ledger que lo explique.

## Prompt

Dos reglas nuevas: una hipótesis es **una** afirmación (si hay un "o" entre afirmaciones que podrían ser ciertas por separado, se
dividen), y los alias se **enumeran** en vez de abreviarse con rangos como `U-0032 a U-0035`, porque al revelarlos se leen como un
rango de valores reales y no lo son.
