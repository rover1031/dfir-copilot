# Falsabilidad como estructura (P1-b.3b)

Un agente puede convencerse de lo que ya sospecha: busca lo que apoya su hipótesis y se da por satisfecho. Pedírselo en el prompt
("busca también evidencia que la refute") no basta. Aquí es una **estructura**: sin criterio de refutación no se propone, y sin un
intento real de refutarla no se pide confirmarla. El analista ve ambas cosas antes de aprobar.

## Las reglas

| Momento | Qué se exige | Quién lo comprueba |
|---|---|---|
| `propose_hypothesis` | `falsifier` (10–500 caracteres): el resultado concreto en los datos que la **refutaría**, fijado **antes** de probarla | el esquema de la herramienta |
| `update_hypothesis(status="confirmada")` | `refutation_checks`: al menos un intento `{ref, would_refute_if, observed}` | el código (abajo) |
| `update_hypothesis(status="refutada")` | solo evidencia, como antes: refutar no necesita demostrar que se intentó refutar | — |

Un intento de refutación **cuenta** si `ref` es una consulta `q-…` que existe en el ledger, terminó con éxito y se ejecutó
**después** de proponer la hipótesis, y si `would_refute_if` y `observed` dicen algo (mín. 10 caracteres). El orden se comprueba por
la posición en el ledger: citar como "prueba" una consulta que ya estaba hecha antes de formular la hipótesis se rechaza.

**Lo que el código no puede comprobar** es si esa consulta buscaba de verdad refutarla. Por eso la vista de aprobación te la enseña
completa y la decisión es tuya:

```python
for req in agent.pending():
    req["hipotesis"]
    req["criterio_de_refutacion"]       # lo que se fijó al proponerla
    req["intentos_de_refutacion"]       # [{"ref", "tipo", "detalle" (el SQL), "habria_refutado_si", "observado"}, …]
```

Si el modelo pide confirmar sin intentos válidos, **el analista no recibe ninguna petición**: el modelo recibe el error con lo que le
falta y puede corregirlo (o decir que no pudo probarla).

## Qué queda en el ledger

* `hypothesis.falsifier`: se escribe al proponer y no se puede cambiar después (el ledger es append-only).
* `hypothesis_update.refutation_checks`: solo en las confirmaciones **aprobadas**; si rechazas, no se guardan como intentos válidos.
* El *briefing* de cada pregunta lleva el `criterio_de_refutacion` de cada hipótesis, para que el agente no lo olvide ni lo mueva.
  Con la copia seudonimizada solo se muestra si la hipótesis se formuló sobre esa misma copia (igual que su texto).

## Hipótesis anteriores

Las formuladas antes de P1-b.3b no tienen criterio: la vista de aprobación lo dice (`sin criterio: formulada antes de existir este
requisito`). Para **confirmarlas** se exigen igualmente los intentos de refutación.

## Cómo medirlo

Todo sale del ledger, sin instrumentación aparte. El notebook `15_falsabilidad.ipynb` (sección final) saca por hipótesis: si tiene
criterio, cuántos intentos de refutación registrados tiene y, en conjunto, cuántas peticiones aprobaste y cuántas rechazaste. La
proporción de **rechazos** tras presentar intentos de refutación es una medida directa de la calidad con la que el agente prueba sus
hipótesis, y sirve para comparar modelos, prompts o versiones del framework sobre el mismo caso.
