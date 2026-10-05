# Informe forense (P2)

Un informe por caso (= por archivo analizado), en Markdown, generado **desde el ledger**. Es una decisión del analista: el botón
**Exportar informe** (cabecera del caso y pestaña *Informe*) lo genera, lo guarda y lo registra.

```python
from dfir_copilot.reporting import export_report, build_report
out = export_report(ws, variant="compartible", lang="es", recommendations="…")   # escribe reports/<caso>/informe.es.compartible.md
out.report.sha256                                                                 # hash del contenido; también en el pie y en el ledger
```

## Estructura (la aprobada)

| § | Sección | De dónde sale |
|---|---|---|
| — | Portada: caso, archivo y su hash, analista, idioma, variante, versión, estado de integridad, `head_hash` | `case_opened`, `ws.verify()` |
| 1 | Resumen: hipótesis **confirmadas por el analista**, con el límite que él señaló | hipótesis y tu nota de decisión |
| 2 | Datos y supuestos: filas, rango UTC, zona (declarada, sin verificar), formato de fecha, roles, columnas sin datos, hash del mapping | manifiesto y ledger |
| 3 | Qué vio el modelo: política `priv-1`, tratamiento por columna, copia, modelo, tokens | `data_copy`, `agent_turn` |
| 4 | Hallazgos: 4.1 detectores (código) · 4.2 hipótesis decididas con su criterio de refutación, intentos (con su SQL), evidencia y decisión | ledger |
| 5 | Línea de tiempo calculada por código (semanal, global y de las entidades señaladas), con la reserva de la zona | herramientas de serie temporal |
| 6 | Hipótesis no concluyentes, líneas abiertas y retiradas | estados `propuesta`, `en_prueba`, `retirada` |
| 7 | Limitaciones calculadas por código (zona, columnas sin datos, valores desplazados, "un 200 no prueba contenido", consultas no verificadas) y tus notas | manifiesto, replay, notas |
| 8 | Recomendaciones y próximos pasos: **las redactas tú** al exportar | cuadro del botón |
| A | Cadena de custodia: hashes, comprobaciones de integridad y plantilla de firma | ledger, `verify()` |
| B | Registro de consultas con su estado del replay: coincide · sin motor · deriva de esquema · no determinista · NO coincide | ledger, replay |
| C | Métricas del proceso: preguntas, tokens, cortes por presupuesto, aprobaciones y rechazos, intentos de refutación, consultas, hallazgos, duración, credenciales redactadas | ledger |
| D | Salida del asistente **sin verificar** (etiquetada) | `agent_turn` |
| E | Diccionario de alias (**solo la variante interna**) | diccionario local |

## Principios

* **Lo calcula el código.** El texto libre del modelo solo aparece en el anexo D. Cada afirmación lleva su referencia (`q-`, `f-`, `c-`, `h-`).
  Solo cuentan como confirmadas las hipótesis que aprobó el analista.
* **Determinista.** Con el mismo ledger y las mismas opciones sale el mismo documento. Su SHA-256 va al pie, calculado sobre el contenido; la hora de
  generación va después y no lo altera. Con "verificar con el replay" activado, el replay añade una entrada al ledger (queda registrado), así que
  un informe posterior ya parte de otro ledger.
* **Dos variantes.**
  * `interno`: valores reales, consultas sobre datos reales y anexo E.
  * `compartible`: alias, **sin** diccionario, y solo lo que corrió sobre la copia seudonimizada. Se excluyen las consultas, hipótesis, notas y
    hallazgos de datos reales (casos antiguos) y se dice cuántos. Antes de entregarlo, el generador **comprueba por código** que ningún valor real
    conocido aparece en el documento; si aparece, no se entrega (`ReportLeak`, sin mostrar el valor).
* **Credenciales siempre redactadas** en las dos variantes (`authtoken=…`, `password=…`, `Authorization: Bearer …`, claves de API). El recuento va en el anexo C.
* **Lo que escribes se traduce a alias** también aquí: las recomendaciones pasan por el traductor dentro del generador, no solo en el botón; una
  recomendación ambigua (un número que podría ser un identificador) se rechaza con la pista de qué escribir.
* **Bilingüe.** Un único catálogo de etiquetas con las dos lenguas por clave (un test comprueba que ninguna falta y que llevan los mismos marcadores).

## Qué escribe en el ledger

`report_export`: variante, idioma, SHA-256, nombre del archivo, analista, tus recomendaciones (en alias), recuento de redacciones y resultado de la comprobación de fugas.
El archivo se sobrescribe si repites idioma y variante; el ledger conserva el historial de hashes.

## Límites

* La zona horaria sigue siendo una decisión humana: el informe lo dice (§2 y §7) mientras no esté verificada.
* La comprobación de fugas mira los valores **no ambiguos** del diccionario; un número suelto no se puede distinguir de una cifra corriente.
* Un caso antiguo, con detectores ejecutados sobre datos reales, produce una variante compartible con menos contenido (y lo indica).
* PDF queda para después: el Markdown es la fuente.
