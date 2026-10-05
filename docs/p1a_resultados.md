# P1-a: resultados medidos (línea base)

Llamadas reales de la interpretación del perfil sobre `three_months.csv` (dataset externo, 4 478 619 filas, SHA-256
`128f5d7d…`), modelo `claude-sonnet-5-5`, 2026-10-05. Sirven de línea base: cualquier cambio de prompt o de herramientas se
compara contra esta tabla. Sin nombres de cuentas ni IPs: solo conteos.

| # | Ejecución | Prompt | Columnas visibles | Tokens entrada / salida / total | Tiempo | Aceptadas | Descartes | Aceptadas que fallan con datos reales | Estimación previa de entrada |
|---|---|---|---|---|---|---|---|---|---|
| 1 | script | `p1a-1` | 12 | 5 956 / 5 446 / 11 402 | 53,0 s | 7 | 2 (los dos por un error del validador: vocabulario) | no medido | 2 596 (−56 %, estimador viejo) |
| 2 | notebook 11 | `p1a-2` | 15 | no registrado | 49,7 s | 7 | no registrado | **0 de 7** | estimador viejo |
| 3 | script | `p1a-2` | 15 | 6 281 / 6 780 / 13 061 | 47,1 s | 8 | 1 (`add user_id`) | no medido | 6 259 (−0,4 %) |
| 4 | notebook 11 | `p1a-3` | 16 (+ `timestamp_local`) | 6 684 / 7 207 / 13 891 | 48,8 s | 8 | 1 (`add user_id`) | **0 de 8** | 6 820 (+2 %) |

## Lectura

* **Calidad del SQL:** 0 consultas aceptadas fallaron con datos reales en las 15 medidas. El validador sobre el gemelo vacío no
  dejó pasar nada que rompiera con los datos.
* **Descartes:** los dos de la ejecución 1 eran fallos del validador (dos vocabularios mezclados), corregidos en `p1a-2`. Desde
  entonces queda uno recurrente: el modelo intenta `add user_id` aunque el Inspector ya lo deriva. Es inofensivo (el validador lo
  descarta) y es candidato a una aclaración en el prompt.
* **Zona horaria:** con `p1a-3` el modelo deja de preguntar *qué* zona es, pide *confirmarla* y usa `timestamp_local` advirtiendo
  que depende de una zona declarada sin verificar.
* **Coste:** unos 13 000 a 14 000 tokens y unos 48 s por llamada; la salida pesa más que la entrada.
* **Estimador de tokens:** 2,1 caracteres por token, calibrado con la ejecución 1; error de −0,4 % y +2 % después.

## Lo que no se puede medir con este dataset

* **Recall:** no hay una respuesta conocida del caso. Lo que hay es un hallazgo: en la primera consulta del modelo, 4 tokens
  consultan unas 7 100 a 7 200 facturas distintas con unas 15 500 peticiones, frente a 5 001 facturas con unas 142 000 peticiones
  del resto. Medir recall exige un dataset con la respuesta etiquetada.
* **Detectores de comportamiento temporal:** el tráfico de fondo es uniforme (cada hora laborable tiene exactamente 133 226
  peticiones y cada hora de fin de semana 53 111; todos los tokens usan las mismas 5 721 IPs; cada IP usa 31 tokens). Lo más
  probable es que el dataset sea generado o remuestreado: un detector de horario o de ritmo daría "nada raro" sin que eso pruebe
  que funciona. Hará falta otro dataset para evaluar esa parte.

## Cómo añadir una medición

Una fila por llamada real: prompt (`PROMPT_VERSION`), tokens (`resultado.usage`), tiempo (`resultado.elapsed_ms`), aceptadas y
descartes (`render_interpretation`) y `accepted_but_failed` (`summarize_runs` del notebook 11).
