# Perfil de datos (etapa `profile`)

Antes de investigar, el análisis automático hace el desglose que haría un ingeniero de datos. Es local, sin modelo, y se calcula con DuckDB
sobre el dataset COMPLETO (no una muestra), después de la copia seudonimizada y antes de los detectores.

| Bloque | Qué calcula |
|---|---|
| Por campo | tipo, % de celdas con valor, valores distintos, los 10 más frecuentes con su conteo; mín, p50, p95 y máx si es numérico. Un campo con un valor distinto por fila se marca como identificador |
| IPs | para cada columna IP: eventos e IPs distintas por alcance (privada, pública, reservada…) |
| Tiempo | eventos por día y por hora (zona local si se declaró; si no, UTC), y los 5 huecos más largos entre eventos consecutivos frente al hueco típico |
| Calidad | filas duplicadas exactas, horas ilegibles, columnas vacías |

* Se calcula sobre la **copia con alias**: se guarda en `p1/perfil_datos.json` del caso, con su SHA-256 en el ledger (`data_profile`).
* La pestaña **Datos** lo muestra en alias; el interruptor «Mostrar valores reales» los traduce solo en pantalla.
* El **triaje del agente parte de un resumen de este perfil** (va en la pregunta del triaje, no en el prompt de sistema, para no invalidar
  conversaciones guardadas). Las cifras del resumen las calculó el código y se marcan como literales para el guardián de privacidad.
* Un caso creado antes de esta etapa muestra en **Datos** el botón «Calcular el perfil»; al reanalizar un proyecto, la etapa se añade sola
  a su estado sin repetir lo ya hecho.

Un hueco largo no es por sí mismo un indicio: puede ser una caída del recolector, un borrado o simplemente la noche. Compáralo con el
patrón por hora antes de concluir nada.
