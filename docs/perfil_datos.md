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

## Versión 2: entidades, relaciones, apariciones y formatos

| Bloque | Qué añade |
|---|---|
| Entidades | valores distintos de cada tipo que traiga el log: IPs (de origen, de destino y en total), usuarios, equipos, procesos (por nombre del ejecutable), puertos, protocolos, acciones, reglas, aplicaciones, rutas, métodos, códigos, user-agents, sesiones, hashes, tipos de evento |
| Relaciones | hasta 6 pares con sus 10 combinaciones más frecuentes: origen→destino, origen→puerto, equipo→proceso, proceso→destino, usuario→IP, regla→acción, origen→ruta, usuario→equipo... |
| Primera y última aparición | para IPs, usuarios, equipos y procesos: las 10 entidades más activas con sus eventos, primera y última vez y días activos |
| Formato de los valores | por campo de texto: qué % parece IPv4, IPv6, correo, URL, hash, ruta, número, alias o texto libre, y su longitud |

**Es genérico**: las listas `ENTITIES` y `RELATIONS` de `data_profile.py` son datos. Cada log usa las que le apliquen según sus columnas;
un tipo de log nuevo solo añade nombres ahí, no código.

## Preguntas rápidas sin modelo

En la pestaña **Datos**, «Pregúntale a los datos» responde al instante y sin gastar tokens preguntas como: ¿cuántas columnas hay?,
¿cuántas IPs distintas?, ¿cuántos usuarios?, top 10 de dst_port, ¿qué campos están vacíos?, ¿rango de fechas?, ¿hay huecos?, ¿quién habla
con quién?, ¿cuándo apareció IP-0001? (también con el valor real: se traduce a su alias antes de buscar). Los rankings y las apariciones
consultan el dataset completo y muestran la consulta usada. Lo que no sabe responder lo dice y sugiere preguntárselo al agente
(`data_questions.py`).

El **agente recibe un resumen del perfil en cada pregunta** (no solo en el triaje): las preguntas de datos que le hagas se resuelven con
menos pasos y menos tokens. Un perfil de la versión 1 se puede recalcular desde la propia pestaña.
