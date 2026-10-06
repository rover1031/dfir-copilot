> **Ejemplo real generado por DFIR Co-pilot** — variante *compartible* del informe del caso de estudio
> (explotación de un IDOR en `/invoices/search`, dataset externo de tráfico de prueba sin relación con ninguna organización).
> Los valores sensibles van como alias y el diccionario de alias no se incluye; el código comprobó que no lleva ningún valor real.
> La zona horaria (`America/Santiago`) la decidió el analista sin confirmación externa, y así consta en el propio informe.

# Informe forense · IDOR-INVOICES-2020Q4-TZ-SANTIAGO

> **COMPARTIBLE** — Los valores sensibles van seudonimizados (alias) y el diccionario de alias NO se incluye. Se comprobó que ningún valor real conocido aparece en el documento.

## Portada

| Métrica | Valor |
|---|---|
| Caso | IDOR-INVOICES-2020Q4-TZ-SANTIAGO |
| Archivo analizado | three_months.csv |
| SHA-256 del archivo | `128f5d7d57ce8ee30d2d22df2c6f43552963b55c44e3e560f6db8032aca9841a` |
| Analista | eder |
| Idioma | es |
| Variante | COMPARTIBLE |
| Versión del framework | 0.1.0 |
| Integridad de la cadena de custodia | verificada: sin discrepancias |
| Último hash del ledger | `993b6e49d5e01836b2bca9e48ca86a37d15d07c6f03f04c183c478aacfc3e924` |
| Entradas del ledger | 217 |

## 1. Resumen

**Hipótesis confirmadas por el analista**

- `h-aa79d3ab` — U-0032..U-0035 forman un grupo coordinado que enumera x_invoice_id en /invoices/search: solicitan IDs de factura que ningún otro usuario consulta (o con patrón secuencial/barrido), desde 5 IPs exclusivas, con escalada de volumen en el tramo final.
  - Decisión de eder el 2026-10-05T20:16:54+00:00
  - Límite señalado por el analista: Aprobada solo en lo observable en los logs: grupo cerrado de cuatro cuentas con cinco IPs exclusivas, IDs que nadie más consulta y orden no secuencial. NO establece que las facturas sean ajenas (falta el mapa factura-propietario) ni que se devolviera contenido (un 200 no lo prueba).

**Hipótesis por estado:** confirmada: 1, en_prueba: 1, propuesta: 1

Hallazgos de los detectores: 12 (alta: 4, media: 8, baja/info: 0).

## 2. Datos y supuestos

| Métrica | Valor |
|---|---|
| Filas | 4,478,619 |
| Rango temporal (UTC) | 2020-10-01 03:00:00+00 → 2021-01-01 02:59:00+00 |
| Zona horaria de las horas del archivo | `America/Santiago` — declarada, SIN verificar con el dueño del export |
| Formato de fecha del mapping | `%Y-%d-%mT%H:%M` |
| Roles de análisis | actor (quién actúa): `user_id` · recurso (sobre qué actúa): `x_invoice_id` |
| Columnas sin datos en este archivo | `bytes_out`, `session_id` |
| SHA-256 del mapping | `c698cd89c786fae89a2c3c793997ae2a5bc32b95e717a178e62d9587209b6e7e` |
| Avisos de la ingesta | Zona horaria NO verificada: se asumió America/Santiago |

## 3. Qué vio el modelo

Regla: el modelo no ve el archivo completo ni valores reales; consulta una copia seudonimizada a través de herramientas de solo lectura y todo queda en el ledger.

- Política de seudonimización: `priv-1` · Copia que consultó el modelo: `pseudonymized:ecaea2d54886`

| Columna | Tratamiento |
|---|---|
| `bytes_out` | keep |
| `endpoint` | mask_ids |
| `host` | alias |
| `http_method` | keep |
| `query_string` | mask_values |
| `referer` | alias |
| `session_id` | keep |
| `source_row` | keep |
| `src_ip` | ip |
| `status_code` | keep |
| `timestamp_raw` | keep |
| `timestamp_utc` | keep |
| `user_agent` | scrub |
| `user_id` | alias |
| `x_authtoken_type` | alias |
| `x_invoice_id` | shift |
| `x_site_id` | alias |

- Modelo(s) usados: `claude-sonnet-5-5`
- Turnos del agente: 6
- Tokens gastados en el caso: 218,554

## 4. Hallazgos

### 4.1 Hallazgos de los detectores (código)

| Severidad | Detector | Entidad | Resumen | id |
|---|---|---|---|---|
| high | activity_ramp | user_id=U-0034 | U-0034 pasó de 409 peticiones en el primer tercio del periodo a 11176 en el último (27.3x); sus pares cambian 0.64x. | `f-4cce7ad59de0` |
| high | activity_ramp | user_id=U-0033 | U-0033 pasó de 357 peticiones en el primer tercio del periodo a 11342 en el último (31.7x); sus pares cambian 0.64x. | `f-992ca6e32217` |
| high | activity_ramp | user_id=U-0035 | U-0035 pasó de 354 peticiones en el primer tercio del periodo a 11251 en el último (31.7x); sus pares cambian 0.64x. | `f-a7788cbdf5db` |
| high | activity_ramp | user_id=U-0032 | U-0032 pasó de 368 peticiones en el primer tercio del periodo a 11133 en el último (30.2x); sus pares cambian 0.64x. | `f-f4d2e1019af3` |
| medium | resource_breadth | user_id=U-0033 | U-0033 accedió a 7177 x_invoice_id distintos, 1.44x la mediana de sus pares (5001). | `f-2709625a91cb` |
| medium | resource_breadth | user_id=U-0035 | U-0035 accedió a 7200 x_invoice_id distintos, 1.44x la mediana de sus pares (5001). | `f-5165974bf162` |
| medium | automation_clients | user_id=U-0033 | U-0033: el 100% de sus peticiones (15569 de 15569) viene de clientes automatizados: Scrapy/2.3.0 (+https://scrapy.org), crawler4j, wget. | `f-59e1ed336f24` |
| medium | automation_clients | user_id=U-0035 | U-0035: el 100% de sus peticiones (15526 de 15526) viene de clientes automatizados: Scrapy/2.3.0 (+https://scrapy.org), crawler4j, wget. | `f-81f4ed056712` |
| medium | resource_breadth | user_id=U-0034 | U-0034 accedió a 7112 x_invoice_id distintos, 1.42x la mediana de sus pares (5001). | `f-a7ec3c99d683` |
| medium | automation_clients | user_id=U-0034 | U-0034: el 100% de sus peticiones (15468 de 15468) viene de clientes automatizados: Scrapy/2.3.0 (+https://scrapy.org), crawler4j, wget. | `f-b3baf77d91d1` |
| medium | automation_clients | user_id=U-0032 | U-0032: el 100% de sus peticiones (15398 de 15398) viene de clientes automatizados: Scrapy/2.3.0 (+https://scrapy.org), crawler4j, wget. | `f-cb85f3211803` |
| medium | resource_breadth | user_id=U-0032 | U-0032 accedió a 7183 x_invoice_id distintos, 1.44x la mediana de sus pares (5001). | `f-e727c310c32b` |

13 hallazgo(s) calculados sobre datos reales no se incluyen en la versión compartible.

### 4.2 Hipótesis decididas por el analista

#### `h-aa79d3ab` · confirmada

- **Enunciado:** U-0032..U-0035 forman un grupo coordinado que enumera x_invoice_id en /invoices/search: solicitan IDs de factura que ningún otro usuario consulta (o con patrón secuencial/barrido), desde 5 IPs exclusivas, con escalada de volumen en el tramo final.
- **Criterio de refutación (fijado al proponerla):** Se refuta si (a) los IDs de factura de los 4 usuarios están contenidos en el conjunto que consultan los demás usuarios (solapamiento ~100% y sin IDs exclusivos), o (b) los IDs consultados no muestran patrón secuencial/barrido ni diferencia frente a pares, o (c) las 5 IPs también son usadas por otros usuarios, o (d) la proporción de respuestas 2xx no difiere de la de pares.

**Intentos de refutación**

- `q-a446337c9382` — 3 filas

```sql
WITH o AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')),
g AS (SELECT l.*, (o.x_invoice_id IS NULL) AS excl FROM logs l LEFT JOIN o USING (x_invoice_id) WHERE l.user_id IN ('U-0032','U-0033','U-0034','U-0035'))
SELECT excl, count(*) reqs, count(DISTINCT x_invoice_id) ids, min(x_invoice_id) mn, max(x_invoice_id) mx, round(avg((status_code BETWEEN 200 AND 299)::int)*100,1) pct2xx, min(timestamp_local) first_seen, max(timestamp_local) last_seen FROM g GROUP BY 1
UNION ALL SELECT NULL, count(*), count(DISTINCT x_invoice_id), min(x_invoice_id), max(x_invoice_id), NULL, min(timestamp_local), max(timestamp_local) FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')
```
  - La habría refutado si: Los IDs consultados por el grupo estuvieran todos dentro del conjunto que consultan los demás usuarios (0 IDs exclusivos).
  - Observado: 5232 IDs exclusivos del grupo (rango 4001–9340, 21029 peticiones, todas 2xx); los demás usuarios solo tocan 5001 IDs, ninguno en ese rango salvo el 4000.

- `q-ca61f3045b89` — 5 filas

```sql
SELECT src_ip, count(DISTINCT user_id) users, count(*) n, min(timestamp_local) f, max(timestamp_local) l, src_ip_scope FROM logs WHERE user_id IN ('U-0032','U-0033','U-0034','U-0035') GROUP BY src_ip, src_ip_scope ORDER BY 1
```
  - La habría refutado si: Las 5 IPs (IP-1806..IP-1810) fueran usadas también por usuarios ajenos al grupo.
  - Observado: Cada IP solo tiene 4 usuarios (los del grupo), 12.2k–12.5k peticiones cada una, activas durante todo el periodo; scope public. El total de IPs distintas (5726) = 5721 de los demás + 5 del grupo.

- `q-a78686b82081` — 8 filas

```sql
WITH o AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')),
e AS (SELECT l.user_id, l.x_invoice_id, l.timestamp_utc, l.source_row FROM logs l ANTI JOIN o USING (x_invoice_id) WHERE l.user_id IN ('U-0032','U-0033','U-0034','U-0035')),
d AS (SELECT user_id, x_invoice_id, x_invoice_id - lag(x_invoice_id) OVER (PARTITION BY user_id ORDER BY timestamp_utc, source_row) AS diff FROM e)
SELECT diff, count(*) n FROM d GROUP BY 1 ORDER BY 2 DESC LIMIT 8
```
  - La habría refutado si: No hubiera patrón de barrido: diferencias consecutivas aleatorias y sin cobertura sistemática.
  - Observado: Las diferencias entre IDs consecutivos son dispersas (máx. 12 repeticiones por valor): orden NO secuencial. Sin embargo cubre ~98% del rango (5232 de 5340 IDs), es decir, un barrido exhaustivo en orden aleatorio, no una consulta puntual.

- `q-a5cb4b35f9fe` — 2 filas

```sql
SELECT (user_id IN ('U-0032','U-0033','U-0034','U-0035')) grp, count(*) reqs, count(DISTINCT user_id) users, count(DISTINCT src_ip) ips, round(avg((status_code BETWEEN 200 AND 299)::int)*100,1) pct2xx, round(avg((status_code=404)::int)*100,1) pct404, round(avg((status_code IN (401,403))::int)*100,1) pct4013, count(DISTINCT x_invoice_id) inv, count(*) FILTER (WHERE x_invoice_id IS NULL) null_inv FROM logs GROUP BY 1
```
  - La habría refutado si: El grupo mostrara la misma proporción de respuestas 2xx que sus pares (~50%).
  - Observado: 78.8% 2xx frente a 50.0%; distribución de códigos distinta (200/201/400/406/408 frente a 200/201/202/304/400/401).

**Evidencia citada**

- `f-725c25c75086` — consulta sobre datos reales: no incluida en la versión compartible
- `q-6604268f96e3` — 19 filas

```sql
SELECT (x_invoice_id BETWEEN 4001 AND 9340) AS fuera_rango, date_trunc('week', timestamp_local) w, count(*) n, count(*) FILTER (WHERE status_code BETWEEN 200 AND 299) ok FROM logs WHERE user_id IN ('U-0032','U-0033','U-0034','U-0035') GROUP BY 1,2 ORDER BY 2,1
```
- `q-a446337c9382` — 3 filas

```sql
WITH o AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')),
g AS (SELECT l.*, (o.x_invoice_id IS NULL) AS excl FROM logs l LEFT JOIN o USING (x_invoice_id) WHERE l.user_id IN ('U-0032','U-0033','U-0034','U-0035'))
SELECT excl, count(*) reqs, count(DISTINCT x_invoice_id) ids, min(x_invoice_id) mn, max(x_invoice_id) mx, round(avg((status_code BETWEEN 200 AND 299)::int)*100,1) pct2xx, min(timestamp_local) first_seen, max(timestamp_local) last_seen FROM g GROUP BY 1
UNION ALL SELECT NULL, count(*), count(DISTINCT x_invoice_id), min(x_invoice_id), max(x_invoice_id), NULL, min(timestamp_local), max(timestamp_local) FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')
```
- `q-a5cb4b35f9fe` — 2 filas

```sql
SELECT (user_id IN ('U-0032','U-0033','U-0034','U-0035')) grp, count(*) reqs, count(DISTINCT user_id) users, count(DISTINCT src_ip) ips, round(avg((status_code BETWEEN 200 AND 299)::int)*100,1) pct2xx, round(avg((status_code=404)::int)*100,1) pct404, round(avg((status_code IN (401,403))::int)*100,1) pct4013, count(DISTINCT x_invoice_id) inv, count(*) FILTER (WHERE x_invoice_id IS NULL) null_inv FROM logs GROUP BY 1
```
- `q-a78686b82081` — 8 filas

```sql
WITH o AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')),
e AS (SELECT l.user_id, l.x_invoice_id, l.timestamp_utc, l.source_row FROM logs l ANTI JOIN o USING (x_invoice_id) WHERE l.user_id IN ('U-0032','U-0033','U-0034','U-0035')),
d AS (SELECT user_id, x_invoice_id, x_invoice_id - lag(x_invoice_id) OVER (PARTITION BY user_id ORDER BY timestamp_utc, source_row) AS diff FROM e)
SELECT diff, count(*) n FROM d GROUP BY 1 ORDER BY 2 DESC LIMIT 8
```
- `q-ab2cad720327` — 12 filas

```sql
SELECT date_trunc('month', timestamp_local) m, user_id, count(*) n, count(DISTINCT x_invoice_id) ids FROM logs WHERE user_id IN ('U-0032','U-0033','U-0034','U-0035') GROUP BY 1,2 ORDER BY 1,2
```
- `q-ca61f3045b89` — 5 filas

```sql
SELECT src_ip, count(DISTINCT user_id) users, count(*) n, min(timestamp_local) f, max(timestamp_local) l, src_ip_scope FROM logs WHERE user_id IN ('U-0032','U-0033','U-0034','U-0035') GROUP BY src_ip, src_ip_scope ORDER BY 1
```

**Decisión del analista** (approved, eder, 2026-10-05T20:16:54+00:00): Aprobada solo en lo observable en los logs: grupo cerrado de cuatro cuentas con cinco IPs exclusivas, IDs que nadie más consulta y orden no secuencial. NO establece que las facturas sean ajenas (falta el mapa factura-propietario) ni que se devolviera contenido (un 200 no lo prueba).

## 5. Línea de tiempo (calculada por código)

Los cortes de día y semana usan America/Santiago; esa zona no está verificada.

**Peticiones por semana**

| Semana | Peticiones |
|---|---|
| 2020-09-28 | 230,592 |
| 2020-10-05 | 403,536 |
| 2020-10-12 | 403,536 |
| 2020-10-19 | 403,536 |
| 2020-10-26 | 395,832 |
| 2020-11-02 | 349,608 |
| 2020-11-09 | 349,608 |
| 2020-11-16 | 349,608 |
| 2020-11-23 | 349,608 |
| 2020-11-30 | 280,632 |
| 2020-12-07 | 269,136 |
| 2020-12-14 | 269,136 |
| 2020-12-21 | 269,703 |
| 2020-12-28 | 154,548 |

## 6. Hipótesis no concluyentes y líneas abiertas

- `h-7a1d7576` · en_prueba — U-0032..U-0035 son una operación coordinada de scraping/enumeración de x_invoice_id en /invoices/search desde 5 IPs exclusivas, iniciada en el último tercio del periodo.
- `h-cfec051d` · propuesta — U-0032..U-0035 operan como un grupo automatizado coordinado (Scrapy/crawler4j/wget) desde 5 IPs exclusivas, presente desde el inicio del periodo con escalones de volumen el 2020-11-01 y 2020-12-01, y consulta IDs de factura fuera del conjunto que usan los demás usuarios.

## 7. Limitaciones

- La zona horaria de las horas del archivo NO está verificada. Los resultados que dependen de la hora del día, de los fines de semana o de los límites de día pueden desplazarse; los conteos, los conjuntos de identificadores y de IPs no dependen de ella.
- Sin datos en `bytes_out`, `session_id`: no se puede afirmar nada que dependa de ellas (por ejemplo volumen transferido).
- En la copia seudonimizada los valores absolutos de `x_invoice_id` están desplazados: las diferencias y el orden son exactos, el número en sí no es el real.
- Un código de respuesta 200 no prueba que se haya devuelto contenido.
- Las conclusiones del modelo se apoyan en una copia seudonimizada; las hipótesis solo cuentan como confirmadas cuando las aprueba el analista.
- Consultas que no se pudieron verificar con el replay: 5. Ver el anexo B.

**Notas del analista**

|  | Valoración | Resumen |
|---|---|---|
| 2026-10-05 | confirmed | La consulta q-a78686b82081 no es reproducible: ORDER BY 2 DESC LIMIT 8 sin desempate corta un empate de varios valores con 10 repeticiones. Se repitió con orden total (q-84e808e59629), que sí reproduce. Lo que sostiene: ninguna diferencia entre IDs consecutivos domina (máximo 12 repeticiones). |
| 2026-10-05 | confirmed | Orden de fecha verificado con los datos: en timestamp_raw el campo 2 tiene 31 valores (día) y el campo 3 solo 10, 11 y 12 (mes). Formato año-día-mes, el del mapping. Ejemplo: 2020-01-12T00:16 es el 1 de diciembre. |
| 2026-10-05 | inconclusive | Zona horaria sin verificar: el caso conserva America/Santiago. El -5 mencionado es la zona del analista, no hay confirmación de la del export. Lo que dependa de hora del día, fines de semana o límites de día debe decirlo. |


## 8. Recomendaciones y próximos pasos

(El analista no añadió recomendaciones en esta exportación.)

## Anexo A · Cadena de custodia

| Métrica | SHA-256 |
|---|---|
| Archivo de entrada | `128f5d7d57ce8ee30d2d22df2c6f43552963b55c44e3e560f6db8032aca9841a` |
| Parquet normalizado | `fbe826a694217de25de7129fb0426f63e72ede4d7beceae63bff78893026254b` |
| SHA-256 del mapping | `c698cd89c786fae89a2c3c793997ae2a5bc32b95e717a178e62d9587209b6e7e` |
| Último hash del ledger | `993b6e49d5e01836b2bca9e48ca86a37d15d07c6f03f04c183c478aacfc3e924` |
| Copia seudonimizada | `pseudonymized:ecaea2d54886` |
| Diccionario de alias (solo hash) | `389316a3a478306d84088cdd936952a87e63892caee38d9b4fe745bbe396341a` |

**Comprobaciones de integridad**

```
OK Parquet coincide con el manifiesto: correcto
OK Mapping del caso coincide con el manifiesto: correcto
OK Archivo original en raw/ coincide con el manifiesto: correcto
OK Cadena de hashes del ledger: correcto
OK Parquet coincide con lo registrado en el ledger: correcto
OK Mapping coincide con lo registrado en el ledger: correcto
```

Entregado por: ____________________  Fecha: ____________  Firma: ____________

Recibido por: ____________________  Fecha: ____________  Firma: ____________

## Anexo B · Registro de consultas

| Consulta | Copia | filas | Verificación | SQL |
|---|---|---|---|---|
| `q-9e5fbb5de7eb` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count(*) AS filas, min(timestamp_utc) AS desde, max(timestamp_utc) AS hasta, count(DISTINCT "src_ip") AS "src_ip_distintos", count(D…` |
| `q-1af7855f7e5f` | `pseudonymized:ecaea2d548` | 20 | coincide | `DESCRIBE logs` |
| `q-0c8bb8e02507` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("user_agent") AS "user_agent" FROM logs` |
| `q-1c4095d326f0` | `pseudonymized:ecaea2d548` | 4 | coincide | `WITH ua AS (SELECT DISTINCT user_agent FROM logs WHERE user_agent IS NOT NULL), cls AS (SELECT user_agent, CASE WHEN regexp_matches(user_ag…` |
| `q-a7c4c01afe35` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count(DISTINCT "user_id") FROM logs WHERE "user_id" IS NOT NULL` |
| `q-766231ed0969` | `pseudonymized:ecaea2d548` | 20 | coincide | `DESCRIBE logs` |
| `q-c5d92b274c93` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("x_invoice_id") AS "x_invoice_id" FROM logs` |
| `q-a2e4c86cff1e` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH per AS (SELECT "user_id" AS actor, count(DISTINCT "x_invoice_id") AS recursos FROM logs WHERE "user_id" IS NOT NULL AND "x_invoice_id"…` |
| `q-b2b0d5d5129a` | `pseudonymized:ecaea2d548` | 4 | coincide | `SELECT "user_id" AS actor, count(DISTINCT "x_invoice_id") AS recursos, count(*) AS peticiones, count(DISTINCT src_ip) AS ips, count(DISTINC…` |
| `q-50102137f629` | `pseudonymized:ecaea2d548` | 20 | coincide | `DESCRIBE logs` |
| `q-ec5e99d1a23d` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("src_ip") AS "src_ip" FROM logs` |
| `q-e9c681247a77` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH pairs AS (SELECT "user_id" AS actor, src_ip, count(*) AS n FROM logs WHERE "user_id" IS NOT NULL AND src_ip IS NOT NULL GROUP BY 1, 2)…` |
| `q-7fa109092327` | `pseudonymized:ecaea2d548` | 20 | coincide | `WITH pairs AS (SELECT "user_id" AS actor, src_ip, count(*) AS n FROM logs WHERE "user_id" IS NOT NULL AND src_ip IS NOT NULL GROUP BY 1, 2)…` |
| `q-e0b3eda040c2` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("timestamp_utc") AS "timestamp_utc" FROM logs` |
| `q-0ff6a50607c9` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT date_diff('day', min(timestamp_utc), max(timestamp_utc)) FROM logs` |
| `q-a2d702dde1f6` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH bounds AS (SELECT min(timestamp_utc) AS t0, max(timestamp_utc) AS t1 FROM logs), per AS (SELECT "user_id" AS actor, count(*) AS total,…` |
| `q-9da7c9ec81e7` | `pseudonymized:ecaea2d548` | 4 | coincide | `WITH bounds AS (SELECT min(timestamp_utc) AS t0, max(timestamp_utc) AS t1 FROM logs), per AS (SELECT "user_id" AS actor, count(*) AS total,…` |
| `q-5f2e084fd023` | `pseudonymized:ecaea2d548` | 28 | coincide | `SELECT date_trunc('week', timestamp_local) AS wk, CASE WHEN user_id IN ('U-0032','U-0033','U-0034','U-0035') THEN 'grupo' ELSE 'resto' END …` |
| `q-8c4881f632a3` | `pseudonymized:ecaea2d548` | 20 | coincide | `SELECT user_id, status_code, http_method, count(*) n, min(timestamp_utc) mn, max(timestamp_utc) mx, count(DISTINCT src_ip) ips, min(src_ip_…` |
| `q-f555327d511b` | `pseudonymized:ecaea2d548` | 2 | coincide | `WITH g AS (SELECT *, user_id IN ('U-0032','U-0033','U-0034','U-0035') AS grp FROM logs WHERE status_code<300) SELECT grp, count(*) n, count…` |
| `q-7d2baafdd80b` | `pseudonymized:ecaea2d548` | 19 | coincide | `SELECT user_id, user_agent, query_string, referer, x_authtoken_type, count(*) n FROM logs WHERE user_id IN ('U-0032','U-0035','U-0001') GRO…` |
| `q-1cde9458aeb6` | `pseudonymized:ecaea2d548` | 6 | coincide | `WITH s AS (SELECT user_id, x_invoice_id, timestamp_utc, lag(x_invoice_id) OVER (PARTITION BY user_id ORDER BY timestamp_utc, source_row) p …` |
| `q-1616f39be389` | `pseudonymized:ecaea2d548` | 4 | coincide | `WITH rest AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')), gr AS (SELECT user_id, x_…` |
| `q-0e374cf933bc` | `pseudonymized:ecaea2d548` | 12 | coincide | `SELECT date_trunc('day', timestamp_local) d, count(*) n, sum(CASE WHEN status_code<300 THEN 1 ELSE 0 END) ok FROM logs WHERE user_id='U-003…` |
| `q-a511fa1e87e9` | `pseudonymized:ecaea2d548` | 5 | coincide | `SELECT src_ip, src_ip_net, count(*) n, count(DISTINCT user_id) u, min(timestamp_utc) mn, max(timestamp_utc) mx FROM logs WHERE src_ip IN ('…` |
| `q-5e8176afbdaf` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH rest AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')), o AS (SELECT l.user_id, l…` |
| `q-ae02bd53e32d` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT date_trunc('month', timestamp_local) m, sum(CASE WHEN status_code<300 THEN 1 ELSE 0 END) ok, count(*) n FROM logs WHERE user_id IN (…` |
| `q-c85a220143c2` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count(*) AS filas, min(timestamp_utc) AS desde, max(timestamp_utc) AS hasta, count(DISTINCT "src_ip") AS "src_ip_distintos", count(D…` |
| `q-70a9b644aadc` | `pseudonymized:ecaea2d548` | 20 | coincide | `DESCRIBE logs` |
| `q-0aa1efa5e626` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("user_agent") AS "user_agent" FROM logs` |
| `q-0150ca442856` | `pseudonymized:ecaea2d548` | 4 | coincide | `WITH ua AS (SELECT DISTINCT user_agent FROM logs WHERE user_agent IS NOT NULL), cls AS (SELECT user_agent, CASE WHEN regexp_matches(user_ag…` |
| `q-69b1d2fa58fe` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count(DISTINCT "user_id") FROM logs WHERE "user_id" IS NOT NULL` |
| `q-5880155807f6` | `pseudonymized:ecaea2d548` | 20 | coincide | `DESCRIBE logs` |
| `q-0d023bde2325` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("x_invoice_id") AS "x_invoice_id" FROM logs` |
| `q-593bc2975081` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH per AS (SELECT "user_id" AS actor, count(DISTINCT "x_invoice_id") AS recursos FROM logs WHERE "user_id" IS NOT NULL AND "x_invoice_id"…` |
| `q-0b9135a40f93` | `pseudonymized:ecaea2d548` | 4 | coincide | `SELECT "user_id" AS actor, count(DISTINCT "x_invoice_id") AS recursos, count(*) AS peticiones, count(DISTINCT src_ip) AS ips, count(DISTINC…` |
| `q-8dc16e2c9c94` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("src_ip") AS "src_ip" FROM logs` |
| `q-b2bfcb28d21d` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH pairs AS (SELECT "user_id" AS actor, src_ip, count(*) AS n FROM logs WHERE "user_id" IS NOT NULL AND src_ip IS NOT NULL GROUP BY 1, 2)…` |
| `q-73a0a68d46aa` | `pseudonymized:ecaea2d548` | 20 | coincide | `WITH pairs AS (SELECT "user_id" AS actor, src_ip, count(*) AS n FROM logs WHERE "user_id" IS NOT NULL AND src_ip IS NOT NULL GROUP BY 1, 2)…` |
| `q-6b316f84c1a5` | `pseudonymized:ecaea2d548` | 20 | coincide | `DESCRIBE logs` |
| `q-688af029eb5a` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("timestamp_utc") AS "timestamp_utc" FROM logs` |
| `q-2650a4306bf3` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT date_diff('day', min(timestamp_utc), max(timestamp_utc)) FROM logs` |
| `q-c811faa78f42` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH bounds AS (SELECT min(timestamp_utc) AS t0, max(timestamp_utc) AS t1 FROM logs), per AS (SELECT "user_id" AS actor, count(*) AS total,…` |
| `q-63e1d081f816` | `pseudonymized:ecaea2d548` | 4 | coincide | `WITH bounds AS (SELECT min(timestamp_utc) AS t0, max(timestamp_utc) AS t1 FROM logs), per AS (SELECT "user_id" AS actor, count(*) AS total,…` |
| `q-10a124690600` | `pseudonymized:ecaea2d548` | 14 | coincide | `SELECT date_trunc('week', timestamp_local) AS wk, count(*) n, count(DISTINCT user_id) u, min(timestamp_utc) mn, max(timestamp_utc) mx FROM …` |
| `q-98abff227c6f` | `pseudonymized:ecaea2d548` | 20 | coincide | `SELECT user_id, status_code, http_method, count(*) n, count(DISTINCT x_invoice_id) inv, count(DISTINCT src_ip) ips, count(DISTINCT x_site_i…` |
| `q-597ae3a9b16c` | `pseudonymized:ecaea2d548` | 2 | coincide | `SELECT CASE WHEN user_id IN ('U-0032','U-0033','U-0034','U-0035') THEN 'grupo' ELSE 'otros' END g, count(*) n, count(DISTINCT user_id) u, c…` |
| `q-2daed1684a78` | `pseudonymized:ecaea2d548` | 2 | coincide | `WITH o AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')), g AS (SELECT x_invoice_id, c…` |
| `q-06d26918a58f` | `pseudonymized:ecaea2d548` | 9 | coincide | `SELECT user_agent, CASE WHEN user_id IN ('U-0032','U-0033','U-0034','U-0035') THEN 'grupo' ELSE 'otros' END g, count(*) n FROM logs GROUP B…` |
| `q-0e0c15299be7` | `pseudonymized:ecaea2d548` | 7 | coincide | `SELECT user_id, count(*) n, count(DISTINCT date_trunc('day',timestamp_local)) dias, min(timestamp_local) mn, max(timestamp_local) mx, min(h…` |
| `q-2a753f6904a6` | `pseudonymized:ecaea2d548` | 4 | coincide | `WITH t AS (SELECT user_id, timestamp_utc, x_invoice_id, lag(x_invoice_id) OVER (PARTITION BY user_id ORDER BY timestamp_utc, source_row) p …` |
| `q-2470247b1360` | `pseudonymized:ecaea2d548` | 47 | coincide | `SELECT date_trunc('day',timestamp_local) d, count(*) n FROM logs WHERE user_id IN ('U-0032','U-0033','U-0034','U-0035') AND timestamp_local…` |
| `q-554f94317c1e` | `pseudonymized:ecaea2d548` | 5 | coincide | `SELECT src_ip, src_ip_scope, src_ip_net, count(*) n, count(DISTINCT user_id) u, min(timestamp_utc) mn, max(timestamp_utc) mx FROM logs WHER…` |
| `q-3b3cdf786389` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count(*) AS filas, min(timestamp_utc) AS desde, max(timestamp_utc) AS hasta, count(DISTINCT "src_ip") AS "src_ip_distintos", count(D…` |
| `q-cb01fe74a36b` | `pseudonymized:ecaea2d548` | 20 | coincide | `DESCRIBE logs` |
| `q-f6adf1621593` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("user_agent") AS "user_agent" FROM logs` |
| `q-043d643e63e3` | `pseudonymized:ecaea2d548` | 4 | coincide | `WITH ua AS (SELECT DISTINCT user_agent FROM logs WHERE user_agent IS NOT NULL), cls AS (SELECT user_agent, CASE WHEN regexp_matches(user_ag…` |
| `q-7ee482f2f4b2` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count(DISTINCT "user_id") FROM logs WHERE "user_id" IS NOT NULL` |
| `q-96985ebbc5a8` | `pseudonymized:ecaea2d548` | 20 | coincide | `DESCRIBE logs` |
| `q-25fedaedf99a` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("x_invoice_id") AS "x_invoice_id" FROM logs` |
| `q-e6e1c7d9dcef` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH per AS (SELECT "user_id" AS actor, count(DISTINCT "x_invoice_id") AS recursos FROM logs WHERE "user_id" IS NOT NULL AND "x_invoice_id"…` |
| `q-8d395961553d` | `pseudonymized:ecaea2d548` | 4 | coincide | `SELECT "user_id" AS actor, count(DISTINCT "x_invoice_id") AS recursos, count(*) AS peticiones, count(DISTINCT src_ip) AS ips, count(DISTINC…` |
| `q-72ec262d74bd` | `pseudonymized:ecaea2d548` | 20 | coincide | `DESCRIBE logs` |
| `q-c9fae6727cfb` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("src_ip") AS "src_ip" FROM logs` |
| `q-08abcb6bc667` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH pairs AS (SELECT "user_id" AS actor, src_ip, count(*) AS n FROM logs WHERE "user_id" IS NOT NULL AND src_ip IS NOT NULL GROUP BY 1, 2)…` |
| `q-88d59071c907` | `pseudonymized:ecaea2d548` | 20 | coincide | `WITH pairs AS (SELECT "user_id" AS actor, src_ip, count(*) AS n FROM logs WHERE "user_id" IS NOT NULL AND src_ip IS NOT NULL GROUP BY 1, 2)…` |
| `q-689f584aa347` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT count("user_id") AS "user_id", count("timestamp_utc") AS "timestamp_utc" FROM logs` |
| `q-9db0ecbf6dd7` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT date_diff('day', min(timestamp_utc), max(timestamp_utc)) FROM logs` |
| `q-936c728e16a5` | `pseudonymized:ecaea2d548` | 1 | coincide | `WITH bounds AS (SELECT min(timestamp_utc) AS t0, max(timestamp_utc) AS t1 FROM logs), per AS (SELECT "user_id" AS actor, count(*) AS total,…` |
| `q-ac8090fd53a8` | `pseudonymized:ecaea2d548` | 4 | coincide | `WITH bounds AS (SELECT min(timestamp_utc) AS t0, max(timestamp_utc) AS t1 FROM logs), per AS (SELECT "user_id" AS actor, count(*) AS total,…` |
| `q-fbb3a69391bc` | `pseudonymized:ecaea2d548` | 3 | coincide | `WITH g AS (SELECT x_invoice_id, user_id IN ('U-0032','U-0033','U-0034','U-0035') AS grp FROM logs WHERE x_invoice_id IS NOT NULL), s AS (SE…` |
| `q-a5cb4b35f9fe` | `pseudonymized:ecaea2d548` | 2 | coincide | `SELECT (user_id IN ('U-0032','U-0033','U-0034','U-0035')) grp, count(*) reqs, count(DISTINCT user_id) users, count(DISTINCT src_ip) ips, ro…` |
| `q-57284c9b4b89` | `pseudonymized:ecaea2d548` | 11 | coincide | `SELECT status_code, user_id IN ('U-0032','U-0033','U-0034','U-0035') grp, count(*) n FROM logs GROUP BY 1,2 ORDER BY 2,1` |
| `q-a446337c9382` | `pseudonymized:ecaea2d548` | 3 | coincide | `WITH o AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')), g AS (SELECT l.*, (o.x_invoi…` |
| `q-ab2cad720327` | `pseudonymized:ecaea2d548` | 12 | coincide | `SELECT date_trunc('month', timestamp_local) m, user_id, count(*) n, count(DISTINCT x_invoice_id) ids FROM logs WHERE user_id IN ('U-0032','…` |
| `q-ca61f3045b89` | `pseudonymized:ecaea2d548` | 5 | coincide | `SELECT src_ip, count(DISTINCT user_id) users, count(*) n, min(timestamp_local) f, max(timestamp_local) l, src_ip_scope FROM logs WHERE user…` |
| `q-a78686b82081` | `pseudonymized:ecaea2d548` | 8 | no determinista | `WITH o AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')), e AS (SELECT l.user_id, l.x_…` |
| `q-01db21d354e6` | `pseudonymized:ecaea2d548` | 17 | coincide | `SELECT floor(x_invoice_id/1000)*1000 b, user_id IN ('U-0032','U-0033','U-0034','U-0035') grp, count(*) n, count(DISTINCT x_invoice_id) ids …` |
| `q-cee58e78377c` | `pseudonymized:ecaea2d548` | 8 | coincide | `SELECT user_id, count(*) n, count(DISTINCT x_invoice_id) ids, count(DISTINCT src_ip) ips, round(avg((status_code BETWEEN 200 AND 299)::int)…` |
| `q-0ec195ec1dce` | `pseudonymized:ecaea2d548` | 4 | coincide | `WITH e AS (SELECT user_id, x_invoice_id, count(*) c FROM logs WHERE x_invoice_id BETWEEN 4001 AND 9340 AND user_id IN ('U-0032','U-0033','U…` |
| `q-9c82ea40ff5d` | `pseudonymized:ecaea2d548` | 9 | coincide | `SELECT user_id IN ('U-0032','U-0033','U-0034','U-0035') grp, user_agent, count(*) n FROM logs GROUP BY 1,2 ORDER BY 1,3 DESC` |
| `q-6604268f96e3` | `pseudonymized:ecaea2d548` | 19 | coincide | `SELECT (x_invoice_id BETWEEN 4001 AND 9340) AS fuera_rango, date_trunc('week', timestamp_local) w, count(*) n, count(*) FILTER (WHERE statu…` |
| `q-84e808e59629` | `pseudonymized:ecaea2d548` | 8 | coincide | `WITH o AS (SELECT DISTINCT x_invoice_id FROM logs WHERE user_id NOT IN ('U-0032','U-0033','U-0034','U-0035')), e AS (SELECT l.user_id, l.x_…` |
| `q-f9c94e8571a4` | `pseudonymized:ecaea2d548` | 3 | coincide | `SELECT user_id, COUNT(*) AS n, COUNT(*) OVER () AS cuentas_filas FROM logs GROUP BY user_id ORDER BY n DESC, user_id LIMIT 3` |
| `q-099a2c68e3ee` | `pseudonymized:ecaea2d548` | 1 | coincide | `SELECT COUNT(DISTINCT user_id) AS cuentas, COUNT(*) AS filas, SUM(CASE WHEN user_id IS NULL THEN 1 ELSE 0 END) AS sin_usuario FROM logs` |

17 consulta(s) sobre datos reales no se incluyen en la versión compartible.

## Anexo C · Métricas del proceso

| Métrica | Valor |
|---|---|
| Preguntas al agente | 5 |
| Tokens gastados en el caso | 218,554 |
| Respuestas cortadas por presupuesto | 0 |
| Aprobaciones del analista | 1 |
| Rechazos del analista | 0 |
| Consultas registradas | 102 |
| Hallazgos de detectores | 25 |
| Duración registrada (primer a último evento) | 5:56:26 |
| Credenciales redactadas en el documento | 0 |

**Intentos de refutación por hipótesis confirmada**

| id | Valor |
|---|---|
| `h-aa79d3ab` | 4 |

## Anexo D · Salida del asistente (sin verificar)

_Texto generado por el modelo. No es evidencia: los hechos están en las consultas citadas._

### 2026-10-05T19:26:18+00:00 · `claude-sonnet-5-5` · 78059 tokens

> ¿Hay actividad anómala sobre /invoices/search? Investiga el dataset, formula hipótesis y pruébalas.

> ## Resumen
> Sí, hay actividad anómala en `/invoices/search`. Cuatro usuarios (U-0032, U-0033, U-0034 y U-0035) forman un grupo automatizado y coordinado. La hipótesis h-7a1d7576 se sostiene en lo esencial, pero tiene dos fallos: el grupo no empezó en el último tercio y no hay un barrido secuencial de IDs. Registré h-cfec051d como versión corregida.
> 
> ## Hallazgos con evidencia
> - **Automatización:** el 100 % de las peticiones de los cuatro usuarios viene de Scrapy/2.3.0, crawler4j y wget (f-cb85f3211803, f-dc… ver f-59e1ed336f24, f-b3baf77d91d1, f-81f4ed056712). Los otros 31 usuarios usan navegadores, salvo 5074 filas con PostmanRuntime (q-06d26918a58f).
> - **Grupo cerrado:** los cuatro operan solo desde IP-1806 a IP-1810, que son públicas y están en /24 distintas. Ninguna otra identidad usa esas IPs: cada IP tiene exactamente 4 usuarios (q-554f94317c1e). Son 61 961 peticiones, unas 12 392 por IP frente a unas 25 típicas (f-725c25c75086).
> - **Amplitud de IDs:** cada uno accede a unos 7100–7200 `x_invoice_id` distintos, frente a 5001 de los pares (f-5165974bf162 y los otros tres hallazgos de resource_breadth). Juntos tocan 10 181 IDs. 5232 de ellos no los consulta ningún otro usuario, con 21 029 peticiones (q-2daed1684a78, q-597ae3a9b16c).
> - **Escalada por pasos, no inicio tardío (refuta parte de h-7a1d7576):**
>   - El grupo está activo desde el 2020-10-01 (q-10a124690600, q-0e0c15299be7).
>   - Hace 48 peticiones al día en octubre, 504 al día en noviembre y 1463 al día en diciembre (q-2470247b1360).
>   - Los escalones caen justo el 1 de noviembre y el 1 de diciembre. Esa regularidad parece programada.
>   - El detector de rampa (f-a7788cbdf5db y los otros tres) mide el efecto, pero oculta que empezó antes.
> - **No parece un barrido secuencial:** el salto mediano entre IDs consecutivos por usuario es de unos 3900. Solo 28–42 de unas 15 500 peticiones por usuario avanzan 1–10 unidades (q-2a753f6904a6). Los IDs vienen desplazados, pero el orden y las diferencias son exactos. Esto parece muestreo disperso o por lista, no un IDOR incremental clásico.
> - **Respuestas:** los cuatro usuarios reciben 200 (~72 %), 400, 406, 408 y 201, todas con GET (q-98abff227c6f). Su tasa de error es del 21 %, frente al 33 % del resto (q-597ae3a9b16c).
> - **Horario:** actúan las 24 horas, todos los días, incluidos fines de semana (q-0e0c15299be7).
> 
> ## Hipótesis y estado
> - **h-7a1d7576 (en prueba):** la parte "grupo coordinado, IPs exclusivas, automatización" está respaldada. "Iniciada en el último tercio" no: ya existía en octubre. "Enumeración de x_invoice_id" es solo parcial.
> - **h-cfec051d (propuesta):** versión corregida. No la he marcado en prueba ni pedido su cierre. Pendiente de que decidas.
> 
> ## Límites
> - La zona horaria está declarada pero no verificada.
> - `bytes_out` y `session_id` no tienen datos. Un 200 o 201 no prueba que se devolviera contenido, así que no puedo afirmar que hubo exfiltración.
> - Los IDs de factura están desplazados, por lo que no puedo decir qué facturas son reales ni cuáles son legítimas.
> - Que 5232 IDs sean "exclusivos" solo indica que ningún otro usuario los consultó. No prueba que no existan.
> - Los alias de IP no permiten atribución.
> - Los 31 usuarios restantes muestran un patrón muy uniforme, con mediana de 5001 IDs y MAD 0. Parece tráfico sintético o de línea base, y eso reduce la fiabilidad de la comparación.
> 
> ## Próximas líneas
> 1. Analizar los 5232 IDs exclusivos del grupo: cuándo se consultaron, con qué status y si aparecen en otros endpoints o sistemas. Comprobar también si los cuatro usuarios reparten el espacio de IDs entre sí (solapamiento entre ellos).
> 2. Revelar en local IP-1806 a IP-1810 y las /24 N-0273 a N-0277 (propietario, ASN, hosting). Revisar con el equipo de cuentas cómo se crearon U-0032 a U-0035 y qué tokens usan.
> 3. Revisar quién usa PostmanRuntime (5074 filas) y comparar la distribución de status 406/408/400 entre el grupo y los pares.

### 2026-10-05T20:17:12+00:00 · `claude-sonnet-5-5` · 119662 tokens

> —

> ## Resumen
> Sí hay un grupo coordinado, y el analista aprobó **h-aa79d3ab** en lo que los logs permiten observar. Son U-0032, U-0033, U-0034 y U-0035, que usan solo IP-1806 a IP-1810. Desde el 2020-12-01 barren IDs de factura que ningún otro usuario consulta. Los logs no prueban que esas facturas sean ajenas ni que se devolviera contenido. Un 200 no demuestra lo segundo.
> 
> ## Hallazgos
> - **Grupo cerrado.** Las 5 IPs son públicas y solo las usan estos 4 usuarios, con unas 12.2k–12.5k peticiones cada una durante todo el periodo (q-ca61f3045b89, f-725c25c75086). Las 5726 IPs distintas del dataset son las 5721 de los demás usuarios más estas 5 (q-a5cb4b35f9fe, q-ca61f3045b89).
> - **IDs que nadie más consulta.**
>   - El grupo consultó 5232 `x_invoice_id` exclusivos, en el rango 4001–9340, con 21029 peticiones, todas 2xx. La primera es del 2020-12-01 (q-a446337c9382).
>   - Los otros 31 usuarios tocan solo 5001 IDs, y casi todos están por debajo de 4000 (q-01db21d354e6).
>   - Esos IDs exclusivos cubren cerca del 98% del rango (5232 de 5340), así que es un barrido exhaustivo.
>   - Los 4 usuarios se solapan mucho: 831 de los IDs exclusivos los consultan los 4 y otros 1945 los consultan 3 (q-0ec195ec1dce).
> - **El orden no es secuencial.** Las diferencias entre IDs consecutivos son dispersas (q-a78686b82081). Es un barrido aleatorio, no incremental.
> - **Automatización.** El 100% del tráfico del grupo es Scrapy, crawler4j o wget (q-9c82ea40ff5d, f-cb85f3211803, f-992ca6e32217, f-b3baf77d91d1, f-81f4ed056712). Los demás usan navegadores, más 5074 peticiones de PostmanRuntime.
> - **Perfil de respuestas distinto.** El grupo tiene 78.8% de 2xx frente a 50.0% de los demás. Solo el grupo recibe 406 y 408 (q-a5cb4b35f9fe, q-57284c9b4b89).
> - **Escalones de actividad** (q-ab2cad720327, q-6604268f96e3):
>   - Octubre: unas 350–400 peticiones por usuario, constantes, sin ninguna respuesta 2xx.
>   - Noviembre: unas 3.8k por usuario, con 2xx esporádicos.
>   - Diciembre: unas 11.3k por usuario, con el barrido fuera de rango y 100% 2xx.
> 
> ## Hipótesis y estado
> - **h-aa79d3ab: confirmada.** Intenté refutarla por cuatro vías y ninguna prosperó:
>   - **Solapamiento de IDs.** Hay 5232 IDs exclusivos del grupo, así que no están contenidos en los de los demás (q-a446337c9382).
>   - **IPs compartidas.** Ningún otro usuario usa las 5 IPs (q-ca61f3045b89).
>   - **Orden secuencial.** No se cumple. Se sostiene como barrido por la cobertura casi total del rango (q-a78686b82081).
>   - **Tasa de 2xx.** Es claramente distinta de la de los pares (q-a5cb4b35f9fe).
> - **h-7a1d7576: matizar.** El grupo no empezó en el último tercio. Está activo desde 2020-10-01 y lo que escala después es el volumen (q-ab2cad720327). Esto encaja mejor con **h-cfec051d**, que puede cerrarse con estos mismos datos. Ninguna de las dos está actualizada.
> 
> ## Límites
> - **Propiedad de las facturas.** No existe mapa factura→propietario. "Ajenas" se infiere de que nadie más consulta esos IDs, no se prueba.
> - **Contenido devuelto.** Los 2xx no prueban que se entregara contenido. `bytes_out` está vacía.
> - **IDs desplazados.** `x_invoice_id` está desplazado: el orden y las diferencias son exactos, pero el valor absoluto no es el real. Hay un bloque de IDs cerca de 111111000 en todos los usuarios que no he investigado.
> - **Zona horaria.** America/Santiago es declarada y no está verificada. Los escalones del 1 de noviembre y del 1 de diciembre son por fecha local.
> - **Misma actividad en los demás usuarios.** Los 31 usuarios restantes tienen volúmenes y 5001 IDs casi idénticos, y todos aparecen en las mismas 5721 IPs. Parece un artefacto o una naturaleza sintética del dato, y no lo he explicado.
> - **Resource breadth.** El detector `resource_breadth` marca solo 1.44x la mediana (f-5165974bf162), una señal débil por sí sola. La señal fuerte es el rango exclusivo.
> 
> ## Próximas líneas
> 1. Cruzar los IDs 4001–9340 con el sistema de origen: si existen, a quién pertenecen y si las respuestas 200 llevaron cuerpo. Esto es lo que decide si son facturas ajenas.
> 2. Investigar el origen de las 4 cuentas y de las 5 IPs: cuándo se crearon, si se comparten credenciales y por qué en octubre solo producían errores (¿pruebas del atacante antes de acertar el acceso?).
> 3. Revisar el tramo de IDs cerca de 111111000, donde el grupo y los demás tocan 1000 IDs. Hay que ver si el grupo hace ahí algo distinto, y qué significan los 406/408 y los 52 IDs que solo usan los demás.

### 2026-10-05T21:00:56+00:00 · `claude-sonnet-5-5` · 12624 tokens

> ¿Cuántas cuentas distintas hay y cuáles son las tres con más peticiones? Responde en pocas líneas.

> **Resumen:** hay 35 cuentas distintas (`user_id`) en 4.478.619 filas, y ninguna fila tiene `user_id` nulo (q-099a2c68e3ee).
> 
> **Las tres con más peticiones** (q-f9c94e8571a4):
> 1. U-0018: 144.425
> 2. U-0009: 144.263
> 3. U-0031: 144.010
> 
> **Límites:** la diferencia entre ellas es mínima, de unas 400 peticiones. Por eso el volumen no las distingue del resto. Esta consulta no dice nada sobre la actividad de U-0032 a U-0035 de las hipótesis del caso. Los alias son seudónimos, no los valores reales.

### 2026-10-05T21:00:58+00:00 · `claude-sonnet-5-5` · 8209 tokens

> De lo que acabas de ver, ¿cuál era la segunda cuenta con más peticiones y cuántas tenía? Responde en una línea.

> La segunda cuenta con más peticiones era U-0009, con 144.263 (q-f9c94e8571a4).

---
SHA-256 del contenido: `c01ef8b7f118f064b3d735c7daa16ab26cd5eb9559dfa61385955302125093cc`  
Generado el: 2026-10-05T22:24:23+00:00 · Generado por DFIR Co-pilot
