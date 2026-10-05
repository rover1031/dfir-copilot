# Privacidad hacia el LLM: copia seudonimizada (P1-b.2)

Principio: el modelo recibe **lo suficiente para decidir bien y lo mínimo en privacidad**. El análisis lo hace el código sobre
los datos reales; lo que vea el modelo sale de una **copia seudonimizada** del dataset, creada en local.

## Por qué en el origen y no en las respuestas

El agente consulta la copia, donde los valores sensibles ya son alias. Así:

* cualquier consulta, agregación o `min`/`max` sale en el espacio de alias **por construcción**, sin depender de detectar
  valores sensibles en cada respuesta;
* el SQL del modelo no necesita traducción: `WHERE user_id = 'U-0003'` funciona tal cual en la copia;
* es reproducible y verificable: un Parquet con su hash, como el dataset real, y el `replay` del ledger puede re-ejecutar
  las consultas del agente sobre esa misma copia.

## Qué ve el modelo (política `priv-1`)

| Columna | Tratamiento | El modelo ve |
|---|---|---|
| `src_ip` | `ip` | `IP-0042`, más `src_ip_scope` (public, private, loopback, link_local, shared, reserved, invalid) y `src_ip_net` (`N-0007`: misma /24 o /64, mismo alias) |
| `user_id`, `session_id`, `host`, `referer` | `alias` | `U-0003`, `S-0001`, `H-0001`, `REF-0002` |
| `query_string` | `mask_values` | nombres de parámetro sin valores: `invoice_id=*&authtoken=*` |
| `endpoint` | `mask_ids` | segmentos con aspecto de identificador como `{id}`: `/users/{id}/invoices` |
| `user_agent` | `scrub` | el agente sin IPs, correos ni cadenas tipo token (`{ip}`, `{email}`, `{token}`) |
| `x_*` numéricas (p. ej. `x_invoice_id`) | `shift` | el número menos el mínimo de la columna: diferencias y orden exactos, ningún identificador real |
| `x_*` de texto | `alias` | `SITE_ID-0002` |
| tiempo, método, código de estado, bytes, nº de fila | `keep` | sin cambios |

* Alias **estables** dentro del caso y numerados por orden de primera aparición: el mismo dataset con la misma política da
  siempre los mismos alias.
* Las columnas vacías no se tocan.
* Excepciones por caso: `PrivacyPolicy(overrides={"x_authtoken_type": "keep"})` para un vocabulario técnico que no identifica a
  nadie. Otra política da otro archivo (`.pseudo-<huella>.parquet`), nunca sobrescribe.
* "private" son solo redes internas reales (RFC 1918 y ULA). Documentación, multicast y demás rangos especiales son
  `reserved`: en un log de acceso merecen atención. IPv4 se clasifica en SQL con la misma tabla de rangos que Python
  (`IPV4_RANGES`); un test garantiza que coinciden.

## El diccionario: solo local

`<stem>.aliases-<huella>.parquet`, junto al Parquet del caso: alias -> valor real y el desplazamiento de cada columna `shift`.
**Nunca se envía.** Su hash va en el manifiesto de la copia, y `Pseudonymizer` lo verifica al cargarlo.

```python
engine, ps = ws.pseudonymized()                  # crea la copia la primera vez; luego la reutiliza
engine.query("SELECT user_id, count(*) FROM logs GROUP BY 1")    # alias
ps.reveal("user_id", "U-0003")                   # valor real (solo en local)
ps.reveal_any("U-0003 consulta desde IP-0042")   # revela un texto del modelo (límites de alias respetados)
```

## Coste medido

4,48 M de filas: unos 13 s con 43 000 IPs distintas; 27 s en el peor caso (una IP distinta por fila), con 2 GB de memoria. Se
hace una vez por caso y política.

## El agente sobre la copia (P1-b.2b)

```python
ws = CaseWorkspace.open("IDOR-INVOICES-2020Q4-TZ-SANTIAGO")
engine, ps = ws.pseudonymized(timeout_s=120)   # motor sobre la copia + diccionario local
ledger = ws.ledger()                            # el ledger se abre SIEMPRE con el motor de los datos reales
agent = build_agent(engine, ledger, make_llm())
...
ledger.replay([ws.engine(), engine])            # cada consulta se re-ejecuta sobre la copia en la que corrió
```

**El agente rechaza un motor de datos reales** (`PrivacyError`) salvo `allow_real=True`, pensado para datos sintéticos o no
sensibles. No es solo una advertencia: lo que devuelven las herramientas viaja a un LLM externo.

### Qué se registra y dónde

| Dónde | Qué |
|---|---|
| Cada consulta (`query`) | campo `copy` **dentro** del registro hasheado: `real:<sha12>` o `pseudonymized:<sha12>` (hash del Parquet que se abre) |
| `data_copy` (una vez por copia) | política y tratamientos, hash del Parquet, hash del diccionario (**nunca su contenido**) y hash del Parquet real del que sale |
| `tool_call`, `agent_turn`, `hypothesis` | el mismo `copy` |

El sello va dentro del registro porque copia y real comparten `dataset_sha256` (es el mismo archivo de origen). Sin él, una
consulta como `SELECT count(*) FROM logs` produce el mismo registro en ambas y el ledger daría por hecha la primera (hay un test
que lo demuestra). Las entradas anteriores a P1-b.2b no llevan sello y se tratan como hechas sobre los datos reales.

El ledger **rechaza** `record_queries` de una copia seudonimizada sin registrar (`CopyNotRegistered`, antes de escribir nada) y
`record_copy` de una copia construida desde otro Parquet que el que abrió el caso (`CopyMismatch`). El toolkit y el agente la
registran solos; con motores a mano, `ledger.record_copy(engine)`.

### Replay copia por copia

`ledger.replay(engine)` acepta un motor o una lista. Cada consulta se re-ejecuta en el motor de **su** copia (`U-0003` no existe en
los datos reales). Si falta el motor de alguna copia, esas consultas salen con `skipped=True` y `match=False`: **no verificada no es
lo mismo que alterada**, así que no cuentan en `mismatches` de la entrada `replay` (van en `skipped`, y `by_copy` resume cada copia).
Una copia con otra política (otro alias) o un Parquet reconstruido se rechaza (`CopyMismatch`).

### Decisión: los detectores corren sobre la copia, no sobre los datos reales

La primera idea fue ejecutarlos sobre los datos reales y traducir los hallazgos a alias. Se descartó: un hallazgo arrastra valores en
campos que no son `entity` ni `related`. Medido sobre el dataset sintético, `automation_clients` sobre datos reales devuelve en
`metrics.herramientas` el User-Agent crudo (`wget (ops@acme.com 10.9.8.7)`); sobre la copia sale `wget ({email} {ip})`. Traducir por
columna deja esa fuga, y traducir texto libre es poco fiable (¿ese número es un id o una cifra?). Es el mismo argumento de "por qué
en el origen y no en las respuestas".

El precio: `scrub` y `mask_*` pueden fundir valores distintos en uno. **`detector_parity(real, copia, ps)`** lo mide en local:
cruza los hallazgos de ambos lados por detector + entidad traducida a alias y compara severidad y métricas numéricas. Las
diferencias de texto (p. ej. la lista de User-Agent) se listan **por nombre de métrica, nunca por valor**, de modo que el resultado
solo lleva alias y cifras. Conviene correrla una vez por dataset real antes de fiarse de los hallazgos de la copia.

### Lo que el modelo sabe de la copia

El prompt de sistema lleva un bloque generado del manifiesto (`privacy_context`): alias y su formato, `src_ip_scope`/`src_ip_net`,
qué columnas están desplazadas y qué significa eso (el valor absoluto no es real), qué se oculta en `query_string`, `endpoint` y
`user_agent`, y qué queda sin cambios. Sin él se interpreta mal lo que se ve: `x_invoice_id = 0` no es una factura, y `src_ip LIKE
'10.%'` no devuelve nada porque la columna ya es un alias. El bloque es estático durante un hilo (invariante de prefijo).
`describe_dataset` añade `privacy` con los tratamientos de las columnas que tienen datos.

### Hipótesis anteriores

El *briefing* devuelve al modelo el texto de las hipótesis del caso. Una hipótesis formulada cuando el agente veía datos reales (o
sobre otra política) puede contener valores que la copia oculta, así que su texto **no se muestra**: el modelo ve el id, el estado y
la evidencia, y la marca `[texto no mostrado…]`. Solo se muestra el texto de las formuladas sobre la misma copia (campo `copy`).
Si sigue vigente, se vuelve a formular con alias.

Además, `describe_dataset` ya no envía `timezone.note` (texto libre del analista: quién declaró la zona y cuándo); P1-a ya lo
excluía del perfil y el toolkit lo dejaba pasar.

### Lo que escribes tú: preguntas y notas (P1-b.3a)

Lo que escribes en `ask()` y en la nota de `resolve()` también llega al modelo. Con la copia, pasa antes por el diccionario local
(`Pseudonymizer.alias_text`, la inversa de `reveal_any`) y los valores reales se sustituyen por su alias. El agente abre el
diccionario él solo desde el manifiesto de la copia: no hay un parámetro que se pueda olvidar.

```python
agent.preview("¿Qué otras cuentas usaron 66.6.6.1?").text   # qué recibiría el modelo, sin llamarlo (no gasta API)
r = agent.ask("¿Qué otras cuentas usaron 66.6.6.1?")
r.sent            # lo que se envió, ya en alias: "¿Qué otras cuentas usaron IP-0042?"
r.substitutions   # ({"column": "src_ip", "alias": "IP-0042", "count": 1},) — nunca el valor real
```

* **Qué se traduce.** Los valores reales de las columnas con alias y de IP, y las redes (`/24`, `/64`). Coincidencia exacta,
  distingue mayúsculas, con límites de palabra: `10.1.0.1` no se toca dentro de `10.1.0.10`. Ante un solape gana el valor más largo.
* **Qué se bloquea (`AmbiguousText`).** Un valor que solo tiene dígitos o menos de 4 caracteres puede ser el identificador o una cifra
  corriente, y un número de 6+ dígitos que cae en el rango real de una columna desplazada (un id de factura) no se puede traducir
  a ciegas. No se envía nada ni se registra nada, y el mensaje dice qué escribir (`su alias es U-0042`, `el modelo lo ve como 123`).
  Si es una cifra corriente, confírmalo con `literal=("12345",)`; queda anotado el recuento, no el valor.
* **Notas de aprobación.** Se traducen igual. Si una es ambigua, la excepción salta **antes** de reanudar: la aprobación sigue pendiente y
  puedes reescribir la nota. La nota que queda en el ledger (`hypothesis_update`) es la ya traducida.
* **Ledger.** `agent_turn.question` guarda lo enviado (en alias) y `text_substitutions` / `text_literal` los recuentos. Los valores
  reales no se escriben. Para leerlo tú: `ps.reveal_any(texto)`.
* **Coste.** Una búsqueda por valor del diccionario; con 60 000 valores tarda décimas de segundo. Con millones de valores distintos
  conviene medirlo.

### Qué NO cubre todavía

* **Valores en otra forma.** No distingue mayúsculas de minúsculas, ni detecta un valor partido o escrito con otra puntuación
  (`66.6.6. 1`). El diccionario solo conoce lo que está en el dataset.
* **Números desplazados escritos con otro sentido.** Un número de 6+ dígitos por encima del mínimo real de una columna desplazada se
  trata como posible id y se bloquea hasta que lo confirmes con `literal` o lo escribas como lo ve el modelo.
* **`ledger.note()`** (notas tuyas al ledger) no pasa por el modelo y no se traduce; lo que escribas ahí se queda como lo escribas.
* `CaseWorkspace.verify()` aún no comprueba la copia (hash del Parquet seudonimizado y del diccionario frente a la entrada
  `data_copy`); hoy lo comprueban `QueryEngine` y `Pseudonymizer` al abrirlos.
* Con `resource` inferido como `endpoint` (log sin identificador de recurso), el recurso queda enmascarado a `{id}` y la
  amplitud de recursos pierde resolución. No afecta al caso `x_invoice_id`.
