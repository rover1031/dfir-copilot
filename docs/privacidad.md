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

## Pendiente (P1-b.2b)

Conectar la copia al toolkit y al agente, seudonimizar los hallazgos de los detectores (que corren sobre los datos reales) antes
de mostrarlos al modelo, registrar en el ledger sobre qué copia corrió cada consulta y que el `replay` la use.
