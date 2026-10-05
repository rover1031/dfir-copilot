# Zona horaria: por archivo, declarada y trazable

La zona horaria **no es global**: se declara en el mapping de cada archivo, y cambiarla en un archivo ya investigado es un
**caso nuevo** (un caso sellado no cambia de mapping). Todo se guarda en UTC; la zona solo dice cómo leer la hora del archivo.

## De dónde sale la zona (`timezone_source`)

| Valor | Cuándo | Qué hace el ingestor |
|---|---|---|
| `in_data` | El dato trae la zona: `iso8601` con `timezone_in_data`, `%z`, `epoch_s`/`epoch_ms`, `native` con `TIMESTAMPTZ` | Usa la del dato. Si además se declaró otra, **avisa** de que no se aplica. No hay nada que verificar |
| `declared` | El analista la declara (`timezone: America/Santiago`) | La aplica. Queda sin verificar hasta que se confirme |
| `default` | Nadie la declaró | Asume UTC y avisa en cada ingesta |

Si el mapping no dice `timezone_source`, se deduce. Si lo dice y no cuadra (`in_data` con un formato sin zona, `default` con una
zona distinta de UTC), el mapping se rechaza.

## Claves de `timestamp` en el mapping

```yaml
timestamp:
  format: '%Y-%d-%mT%H:%M'
  timezone: 'America/Santiago'          # nombre IANA exacto
  timezone_source: 'declared'            # in_data | declared | default
  timezone_note: 'Confirmada por <quién> el <fecha> por <medio>'
  timezone_verified: false               # true solo cuando el dueño del export la confirme
  timezone_fixed_offset: true            # solo si el sistema usa de verdad un desfase fijo (ver abajo)
```

Una clave desconocida (p. ej. `timezone_verifed`) **se rechaza**: antes se ignoraba y dejaba la zona sin verificar sin avisar.

## Validación del nombre

Se valida contra `pg_timezone_names()` del propio DuckDB (la misma base que convierte) al **cargar** el mapping, no al ingerir:

* Escritura exacta: `america/santiago` o `America/Santigo` se rechazan con la sugerencia `America/Santiago`.
* `UTC-3`, `-03:00`, `CLT`, `Chile` se rechazan (DuckDB acepta `UTC-3`, pero es un desfase fijo disfrazado).
* `Etc/GMT±N`, `EST`, `MST`, `HST` son **desfases fijos sin cambio de horario** y se rechazan salvo `timezone_fixed_offset: true`.
  Ojo: en `Etc/GMT` el signo va al revés (`Etc/GMT+3` = UTC−03:00), y `EST` no es Nueva York (`America/New_York`).

## Cambios de horario: horas repetidas e inexistentes

DuckDB resuelve estas horas **sin avisar** (verificado en 1.5.6):

| Caso | Ejemplo | Qué hace DuckDB |
|---|---|---|
| Retroceso: la hora ocurre dos veces | Santiago, 2021-04-03 23:30 | La lee como la **segunda** ocurrencia (03:30 UTC) |
| Avance: la hora no existe | Santiago, 2021-09-05 00:30 | La **desplaza** (04:30 UTC) |

El ingestor no cambia ese resultado; lo **hace visible**: cuenta las filas afectadas, las registra en el manifiesto
(`dst_ambiguous_rows`, `dst_nonexistent_rows`), avisa en la ingesta y el agente lo ve en su contexto. Se comprueban saltos de
30 min, 1 h y 2 h (p. ej. `Australia/Lord_Howe` cambia 30 min). Coste: unos 7 s por 4,5 M de filas; con UTC o un desfase fijo no
se ejecuta.

Muchas horas inexistentes son una señal en sí: el log puede estar en otra zona o el reloj del sistema mal configurado.

Colombia, Perú, Ecuador, Panamá y República Dominicana no tienen cambio de horario; Chile, Estados Unidos, Europa o Paraguay sí.

## Dónde queda registrada

| Lugar | Qué guarda |
|---|---|
| Manifiesto (`timezone`) | `assumed`, `verified`, `source`, `note`, `applied`, `dst_nonexistent_rows`, `dst_ambiguous_rows` |
| Ledger (`case_opened`) | `timezone_assumed`, `timezone_verified`, `timezone_source`, `timezone_note` |
| Contexto del agente | Zona, procedencia, si está verificada y, si las hay, las horas afectadas por el cambio de horario |

Los manifiestos anteriores a esta entrega (sin `source` ni `note`) siguen abriendo casos: se registran como `null`.

## Inspector

```python
inspect_source(RUTA, timezone="America/Santiago", timezone_note="Declarada por el analista el 2026-10-05")
```

La zona se valida **antes** de perfilar. Si el dato ya trae su zona, la declarada no se usa y el borrador lo dice
(`timezone_ignored`). Ver `notebooks/12_zona_horaria.ipynb`.

## Hora local del cliente (entrega 5b)

Cuando la zona fue **declarada** y se aplicó, el motor añade a la vista `logs` la columna `timestamp_local` (hora local sin zona,
calculada desde `timestamp_utc`). No hay columna local si la zona viene en el dato (cada valor trae su desfase y no se sabe cuál es
la local del cliente) ni con UTC por defecto (sería UTC disfrazada).

* **No toca el Parquet ni su hash**: es una columna calculada en la vista, así que un caso ya sellado la obtiene sin reingerir.
* `timestamp_utc` sirve para **ordenar** eventos y medir intervalos; `timestamp_local` para **hora del día, días y fines de semana**.
* La línea de tiempo del toolkit corta días, semanas y meses en la **medianoche del cliente** y lo dice en el nombre de la columna:
  `periodo_local`; sin zona declarada sigue siendo `periodo` (UTC).
* El agente recibe en su contexto qué columna usar para cada cosa.

## Lo que ve el modelo (P1-a)

El mensaje lleva un bloque `<timezone>` con el estado (`declared`, `in_data` o `not_declared`), si está verificada y, con zona
declarada, el **rango UTC corregido**: el perfil se calcula antes de declarar la zona y su `min_utc`/`max_utc` asume UTC. Con zona
declarada el modelo no pregunta por ella y debe advertir la suposición si no está verificada. La `timezone_note` **nunca** se envía.

Se declara con `inspect_source(..., timezone=)`, `interpret_profile(..., timestamp=borrador.mapping["timestamp"])` o
`python -m dfir_copilot.interpret.smoke RUTA --tz America/Santiago --tz-note "..."`.

## Límites conocidos

* **Un archivo con horas de varias zonas mezcladas no se detecta.** Con horas sin zona es indistinguible de un archivo correcto; con
  horas que traen desfase, ver dos desfases es lo normal en una zona con cambio de horario.
* **`timezone_source: declared` con un formato que trae su zona se rechaza**: la zona declarada no se aplicaría.
