# Logs de firewall (P3, primera pieza)

Un log de firewall se ingiere con el **esquema de red**, que NO sustituye al de accesos web: lo amplía. Los logs web quedan exactamente como
estaban (mismas columnas, mismos hashes); las columnas de red solo aparecen cuando el mapping declara `schema: network`.

## Qué necesita un archivo para ingerirse como firewall

Fecha, IP de origen e IP de destino. El resto es opcional y se aprovecha si está:

| Columna canónica | Qué es | Ejemplos de nombres que reconoce (sin tocar código) |
|---|---|---|
| `timestamp` | hora del evento | `timestamp`, `@timestamp`, `Receive Time`, `fecha_hora` |
| `src_ip` / `dst_ip` | origen y destino | `ip_origen`/`ip_destino`, `Source address`/`Destination address`, `srcip`/`dstip`, `source.ip`/`destination.ip` |
| `src_port` / `dst_port` | puertos | `src_port`, `Source Port`, `srcport`, `source.port`, `puerto_destino` |
| `protocol` | protocolo | `protocolo`, `IP Protocol`, `proto`, `network.transport` |
| `action` | qué hizo el firewall | `accion`, `Action`, `event.action` (valores `ALLOW`, `deny`, `drop`, `reset-both`...) |
| `rule_name` | regla o política | `rule_id`, `Rule`, `policyid`, `rule.name`, `regla` |
| `application` | aplicación identificada | `Application`, `app`, `aplicacion` |
| `user_id` | usuario, si lo hay | `user_origen`, `Source User`, `srcuser`, `user.name` |
| `host` | firewall que generó el log | `device_name`, `devname`, `observer.name` |
| `bytes_out` / `bytes_in` | bytes enviados y recibidos por el origen | `bytes_sent`/`bytes_received`, `sentbyte`/`rcvdbyte`, `source.bytes`/`destination.bytes` |

Soporta CSV, TSV, JSON, NDJSON y Parquet (también comprimidos) y JSON anidado. **Para añadir otro fabricante basta con ampliar
`src/dfir_copilot/profiling/aliases.yaml`**; no hay código que tocar.

Roles para los detectores: actor = `src_ip`, recurso = `dst_ip`.

## Detectores de red

Corren solo sobre logs de red. Dan lo mismo sobre los datos reales y sobre la copia seudonimizada (lo comprueba `detector_parity`, y `tests/test_firewall.py` lo exige).

| Detector | Qué busca | Límite honesto |
|---|---|---|
| `service_fanout` | origen que contacta muchos más destinos y puertos que sus pares | compara contra los pares: con pocos orígenes (< 5) no aplica |
| `policy_contradiction` | regla cuyo nombre indica bloqueo (`block`, `deny`, `drop`, `bloq`...) con acción de permitir | se basa en el NOMBRE de la regla: es un indicio, no una prueba |
| `risky_outbound` | conexiones PERMITIDAS de la red interna a Internet por SSH, RDP, SMB, SQL y similares | un administrador legítimo también lo haría: se valora con el contexto |
| `volume_outlier` | origen que envía a Internet un volumen muy superior al de sus pares (≥ 8 veces la mediana y ≥ 1 MB) | un backup a la nube también lo parece |
| `beaconing` | conexiones con intervalo muy regular (variación ≤ 15 %, ≥ 12 eventos) a un destino externo | un monitor o un cliente de sincronización también es periódico |
| `blocked_then_allowed` | bloqueo seguido de permiso en < 15 min al mismo destino y puerto, ≥ 3 veces | un reintento legítimo tras abrir una regla se ve igual |

Los umbrales son parámetros del detector, no constantes escondidas: `run_detectors(engine, params={"beaconing": {"max_cv": 0.1}})`.

## Probar sin datos reales: el simulador

```python
from dfir_copilot.synthetic_firewall import make_firewall_dataset, write_firewall, STYLES

rows, truth = make_firewall_dataset(seed=11, days=92, hosts=40)       # ~22 000 filas en tres meses
for style in STYLES:                                                   # generic_es, generic_en, paloalto, ecs_json
    write_firewall(rows, f"/workspace/data/inbox/prueba-fw/fw_{style}.{'ndjson' if style == 'ecs_json' else 'csv'}", style)
print(truth)                                                           # qué anomalía está en qué host
```

Planta seis anomalías (barrido de puertos, regla de bloqueo que permite, administración hacia Internet, exfiltración, baliza a 600 s y bloqueo
seguido de permiso) y `tests/test_firewall.py` comprueba que cada detector encuentra exactamente la suya y que los cuatro formatos dan los
mismos hallazgos.

## Límites conocidos

* **Un fabricante que parte la hora en dos columnas** (p. ej. FortiGate con `date` y `time` separadas) o que escribe `clave=valor` en una línea
  de syslog todavía no se ingiere: el mapping admite una sola columna de fecha y no hay lector de `clave=valor`.
* **IPv6**: la copia seudonimizada clasifica su alcance, pero con los datos reales los detectores solo clasifican IPv4. Con tráfico IPv6 la
  verificación de equivalencia lo mostrará como diferencia en vez de ocultarla.
* **Zona horaria**: igual que en logs web, si el dato no la trae queda "sin verificar" hasta que el dueño del export la confirme.
* **Nombres de regla**: se conservan en la copia (vocabulario técnico). Si los tuyos delatan algo, se pasan a alias con
  `PrivacyPolicy(overrides={"rule_name": "alias"})`.
* Sin GeoIP ni inteligencia de amenazas: que un destino sea "conocido" por Tor o por escáneres hay que contrastarlo fuera.
