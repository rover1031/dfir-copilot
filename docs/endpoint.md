# Logs de endpoint (EDR) · entrega D1

Un log de endpoint se ingiere con el **esquema de endpoint**: equipo (`host`), usuario, tipo de evento, proceso, proceso padre, línea de
comandos, PID, ruta y hash; y, en los eventos de conexión de red, también las columnas de red (`src_ip` = IP local del equipo, `dst_ip`,
puertos, protocolo). Como el de red, amplía el esquema base sin tocar los logs web ni de firewall.

## Formatos

| Formato | Qué se espera |
|---|---|
| **CrowdStrike Falcon** | la tabla que exportas de Event Search / NG-SIEM (CSV o JSON) con `timestamp` (ms epoch), `ComputerName`, `UserName`, `event_simpleName`, `ImageFileName`, `CommandLine`, `ParentBaseFileName`, `SHA256HashData`, `LocalAddressIP4`, `LocalPort`, `RemoteAddressIP4`, `RemotePort`. Para tener proceso y conexión en la misma fila, la consulta une `ProcessRollup2` con `NetworkConnectIP4` (`ContextProcessId` = `TargetProcessId`), como en los ejemplos de la documentación de CrowdStrike |
| **Sysmon** (vía Winlogbeat, NDJSON con nombres ECS) | eventos 1 (proceso) y 3 (conexión): `process.executable`, `process.command_line`, `process.parent.executable`, `process.hash.sha256`, `source.ip`, `destination.ip`... |

Otros EDR con nombres parecidos se reconocen ampliando `profiling/aliases.yaml`.

## Privacidad: qué ve el modelo

| Columna | En la copia | Qué se conserva |
|---|---|---|
| Proceso, padre, ruta de archivo | alias (`PROC-0001`): la ruta puede llevar `C:\Users\<usuario>\` | `<col>_base`: solo el nombre del ejecutable (`rundll32.exe`) |
| Línea de comandos | alias (`CMD-0001`): puede llevar usuarios, equipos o secretos | `command_line_flags`: señales calculadas por código (`encoded`, `download`, `hidden`, `bypass`, `script_proxy`) |
| Hash, PID, tipo de evento | igual | vocabulario técnico |

Las mismas expresiones (`endpoint_sql.py`) se usan para crear esas columnas y en los detectores sobre los datos reales: ambas copias dan
los mismos hallazgos. Con el interruptor «Mostrar valores reales», la interfaz te enseña la ruta y la línea completas, solo en pantalla.

## Detectores

| Detector | Qué busca |
|---|---|
| `lolbin_network` | binarios del sistema que usan los atacantes (rundll32, powershell, mshta, certutil...) conectando a Internet |
| `suspicious_parent` | ofimática o lectores de PDF lanzando intérpretes o scripts (adjunto o macro maliciosa) |
| `suspicious_cmdline` | líneas de comandos con señales de ataque (codificadas, descargas, ventana oculta, sin restricciones, proxy de scripts) |
| `beaconing`, `resource_breadth`, `activity_ramp` | los genéricos, también sobre endpoint |

## Simulador

`synthetic_endpoint.make_endpoint_dataset(filas_firewall, verdad_firewall)` genera las MISMAS conexiones del firewall vistas desde los
equipos, con su proceso, una cadena de ataque plantada (Word -> PowerShell codificado -> `rundll32.exe` que hace la baliza), `rclone.exe`
en la exfiltración y el reloj del EDR adelantado 2,5 s. Es la verdad conocida para la correlación entre fuentes (entrega D2).

## Límites

* La unión de eventos crudos de Falcon (Falcon Data Replicator, con proceso y conexión en filas separadas) aún no se hace en la ingesta.
* Sysmon/Winlogbeat: la hora con `Z` se lee como UTC, pero queda «sin verificar» hasta que la confirmes.
* El modelo no ve el contenido de las líneas de comandos, solo sus señales. Es una decisión de privacidad; se puede cambiar por caso con
  `PrivacyPolicy(overrides={"command_line": "keep"})` si el analista lo decide.
