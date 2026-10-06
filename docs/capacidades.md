# Capacidades y límites

Resumen de lo que hace el proyecto, con sus límites declarados. Cada sección enlaza a su documento de detalle.

## Principios que se cumplen en todo el sistema

- **El análisis lo hace el código; el modelo enriquece.** Perfil, mapeo, ingesta, detectores, correlación e IOCs funcionan sin modelo.
- **El modelo nunca lee un log completo.** Consulta con herramientas de solo lectura, acotadas (filas, caracteres) y auditadas.
- **Privacidad por diseño.** El modelo ve una copia seudonimizada (alias); lo que escribe el analista se traduce a alias antes de salir
  y se muestra lo enviado ([privacidad.md](privacidad.md)).
- **Evidencia trazable.** Consultas, hallazgos, hipótesis y decisiones quedan en un ledger con hashes y se pueden reejecutar
  ([persistencia_y_reproducibilidad.md](persistencia_y_reproducibilidad.md)); los archivos entran con cadena de custodia.
- **Hipótesis falsables y decisión humana.** Cada hipótesis fija antes su criterio de refutación; solo el analista la confirma o refuta
  ([falsabilidad.md](falsabilidad.md)).
- **Zona horaria explícita.** Las horas sin zona verificada se marcan así en todo el análisis ([zona_horaria.md](zona_horaria.md)).

## Por fuente

| Fuente | Formatos | Qué obtienes | Detalle |
|---|---|---|---|
| Web | CSV, JSON, NDJSON, Parquet, Excel (por hojas), Nginx | Perfil por campo, preguntas rápidas sin modelo (incluidas las 5 del caso IDOR: IPs, países, tokens, facturas, sitio), detectores, agente | [perfil_datos.md](perfil_datos.md) |
| Firewall | CSV de distintos fabricantes, syslog de PAN-OS | Mapeo al esquema canónico, detectores de red | [firewall.md](firewall.md), [logs_texto.md](logs_texto.md) |
| Endpoint | CrowdStrike Falcon CSV, Sysmon ECS NDJSON | Cadenas de procesos; la copia del modelo no lleva rutas con usuario, líneas de comandos ni equipos, sí el ejecutable y señales técnicas | [endpoint.md](endpoint.md) |
| Incidente (varias fuentes) | Firewall + endpoint | Correlación con estimación de desfase de relojes, línea de tiempo con procedencia, valoración con citas verificadas, tope de tokens del incidente | [correlacion.md](correlacion.md), [incidente.md](incidente.md) |
| Documentos | PDF con texto o escaneado | IOCs validados, OCR, países, resumen extractivo, verificación contra fuente, chat con citas | [documentos.md](documentos.md) |
| Informes | Markdown | Variante interna (valores reales y diccionario) y compartible (alias; el código no la exporta si detecta un valor real) | [informe.md](informe.md) |

## Límites conocidos

- **No soportado todavía:** proxy, DNS y logs de autenticación; FortiGate en formato `clave=valor`; IPv6 en detectores y en el extractor
  de IOCs.
- **Correlación:** necesita que el firewall vea la IP real del equipo (sin NAT entre medias).
- **OCR:** un hash leído por OCR puede tener un carácter mal leído aunque su longitud sea correcta; por eso nunca entra a la lista de
  bloqueo sin verificar contra una fuente de texto ([documentos.md](documentos.md)).
- **Geolocalización:** un país por IP es una aproximación (VPN, nubes, proxies) y depende de la base local que se descargue.
- **Búsqueda en documentos:** léxica; la consulta debe ir en el idioma del documento.
- **Validación:** la mayor parte de lo medido es contra simuladores con verdad conocida y un caso de estudio externo; conviene
  validarlo con exportaciones reales de cada entorno antes de confiar en un detector concreto.
