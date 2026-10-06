# Documentación

Empieza por el [README del repositorio](../README.md) (instalación y demo). Aquí, la documentación por tema.

## Para usar y evaluar

| Documento | Contenido |
|---|---|
| [capacidades.md](capacidades.md) | Qué hace cada parte, qué preguntas responde y sus límites medidos |
| [entrega.md](entrega.md) | Lista de comprobación para evaluar el proyecto, con resultados esperados |
| [instalado.md](instalado.md) | Entorno de referencia: versiones exactas y qué instala cada extra |
| [interfaz_web.md](interfaz_web.md) | La interfaz local (Django + HTMX) |
| [ejemplos/informe_idor_compartible.md](ejemplos/informe_idor_compartible.md) | Un informe real, variante compartible, del caso de estudio |

## Principios de diseño

| Documento | Contenido |
|---|---|
| [arquitectura_p0.md](arquitectura_p0.md) | Arquitectura base: el modelo nunca lee el log; todo pasa por herramientas acotadas |
| [privacidad.md](privacidad.md) | Seudonimización, alias, qué ve el modelo y qué nunca sale de la máquina |
| [falsabilidad.md](falsabilidad.md) | Hipótesis falsables: criterio de refutación fijado antes de probarlas |
| [persistencia_y_reproducibilidad.md](persistencia_y_reproducibilidad.md) | Ledger, conversación persistente y reejecución de consultas |
| [presupuesto_y_notas.md](presupuesto_y_notas.md) | Topes de tokens y notas del analista |
| [zona_horaria.md](zona_horaria.md) | Cómo se declara, verifica y advierte la zona horaria |

## Por fuente y etapa

| Documento | Contenido |
|---|---|
| [perfil_datos.md](perfil_datos.md) | Perfil estadístico por campo y preguntas rápidas sin modelo (esquema en `data_profile.schema.json`, ejemplo en `ejemplo_data_profile.json`) |
| [p1a_interpretacion.md](p1a_interpretacion.md) · [p1a_resultados.md](p1a_resultados.md) | Interpretación del perfil con el modelo y sus resultados |
| [logs_texto.md](logs_texto.md) | Logs de texto: syslog de Palo Alto y Nginx |
| [firewall.md](firewall.md) | Logs de firewall de distintos fabricantes |
| [endpoint.md](endpoint.md) | Endpoint: CrowdStrike Falcon y Sysmon |
| [correlacion.md](correlacion.md) | Correlación firewall × endpoint y desfase de relojes |
| [incidente.md](incidente.md) | Vista del incidente, línea de tiempo y valoración |
| [informe.md](informe.md) | Estructura del informe forense y sus dos variantes |
| [documentos.md](documentos.md) | PDF: IOCs, OCR, verificación contra una fuente, chat con citas |
| [papelera.md](papelera.md) | Eliminar análisis de forma recuperable y con registro |
