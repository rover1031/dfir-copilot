# Interfaz web local (P2)

Django + HTMX, sin base de datos: la verdad sigue siendo el ledger y las carpetas del caso. Una interfaz para **un** analista, en tu máquina.

## Idea

Un **proyecto** es una carpeta con los archivos a analizar. Al crearlo (por ejemplo "Análisis 1"), arranca solo el análisis de cada archivo, un caso
por archivo. Cuando haces preguntas en lenguaje natural, ya hay avance: perfil, mapping, datos normalizados, copia seudonimizada, hallazgos de los
detectores y, si usas el modelo, hipótesis propuestas con su criterio de refutación **esperando tu aprobación**.

| Etapa | Qué hace | ¿Modelo? |
|---|---|---|
| `draft` | perfila el archivo en local y propone el mapping | no |
| `interpret` | P1-a: el modelo recibe solo metadatos del perfil y propone clasificación y consultas | sí |
| `ingest` | normaliza a Parquet; el caso queda atado por hash | no |
| `copy` | copia seudonimizada (`priv-1`) | no |
| `detectors` | detectores sobre la copia, correlación y registro en el ledger | no |
| `explore` | ejecuta en local las consultas que propuso el modelo | no |
| `triage` | el agente (LangGraph) hace un triaje inicial; sus hipótesis quedan pendientes de tu aprobación | sí |

El análisis lo hace el código; el modelo solo enriquece. Las etapas con modelo son opcionales y se saltan solas si no hay clave. Cada etapa es
idempotente y guarda su estado (`<proyecto>/status/<caso>.json`): un fallo se registra, detiene ese archivo y al reintentar se reanuda donde se quedó.

## Pantallas

* **Inicio**: proyectos, casos existentes (los de `data/cases`, anteriores a los proyectos) y el formulario de nuevo proyecto.
* **Proyecto**: archivos con el avance de cada etapa en vivo (se actualiza solo mientras algo corre).
* **Caso**, con el botón **Exportar informe** siempre visible y el interruptor *Mostrar valores reales*:
  * *Resumen*: datos, zona (sin verificar), hallazgos de los detectores, interpretación del perfil.
  * *Hipótesis*: lo que espera tu decisión, con el criterio de refutación, los intentos con su SQL y su resultado; aprobar, rechazar o retirar.
  * *Preguntar*: lenguaje natural; verás exactamente lo que recibió el modelo (en alias) y el gasto de tokens.
  * *Notas*: contexto tuyo que el agente verá en cada pregunta.
  * *Informe*: variante, idioma, recomendaciones y **Exportar**; historial con hashes.
  * *Integridad*: cadena de custodia, ledger, copias que vio el modelo y presupuesto.

## Arrancarla

En el contenedor (donde ya corre JupyterLab), desde `/workspace`:

```bash
pip install -e ".[web]"                        # una vez: instala Django (si reconstruyes la imagen, añade el extra al Dockerfile)
python -m dfir_copilot.web --host 0.0.0.0      # escucha dentro del contenedor; abre http://localhost:8000
```

Para llegar desde el navegador de Windows, **publica el puerto solo en localhost** en `docker-compose.yml` (servicio donde corre el código) y recrea el contenedor:

```yaml
    ports:
      - "127.0.0.1:8000:8000"
```

`docker compose up -d` aplica el cambio. La clave de API se lee del entorno del contenedor, como en los notebooks.

## Variables de entorno

| Variable | Por defecto | Para qué |
|---|---|---|
| `DFIR_DATA_ROOT` | `/workspace/data` | Raíz de datos: la carpeta de un proyecto debe estar DENTRO de ella |
| `DFIR_PROJECTS_ROOT` | `<DATA_ROOT>/projects` | Dónde viven los proyectos |
| `DFIR_CASES_ROOT` | `/workspace/data/cases` | Casos sueltos (anteriores a los proyectos) |
| `DFIR_REPORTS_ROOT` | `/workspace/reports` | Dónde se escriben los informes |
| `DFIR_WEB_SECRET` | generada y guardada en `<DATA_ROOT>/.web_secret` | Clave de Django |
| `DFIR_WEB_ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` | Hosts admitidos |
| `DFIR_WEB_DEBUG` | apagado | `1` activa el modo depuración de Django |
| `DFIR_WEB_WORKERS` | `1` | Archivos que se analizan a la vez |

## Seguridad

* **Sin cuentas ni autenticación**: es una herramienta local de un analista. Escucha en `127.0.0.1` por defecto y, en Docker, el puerto se publica solo en localhost.
  Si la expones en otra interfaz, protégela con un proxy con autenticación.
* **CSRF** activo en todos los `POST` (HTMX envía el token en una cabecera).
* La carpeta de origen se resuelve (incluidos los enlaces simbólicos) y debe quedar dentro de la raíz de datos: la interfaz no lee otras rutas de la máquina.
* Las descargas solo sirven archivos con el nombre que genera el informe (`informe.<es|en>.<interno|compartible>.md`) dentro de la carpeta del caso.
* HTMX va incluido en el paquete: no hace falta internet para la interfaz. Lo único que sale de la máquina es lo que ya salía: las llamadas al modelo, con la copia seudonimizada.
* Un solo trabajo con el modelo a la vez por caso; el resultado se consulta por sondeo.

## Coste

Las etapas con el modelo gastan API: la interpretación del perfil (unos miles de tokens) y el triaje (con tope por pregunta, 210 000 por defecto y el que pongas al
crear el proyecto). Con "usar el modelo" apagado, el análisis es 100 % local y gratuito.

## Límites

* La interfaz está en español; el informe sí es bilingüe.
* Si el servidor se reinicia a mitad de un análisis, el archivo se ve como *interrumpido* y se reanuda con *Reanalizar*.
* Las aprobaciones reanudan al agente, así que necesitan el modelo configurado.

## Estados de un archivo

`done`, `needs_attention` (terminó y hay algo que revisar), `skipped`, `failed` (error: se corrige y **Reanalizar** reanuda) y
`unsupported` (el formato o el tipo de log todavía no se sabe ingerir: **no es un error** y reanalizar no cambia nada). El botón
**Abrir caso** solo aparece cuando el archivo llegó a ingerirse.

## Nuevo análisis (asistente) y evidencia

**+ Nuevo análisis** en el inicio abre un asistente de tres pasos:

1. **Datos**: nombre, ticket o caso, analista, zona horaria de las horas de los archivos, idioma, si usa el modelo y con qué tope, y una descripción.
2. **Archivos** (uno o más), por dos caminos que se pueden combinar:
   * *Subir desde tu equipo*: arrastrar y soltar o elegir, con barra de progreso. Límite por archivo: `DFIR_WEB_MAX_UPLOAD_MB` (4096 por defecto).
   * *Elegir del servidor*: navegar las carpetas de la raíz de datos y marcar archivos. **Copiar** (recomendado: la evidencia no depende del
     original) o **enlazar** (archivos muy grandes: no duplica espacio, pero si alguien toca el original la custodia lo detectará).
3. **Analizar**: arranca el análisis automático de cada log, igual que antes.

Cada análisis tiene su carpeta: `<raíz de datos>/projects/<análisis>/evidencia/`. Todo lo que entra queda en `custodia.jsonl`, encadenado por
hash: archivo, SHA-256, tamaño, origen (subido o ruta del servidor, copiado o enlazado), quién y cuándo. `Project.verify_custody()` comprueba
que nadie editó la custodia y que cada archivo sigue teniendo su SHA-256.

| Tipo | Qué pasa |
|---|---|
| CSV, TSV, JSON, NDJSON, Parquet (y `.gz`) | se analiza como log (un caso por archivo) |
| Excel `.xlsx`, `.xls` | se guarda como evidencia y **cada hoja con datos se convierte en un CSV derivado** que se analiza como un caso. Las fechas salen legibles (`2026-10-04 23:02:59`), no como número de serie de Excel; la custodia registra de qué archivo y de qué hoja sale cada CSV |
| PDF | se guarda como evidencia (con su hash); **no es un log** y no se analiza como tal |
| Otros | se rechazan sin dejar rastro |

Los nombres de archivo se sanean (sin rutas, sin caracteres raros) y nunca se pisa un archivo existente: el segundo `fw.csv` se guarda como
`fw-2.csv`. Ninguna ruta sale de la raíz de datos, ni con `..` ni con enlaces.

## Confirmar la zona horaria

En **Resumen** de un caso con la zona «sin verificar», *Confirmar la zona horaria* registra en el ledger la base de la confirmación:
**decisión del analista, sin confirmación externa** o **confirmada por el dueño del export**, con quién y cuándo. No cambia ningún dato (las
horas ya se convirtieron con esa zona) y el informe lo dice tal cual, con su limitación. Para usar OTRA zona hay que reingestar.

## Decidir las propuestas del agente

En **Hipótesis**, cada propuesta pendiente tiene su propio Aprobar/Rechazar y su nota: se deciden por separado y se registran juntas con
«Registrar decisiones» (una propuesta sin decidir no se rechaza en silencio: la interfaz la pide). Por defecto las decisiones se registran
**al instante y sin llamar al modelo**; la casilla «que el agente siga investigando» lo reanuda con tus decisiones (más lento y gasta tokens).

## Pestaña Datos

El perfil de ingeniero de datos del caso (campos, IPs por alcance, eventos por día y hora, huecos, calidad del dato). Ver `docs/perfil_datos.md`.
