# DFIR Co-pilot

Motor de triage e investigación forense sobre logs, con un agente que propone hipótesis y un analista que decide.

El análisis lo hace **el código** (perfilado, mapeo a un esquema canónico, detectores, correlación entre fuentes, extracción de IOCs) y
el modelo de lenguaje **solo enriquece**: interpreta perfiles, formula hipótesis falsables y responde preguntas consultando los datos a
través de herramientas acotadas. **El modelo nunca recibe un log completo** ni valores sensibles: trabaja sobre una copia seudonimizada,
y cada consulta, hallazgo y decisión queda en un registro auditable y reproducible.

Funciona sin clave de API: todo lo local (perfil, ingesta, detectores, correlación, preguntas rápidas, IOCs de documentos) va sin modelo.

## Qué hace

| Fuente | Qué hace |
|---|---|
| Logs web (CSV/JSON/NDJSON/Parquet, Nginx) | Perfil por campo, detectores (p. ej. IDOR/enumeración), preguntas rápidas sin modelo, agente con hipótesis falsables |
| Firewall (CSV de distintos fabricantes, syslog de PAN-OS) | Ingesta con mapeo al esquema canónico, detectores de red |
| Endpoint (CrowdStrike Falcon CSV, Sysmon ECS NDJSON) | Cadenas de procesos sin exponer rutas ni usuarios al modelo |
| Varias fuentes de un mismo análisis | Correlación firewall × endpoint (detecta desfases de reloj), línea de tiempo del incidente, valoración con citas verificadas |
| Documentos PDF (boletines de amenazas) | IOCs validados (hash, IP, dominio, URL, CVE…), OCR de PDF escaneados, países de las IPs, resumen extractivo, chat con citas que el código comprueba |
| Informes | Variante interna y compartible (con alias; el código comprueba que no lleve ningún valor real) |

El detalle, con sus límites medidos, está en [docs/capacidades.md](docs/capacidades.md). Un informe real de ejemplo:
[docs/ejemplos/informe_idor_compartible.md](docs/ejemplos/informe_idor_compartible.md).

## Requisitos

- **Docker** con **Docker Compose v2** (Docker Desktop en Windows/macOS, o Docker Engine en Linux). En Windows, con WSL2.
- **git** y unos **4 GB** libres (la imagen ocupa ~1,7 GB).
- Opcional: una clave de API de Anthropic (u OpenAI) para las funciones con modelo.

## Instalación

> **En Windows:** todos los comandos van en la terminal de **WSL (Ubuntu)**, no en PowerShell ni en CMD, y el repositorio se clona
> **dentro de WSL** (por ejemplo en `~/projects`), no en `C:\` ni en `/mnt/c/…`: allí los permisos y el rendimiento dan problemas.

```bash
git clone https://github.com/rover1031/dfir-copilot.git
cd dfir-copilot
cp .env.example .env              # obligatorio: Compose lo exige (la clave de API dentro es opcional)
mkdir -p data/raw data/inbox      # antes de levantar: si no, Docker crea data/ como root y el contenedor no puede escribir
DFIR_UID=$(id -u) docker compose up -d --build
```

La primera construcción tarda unos minutos. `DFIR_UID` hace que el usuario del contenedor sea el tuyo, para que pueda escribir en la
carpeta del proyecto (en WSL suele ser 1000, el valor por defecto).

Al terminar quedan **dos servicios en marcha** (compruébalo con `docker compose ps`):

| Servicio | Dirección | Para qué |
|---|---|---|
| `web` | **http://127.0.0.1:8000** | La interfaz: análisis, casos, documentos, papelera |
| `lab` | **http://127.0.0.1:8888** | Jupyter, con los cuadernos de cada fase |

**Entrar en Jupyter:** abre http://127.0.0.1:8888 y pega el token, o pide el enlace completo (el comando cambia el nombre interno del contenedor por `127.0.0.1`):

```bash
docker compose exec lab jupyter server list | sed -E 's#http://[^/]+:8888#http://127.0.0.1:8888#'
```

El token es `JUPYTER_TOKEN` de tu `.env` (por defecto `cambia-este-token`; cámbialo si quieres). Si el navegador da un error de
credenciales o de `_xsrf`, abre el enlace en una ventana privada: suele ser una sesión guardada de otra instancia en el mismo puerto.

## Probarlo en dos minutos

```bash
docker compose exec lab python tools/demo.py        # datos sintéticos, sin modelo
```

Abre (o recarga) **http://127.0.0.1:8000**. Verás dos análisis:

- **Demo IDOR**: un log web con una explotación IDOR plantada en `/invoices/search` (el caso de estudio del proyecto).
- **Demo incidente**: firewall + endpoint del mismo entorno con una cadena maliciosa que la correlación une, y un boletín PDF con IOCs
  ficticios (direcciones de documentación y dominios `.test`, que no existen).

## Usarlo con tus datos

En la interfaz, **+ Nuevo análisis**: sube archivos desde tu equipo o elígelos de `data/inbox/`. Cada archivo entra en la cadena de
custodia con su SHA-256 y se analiza solo; los PDF se leen y se extraen sus IOCs. Indica la zona horaria de los logs si la conoces: las
horas sin zona verificada se marcan así en todo el análisis.

Para eliminar un análisis: «Eliminar…» en su tarjeta. Va a una **papelera recuperable**; eliminarlo definitivamente queda en un registro
encadenado de eliminaciones (ver [docs/papelera.md](docs/papelera.md)).

## Modelo de lenguaje (opcional)

Pon tu clave en `.env` (`ANTHROPIC_API_KEY`, o `LLM_PROVIDER=openai` y `OPENAI_API_KEY`) y recrea los servicios para que la lean
(`docker compose up -d --force-recreate`). El modelo se usa para interpretar perfiles, el triaje del agente, las preguntas en lenguaje natural, la
valoración del incidente y el chat con documentos. Hay tope de tokens por pregunta, por caso y por análisis. Con documentos, el envío de
pasajes al modelo hay que **permitirlo documento a documento**.

## Geolocalización (opcional)

Descarga **DB-IP «IP to Country Lite»** (CSV, gratuita, CC BY 4.0) y déjala en `data/geoip/`, o indica su ruta con `DFIR_GEOIP_DB`. Sin
ella, todo funciona y donde haría falta se dice «sin base GeoIP». Nada sale de la máquina: es una búsqueda en un archivo.

## Pruebas

```bash
docker compose exec lab python -m pytest -q          # ~960 pruebas, unos 6-7 minutos
docker compose exec lab python tools/diagnostico.py  # diagnóstico de solo lectura del entorno y del código
```

Las pruebas no necesitan clave de API ni red: los modelos están simulados y los datos son sintéticos con verdad conocida.

## Estructura

```
src/dfir_copilot/   código: ingesta, perfilado, detectores, privacidad, agente, informes, documentos, papelera, interfaz web
tests/              pruebas (pytest)
notebooks/          cuadernos de cada fase de la construcción
docs/               documentación por tema (índice en docs/README.md) y ejemplos
tools/              demo, diagnóstico, changelog y utilidades
docker/             Dockerfile
data/               datos y análisis (NO se versiona)
reports/            informes exportados (NO se versiona)
```

## Contribuir

Pruebas, estilo y cómo publicar una versión: [CONTRIBUTING.md](CONTRIBUTING.md).

### Seguridad

`.env` y `data/` están fuera de git. Para bloquear además cualquier commit que lleve un `.env` o algo con forma de clave de API:

```bash
cp tools/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

## Problemas comunes

| Síntoma | Causa y solución |
|---|---|
| `env file .env not found` | Falta `cp .env.example .env` |
| `Permission denied` al crear análisis | `data/` quedó de root: `sudo chown -R $(id -u):$(id -g) data` y reconstruye con `DFIR_UID=$(id -u) docker compose up -d --build` |
| La web no responde en 127.0.0.1:8000 | Mira su registro con `docker compose logs --tail 50 web` y reiníciala con `docker compose restart web`. Desde WSL, `curl -sI http://127.0.0.1:8000/` debe dar `200`; si responde ahí pero no en el navegador de Windows, prueba `http://localhost:8000` |
| `port is already allocated` | Otra instancia usa el puerto 8000 u 8888: detenla (`docker compose down` en su carpeta) antes de levantar esta |
| No puedo entrar en Jupyter | Abre http://127.0.0.1:8888 con el token de tu `.env`, no la dirección con el nombre interno del contenedor que imprime `jupyter server list`; si da error de `_xsrf`, usa una ventana privada del navegador |
| «No hay un modelo configurado» | Normal sin clave; pon la clave en `.env` y `docker compose up -d --force-recreate` |
| Un PDF escaneado no da hashes en la lista de bloqueo | Es intencionado: lo leído por OCR queda «sin verificar» hasta contrastarlo con una fuente de texto (ver [docs/documentos.md](docs/documentos.md)) |

## Licencia y terceros

Código bajo licencia **MIT** (ver [LICENSE](LICENSE)). Dependencias y datos de terceros con su propia licencia:

- **PyMuPDF** (extra `pdf`) se distribuye bajo **AGPL-3.0**: si redistribuyes el software o lo ofreces como servicio con ese extra,
  revisa sus términos.
- **DB-IP Lite** (opcional, no incluida): CC BY 4.0, requiere atribución — «IP Geolocation by DB-IP» (https://db-ip.com).
- **htmx** se incluye en `src/dfir_copilot/web/static/` (licencia de su autor: https://github.com/bigskysoftware/htmx).
- Tesseract OCR (Apache-2.0), Django (BSD), DuckDB (MIT), LangChain/LangGraph (MIT) se instalan como dependencias.
