# Evaluar el proyecto

Lista de comprobación para quien recibe el repositorio, con lo que debería ver en cada paso. Todo funciona sin clave de API.

| # | Paso | Resultado esperado |
|---|---|---|
| 1 | `git clone https://github.com/rover1031/dfir-copilot.git && cd dfir-copilot` | Repositorio de unos 2 MB |
| 2 | `cp .env.example .env && mkdir -p data/raw data/inbox` | `.env` creado (la clave de API puede quedar vacía) |
| 3 | `DFIR_UID=$(id -u) docker compose up -d --build` | Contenedor `lab` en marcha (`docker compose ps`) |
| 4 | `docker compose exec lab python tools/diagnostico.py` | Informe en `reports/`: todos los módulos importan; sin fallos de entorno |
| 5 | `docker compose exec lab python -m pytest -q` | Unas 960 pruebas pasadas y 8 saltadas, en unos 6-7 minutos |
| 6 | `docker compose exec lab python tools/demo.py` | «Demo IDOR» y «Demo incidente» creados y analizados (estados `done` o `needs_attention`) |
| 7 | `docker compose exec lab python -m dfir_copilot.web --host 0.0.0.0 --restart` y abrir http://127.0.0.1:8000 | Los dos análisis, con sus hallazgos, la correlación del incidente y el boletín PDF con sus IOCs |
| 8 | Opcional: clave en `.env`, `docker compose up -d` y preguntar en un caso o en el documento | Respuestas con referencias a consultas y hallazgos, o con citas verificadas |

Qué mirar en la interfaz:

- **Demo IDOR:** las preguntas rápidas sin modelo (pestaña Datos) responden las cinco preguntas del caso; los detectores señalan la
  enumeración de facturas.
- **Demo incidente:** la correlación atribuye el tráfico del firewall al equipo y proceso del endpoint; la línea de tiempo conserva de qué
  fuente sale cada evento.
- **Boletín PDF:** los IOCs válidos en la lista de bloqueo, las IPs de documentación marcadas como no públicas y el dominio `.test` del
  correo sin contar como IOC.
- **Papelera:** eliminar un análisis, restaurarlo y comprobar que su custodia sigue íntegra.

## Antes de publicar una versión (para el autor)

1. `python tools/diagnostico.py --tests`: suite completa en verde y sin fallos.
2. Comprobar que no hay claves ni datos versionados, también en el historial (ver el README, «Seguridad al contribuir»).
3. Prueba de clonado limpio: los pasos 1-7 de arriba en una carpeta nueva, clonando desde GitHub.
4. `python3 tools/changelog.py` para regenerar `CHANGELOG.md`.
