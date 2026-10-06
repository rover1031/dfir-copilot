# Entorno de referencia

Lo que había instalado en el entorno donde se desarrolló y probó el proyecto (diagnóstico del 6 de octubre de 2026). Para ver el tuyo:
`docker compose exec lab python tools/diagnostico.py`.

## Imagen

- Base `python:3.12-slim` (Python 3.12.15), con **Tesseract OCR 5.5** (idiomas `eng`, `spa`, `osd`).
- Se instala el paquete en modo editable con los extras `notebook, dev, pdf, agent, openai, web`.
- Usuario sin privilegios `analyst`, con el uid de quien construye (`DFIR_UID`, por defecto 1000).
- Tamaño de la imagen: ~1,7 GB. Puertos publicados solo en `127.0.0.1`: 8888 (Jupyter) y 8000 (interfaz web).

## Extras del paquete (`pyproject.toml`)

| Extra | Para qué | Paquetes |
|---|---|---|
| (base) | Ingesta, perfil, detectores, privacidad, informes | duckdb, pandas, pyarrow, pydantic, openpyxl, xlrd, pyyaml |
| `agent` | Agente y modelo de Anthropic | langgraph, langchain-core, langchain-anthropic |
| `openai` | Proveedor alternativo | langchain-openai |
| `web` | Interfaz local | django (5.x) |
| `pdf` | Documentos PDF | pymupdf, pillow, numpy (+ el binario tesseract para escaneados) |
| `geoip` | Bases GeoIP `.mmdb` (opcional; el CSV de DB-IP no lo necesita) | maxminddb |
| `notebook` | Cuadernos | jupyterlab, matplotlib, plotly |
| `dev` | Pruebas y estilo | pytest, ruff |

## Versiones probadas

| Paquete | Versión |
|---|---|
| django | 5.2.18 |
| duckdb | 1.5.6 |
| pandas | 3.0.6 |
| pyarrow | 25.0.1 |
| pydantic | 2.13.5 |
| langchain-core | 1.6.6 |
| langgraph | 1.2.13 |
| langchain-anthropic | 1.7.5 |
| langchain-openai | 1.6.7 |
| anthropic | 1.11.0 |
| openai | 3.24.0 |
| pymupdf | 1.28.2 |
| openpyxl | 3.1.5 |
| xlrd | 2.0.2 |
| pyyaml | 6.0.3 |
| pytest | 9.1.1 |
| ruff | 0.16.10 |
| jupyterlab | 4.6.4 |

## Variables de entorno (`.env`)

| Variable | Uso |
|---|---|
| `JUPYTER_TOKEN` | Token de acceso a Jupyter |
| `LLM_PROVIDER` | `anthropic` (por defecto) u `openai` |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | Clave del proveedor (opcional: sin ella todo lo local funciona) |
| `LLM_MODEL`, `LLM_TEMPERATURE`, `LLM_MAX_TOKENS`, `LLM_TIMEOUT_S` | Ajustes opcionales del modelo (ver comentarios en `.env.example`) |
| `DFIR_GEOIP_DB` | Ruta a la base GeoIP si no está en `data/geoip/` |
| `DFIR_UID` | (al construir) uid del usuario del contenedor |
