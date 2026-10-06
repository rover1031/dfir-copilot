# Contribuir y publicar versiones

## Entorno

El mismo del [README](README.md): Docker con Compose v2 y, en Windows, la terminal de WSL. Los servicios montan la carpeta del proyecto,
así que los cambios en `src/` se ven sin reconstruir (reinicia la web con `docker compose restart web`).

## Antes de cada commit

1. Instala una vez el gancho que bloquea commits con un `.env` o con algo con forma de clave de API:

   ```bash
   cp tools/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
   ```

2. Pruebas y estilo:

   ```bash
   docker compose exec lab python -m pytest -q
   docker compose exec lab ruff check src tests
   ```

Las pruebas no usan red ni claves: los modelos están simulados y los datos son sintéticos con verdad conocida. Una prueba nueva que
necesite datos debe generarlos (ver `src/dfir_copilot/synthetic*.py`); nunca se versionan datos reales (`data/` y `reports/` están
excluidos).

## Publicar una versión

1. **Suite y diagnóstico en verde:** `docker compose exec lab python tools/diagnostico.py --tests` (suite completa, dependencias
   declaradas, secretos, configuración de la web).
2. **Nada sensible versionado, tampoco en el historial:**

   ```bash
   git grep -nE 'sk-ant-|sk-proj-' | grep -v FAKE | grep -v tools/diagnostico.py      # vacío
   git ls-files | grep -E '(^|/)\.env$|^(data|reports)/'                              # vacío
   for c in $(git rev-list --all); do git grep -lE 'sk-ant-[A-Za-z0-9_-]{20,}' "$c" 2>/dev/null; done | grep -v FAKE   # vacío
   ```

3. **Instalación limpia desde el repositorio remoto**, siguiendo solo el README, en una carpeta nueva y con la instancia de trabajo
   detenida (comparten puertos):

   ```bash
   docker compose down
   git clone <url-del-repositorio> /tmp/limpio && cd /tmp/limpio
   cp .env.example .env && mkdir -p data/raw data/inbox
   DFIR_UID=$(id -u) docker compose -p limpio up -d --build
   docker compose -p limpio exec lab python tools/demo.py
   docker compose -p limpio exec lab python -m pytest -q
   ```

   La web debe responder en http://127.0.0.1:8000 con los dos análisis de la demo. Al terminar:
   `docker compose -p limpio down && docker image rm limpio-lab limpio-web`.

4. **Cambios:** `python3 tools/changelog.py` regenera `CHANGELOG.md` desde el historial de git.
