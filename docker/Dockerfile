FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
        tesseract-ocr tesseract-ocr-eng tesseract-ocr-spa \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src
RUN pip install -e ".[notebook,dev,pdf,agent,openai,web]"

# Usuario sin privilegios con el uid de quien construye (DFIR_UID en docker compose), para poder escribir en la carpeta montada
ARG UID=1000
RUN useradd -m -u ${UID} analyst && chown -R analyst /workspace
USER analyst

EXPOSE 8888 8000
CMD ["sh", "-c", "jupyter lab --ip=0.0.0.0 --no-browser --ServerApp.token=${JUPYTER_TOKEN}"]
