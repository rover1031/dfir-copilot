FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace

COPY pyproject.toml ./
COPY src ./src
RUN pip install -e ".[notebook,dev,pdf]"

RUN useradd -m -u 1000 analyst && chown -R analyst /workspace
USER analyst

EXPOSE 8888
CMD ["sh", "-c", "jupyter lab --ip=0.0.0.0 --no-browser --ServerApp.token=${JUPYTER_TOKEN}"]
