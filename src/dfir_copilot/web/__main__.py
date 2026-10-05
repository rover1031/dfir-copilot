"""`python -m dfir_copilot.web` (o `dfir-web`): arranca la interfaz. Por defecto en 127.0.0.1:8000; en Docker usa --host 0.0.0.0 y publica
el puerto solo en localhost (`127.0.0.1:8000:8000`)."""
import argparse
import os


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="dfir-web", description="Interfaz web local del DFIR Co-pilot")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dfir_copilot.web.settings")
    from django.core.management import execute_from_command_line

    # --insecure: sirve el CSS y HTMX incluidos aunque DEBUG esté apagado (sin él la página sale sin estilos y sin interacciones).
    # No es un riesgo para una herramienta local que no usa más archivos estáticos que los suyos.
    execute_from_command_line(["dfir-web", "runserver", f"{args.host}:{args.port}", "--noreload", "--insecure"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
