"""`python -m dfir_copilot.web` (o `dfir-web`): arranca la interfaz. Por defecto en 127.0.0.1:8000; en Docker usa --host 0.0.0.0 y publica
el puerto solo en localhost (`127.0.0.1:8000:8000`).

`--restart` detiene antes la interfaz que siga corriendo (de una ejecución anterior) y espera a que el puerto quede libre: así no hace falta
buscar el proceso a mano. Usa /proc (Linux, también en el contenedor, que no trae `pkill`)."""
import argparse
import os
import signal
import socket
import time
from pathlib import Path


def _port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def stop_running(port: int = 8000, wait_s: float = 8.0, markers: tuple = ("dfir_copilot.web", "dfir-web")) -> list[int]:
    """Detiene los procesos de esta interfaz que no sean este (ni su padre) y espera hasta `wait_s` a que el puerto quede libre."""
    me, parent, stopped = os.getpid(), os.getppid(), []
    proc = Path("/proc")
    for p in (proc.iterdir() if proc.is_dir() else ()):
        if not p.name.isdigit() or int(p.name) in (me, parent):
            continue
        try:
            cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if any(m in cmd for m in markers):
            try:
                os.kill(int(p.name), signal.SIGTERM)
                stopped.append(int(p.name))
            except OSError:
                pass
    deadline = time.monotonic() + wait_s
    while not _port_free(port) and time.monotonic() < deadline:
        time.sleep(0.2)
    return stopped


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="dfir-web", description="Interfaz web local del DFIR Co-pilot")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--restart", action="store_true", help="detiene antes la interfaz que siga corriendo")
    args = parser.parse_args(argv)
    if args.restart:
        stopped = stop_running(args.port)
        print(f"Detenida(s) {len(stopped)} instancia(s) anterior(es)." if stopped else "No había otra instancia corriendo.")
        if not _port_free(args.port):
            print(f"El puerto {args.port} sigue ocupado por otro programa: usa --port con otro número o ciérralo.")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dfir_copilot.web.settings")
    from django.core.management import execute_from_command_line

    # --insecure: sirve el CSS y HTMX incluidos aunque DEBUG esté apagado (sin él la página sale sin estilos y sin interacciones).
    # No es un riesgo para una herramienta local que no usa más archivos estáticos que los suyos.
    execute_from_command_line(["dfir-web", "runserver", f"{args.host}:{args.port}", "--noreload", "--insecure"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
