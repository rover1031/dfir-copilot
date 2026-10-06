"""`python -m dfir_copilot.web --restart`: detiene la interfaz anterior sin buscar el proceso a mano (el contenedor no trae pkill)."""
import socket
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from dfir_copilot.web.__main__ import stop_running

pytestmark = pytest.mark.skipif(not Path("/proc").is_dir(), reason="usa /proc (Linux)")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_restart_detiene_la_instancia_anterior_y_no_toca_otros_procesos():
    port, mark = free_port(), f"dfir-prueba-{uuid.uuid4().hex}"           # marcador propio: el test no toca una interfaz real abierta
    old = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", mark, "--port", str(port)])
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "otro-programa"])
    try:
        stopped = stop_running(port, wait_s=1, markers=(mark,))
        assert old.pid in stopped and other.pid not in stopped
        assert old.wait(timeout=5) is not None and other.poll() is None
    finally:
        for p in (old, other):
            p.kill()
            p.wait()
