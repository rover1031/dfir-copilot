"""real_hits: el escaneo de fugas ignora un nombre de ejecutable suelto en columnas de proceso (vocabulario técnico, como en `<col>_base`)."""
from dfir_copilot.privacy.pseudonymize import real_hits


class _PS:
    """Doble mínimo del seudonimizador: `found` es lo que devolvería find_real; `real` mapea alias -> valor real."""

    def __init__(self, found, real):
        self._found, self._real = found, real

    def find_real(self, text):
        return list(self._found)

    def reveal_any(self, alias):
        return self._real.get(alias)


def _hit(column, alias):
    return {"column": column, "alias": alias}


def test_ejecutable_suelto_de_falcon_no_es_fuga():
    ps = _PS([_hit("parent_process", "PPROC-1")], {"PPROC-1": "explorer.exe"})
    assert real_hits(ps, "padre explorer.exe") == []


def test_ruta_con_usuario_sigue_siendo_fuga():
    ps = _PS([_hit("parent_process", "PPROC-2")], {"PPROC-2": r"C:\Users\jperez\AppData\x.exe"})
    assert len(real_hits(ps, "x")) == 1


def test_linea_de_comandos_con_argumentos_sigue_siendo_fuga():
    ps = _PS([_hit("command_line", "CMD-1")], {"CMD-1": "powershell.exe -enc AAAA"})
    assert len(real_hits(ps, "x")) == 1


def test_fuera_de_columnas_de_proceso_no_hay_excepcion():
    ps = _PS([_hit("host", "H-1")], {"H-1": "srv01.exe"})
    assert len(real_hits(ps, "x")) == 1


def test_mezcla_solo_queda_lo_que_fuga():
    ps = _PS([_hit("process_name", "PROC-1"), _hit("user_id", "U-1")], {"PROC-1": "cmd.exe", "U-1": "jperez"})
    assert [h["column"] for h in real_hits(ps, "x")] == ["user_id"]
