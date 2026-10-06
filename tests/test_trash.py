"""Papelera: eliminar análisis y casos sueltos de forma recuperable. Lo esencial: mover y restaurar deja todo igual (custodia íntegra,
informes de vuelta); restaurar nunca sobrescribe; eliminar definitivamente exige escribir el identificador y deja constancia en un registro
encadenado que detecta ediciones; no se elimina nada mientras se analiza; un análisis vinculado no toca la carpeta del servidor; y un
identificador manipulado no sale de la papelera."""
import json
import os

import pytest

pytest.importorskip("django", reason="la interfaz web es opcional: pip install -e '.[web]'")
os.environ.setdefault("DFIR_WEB_SECRET", "secreto-de-pruebas")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dfir_copilot.web.settings")

import django  # noqa: E402

django.setup()
from django.test import Client  # noqa: E402

from dfir_copilot import trash as T  # noqa: E402
from dfir_copilot.projects import Project, ProjectSettings  # noqa: E402
from dfir_copilot.web import trash_views as TV  # noqa: E402
from dfir_copilot.web.services import reset_services  # noqa: E402


@pytest.fixture
def roots(tmp_path, monkeypatch):
    data = tmp_path / "data"
    (data / "inbox").mkdir(parents=True)
    monkeypatch.setenv("DFIR_DATA_ROOT", str(data))
    monkeypatch.setenv("DFIR_PROJECTS_ROOT", str(data / "projects"))
    monkeypatch.setenv("DFIR_REPORTS_ROOT", str(tmp_path / "reports"))
    reset_services(sync=True, cases_root=tmp_path / "cases")
    return TV.roots()


def _project(name="Borrar uno"):
    p = Project.create(name, None, ProjectSettings(language="es"))
    p.add_upload("datos.csv", [b"a,b\n1,2\n"], analyst="eder")
    return p


def _ids():
    return [p.id for p in Project.list()]


def test_mover_y_restaurar_deja_todo_igual(roots):
    p = _project()
    cid = p.files()[0].case_id
    (roots.reports / cid).mkdir(parents=True)
    (roots.reports / cid / "informe.md").write_text("informe", encoding="utf-8")
    card = T.trash_project(p, roots, by="eder")
    assert p.id not in _ids() and not (roots.reports / cid).exists()
    [item] = T.items(roots)
    assert item["files"][0]["file"] == "datos.csv" and len(item["files"][0]["sha256"]) == 64 and item["reports"] == [cid]
    T.restore(card["item"], roots, by="eder")
    assert p.id in _ids() and (roots.reports / cid / "informe.md").read_text(encoding="utf-8") == "informe"
    assert Project.open(p.id).verify_custody()["ok"] and T.items(roots) == []
    assert [e["action"] for e in T.registry(roots)] == ["moved_to_trash", "restored"] and T.verify_registry(roots)["ok"]


def test_restaurar_nunca_sobrescribe(roots):
    card = T.trash_project(_project(), roots)
    _project()                                                            # otro con el mismo identificador
    with pytest.raises(T.TrashError, match="Ya existe"):
        T.restore(card["item"], roots)
    assert len(T.items(roots)) == 1


def test_eliminar_definitivamente_exige_identificador_y_deja_constancia(roots):
    p = _project()
    card = T.trash_project(p, roots, by="eder")
    with pytest.raises(T.TrashError, match="escribe exactamente"):
        T.purge(card["item"], roots, confirmation="otra-cosa")
    T.purge(card["item"], roots, by="eder", confirmation=p.id)
    assert T.items(roots) == [] and not (roots.trash / card["item"]).exists()
    last = T.registry(roots)[-1]
    assert last["action"] == "purged" and last["id"] == p.id and last["files"][0]["file"] == "datos.csv"
    assert T.verify_registry(roots)["ok"]
    path = roots.trash / T.REGISTRY
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["by"] = "otro"
    path.write_text("\n".join([json.dumps(tampered)] + lines[1:]) + "\n", encoding="utf-8")
    assert not T.verify_registry(roots)["ok"]                            # una edición a mano se detecta


def test_vaciar_exige_la_palabra(roots):
    T.trash_project(_project("Uno"), roots)
    T.trash_project(_project("Dos"), roots)
    with pytest.raises(T.TrashError, match="VACIAR"):
        T.purge_all(roots, confirmation="vaciar")
    assert T.purge_all(roots, confirmation="VACIAR") == 2 and T.items(roots) == []


def test_no_se_elimina_mientras_se_analiza(roots):
    p = _project()
    with pytest.raises(T.TrashError, match="analizándose"):
        T.trash_project(p, roots, running=True)
    assert p.id in _ids()


def test_un_analisis_vinculado_no_toca_la_carpeta_del_servidor(roots, tmp_path):
    inbox = tmp_path / "data" / "inbox" / "srv"
    inbox.mkdir()
    (inbox / "log.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    p = Project.create("Vinculado", str(inbox), ProjectSettings(language="es"))
    card = T.trash_project(p, roots)
    assert (inbox / "log.csv").is_file() and card["source_dir_kept"] == str(inbox) and p.id not in _ids()


def test_caso_suelto_se_mueve_y_vuelve(roots):
    case = roots.cases / "CASO-VIEJO"
    case.mkdir(parents=True)
    (case / "meta.json").write_text("{}", encoding="utf-8")
    card = T.trash_case("CASO-VIEJO", roots, by="eder")
    assert not case.exists()
    T.restore(card["item"], roots)
    assert (case / "meta.json").is_file()


@pytest.mark.parametrize("bad", ["../etc", "..", "", "a/b", "caso con espacios"])
def test_identificadores_manipulados_se_rechazan(roots, bad):
    with pytest.raises(T.TrashError):
        T.trash_case(bad, roots)
    with pytest.raises(T.TrashError):
        T.restore(bad, roots)
    with pytest.raises(T.TrashError):
        T.purge(bad, roots, confirmation=bad)


# --- web ------------------------------------------------------------------------------------------------------------------------------
def test_eliminar_desde_la_interfaz_exige_confirmacion_escrita(roots):
    p = _project()
    page = Client().get(f"/proyectos/{p.id}/eliminar/")
    assert page.status_code == 200 and p.id in page.content.decode() and "Mover a la papelera" in page.content.decode()
    bad = Client().post(f"/proyectos/{p.id}/eliminar/", {"confirmacion": "no"})
    assert bad.status_code == 400 and p.id in _ids()
    ok = Client().post(f"/proyectos/{p.id}/eliminar/", {"confirmacion": p.id, "analista": "eder"})
    assert ok.status_code == 302 and ok["Location"] == "/papelera/" and p.id not in _ids()
    assert T.registry(roots)[-1]["by"] == "eder"


def test_papelera_restaurar_eliminar_y_vaciar_desde_la_interfaz(roots):
    p, q = _project("Uno"), _project("Dos")
    Client().post(f"/proyectos/{p.id}/eliminar/", {"confirmacion": p.id})
    Client().post(f"/proyectos/{q.id}/eliminar/", {"confirmacion": q.id})
    html = Client().get("/papelera/").content.decode()
    assert "Uno" in html and "Dos" in html and "íntegro" in html
    item_p = next(i["item"] for i in T.items(roots) if i["id"] == p.id)
    assert Client().post(f"/papelera/{item_p}/restaurar/").status_code == 200 and p.id in _ids()
    item_q = T.items(roots)[0]["item"]
    assert Client().post(f"/papelera/{item_q}/eliminar/", {"confirmacion": "no"}).status_code == 409
    assert Client().post(f"/papelera/{item_q}/eliminar/", {"confirmacion": q.id}).status_code == 200 and T.items(roots) == []
    T.trash_project(Project.open(p.id), roots)
    assert Client().post("/papelera/vaciar/", {"confirmacion": "x"}).status_code == 409
    assert Client().post("/papelera/vaciar/", {"confirmacion": "VACIAR"}).status_code == 200 and T.items(roots) == []


def test_caso_suelto_desde_la_interfaz_y_404_si_no_existe(roots):
    (roots.cases / "CASO-VIEJO").mkdir(parents=True)
    assert Client().get("/casos/NO-EXISTE/eliminar/").status_code == 404
    assert Client().post("/casos/CASO-VIEJO/eliminar/", {"confirmacion": "CASO-VIEJO"}).status_code == 302
    assert not (roots.cases / "CASO-VIEJO").exists()
