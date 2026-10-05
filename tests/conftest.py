"""Fixtures compartidas: motores de consulta sobre datasets sintéticos con verdad conocida."""
import itertools

import pytest

from dfir_copilot.engine.query_engine import QueryEngine
from dfir_copilot.ingest.ingestor import ingest_csv
from dfir_copilot.synthetic import make_idor_dataset, write_csv


@pytest.fixture()
def engine_from_rows(tmp_path):
    """Devuelve una función rows -> QueryEngine (admite varios datasets por test)."""
    counter = itertools.count()

    def build(rows):
        d = tmp_path / f"ds{next(counter)}"
        d.mkdir()
        manifest = ingest_csv(write_csv(d / "synthetic.csv", rows), "web_access_meli", out_dir=d / "out")
        return QueryEngine(manifest["output"]["path"])

    return build


@pytest.fixture()
def make_engine(engine_from_rows):
    """Devuelve una función **kwargs -> (QueryEngine, GroundTruth) con un ataque IDOR sintético."""

    def build(**kwargs):
        rows, truth = make_idor_dataset(**kwargs)
        return engine_from_rows(rows), truth

    return build


# --- modelo simulado para probar el agente sin gastar tokens ---------------------------------
from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402


class ScriptedChat(BaseChatModel):
    """Responde con una lista de mensajes (o funciones messages -> AIMessage) y registra lo que recibe."""

    script: list
    cursor: list = [0]
    log: list = []
    tools_bound: bool = False
    strict: bool = True  # emula la API: el prompt de sistema y las herramientas no cambian durante el hilo
    first: list = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools, **kwargs):
        return self.model_copy(update={"tools_bound": True})

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        i = self.cursor[0]
        self.cursor[0] += 1
        assert i < len(self.script), f"el guion se agotó en la llamada {i + 1}"
        item = self.script[i]
        system = messages[0].content if messages and messages[0].type == "system" else None
        if self.strict:
            if not self.first:
                self.first.extend([system, self.tools_bound])
            elif self.first != [system, self.tools_bound]:
                raise ValueError("prefix mismatch: el prompt de sistema o las herramientas cambiaron a mitad del hilo")
        self.log.append({"tools_bound": self.tools_bound, "messages": list(messages)})
        message = item(messages) if callable(item) else item
        return ChatResult(generations=[ChatGeneration(message=message)])


@pytest.fixture()
def scripted():
    return lambda script: ScriptedChat(script=script)
