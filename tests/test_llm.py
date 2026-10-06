"""Pruebas de la fábrica de modelos. No hacen llamadas de red: solo construyen los clientes."""
import pytest

from dfir_copilot.agent.llm import LLMConfig, LLMConfigError, make_llm, mask_secret


def test_valores_por_defecto():
    cfg = LLMConfig.from_env({})
    assert cfg.provider == "anthropic" and cfg.model is None and cfg.temperature is None
    assert cfg.resolved_model == "claude-sonnet-5-5"


def test_la_configuracion_se_lee_del_entorno():
    cfg = LLMConfig.from_env({"LLM_PROVIDER": " OpenAI ", "LLM_MODEL": "mi-modelo", "LLM_TEMPERATURE": "none",
                              "LLM_MAX_TOKENS": "512", "LLM_TIMEOUT_S": "15"})
    assert (cfg.provider, cfg.model, cfg.temperature, cfg.max_tokens, cfg.timeout_s) == ("openai", "mi-modelo", None, 512, 15.0)


@pytest.mark.parametrize("bad", [{"LLM_TEMPERATURE": "caliente"}, {"LLM_MAX_TOKENS": "mucho"}, {"LLM_TIMEOUT_S": "x"}])
def test_valores_numericos_invalidos(bad):
    with pytest.raises(LLMConfigError):
        LLMConfig.from_env(bad)


def test_proveedor_no_soportado():
    with pytest.raises(LLMConfigError, match="no soportado"):
        make_llm(env={"LLM_PROVIDER": "inventado"})


def test_anthropic_sin_clave_da_un_mensaje_accionable():
    with pytest.raises(LLMConfigError, match="ANTHROPIC_API_KEY"):
        make_llm(env={})


def test_openai_exige_clave_y_modelo():
    with pytest.raises(LLMConfigError, match="OPENAI_API_KEY"):
        make_llm(env={"LLM_PROVIDER": "openai", "LLM_MODEL": "m"})
    with pytest.raises(LLMConfigError, match="LLM_MODEL"):
        make_llm(env={"LLM_PROVIDER": "openai", "OPENAI_API_KEY": "sk-prueba-1234"})


def test_construye_el_cliente_de_anthropic_sin_filtrar_la_clave():
    pytest.importorskip("langchain_anthropic")
    llm = make_llm(env={"ANTHROPIC_API_KEY": "sk-ant-FAKE-pruebas-1234"})
    assert type(llm).__name__ == "ChatAnthropic" and llm.model == "claude-sonnet-5-5"
    assert "sk-ant-FAKE-pruebas-1234" not in repr(llm)


def test_construye_el_cliente_de_openai():
    pytest.importorskip("langchain_openai")
    llm = make_llm(env={"LLM_PROVIDER": "openai", "LLM_MODEL": "mi-modelo", "OPENAI_API_KEY": "sk-prueba-1234567890"})
    assert type(llm).__name__ == "ChatOpenAI" and llm.model_name == "mi-modelo"


def test_mask_secret():
    assert mask_secret(None) == "(no definida)" and mask_secret("corta") == "****"
    assert mask_secret("sk-ant-FAKE-pruebas-1234") == "…1234"


def test_la_temperatura_solo_se_envia_si_se_configura():
    assert LLMConfig.from_env({"LLM_TEMPERATURE": "0.5"}).temperature == 0.5
    assert LLMConfig.from_env({"LLM_TEMPERATURE": ""}).temperature is None


def test_anthropic_por_defecto_no_fija_temperature():
    """Regresión: claude-sonnet-5-5 rechaza temperature distinta de la predeterminada (ValueError al invocar)."""
    pytest.importorskip("langchain_anthropic")
    llm = make_llm(env={"ANTHROPIC_API_KEY": "sk-ant-FAKE-pruebas-1234"})
    assert llm.temperature is None
    llm._get_request_payload("hola")  # antes de la corrección lanzaba ValueError
