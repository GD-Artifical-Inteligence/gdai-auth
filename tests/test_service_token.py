"""Tokens de serviço.

Este código existia em três repositórios, em três formatos diferentes — e as
três cópias de quem *assina* foram escritas na mesma semana, durante a migração
para o gdai-core. Duplicação recém-criada é a mais barata de desfazer.
"""

import time

import pytest
from jose import jwt

from gdai_auth import InvalidServiceToken, ServiceTokenProvider, verify_service_token

SEGREDO = "segredo-compartilhado"
PERMITIDOS = {"lq-api", "credits-api", "billing-api"}


def provider(service: str = "lq-api", **kw) -> ServiceTokenProvider:
    return ServiceTokenProvider(SEGREDO, service, **kw)


class TestAssinatura:
    def test_token_tem_a_forma_que_os_servicos_validam(self):
        payload = jwt.decode(provider().sign(), SEGREDO, algorithms=["HS256"])
        assert payload["type"] == "service"
        assert payload["service"] == "lq-api"

    def test_token_nasce_valido(self):
        """O jose serializa datetime com utctimetuple(), que trata naive como se
        já fosse UTC — em UTC-3 um naive nasceria vencido. Por isso exp é int."""
        payload = jwt.decode(provider().sign(), SEGREDO, algorithms=["HS256"])
        assert payload["exp"] > time.time()

    def test_ttl_configuravel(self):
        payload = jwt.decode(
            provider(ttl_seconds=60).sign(), SEGREDO, algorithms=["HS256"]
        )
        assert payload["exp"] - payload["iat"] == 60

    def test_recusa_construir_sem_segredo(self):
        """Um provider sem segredo assinaria com string vazia e o token passaria
        na validação de qualquer um que também não tenha configurado."""
        with pytest.raises(ValueError):
            ServiceTokenProvider("", "lq-api")

    async def test_implementa_o_protocolo_do_gdai_core(self):
        assert await provider().token_for("credits-api")

    def test_assina_de_novo_a_cada_chamada(self):
        """Guardar o token faz worker de vida longa mandar token vencido — e o
        sintoma é 401 esporádico, dos mais caros de diagnosticar."""
        p = provider(ttl_seconds=3600)
        primeiro = jwt.decode(p.sign(), SEGREDO, algorithms=["HS256"])
        time.sleep(1.05)
        segundo = jwt.decode(p.sign(), SEGREDO, algorithms=["HS256"])
        assert segundo["iat"] > primeiro["iat"]


class TestValidacao:
    def test_aceita_token_de_servico_permitido(self):
        assert verify_service_token(provider().sign(), SEGREDO, PERMITIDOS) == "lq-api"

    def test_recusa_token_ausente(self):
        with pytest.raises(InvalidServiceToken):
            verify_service_token(None, SEGREDO, PERMITIDOS)

    def test_recusa_outro_segredo(self):
        with pytest.raises(InvalidServiceToken):
            verify_service_token(provider().sign(), "outro-segredo", PERMITIDOS)

    def test_recusa_servico_fora_da_lista(self):
        """Token válido de quem não deveria estar chamando continua sendo recusa."""
        token = ServiceTokenProvider(SEGREDO, "servico-desconhecido").sign()
        with pytest.raises(InvalidServiceToken):
            verify_service_token(token, SEGREDO, PERMITIDOS)

    def test_recusa_token_vencido(self):
        vencido = jwt.encode(
            {"type": "service", "service": "lq-api", "exp": int(time.time()) - 10},
            SEGREDO,
            algorithm="HS256",
        )
        with pytest.raises(InvalidServiceToken):
            verify_service_token(vencido, SEGREDO, PERMITIDOS)

    def test_recusa_token_sem_type(self):
        sem_type = jwt.encode(
            {"service": "lq-api", "exp": int(time.time()) + 60},
            SEGREDO,
            algorithm="HS256",
        )
        with pytest.raises(InvalidServiceToken):
            verify_service_token(sem_type, SEGREDO, PERMITIDOS)

    def test_lista_vazia_recusa_tudo(self):
        """Não configurar a lista não pode ser o mesmo que permitir todos."""
        with pytest.raises(InvalidServiceToken):
            verify_service_token(provider().sign(), SEGREDO, [])
