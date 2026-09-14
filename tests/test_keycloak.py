"""Testes do validador de token do Keycloak.

Assina tokens de verdade com uma chave RSA gerada na hora, em vez de mockar o
`jwt.decode`. Mockar o decode testaria que o código chama a biblioteca, não que
o token é recusado — e é a recusa que importa aqui.
"""

import base64
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from gdai_core.client import ServiceClient
from gdai_core.errors import ServiceUnavailable
from gdai_core.policy import RequestPolicy
from gdai_core.transport import RawResponse, Request
from jose import jwt

from gdai_auth.keycloak import (
    AuthProviderUnavailable,
    InvalidToken,
    KeycloakConfig,
    KeycloakValidator,
)

SERVER = "http://keycloak:8080"
PUBLICO = "https://auth.gdai.chat"
REALM = "gd-ai"
EMISSOR_INTERNO = f"{SERVER}/realms/{REALM}"
EMISSOR_PUBLICO = f"{PUBLICO}/realms/{REALM}"


def _para_base64url(valor: int) -> str:
    bruto = valor.to_bytes((valor.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(bruto).rstrip(b"=").decode()


class ChaveDeTeste:
    """Uma chave RSA e o JWKS que a anuncia."""

    def __init__(self, kid: str) -> None:
        self.kid = kid
        self._privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self._privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    def jwk(self) -> dict:
        numeros = self._privada.public_key().public_numbers()
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": _para_base64url(numeros.n),
            "e": _para_base64url(numeros.e),
        }

    def assinar(self, claims: dict) -> str:
        return jwt.encode(
            claims, self.pem, algorithm="RS256", headers={"kid": self.kid}
        )


def claims(**overrides) -> dict:
    agora = int(time.time())
    base = {
        "sub": "user-1",
        "iss": EMISSOR_PUBLICO,
        "iat": agora,
        "exp": agora + 300,
        "realm_access": {"roles": ["user"]},
        "resource_access": {"lq-api": {"roles": ["company-admin"]}},
        "groups": ["/company-acme"],
        "email": "quem@exemplo.com",
        "name": "Quem Chamou",
        "preferred_username": "quem",
    }
    base.update(overrides)
    return base


class TransporteFalso:
    """Responde discovery e JWKS, e conta quantas vezes foi chamado."""

    def __init__(self, jwks: dict, *, jwks_url: str | None = None) -> None:
        self.jwks = jwks
        self.jwks_url = (
            jwks_url or f"{SERVER}/realms/{REALM}/protocol/openid-connect/certs"
        )
        self.urls: list[str] = []
        self.falhar = False

    async def send(self, request: Request) -> RawResponse:
        self.urls.append(request.url)
        if self.falhar:
            raise ConnectionError("sem rota")
        import json

        if ".well-known" in request.url:
            corpo = {"issuer": EMISSOR_INTERNO, "jwks_uri": self.jwks_url}
        else:
            corpo = self.jwks
        return RawResponse(
            status=200,
            headers={"content-type": "application/json"},
            content=json.dumps(corpo).encode(),
        )


def montar(config: KeycloakConfig, transporte: TransporteFalso) -> KeycloakValidator:
    cliente = ServiceClient(
        base_url=SERVER,
        service="keycloak",
        policy=RequestPolicy(timeout=1.0),
        transport=transporte,
    )
    return KeycloakValidator(config, client=cliente)


@pytest.fixture
def chave() -> ChaveDeTeste:
    return ChaveDeTeste("kid-1")


@pytest.fixture
def config() -> KeycloakConfig:
    return KeycloakConfig(
        server_url=SERVER,
        realm=REALM,
        public_url=PUBLICO,
        client_id="lq-api",
    )


async def test_token_valido_vira_usuario(chave, config):
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    usuario = await validador.validate(chave.assinar(claims()))

    assert usuario.sub == "user-1"
    assert usuario.groups == ("/company-acme",)
    assert usuario.email == "quem@exemplo.com"


async def test_roles_juntam_realm_e_client(chave, config):
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    usuario = await validador.validate(chave.assinar(claims()))

    assert set(usuario.roles) == {"user", "company-admin"}


async def test_roles_do_client_ficam_de_fora_sem_client_id(chave):
    config = KeycloakConfig(server_url=SERVER, realm=REALM, public_url=PUBLICO)
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    usuario = await validador.validate(chave.assinar(claims()))

    assert set(usuario.roles) == {"user"}


async def test_aceita_o_emissor_interno_alem_do_publico(chave, config):
    """Atrás de proxy, o discovery anuncia a URL interna e o token traz a pública."""
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    usuario = await validador.validate(chave.assinar(claims(iss=EMISSOR_INTERNO)))

    assert usuario.sub == "user-1"


async def test_recusa_emissor_desconhecido(chave, config):
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    with pytest.raises(InvalidToken):
        await validador.validate(
            chave.assinar(claims(iss="https://invasor.exemplo/realms/gd-ai"))
        )


async def test_recusa_token_expirado(chave, config):
    agora = int(time.time())
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    with pytest.raises(InvalidToken):
        await validador.validate(chave.assinar(claims(exp=agora - 10, iat=agora - 600)))


async def test_recusa_token_de_outra_chave(chave, config):
    """Assinado por uma chave que o realm não anuncia."""
    invasora = ChaveDeTeste("kid-1")  # mesmo kid, chave diferente
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    with pytest.raises(InvalidToken):
        await validador.validate(invasora.assinar(claims()))


async def test_recusa_token_ausente(config, chave):
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    with pytest.raises(InvalidToken):
        await validador.validate(None)


async def test_audience_nao_e_verificada_por_padrao(chave, config):
    """O comportamento de hoje nos três serviços, explícito em vez de implícito."""
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    usuario = await validador.validate(chave.assinar(claims(aud="outro-client")))

    assert usuario.sub == "user-1"


async def test_audience_configurada_e_verificada(chave):
    config = KeycloakConfig(
        server_url=SERVER, realm=REALM, public_url=PUBLICO, audience="lq-api"
    )
    validador = montar(config, TransporteFalso({"keys": [chave.jwk()]}))

    assert (
        await validador.validate(chave.assinar(claims(aud="lq-api")))
    ).sub == "user-1"

    with pytest.raises(InvalidToken):
        await validador.validate(chave.assinar(claims(aud="outro-client")))


async def test_jwks_fica_em_cache_entre_chamadas(chave, config):
    transporte = TransporteFalso({"keys": [chave.jwk()]})
    validador = montar(config, transporte)

    await validador.validate(chave.assinar(claims()))
    await validador.validate(chave.assinar(claims()))

    # Discovery + JWKS uma vez só, não uma vez por requisição.
    assert len(transporte.urls) == 2


async def test_rotacao_de_chave_nao_derruba_autenticacao(chave, config):
    """Kid desconhecido dispara uma busca extra antes de recusar.

    Sem isto, uma rotação no Keycloak vira 401 para todo mundo até alguém
    reiniciar o processo — e nada no log do serviço aponta para a causa.
    """
    transporte = TransporteFalso({"keys": [chave.jwk()]})
    validador = montar(config, transporte)
    await validador.validate(chave.assinar(claims()))

    nova = ChaveDeTeste("kid-2")
    transporte.jwks = {"keys": [nova.jwk()]}

    usuario = await validador.validate(nova.assinar(claims()))

    assert usuario.sub == "user-1"


async def test_kid_desconhecido_ainda_e_recusado_depois_da_rebusca(chave, config):
    transporte = TransporteFalso({"keys": [chave.jwk()]})
    validador = montar(config, transporte)
    desconhecida = ChaveDeTeste("kid-forjado")

    with pytest.raises(InvalidToken):
        await validador.validate(desconhecida.assinar(claims()))


async def test_jwks_url_explicita_vence_o_discovery(chave, config):
    """Override é configuração, não heurística de substring em hostname."""
    interna = "http://keycloak.keycloak.svc.cluster.local:8080/certs"
    config = KeycloakConfig(
        server_url=SERVER, realm=REALM, public_url=PUBLICO, jwks_url=interna
    )
    transporte = TransporteFalso(
        {"keys": [chave.jwk()]}, jwks_url="http://anunciado-errado/certs"
    )
    validador = montar(config, transporte)

    await validador.validate(chave.assinar(claims()))

    assert interna in transporte.urls
    assert "http://anunciado-errado/certs" not in transporte.urls


async def test_keycloak_fora_do_ar_nao_vira_token_invalido(chave, config):
    """503, não 401: a credencial de quem chamou não tem culpa."""
    transporte = TransporteFalso({"keys": [chave.jwk()]})
    transporte.falhar = True
    validador = montar(config, transporte)

    with pytest.raises(AuthProviderUnavailable):
        await validador.validate(chave.assinar(claims()))


async def test_falha_de_transporte_chega_como_causa(chave, config):
    transporte = TransporteFalso({"keys": [chave.jwk()]})
    transporte.falhar = True
    validador = montar(config, transporte)

    with pytest.raises(AuthProviderUnavailable) as exc:
        await validador.validate(chave.assinar(claims()))

    assert isinstance(exc.value.__cause__, ServiceUnavailable)


def test_config_exige_server_url():
    with pytest.raises(ValueError):
        KeycloakConfig(server_url="", realm=REALM)


def test_config_exige_realm():
    with pytest.raises(ValueError):
        KeycloakConfig(server_url=SERVER, realm="")


def test_issuers_aceitos_nao_incluem_o_do_token():
    config = KeycloakConfig(server_url=SERVER, realm=REALM, public_url=PUBLICO)

    aceitos = config.accepted_issuers(EMISSOR_INTERNO)

    assert aceitos == (EMISSOR_INTERNO, EMISSOR_PUBLICO)
