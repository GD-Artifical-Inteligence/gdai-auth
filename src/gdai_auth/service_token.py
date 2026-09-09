"""Tokens de serviço: assinar na saída, validar na entrada.

Chamada entre serviços usa HS256 sobre um `JWT_SECRET_KEY` compartilhado, com
`type == "service"` e o nome de quem chama. Não é token de usuário do Keycloak,
e um não vale pelo outro: aceitar token de usuário numa rota de serviço daria a
qualquer pessoa logada o que a rota expõe de todas as empresas.
"""

import time
from typing import Iterable

from jose import JWTError, jwt

ALGORITHM = "HS256"
TOKEN_TYPE = "service"
DEFAULT_TTL_SECONDS = 3600


class InvalidServiceToken(Exception):
    """Token ausente, malformado, expirado, ou de um serviço fora da lista."""


class ServiceTokenProvider:
    """Assina o token que o `ServiceClient` do gdai-core anexa às chamadas.

    Implementa o protocolo `TokenProvider` que o gdai-core declara — por isso a
    assinatura de `token_for` recebe o serviço de destino e não o usa: quem
    assina é sempre este serviço, e o destino só importa para quem quiser
    variar a chave por upstream.

    Assina a cada requisição em vez de guardar o token. Guardar significa que um
    worker de vida longa acaba mandando token vencido, e a falha aparece como
    401 esporádico, que é dos sintomas mais caros de diagnosticar.
    """

    def __init__(
        self,
        secret_key: str,
        service: str,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        if not secret_key:
            raise ValueError("secret_key é obrigatório para assinar token de serviço")
        self._secret_key = secret_key
        self._service = service
        self._ttl = ttl_seconds

    def sign(self) -> str:
        agora = int(time.time())
        payload = {
            "type": TOKEN_TYPE,
            "service": self._service,
            "iat": agora,
            # Inteiro, e não datetime. O jose serializa datetime com
            # `utctimetuple()`, que trata um naive como se já fosse UTC — em
            # qualquer fuso atrás de UTC o token nasce vencido, e passa
            # despercebido porque o container roda em UTC.
            "exp": agora + self._ttl,
        }
        return jwt.encode(payload, self._secret_key, algorithm=ALGORITHM)

    async def token_for(self, service: str) -> str:
        return self.sign()


def verify_service_token(
    token: str | None,
    secret_key: str,
    allowed_services: Iterable[str],
) -> str:
    """Valida o token e devolve o nome do serviço que o assinou.

    Levanta `InvalidServiceToken` em qualquer recusa, sem distinguir o motivo na
    exceção: dizer a quem chama se o segredo estava errado ou se o serviço não
    era permitido é dizer mais do que ele precisa.

    A lista de serviços permitidos é obrigatória. Um token válido de um serviço
    que não deveria estar chamando esta rota continua sendo uma recusa.
    """
    if not token:
        raise InvalidServiceToken("token ausente")

    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise InvalidServiceToken("token inválido") from exc

    if payload.get("type") != TOKEN_TYPE:
        # Token de usuário do Keycloak chega aqui: é RS256 e não tem `type`,
        # então já falharia no decode — mas a checagem fica explícita para o
        # caso de alguém passar a assinar tokens de usuário com o mesmo segredo.
        raise InvalidServiceToken("não é um token de serviço")

    service = payload.get("service")
    permitidos = set(allowed_services)
    if not service or service not in permitidos:
        raise InvalidServiceToken("serviço não autorizado")

    return service
