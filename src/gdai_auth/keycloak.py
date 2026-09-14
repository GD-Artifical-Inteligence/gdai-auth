"""Validação de token de usuário do Keycloak.

Existe porque três serviços implementaram isto separadamente e as três cópias
já divergiram: só uma tinha a correção de múltiplos issuers, e a `kb-api`
nasceu com uma quarta cópia literal por não haver para onde apontar.

O que este módulo NÃO faz: provisionar usuário, resolver empresa, decidir se
alguém pode ver o quê. Isso é domínio e fica em cada serviço. Aqui só se
responde "este token é válido, e o que ele afirma".

Sem FastAPI: quem usa monta a própria dependency. Amarrar a lib a um framework
inviabilizaria usá-la de um worker do Celery, que é onde a `lq-api` também
precisa validar token.
"""

from dataclasses import dataclass, field
from typing import Any, Mapping

from gdai_core.client import ServiceClient
from gdai_core.errors import ServiceError
from gdai_core.policy import RequestPolicy
from jose import JWTError, jwt

ALGORITHMS = ["RS256"]


class InvalidToken(Exception):
    """O token não vale: assinatura, expiração, issuer ou audience.

    Separada de `AuthProviderUnavailable` porque o chamador responde 401 aqui e
    503 lá. Colapsar as duas transforma "o Keycloak caiu" em "sua sessão
    expirou", e manda todo mundo relogar durante uma indisponibilidade.
    """


class AuthProviderUnavailable(Exception):
    """Não deu para falar com o Keycloak para buscar as chaves."""


@dataclass(frozen=True)
class KeycloakUser:
    """O que o token afirma, já extraído.

    `raw` fica acessível porque cada serviço lê um claim diferente e adivinhar
    quais aqui seria condenar a lib a um release por claim novo.
    """

    sub: str
    roles: tuple[str, ...]
    groups: tuple[str, ...]
    email: str | None
    name: str | None
    preferred_username: str | None
    raw: Mapping[str, Any]


@dataclass(frozen=True)
class KeycloakConfig:
    """Onde fica o Keycloak e o que se aceita de um token.

    `jwks_url` é override explícito, não heurística. A versão anterior disto
    reescrevia a URL anunciada pelo discovery quando `KEYCLOAK_SERVER_URL`
    continha "localhost" ou "keycloak" — o que, com o serviço apontado para
    `keycloak.keycloak.svc.cluster.local`, afrouxaria a validação dentro do
    cluster sem ninguém pedir. Configuração que muda regra de segurança não
    pode depender de substring em hostname.
    """

    server_url: str
    realm: str
    public_url: str | None = None
    client_id: str | None = None
    # `None` significa não verificar audience — que é o comportamento de hoje
    # nos três serviços. Fica explícito no tipo em vez de escondido num
    # `options={"verify_aud": False}` no meio do decode.
    audience: str | None = None
    jwks_url: str | None = None
    extra_issuers: tuple[str, ...] = field(default_factory=tuple)
    # JWKS em cache eterno significa que uma rotação de chave no Keycloak
    # derruba autenticação até alguém reiniciar o processo, e o sintoma é 401
    # para todo mundo sem nada nos logs do serviço.
    cache_ttl_seconds: float = 300.0
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not self.server_url:
            raise ValueError("server_url é obrigatório")
        if not self.realm:
            raise ValueError("realm é obrigatório")

    @property
    def discovery_url(self) -> str:
        base = self.server_url.rstrip("/")
        return f"{base}/realms/{self.realm}/.well-known/openid-configuration"

    def accepted_issuers(self, advertised: str) -> tuple[str, ...]:
        """Os issuers que este serviço aceita, em ordem de descoberta.

        O anunciado pelo discovery mais o público, porque atrás de proxy ou
        túnel o servidor descobre a URL interna enquanto o token do browser
        carrega o hostname público. Nunca o issuer do próprio token: aceitar o
        que o token afirma sobre quem o emitiu não valida nada.
        """
        issuers = [advertised]
        if self.public_url:
            publico = f"{self.public_url.rstrip('/')}/realms/{self.realm}"
            if publico not in issuers:
                issuers.append(publico)
        for extra in self.extra_issuers:
            if extra not in issuers:
                issuers.append(extra)
        return tuple(issuers)


@dataclass(frozen=True)
class _Chaves:
    jwks: Mapping[str, Any]
    issuers: tuple[str, ...]
    obtidas_em: float


class KeycloakValidator:
    """Busca as chaves do realm e valida token contra elas.

    Uma instância por processo: ela guarda o JWKS. Construir uma por requisição
    faz uma chamada ao Keycloak por requisição.
    """

    def __init__(
        self,
        config: KeycloakConfig,
        *,
        client: ServiceClient | None = None,
        agora: Any = None,
    ) -> None:
        self._config = config
        self._client = client or ServiceClient(
            base_url=config.server_url,
            service="keycloak",
            # Uma tentativa a mais: buscar JWKS é idempotente, e a alternativa
            # é derrubar autenticação inteira por um blip de rede.
            policy=RequestPolicy(timeout=config.timeout_seconds, retries=2),
        )
        if agora is None:
            import time

            agora = time.monotonic
        self._agora = agora
        self._chaves: _Chaves | None = None

    async def validate(self, token: str | None) -> KeycloakUser:
        """Valida e devolve o que o token afirma.

        Levanta `InvalidToken` se o token não presta e
        `AuthProviderUnavailable` se não deu para buscar as chaves.
        """
        if not token:
            raise InvalidToken("token ausente")

        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except JWTError as exc:
            raise InvalidToken("cabeçalho do token ilegível") from exc

        chaves = await self._obter_chaves()
        rsa_key = _chave_por_kid(chaves.jwks, kid)
        if rsa_key is None:
            # Pode ser token forjado, mas também é exatamente o que se vê
            # depois de uma rotação de chave. Uma busca extra distingue os dois
            # casos; sem ela, a rotação vira incidente.
            chaves = await self._obter_chaves(forcar=True)
            rsa_key = _chave_por_kid(chaves.jwks, kid)
        if rsa_key is None:
            raise InvalidToken("token assinado por chave desconhecida")

        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                issuer=list(chaves.issuers),
                audience=self._config.audience,
                options={"verify_aud": self._config.audience is not None},
            )
        except JWTError as exc:
            raise InvalidToken("token inválido") from exc

        return self._para_usuario(payload)

    async def _obter_chaves(self, *, forcar: bool = False) -> _Chaves:
        atual = self._chaves
        if not forcar and atual is not None:
            idade = self._agora() - atual.obtidas_em
            if idade < self._config.cache_ttl_seconds:
                return atual

        try:
            discovery = await self._client.get(self._config.discovery_url)
            emissor = (discovery.body or {}).get("issuer")
            jwks_url = self._config.jwks_url or (discovery.body or {}).get("jwks_uri")
            if not emissor or not jwks_url:
                raise AuthProviderUnavailable(
                    "discovery do Keycloak sem issuer ou jwks_uri"
                )
            resposta = await self._client.get(jwks_url)
        except ServiceError as exc:
            # Falha de transporte vira 503 no chamador, nunca 401. O serviço
            # está indisponível; a credencial de quem chamou não tem culpa.
            raise AuthProviderUnavailable("Keycloak não respondeu") from exc

        jwks = resposta.body or {}
        if not jwks.get("keys"):
            raise AuthProviderUnavailable("JWKS vazio")

        novas = _Chaves(
            jwks=jwks,
            issuers=self._config.accepted_issuers(emissor),
            obtidas_em=self._agora(),
        )
        self._chaves = novas
        return novas

    def _para_usuario(self, payload: Mapping[str, Any]) -> KeycloakUser:
        sub = payload.get("sub")
        if not sub:
            raise InvalidToken("token sem sub")

        roles: list[str] = list(payload.get("realm_access", {}).get("roles", []))
        if self._config.client_id:
            acesso = payload.get("resource_access", {}).get(self._config.client_id, {})
            roles.extend(acesso.get("roles", []))

        return KeycloakUser(
            sub=sub,
            roles=tuple(roles),
            groups=tuple(payload.get("groups", [])),
            email=payload.get("email"),
            name=payload.get("name"),
            preferred_username=payload.get("preferred_username"),
            raw=payload,
        )


def _chave_por_kid(jwks: Mapping[str, Any], kid: str | None) -> dict[str, str] | None:
    if not kid:
        return None
    for chave in jwks.get("keys", []):
        if chave.get("kid") == kid:
            return {
                "kty": chave["kty"],
                "kid": chave["kid"],
                "use": chave.get("use", "sig"),
                "n": chave["n"],
                "e": chave["e"],
            }
    return None
