"""Principal de empresa para tokens de serviço."""

import pytest
from jose import jwt

from gdai_auth import (
    CompanyRole,
    CompanyRoleRequired,
    InvalidServiceToken,
    KeycloakUser,
    ServiceTokenProvider,
    company_role,
    is_platform_admin,
    is_service_principal,
    is_service_token,
    require_company_role,
    resolve_company_principal,
    service_company_principal,
)

SEGREDO = "segredo-compartilhado"
PERMITIDOS = {"mcp-gdai"}


def token_de(service: str = "mcp-gdai", segredo: str = SEGREDO) -> str:
    return ServiceTokenProvider(segredo, service).sign()


def usuario() -> KeycloakUser:
    return KeycloakUser(
        sub="user-1",
        roles=(),
        groups=("/company-acme",),
        email="a@b.com",
        name="A",
        preferred_username="a",
        raw={},
    )


class Validador:
    def __init__(self, resultado=None, erro: Exception | None = None) -> None:
        self.resultado = resultado
        self.erro = erro
        self.recebidos: list[str] = []

    async def __call__(self, token: str) -> KeycloakUser:
        self.recebidos.append(token)
        if self.erro:
            raise self.erro
        return self.resultado


def token_rs256() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    return jwt.encode({"sub": "u"}, pem, algorithm="RS256")


class TestIsServiceToken:
    def test_token_do_provider(self):
        assert is_service_token(token_de()) is True

    def test_token_rs256(self):
        assert is_service_token(token_rs256()) is False

    @pytest.mark.parametrize("valor", [None, "", "lixo"])
    def test_entradas_invalidas(self, valor):
        assert is_service_token(valor) is False


class TestServiceCompanyPrincipal:
    def test_manager(self):
        p = service_company_principal("mcp-gdai", "acme", CompanyRole.MANAGER)
        assert p.groups == ("/company-acme", "/company-acme/managers")
        assert company_role(p, "acme") == CompanyRole.MANAGER

    def test_owner(self):
        p = service_company_principal("mcp-gdai", "acme", CompanyRole.OWNER)
        assert p.groups == ("/company-acme", "/company-acme/owners")
        assert company_role(p, "acme") == CompanyRole.OWNER

    def test_member(self):
        p = service_company_principal("mcp-gdai", "acme", CompanyRole.MEMBER)
        assert p.groups == ("/company-acme",)
        assert company_role(p, "acme") == CompanyRole.MEMBER

    def test_campos_do_principal(self):
        p = service_company_principal("mcp-gdai", "acme")
        assert p.sub == "service:mcp-gdai"
        assert p.roles == ()
        assert p.email is None
        assert p.name == "mcp-gdai"
        assert p.preferred_username == "service:mcp-gdai"
        assert p.raw == {"type": "service", "service": "mcp-gdai"}
        assert company_role(p, "acme") == CompanyRole.MANAGER

    def test_nao_vale_em_outra_empresa_nem_e_admin(self):
        p = service_company_principal("mcp-gdai", "acme")
        assert company_role(p, "beta") is None
        assert is_platform_admin(p) is False

    def test_nao_alcanca_papel_acima(self):
        p = service_company_principal("mcp-gdai", "acme")
        with pytest.raises(CompanyRoleRequired):
            require_company_role(p, "acme", CompanyRole.OWNER)


class TestIsServicePrincipal:
    def test_sintetico(self):
        assert is_service_principal(service_company_principal("mcp-gdai", "acme"))

    def test_usuario_comum(self):
        assert is_service_principal(usuario()) is False


class TestResolveCompanyPrincipal:
    async def test_servico_permitido(self):
        validador = Validador(resultado=usuario())
        p = await resolve_company_principal(
            token_de(),
            "acme",
            secret_key=SEGREDO,
            allowed_services=PERMITIDOS,
            validate_user=validador,
        )
        assert p.sub == "service:mcp-gdai"
        assert company_role(p, "acme") == CompanyRole.MANAGER
        assert company_role(p, "beta") is None
        assert validador.recebidos == []

    async def test_servico_fora_da_allowlist(self):
        with pytest.raises(InvalidServiceToken):
            await resolve_company_principal(
                token_de("outro"),
                "acme",
                secret_key=SEGREDO,
                allowed_services=PERMITIDOS,
                validate_user=Validador(),
            )

    async def test_segredo_errado(self):
        with pytest.raises(InvalidServiceToken):
            await resolve_company_principal(
                token_de(segredo="outro-segredo"),
                "acme",
                secret_key=SEGREDO,
                allowed_services=PERMITIDOS,
                validate_user=Validador(),
            )

    async def test_token_nao_hs256_vai_para_validate_user(self):
        esperado = usuario()
        validador = Validador(resultado=esperado)
        token = token_rs256()
        p = await resolve_company_principal(
            token,
            "acme",
            secret_key=SEGREDO,
            allowed_services=PERMITIDOS,
            validate_user=validador,
        )
        assert p is esperado
        assert validador.recebidos == [token]

    async def test_erro_do_validate_user_propaga(self):
        erro = RuntimeError("keycloak fora")
        with pytest.raises(RuntimeError) as info:
            await resolve_company_principal(
                token_rs256(),
                "acme",
                secret_key=SEGREDO,
                allowed_services=PERMITIDOS,
                validate_user=Validador(erro=erro),
            )
        assert info.value is erro

    async def test_service_role_respeitado(self):
        p = await resolve_company_principal(
            token_de(),
            "acme",
            secret_key=SEGREDO,
            allowed_services=PERMITIDOS,
            validate_user=Validador(),
            service_role=CompanyRole.MEMBER,
        )
        assert company_role(p, "acme") == CompanyRole.MEMBER
