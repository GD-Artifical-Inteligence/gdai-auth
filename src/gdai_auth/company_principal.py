"""Principal de empresa para chamadas de serviço.

Rotas de empresa aceitam dois tipos de chamador: o usuário do Keycloak e outro
serviço, autenticado por token HS256 (`ServiceTokenProvider`). Este módulo
transforma o segundo num `KeycloakUser` sintético, para que o resto do serviço
(`company_role`, `require_company_role`) trate os dois do mesmo jeito.

O principal sintético só existe dentro da empresa do path: os grupos citam só
aquela empresa, não há papel de realm e ele nunca é admin da plataforma. O tipo
de retorno local de cada serviço (Company, Caller) continua sendo dele, e a lib
não conhece framework: o serviço traduz `InvalidServiceToken` para o próprio 401.
"""

from typing import Awaitable, Callable, Iterable

from jose import JWTError, jwt

from gdai_auth.company_roles import (
    MANAGERS_SUBGROUP,
    OWNERS_SUBGROUP,
    CompanyRole,
    company_group_path,
    role_subgroup_path,
)
from gdai_auth.keycloak import KeycloakUser
from gdai_auth.service_token import ALGORITHM, verify_service_token

SERVICE_SUBJECT_PREFIX = "service:"
DEFAULT_SERVICE_COMPANY_ROLE = CompanyRole.MANAGER

_ROLE_SUBGROUPS = {
    CompanyRole.OWNER: OWNERS_SUBGROUP,
    CompanyRole.MANAGER: MANAGERS_SUBGROUP,
}


def is_service_token(token: str | None) -> bool:
    if not token:
        return False
    try:
        # Só escolhe o caminho; a confiança vem de verify_service_token.
        return jwt.get_unverified_header(token).get("alg") == ALGORITHM
    except JWTError:
        return False


def service_company_principal(
    service: str,
    external_id: str,
    role: CompanyRole = DEFAULT_SERVICE_COMPANY_ROLE,
) -> KeycloakUser:
    groups = [company_group_path(external_id)]
    subgroup = _ROLE_SUBGROUPS.get(role)
    if subgroup:
        groups.append(role_subgroup_path(external_id, subgroup))
    subject = f"{SERVICE_SUBJECT_PREFIX}{service}"
    return KeycloakUser(
        sub=subject,
        roles=(),
        groups=tuple(groups),
        email=None,
        name=service,
        preferred_username=subject,
        raw={"type": "service", "service": service},
    )


def is_service_principal(user: KeycloakUser) -> bool:
    return user.raw.get("type") == "service" and user.sub.startswith(
        SERVICE_SUBJECT_PREFIX
    )


async def resolve_company_principal(
    token: str,
    external_id: str,
    *,
    secret_key: str,
    allowed_services: Iterable[str],
    validate_user: Callable[[str], Awaitable[KeycloakUser]],
    service_role: CompanyRole = DEFAULT_SERVICE_COMPANY_ROLE,
) -> KeycloakUser:
    """Resolve o chamador de uma rota de empresa.

    Token HS256 vira principal de serviço (`InvalidServiceToken` sobe sem
    tradução). Qualquer outro vai para `validate_user`, com os erros dele.
    """
    if is_service_token(token):
        service = verify_service_token(token, secret_key, allowed_services)
        return service_company_principal(service, external_id, service_role)
    return await validate_user(token)
