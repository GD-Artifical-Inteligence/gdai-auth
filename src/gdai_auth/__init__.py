"""Mecânica de autenticação compartilhada pelos serviços do GD.AI.

Separada do `gdai-core` por cadência de release: correção de autenticação às
vezes precisa sair na hora, e não pode depender do que mais estiver commitado na
lib de mecânica geral.

A dependência aponta para um lado só — `gdai-auth` usa `gdai-core`, nunca o
contrário. Validar token do Keycloak exige buscar o JWKS, que é chamada HTTP.
"""

from gdai_auth.company_roles import (
    COMPANY_ROLE_REQUIRED_CODE,
    MANAGERS_SUBGROUP,
    OWNERS_SUBGROUP,
    PLATFORM_ADMIN_ROLES,
    CompanyAccess,
    CompanyRole,
    CompanyRoleRequired,
    company_access,
    company_group_path,
    company_role,
    has_at_least,
    is_platform_admin,
    require_company_role,
    role_subgroup_path,
    strongest_role,
)
from gdai_auth.keycloak import (
    AuthProviderUnavailable,
    InvalidToken,
    KeycloakConfig,
    KeycloakUser,
    KeycloakValidator,
)
from gdai_auth.redaction import REDACTED, SENSITIVE_HEADERS, redact_headers
from gdai_auth.service_token import (
    InvalidServiceToken,
    ServiceTokenProvider,
    verify_service_token,
)
from gdai_auth.webhook_signature import (
    InvalidSignature,
    expected_signature,
    timestamped_payload,
    verify,
)

__all__ = [
    "COMPANY_ROLE_REQUIRED_CODE",
    "MANAGERS_SUBGROUP",
    "OWNERS_SUBGROUP",
    "PLATFORM_ADMIN_ROLES",
    "REDACTED",
    "SENSITIVE_HEADERS",
    "AuthProviderUnavailable",
    "CompanyAccess",
    "CompanyRole",
    "CompanyRoleRequired",
    "InvalidToken",
    "KeycloakConfig",
    "KeycloakUser",
    "KeycloakValidator",
    "InvalidServiceToken",
    "InvalidSignature",
    "ServiceTokenProvider",
    "company_access",
    "company_group_path",
    "company_role",
    "expected_signature",
    "has_at_least",
    "is_platform_admin",
    "redact_headers",
    "require_company_role",
    "role_subgroup_path",
    "strongest_role",
    "timestamped_payload",
    "verify",
    "verify_service_token",
]
