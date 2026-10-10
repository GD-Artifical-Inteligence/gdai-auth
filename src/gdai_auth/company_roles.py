from dataclasses import dataclass
from enum import StrEnum

from gdai_auth.keycloak import KeycloakUser

COMPANY_GROUP_PREFIX = "company-"
OWNERS_SUBGROUP = "owners"
MANAGERS_SUBGROUP = "managers"
PLATFORM_ADMIN_ROLES = ("admin", "realm-admin")
COMPANY_ROLE_REQUIRED_CODE = "company_role_required"


class CompanyRole(StrEnum):
    OWNER = "owner"
    MANAGER = "manager"
    MEMBER = "member"


ROLE_RANK = {CompanyRole.MEMBER: 1, CompanyRole.MANAGER: 2, CompanyRole.OWNER: 3}

SUBGROUP_ROLES = {
    OWNERS_SUBGROUP: CompanyRole.OWNER,
    MANAGERS_SUBGROUP: CompanyRole.MANAGER,
}


class CompanyRoleRequired(Exception):
    code = COMPANY_ROLE_REQUIRED_CODE

    def __init__(
        self, external_id: str, required: CompanyRole, actual: CompanyRole | None
    ) -> None:
        super().__init__(
            f"company {external_id} requires {required}, caller has {actual}"
        )
        self.external_id = external_id
        self.required = required
        self.actual = actual


@dataclass(frozen=True)
class CompanyAccess:
    role: CompanyRole | None
    is_platform_admin: bool


def company_group_path(external_id: str) -> str:
    return f"/{COMPANY_GROUP_PREFIX}{external_id}"


def role_subgroup_path(external_id: str, subgroup: str) -> str:
    return f"{company_group_path(external_id)}/{subgroup}"


def is_platform_admin(user: KeycloakUser) -> bool:
    return any(role in user.roles for role in PLATFORM_ADMIN_ROLES)


def strongest_role(*roles: CompanyRole | None) -> CompanyRole | None:
    present = [role for role in roles if role is not None]
    return max(present, key=ROLE_RANK.__getitem__, default=None)


def has_at_least(role: CompanyRole | None, minimum: CompanyRole) -> bool:
    return role is not None and ROLE_RANK[role] >= ROLE_RANK[minimum]


# O grupo pai é a fronteira de acesso: subgrupo sem o pai não dá papel nenhum.
def company_role(user: KeycloakUser, external_id: str) -> CompanyRole | None:
    groups = set(user.groups)
    if company_group_path(external_id) not in groups:
        return None
    subgroup_roles = (
        role
        for subgroup, role in SUBGROUP_ROLES.items()
        if role_subgroup_path(external_id, subgroup) in groups
    )
    return strongest_role(CompanyRole.MEMBER, *subgroup_roles)


def company_access(user: KeycloakUser, external_id: str) -> CompanyAccess:
    return CompanyAccess(
        role=company_role(user, external_id), is_platform_admin=is_platform_admin(user)
    )


# O admin de realm é o suporte: passa em qualquer checagem, sem ganhar papel.
def require_company_role(
    user: KeycloakUser,
    external_id: str,
    minimum: CompanyRole,
    *,
    fallback_role: CompanyRole | None = None,
) -> CompanyAccess:
    access = company_access(user, external_id)
    effective = strongest_role(access.role, fallback_role)
    if access.is_platform_admin or has_at_least(effective, minimum):
        return CompanyAccess(role=effective, is_platform_admin=access.is_platform_admin)
    raise CompanyRoleRequired(external_id, minimum, effective)
