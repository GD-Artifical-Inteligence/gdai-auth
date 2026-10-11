import pytest

from gdai_auth import (
    COMPANY_ROLE_REQUIRED_CODE,
    CompanyRole,
    CompanyRoleRequired,
    KeycloakUser,
    company_access,
    company_group_path,
    company_role,
    has_at_least,
    is_platform_admin,
    require_company_role,
    role_subgroup_path,
)

COMPANY = "acme_123"
PARENT = "/company-acme_123"
OWNERS = "/company-acme_123/owners"
MANAGERS = "/company-acme_123/managers"


def _user(groups=(), roles=()) -> KeycloakUser:
    return KeycloakUser(
        sub="kc-1",
        roles=tuple(roles),
        groups=tuple(groups),
        email=None,
        name=None,
        preferred_username=None,
        raw={},
    )


def test_paths_follow_the_keycloak_full_path_claim():
    assert company_group_path(COMPANY) == PARENT
    assert role_subgroup_path(COMPANY, "owners") == OWNERS


def test_parent_group_only_is_member():
    assert company_role(_user([PARENT]), COMPANY) is CompanyRole.MEMBER


def test_managers_subgroup_is_manager():
    assert company_role(_user([PARENT, MANAGERS]), COMPANY) is CompanyRole.MANAGER


def test_owners_subgroup_is_owner():
    assert company_role(_user([PARENT, OWNERS]), COMPANY) is CompanyRole.OWNER


def test_both_subgroups_resolve_to_the_strongest():
    assert company_role(_user([PARENT, MANAGERS, OWNERS]), COMPANY) is CompanyRole.OWNER


def test_no_groups_is_none():
    assert company_role(_user(), COMPANY) is None


def test_subgroup_without_parent_grants_nothing():
    assert company_role(_user([OWNERS]), COMPANY) is None


def test_another_company_does_not_leak():
    other = ["/company-other", "/company-other/owners"]
    assert company_role(_user(other), COMPANY) is None


def test_prefix_of_another_company_does_not_match():
    groups = ["/company-acme_1234", "/company-acme_1234/owners"]
    assert company_role(_user(groups), COMPANY) is None


def test_group_name_without_leading_slash_is_not_accepted():
    assert company_role(_user(["company-acme_123"]), COMPANY) is None


def test_realm_admin_outside_the_group_has_no_role_but_is_platform_admin():
    admin = _user(roles=["admin"])
    access = company_access(admin, COMPANY)
    assert access.role is None
    assert access.is_platform_admin is True


def test_realm_admin_inside_the_group_keeps_the_real_role():
    admin = _user([PARENT, MANAGERS], roles=["realm-admin"])
    access = company_access(admin, COMPANY)
    assert access.role is CompanyRole.MANAGER
    assert is_platform_admin(admin)


def test_plain_user_is_not_platform_admin():
    assert not is_platform_admin(_user([PARENT], roles=["default-roles-gd-ai"]))


@pytest.mark.parametrize(
    ("role", "minimum", "expected"),
    [
        (CompanyRole.OWNER, CompanyRole.MANAGER, True),
        (CompanyRole.MANAGER, CompanyRole.MANAGER, True),
        (CompanyRole.MEMBER, CompanyRole.MANAGER, False),
        (CompanyRole.MANAGER, CompanyRole.OWNER, False),
        (None, CompanyRole.MEMBER, False),
    ],
)
def test_has_at_least(role, minimum, expected):
    assert has_at_least(role, minimum) is expected


def test_require_role_passes_with_enough_role():
    access = require_company_role(
        _user([PARENT, MANAGERS]), COMPANY, CompanyRole.MANAGER
    )
    assert access.role is CompanyRole.MANAGER


def test_require_role_refuses_member_with_stable_code():
    with pytest.raises(CompanyRoleRequired) as raised:
        require_company_role(_user([PARENT]), COMPANY, CompanyRole.MANAGER)
    assert raised.value.code == COMPANY_ROLE_REQUIRED_CODE == "company_role_required"
    assert raised.value.required is CompanyRole.MANAGER
    assert raised.value.actual is CompanyRole.MEMBER


def test_require_role_refuses_outsider():
    with pytest.raises(CompanyRoleRequired):
        require_company_role(_user(["/company-other"]), COMPANY, CompanyRole.MEMBER)


def test_require_role_lets_realm_admin_through_as_support():
    access = require_company_role(_user(roles=["admin"]), COMPANY, CompanyRole.OWNER)
    assert access.is_platform_admin is True
    assert access.role is None


def test_fallback_role_raises_the_effective_role():
    access = require_company_role(
        _user([PARENT]), COMPANY, CompanyRole.OWNER, fallback_role=CompanyRole.OWNER
    )
    assert access.role is CompanyRole.OWNER


def test_fallback_role_never_lowers_the_token_role():
    access = require_company_role(
        _user([PARENT, OWNERS]),
        COMPANY,
        CompanyRole.OWNER,
        fallback_role=CompanyRole.MEMBER,
    )
    assert access.role is CompanyRole.OWNER
