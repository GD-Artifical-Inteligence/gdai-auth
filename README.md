# gdai-auth

Authentication mechanics shared by GD.AI services: Keycloak token validation,
company roles, service tokens, webhook signatures, header redaction.

Design and rationale: [lq-api#115](https://github.com/GD-Artifical-Inteligence/lq-api/issues/115).

## Why it is separate from `gdai-core`

Release cadence. An authentication fix sometimes has to ship immediately — a
dependency CVE, a changed issuer, a signature bypass. Shipping it from the same
package as the HTTP client would drag along whatever else happens to be merged.

The dependency points one way: `gdai-auth` uses `gdai-core`, never the reverse.

## Company roles

ADR-0019 in the workspace (`docs/adr/0019-company-roles-and-invitations.md`).
The role lives in Keycloak subgroups of the company group and arrives in the
`groups` claim, full path:

| Groups in the token | `company_role(user, "acme")` |
|---|---|
| `/company-acme` | `CompanyRole.MEMBER` |
| `/company-acme`, `/company-acme/managers` | `CompanyRole.MANAGER` |
| `/company-acme`, `/company-acme/owners` | `CompanyRole.OWNER` |
| `/company-acme/owners` without `/company-acme` | `None` |
| nothing of `acme` | `None` |

```python
from gdai_auth import CompanyRole, CompanyRoleRequired, company_access, require_company_role

access = company_access(user, "acme")      # CompanyAccess(role, is_platform_admin)

try:
    require_company_role(user, "acme", CompanyRole.MANAGER)
except CompanyRoleRequired as exc:
    raise ApiError(403, exc.code, "...")   # exc.code == "company_role_required"
```

**The parent group is the access boundary.** A subgroup without the parent
grants nothing: removing someone from the company is removing them from the
parent, and a leftover subgroup must not keep them in.

**The realm `admin` is support, not a role.** `company_role` returns `None` for
an admin outside the group; `is_platform_admin` (`admin` or `realm-admin`) says
they are support, and `require_company_role` lets them through any minimum, as
the access checks always did. An admin who is also in the group gets the real
role from the subgroups.

**The strongest role wins.** Someone in both subgroups is an owner.
`fallback_role` raises the role from a source outside the token — the
company-api passes `OWNER` for the company's `owner_id`, whose token may not
carry the group yet — and never lowers it.

**A change only counts when the token is renewed.** Nothing here calls
Keycloak; the token is the source.

No FastAPI here either: `CompanyRoleRequired` carries `code`, `required` and
`actual`, and each service turns it into a 403 in its own error format.

## Service tokens

```python
from gdai_auth import ServiceTokenProvider, verify_service_token

# outbound: implements gdai-core's TokenProvider protocol
provider = ServiceTokenProvider(settings.JWT_SECRET_KEY, "billing-api")
client = ServiceClient(..., token_provider=provider)

# inbound
service = verify_service_token(token, settings.JWT_SECRET_KEY, {"lq-api", "credits-api"})
```

The allowlist is required. A valid token from a service that should not be
calling this route is still a refusal, and defaulting to "any signed token" is
how that check gets skipped.

`exp` is an int, not a datetime. `python-jose` serializes datetimes with
`utctimetuple()`, which treats a naive one as if it were already UTC — in any
timezone behind UTC the token is born expired, and it goes unnoticed because
containers run in UTC.

## Keycloak user tokens

```python
from gdai_auth import KeycloakConfig, KeycloakValidator, InvalidToken, AuthProviderUnavailable

validator = KeycloakValidator(KeycloakConfig(
    server_url=settings.KEYCLOAK_SERVER_URL,   # how this process reaches Keycloak
    public_url=settings.KEYCLOAK_PUBLIC_URL,   # what the browser sees
    realm="gd-ai",
    client_id="lq-api",                        # for resource_access roles
))

# one instance per process: it holds the JWKS cache
user = await validator.validate(token)
```

Two errors, and the split is the point: `InvalidToken` is a 401,
`AuthProviderUnavailable` is a 503. Collapsing them turns "Keycloak is down"
into "your session expired" and sends everyone to re-login during an outage.

**Set `jwks_url` when the discovered one is not reachable** — behind a proxy,
a tunnel, or from inside a cluster. It is an explicit override and it is the
only supported way to change that URL: a security rule must not hinge on
inspecting a hostname, because the day someone points `server_url` at an
internal name the rule changes without the diff saying so.

**Accepted issuers never include the token's own.** The discovered issuer plus
the public one, because behind a proxy the server discovers the internal URL
while browser tokens carry the public hostname. Trusting what a token says
about who issued it validates nothing.

**Key rotation does not cause an outage.** The JWKS cache has a TTL, and an
unknown `kid` triggers one extra fetch before the token is refused — which is
what separates a rotation from a forged token. Cache it forever somewhere else
and a rotation becomes 401 for everyone until a restart, with nothing in that
service's logs pointing at the cause.

**Audience is unverified unless you set `audience`.** The default matches what
the services do today. It is a field on the config, not an option buried in a
decode call, so turning it on is a one-line change you can find.

## Webhook signatures

```python
from gdai_auth import verify, timestamped_payload

verify(body, request.headers.get("X-Hub-Signature-256"), settings.META_APP_SECRET)

# Chatwoot signs "{timestamp}.{body}" rather than the raw body
verify(body, sig, secret, payload_builder=timestamped_payload(timestamp))
```

**With a secret configured, a missing signature is a refusal.** Never guard the
check with `if secret and signature:` — that skips validation whenever the
header is absent, which puts the bypass inside the condition meant to prevent
it. This has been written three times in this codebase.

Without a secret, validation does not run. That is the state of a service that
has not configured one yet, not an authorization.

## Header redaction

Lives here rather than with logging, and logging should depend on this. Deciding
what counts as a secret is the security library's job.

Redact before anything persists or ships a header: request logs, traces, error
reports. A log store is a credential store the moment an `Authorization` header
lands in it.

## Company principal

Company routes accept two kinds of caller: a Keycloak user and another service
holding an HS256 service token. `resolve_company_principal` maps the second to a
synthetic `KeycloakUser` that is valid only for the company in the path (role
`MANAGER` by default, no realm roles, never a platform admin), so
`company_role` and `require_company_role` work unchanged. Use
`is_service_principal` to mark the audit actor as a service. The library knows
no framework; each service translates `InvalidServiceToken` into its own error.

```python
async def get_company_principal(
    company_external_id: str, token: str = Depends(oauth2_scheme)
) -> KeycloakUser:
    try:
        return await resolve_company_principal(
            token,
            company_external_id,
            secret_key=settings.JWT_SECRET_KEY,
            allowed_services=COMPANY_SERVICE_CALLERS,
            validate_user=get_current_user,
        )
    except InvalidServiceToken as exc:
        raise <the service's 401 error> from exc
```

## Releases

Services depend on this repo by git tag (`[tool.uv.sources]`, `tag = "vX.Y.Z"`),
and `uv.lock` records the commit. A release is a tag; each service moves to it
in its own commit, so one service can run a new version while the rest stay on
the old one.

- `v0.4.0`: company principal for service tokens (`resolve_company_principal`, `service_company_principal`, `is_service_token`, `is_service_principal`).
- `v0.3.0`: company roles (`company_role`, `require_company_role`).
- `v0.3.1`: same API, now on gdai-core `v0.2.2`.
- `v0.2.0`: Keycloak token validation.

## Development

```bash
uv sync && uv run pytest && uv run ruff check src tests && uv run pyright src
```
