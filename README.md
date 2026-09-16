# gdai-auth

Authentication mechanics shared by GD.AI services: Keycloak token validation,
service tokens, webhook signatures, header redaction.

Design and rationale: [lq-api#115](https://github.com/GD-Artifical-Inteligence/lq-api/issues/115).

## Why it is separate from `gdai-core`

Release cadence. An authentication fix sometimes has to ship immediately — a
dependency CVE, a changed issuer, a signature bypass. Shipping it from the same
package as the HTTP client would drag along whatever else happens to be merged.

The dependency points one way: `gdai-auth` uses `gdai-core`, never the reverse.

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

## Development

```bash
uv sync && uv run pytest && uv run ruff check src tests && uv run pyright src
```
