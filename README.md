# gdai-auth

Authentication mechanics shared by GD.AI services: service tokens, webhook
signatures, header redaction.

Design and rationale: [lq-api#115](https://github.com/GD-Artifical-Inteligence/lq-api/issues/115).

## Why it is separate from `gdai-core`

Release cadence. An authentication fix sometimes has to ship immediately — a
dependency CVE, a changed issuer, a signature bypass. Shipping it from the same
package as the HTTP client would drag along whatever else happens to be merged.

The dependency points one way: `gdai-auth` uses `gdai-core`, never the reverse.

## What it replaces

| Piece | Copies before |
|---|---|
| `ServiceTokenProvider` | 3, written the same week during the gdai-core migration |
| Service token validation | 3, under three different names and shapes |
| Webhook HMAC | 2 in `lq-api` alone |

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

## Webhook signatures

```python
from gdai_auth import verify, timestamped_payload

verify(body, request.headers.get("X-Hub-Signature-256"), settings.META_APP_SECRET)

# Chatwoot signs "{timestamp}.{body}" rather than the raw body
verify(body, sig, secret, payload_builder=timestamped_payload(timestamp))
```

**With a secret configured, a missing signature is a refusal.** The bug this
exists to prevent was written as `if secret and signature:` — omitting the
header skipped the whole check, so the bypass lived inside the condition meant
to stop it. It appeared in three places and was fixed in three separate PRs,
months apart.

Without a secret, validation does not run. That is the state of a service that
has not configured one yet, not an authorization.

## Header redaction

Lives here rather than with logging, and logging should depend on this. Deciding
what counts as a secret is the security library's job.

The reason is concrete: `lq-api`'s request-logging middleware stored full
headers in Mongo — commented `# Get all headers (no filtering)` — and the routes
serving those records required no authentication.

## Development

```bash
uv sync && uv run pytest && uv run ruff check src tests && uv run pyright src
```
