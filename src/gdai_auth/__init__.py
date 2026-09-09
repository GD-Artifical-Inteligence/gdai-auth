"""Mecânica de autenticação compartilhada pelos serviços do GD.AI.

Separada do `gdai-core` por cadência de release: correção de autenticação às
vezes precisa sair na hora, e não pode depender do que mais estiver commitado na
lib de mecânica geral.

A dependência aponta para um lado só — `gdai-auth` usa `gdai-core`, nunca o
contrário. Validar token do Keycloak exige buscar o JWKS, que é chamada HTTP.
"""

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
    "REDACTED",
    "SENSITIVE_HEADERS",
    "InvalidServiceToken",
    "InvalidSignature",
    "ServiceTokenProvider",
    "expected_signature",
    "redact_headers",
    "timestamped_payload",
    "verify",
    "verify_service_token",
]
