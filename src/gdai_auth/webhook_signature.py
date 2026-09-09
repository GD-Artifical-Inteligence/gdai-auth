"""Assinatura HMAC de webhook.

O bug que este módulo existe para não repetir: a checagem estava escrita como
`if secret and signature:`. Com o segredo configurado, **não mandar o header**
pulava a validação inteira — o bypass morava dentro da própria condição que
devia impedi-lo. Apareceu em três lugares (bridge da Meta, `zd-to-chatwoot` e o
provider do Chatwoot) e foi corrigido em três PRs distintos.

Aqui, segredo configurado e assinatura ausente é recusa, sempre.
"""

import hashlib
import hmac
from typing import Callable

PREFIX = "sha256="


class InvalidSignature(Exception):
    """Assinatura ausente quando exigida, ou que não bate com o corpo."""


def expected_signature(body: bytes, secret: str) -> str:
    """A assinatura que o corpo deveria ter."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"{PREFIX}{digest}"


def verify(
    body: bytes,
    signature: str | None,
    secret: str | None,
    *,
    payload_builder: Callable[[bytes], bytes] | None = None,
) -> None:
    """Valida `signature` contra `body`. Não devolve nada; levanta ou passa.

    Sem `secret` configurado a validação não roda — é o estado de quem ainda não
    configurou, não uma autorização. **Mas com o segredo presente, assinatura
    ausente é recusa**, que é o ponto do módulo.

    `payload_builder` existe porque nem todo mundo assina o corpo cru: o Chatwoot
    assina `{timestamp}.{body}`. Sem esse parâmetro haveria uma segunda
    implementação de HMAC, que é exatamente o que existe hoje na lq-api.
    """
    if not secret:
        return

    if not signature:
        raise InvalidSignature("assinatura ausente")

    payload = payload_builder(body) if payload_builder else body
    esperada = expected_signature(payload, secret)

    # compare_digest e não `==`: comparação normal termina no primeiro byte
    # diferente, e o tempo até terminar revela quantos bytes estavam certos.
    if not hmac.compare_digest(esperada, signature):
        raise InvalidSignature("assinatura inválida")


def timestamped_payload(timestamp: str) -> Callable[[bytes], bytes]:
    """Builder para quem assina `{timestamp}.{body}`, como o Chatwoot."""

    def build(body: bytes) -> bytes:
        return f"{timestamp}.".encode("utf-8") + body

    return build
