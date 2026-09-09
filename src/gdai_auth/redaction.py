"""Redação de headers sensíveis.

Mora na lib de segurança e não na de logging, e a inversão é deliberada: quem
decide o que é segredo é esta camada, e o logging depende dela.

O motivo é concreto. O middleware de log da lq-api guardava os headers inteiros
no Mongo — com o comentário `# Get all headers (no filtering)` — e as rotas que
serviam esses registros não pediam autenticação. Qualquer um lia o `Authorization`
de qualquer requisição, com token de usuário válido dentro.
"""

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-hub-signature",
        "x-hub-signature-256",
        "x-chatwoot-signature",
        "x-zd-signature-256",
    }
)

REDACTED = "[redacted]"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Substitui o valor dos headers sensíveis, preservando quais vieram.

    Preserva o nome de propósito: saber que a requisição trazia `Authorization`
    é útil para diagnóstico, e é o valor que não pode ser guardado.
    """
    return {
        nome: (REDACTED if nome.lower() in SENSITIVE_HEADERS else valor)
        for nome, valor in headers.items()
    }
