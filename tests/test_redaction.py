"""Redação de headers.

O middleware de log da lq-api guardava os headers inteiros no Mongo, com o
comentário `# Get all headers (no filtering)`, e as rotas que serviam esses
registros não exigiam autenticação. Qualquer um lia o `Authorization` de
qualquer requisição, com token de usuário válido dentro.
"""

from gdai_auth import REDACTED, redact_headers


class TestRedacao:
    def test_redige_authorization(self):
        assert (
            redact_headers({"Authorization": "Bearer abc"})["Authorization"] == REDACTED
        )

    def test_e_insensivel_a_caixa(self):
        """Header chega em qualquer caixa dependendo do cliente e do proxy."""
        for nome in ("authorization", "Authorization", "AUTHORIZATION"):
            assert redact_headers({nome: "Bearer abc"})[nome] == REDACTED

    def test_preserva_o_nome_do_header(self):
        """Saber que a requisição trazia Authorization é útil; o valor é que não
        pode ser guardado."""
        assert "Authorization" in redact_headers({"Authorization": "Bearer abc"})

    def test_nao_toca_no_que_nao_e_sensivel(self):
        assert redact_headers({"Content-Type": "application/json"})["Content-Type"] == (
            "application/json"
        )

    def test_cobre_as_assinaturas_de_webhook(self):
        headers = {
            "X-Hub-Signature-256": "sha256=a",
            "X-Chatwoot-Signature": "sha256=b",
            "X-ZD-Signature-256": "sha256=c",
        }
        assert all(v == REDACTED for v in redact_headers(headers).values())

    def test_cobre_cookie_e_api_key(self):
        headers = {"Cookie": "s=1", "X-Api-Key": "k", "X-Auth-Token": "t"}
        assert all(v == REDACTED for v in redact_headers(headers).values())

    def test_dicionario_vazio(self):
        assert redact_headers({}) == {}
