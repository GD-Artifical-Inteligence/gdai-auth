"""Assinatura de webhook, e o bypass que este módulo existe para não repetir.

A checagem era `if secret and signature:`. Com o segredo configurado, **omitir o
header** pulava a validação inteira — o bypass morava dentro da própria condição
que devia impedi-lo. Aconteceu em três lugares e foi corrigido em três PRs
separados, meses depois.
"""

import pytest

from gdai_auth import InvalidSignature, expected_signature, timestamped_payload, verify

SEGREDO = "segredo-do-webhook"
CORPO = b'{"event":"message_created","id":42}'


def assinar(corpo: bytes = CORPO, segredo: str = SEGREDO) -> str:
    return expected_signature(corpo, segredo)


class TestOBypass:
    def test_segredo_configurado_e_header_ausente_e_recusa(self):
        """O bug inteiro em uma linha."""
        with pytest.raises(InvalidSignature, match="ausente"):
            verify(CORPO, None, SEGREDO)

    def test_header_vazio_tambem_e_recusa(self):
        with pytest.raises(InvalidSignature):
            verify(CORPO, "", SEGREDO)

    def test_sem_segredo_configurado_nao_valida(self):
        """Estado de quem ainda não configurou, não autorização."""
        verify(CORPO, None, None)
        verify(CORPO, "sha256=qualquer", None)


class TestValidacao:
    def test_assinatura_correta_passa(self):
        verify(CORPO, assinar(), SEGREDO)

    def test_segredo_errado_recusa(self):
        with pytest.raises(InvalidSignature, match="inválida"):
            verify(CORPO, assinar(segredo="outro"), SEGREDO)

    def test_corpo_adulterado_recusa(self):
        with pytest.raises(InvalidSignature):
            verify(b'{"event":"outra_coisa"}', assinar(), SEGREDO)

    def test_assinatura_de_outro_corpo_nao_vale(self):
        outra = assinar(b'{"event":"outro"}')
        with pytest.raises(InvalidSignature):
            verify(CORPO, outra, SEGREDO)

    def test_prefixo_sha256(self):
        assert assinar().startswith("sha256=")


class TestPayloadCustomizado:
    """O Chatwoot assina `{timestamp}.{body}`, não o corpo cru. Sem isto haveria
    uma segunda implementação de HMAC — que é o que existe hoje na lq-api."""

    def test_valida_payload_com_timestamp(self):
        ts = "1757000000"
        assinatura = expected_signature(f"{ts}.".encode() + CORPO, SEGREDO)
        verify(CORPO, assinatura, SEGREDO, payload_builder=timestamped_payload(ts))

    def test_timestamp_diferente_invalida(self):
        assinatura = expected_signature(b"1757000000." + CORPO, SEGREDO)
        with pytest.raises(InvalidSignature):
            verify(
                CORPO,
                assinatura,
                SEGREDO,
                payload_builder=timestamped_payload("1757009999"),
            )

    def test_assinatura_do_corpo_cru_nao_vale_para_payload_com_timestamp(self):
        with pytest.raises(InvalidSignature):
            verify(
                CORPO,
                assinar(),
                SEGREDO,
                payload_builder=timestamped_payload("1757000000"),
            )
