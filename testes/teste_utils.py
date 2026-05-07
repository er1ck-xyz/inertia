"""testes/teste_utils.py — Testes unitários do Inertia."""
import pytest
from inertia.utils.portas import analisar_portas_customizadas, resolver_preset
from inertia.utils.servicos import obter_servico, fingerprint_banner


class TestAnalisarPortas:
    def test_porta_unica(self):        assert analisar_portas_customizadas("80") == [80]
    def test_multiplas(self):          assert analisar_portas_customizadas("22,80,443") == [22, 80, 443]
    def test_intervalo(self):          assert analisar_portas_customizadas("1-5") == [1, 2, 3, 4, 5]
    def test_misturado(self):          assert analisar_portas_customizadas("22,100-103") == [22, 100, 101, 102, 103]
    def test_sem_duplicatas(self):     assert analisar_portas_customizadas("80,80") == [80]
    def test_ordenado(self):           assert analisar_portas_customizadas("443,22") == [22, 443]
    def test_vazio(self):              assert analisar_portas_customizadas("") == []
    def test_espacos(self):            assert analisar_portas_customizadas("80, 443") == [80, 443]
    def test_invalido(self):
        with pytest.raises(ValueError): analisar_portas_customizadas("abc")
    def test_zero(self):
        with pytest.raises(ValueError): analisar_portas_customizadas("0")
    def test_acima_limite(self):
        with pytest.raises(ValueError): analisar_portas_customizadas("65536")
    def test_intervalo_invertido(self):
        with pytest.raises(ValueError): analisar_portas_customizadas("100-50")


class TestObterServico:
    def test_portas_conhecidas(self):
        assert obter_servico(22).nome   == "SSH"
        assert obter_servico(80).nome   == "HTTP"
        assert obter_servico(443).nome  == "HTTPS"
        assert obter_servico(3306).nome == "MYSQL"
        assert obter_servico(6379).nome == "REDIS"
    def test_desconhecida(self):
        assert obter_servico(9999) is None
    def test_retorna_registro(self):
        from inertia.utils.servicos import RegistroServico
        assert isinstance(obter_servico(22), RegistroServico)


class TestFingerprintBanner:
    def test_ssh(self):    assert fingerprint_banner(b"SSH-2.0-OpenSSH") == "ssh"
    def test_http(self):   assert fingerprint_banner(b"HTTP/1.1 200 OK") == "http"
    def test_redis(self):  assert fingerprint_banner(b"+PONG\r\n") == "redis"
    def test_mysql(self):  assert fingerprint_banner(b"5.7.39-MySQL") == "mysql"
    def test_vazio(self):  assert fingerprint_banner(b"") is None
    def test_desconhecido(self): assert fingerprint_banner(b"XYZXYZ") is None
