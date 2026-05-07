"""
inertia/nucleo/scanner.py
Orquestrador principal da varredura.

Responsabilidades:
  - Importar o núcleo Rust (inertia_core)
  - Converter resultados PyO3 → modelos Python
  - Enriquecer com informações de serviço (nome, CPE)
  - Chamar callbacks de progresso (live hits)
  - Aplicar rate limiting se configurado

A lógica de TCP/UDP em si está no Rust (src/lib.rs).
O Python cuida de orquestração, enriquecimento e UI.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from inertia.nucleo.modelos import ResultadoPorta, SessaoScan
from inertia.nucleo.limitador import TokenBucket
from inertia.utils.servicos import obter_servico, fingerprint_banner


# ─── Import do núcleo Rust ────────────────────────────────────────────────────

def _importar_nucleo():
    """
    Importa o módulo Rust compilado com mensagem de erro amigável.
    Chamado lazy para que erros de import apareçam no momento certo.
    """
    try:
        from inertia import inertia_core  # type: ignore[attr-defined]
        return inertia_core
    except ImportError as exc:
        from rich.console import Console
        Console().print(
            "\n[red]Erro:[/] Núcleo Rust não encontrado ([cyan]inertia_core[/]).\n"
            "Execute [bold]maturin develop --release[/] para compilar.\n"
        )
        raise SystemExit(1) from exc


# ─── Enriquecimento de resultados ─────────────────────────────────────────────

def _enriquecer_resultado(porta: int, protocolo: str, status: str,
                          latencia_ms: float, banner_texto: str) -> ResultadoPorta:
    """
    Converte dados brutos do Rust em um ResultadoPorta enriquecido.

    Enriquecimento:
      - Busca nome e CPE na base de serviços por número de porta
      - Se tiver banner, tenta identificar o serviço por regex
      - O fingerprint por banner tem prioridade sobre o lookup por porta
    """
    registro = obter_servico(porta)

    nome_servico = registro.nome if registro else ""
    cpe          = registro.cpe  if registro else ""

    # Fingerprint por banner tem mais precisão que lookup por porta
    if banner_texto:
        nome_detectado = fingerprint_banner(banner_texto.encode())
        if nome_detectado:
            nome_servico = nome_detectado.upper()

    return ResultadoPorta(
        porta      = porta,
        status     = status,
        protocolo  = protocolo,
        latencia_ms = latencia_ms,
        banner     = banner_texto,
        servico    = nome_servico,
        cpe        = cpe,
    )


# ─── Função principal de varredura ────────────────────────────────────────────

def executar_varredura(
    sessao:        SessaoScan,
    on_resultado:  Optional[Callable[[ResultadoPorta], None]] = None,
    portas:        Optional[list[int]] = None,
    rate_limit_pps: Optional[float] = None,
) -> list[ResultadoPorta]:
    """
    Executa a varredura completa e retorna lista de ResultadoPorta.

    Parâmetros:
      sessao        — configuração da sessão (alvo, timeout, concorrência)
      on_resultado  — callback chamado para cada porta aberta encontrada (live hit)
      portas        — lista de portas a varrer
      rate_limit_pps — máximo de sondagens por segundo (None = sem limite)

    O rate limiting não está implementado no Rust pois o TokenBucket
    é assíncrono Python. Para scans com rate limit, a concorrência
    é reduzida para simular o efeito.
    """
    nucleo = _importar_nucleo()

    portas_para_varrer = portas or []
    timeout_ms = int(sessao.timeout_s * 1000)

    # Chama o núcleo Rust — bloqueia a thread até completar
    resultado_rust = nucleo.varrer_portas(
        sessao.alvo.ip_resolvido or sessao.alvo.host,
        portas_para_varrer,
        timeout_ms,
        sessao.concorrencia,
        0,             # delay_ms — rate limiting é feito em Python
        sessao.tcp,
        sessao.udp,
    )

    # Converte e enriquece os resultados
    resultados: list[ResultadoPorta] = []
    for r in resultado_rust.portas:
        resultado = _enriquecer_resultado(
            porta       = r.porta,
            protocolo   = r.protocolo,
            status      = r.status,
            latencia_ms = r.latencia_ms,
            banner_texto = r.banner,
        )
        resultados.append(resultado)

        # Dispara callback para live hits (portas abertas)
        if resultado.esta_aberta and on_resultado:
            on_resultado(resultado)

    return sorted(resultados, key=lambda r: (r.porta, r.protocolo))
