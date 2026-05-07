"""
inertia/nucleo/calibrador.py
Calibração automática de timeout.

Antes de iniciar a varredura, o Inertia mede a latência real
até o alvo conectando em algumas portas comuns. Com base no
pior RTT observado, define um timeout seguro.

Isso resolve dois problemas do timeout fixo:
  - Redes locais (1-2ms): timeout de 1500ms é desnecessariamente lento
  - Alvos distantes (200ms+): timeout curto faz perder portas abertas

Lógica:
  pior_rtt × 6  → margem de segurança para variação de rede
  Mínimo: 1.5s  → suficiente para a maioria dos casos
  Máximo: 8.0s  → evita scans excessivamente lentos

Se nenhuma porta de calibração responder (alvo muito filtrado),
usa o fallback padrão de 1.5s.
"""
from __future__ import annotations

import asyncio
import time

# Portas usadas para medir o RTT do alvo.
# Escolhidas por serem comuns — maior chance de pelo menos uma estar aberta.
PORTAS_CALIBRACAO = (80, 443, 22, 8080)

TIMEOUT_FALLBACK   = 1.5   # segundos — usado se nenhuma porta responder
TIMEOUT_MINIMO     = 1.5   # segundos
TIMEOUT_MAXIMO     = 8.0   # segundos
MULTIPLICADOR_RTT  = 6     # margem de segurança sobre o pior RTT


async def calibrar_timeout(ip: str) -> float:
    """
    Mede a latência real até o alvo e retorna um timeout adequado em segundos.

    Tenta conectar nas portas de calibração em paralelo e usa o pior RTT
    observado para calcular o timeout. Fecha todas as conexões logo após
    a medição, sem fazer nenhuma varredura real.
    """
    rtts: list[float] = []

    for porta in PORTAS_CALIBRACAO:
        rtt = await _medir_rtt(ip, porta)
        if rtt is not None:
            rtts.append(rtt)

    if not rtts:
        # Nenhuma porta de calibração respondeu — usa o fallback
        return TIMEOUT_FALLBACK

    pior_rtt = max(rtts)
    timeout_calculado = pior_rtt * MULTIPLICADOR_RTT

    # Garante que o timeout fica dentro dos limites razoáveis
    return max(TIMEOUT_MINIMO, min(TIMEOUT_MAXIMO, round(timeout_calculado, 3)))


async def _medir_rtt(ip: str, porta: int) -> float | None:
    """
    Tenta uma conexão TCP e retorna o tempo decorrido em segundos.
    Retorna None se a conexão falhar ou expirar.
    """
    writer = None
    inicio = time.monotonic()

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, porta),
            timeout=3.0,
        )
        return time.monotonic() - inicio

    except Exception:
        return None

    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
