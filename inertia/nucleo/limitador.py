"""
inertia/nucleo/limitador.py
Controle de taxa de sondagens (rate limiting).

Implementa o algoritmo Token Bucket:
  - O balde começa cheio com `burst` tokens.
  - Tokens são adicionados na taxa de `taxa_pps` por segundo.
  - Cada sondagem consome 1 token.
  - Se o balde estiver vazio, a sondagem aguarda até um token estar disponível.

Uso:
  balde = TokenBucket(taxa_pps=300, burst=400)
  await balde.adquirir()  # aguarda se necessário
  # ... faz a sondagem

Isso evita sobrecarregar o alvo ou disparar firewalls por excesso de tráfego.
"""
from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """
    Limitador de taxa assíncrono baseado em Token Bucket.

    Parâmetros:
      taxa_pps — máximo de tokens por segundo (probes per second)
      burst    — máximo de tokens acumulados (controla rajadas)
    """

    def __init__(self, taxa_pps: float, burst: int) -> None:
        if taxa_pps <= 0:
            raise ValueError("taxa_pps deve ser positivo")

        self._taxa   = taxa_pps
        self._burst  = burst
        self._tokens = float(burst)   # começa com o balde cheio
        self._ultimo = time.monotonic()

    async def adquirir(self) -> None:
        """
        Aguarda até que um token esteja disponível e o consome.
        Retorna imediatamente se houver tokens no balde.
        """
        while True:
            agora    = time.monotonic()
            decorrido = agora - self._ultimo

            # Reabastece os tokens com base no tempo decorrido
            self._tokens = min(
                self._burst,
                self._tokens + decorrido * self._taxa,
            )
            self._ultimo = agora

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return

            # Calcula quanto tempo falta para o próximo token
            espera = (1.0 - self._tokens) / self._taxa
            await asyncio.sleep(espera)
