"""
inertia/nucleo/resolucao.py
Resolução de hostname para IP e reverse DNS.

Separado do scanner para manter responsabilidades claras.
"""
from __future__ import annotations

import asyncio
import socket
from typing import Optional


async def resolver_host(host: str) -> tuple[str, Optional[str]]:
    """
    Resolve um hostname para endereço IPv4.

    Retorna tupla (ip, rdns) onde rdns é o reverse DNS se disponível.
    Lança OSError se o host não puder ser resolvido.
    """
    loop = asyncio.get_running_loop()

    # Resolve para IPv4 (AF_INET força IPv4, evita problemas com IPv6)
    info = await loop.getaddrinfo(
        host, None,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
    )
    if not info:
        raise OSError(f"Não foi possível resolver: {host}")

    ip = info[0][4][0]

    # Tenta obter o reverse DNS (falha silenciosa — não é crítico)
    rdns = await _obter_reverse_dns(loop, ip)

    return ip, rdns


async def _obter_reverse_dns(
    loop: asyncio.AbstractEventLoop,
    ip: str,
) -> Optional[str]:
    """
    Tenta resolver o reverse DNS de um IP.
    Retorna None se falhar ou se o resultado for igual ao próprio IP.
    """
    try:
        resultado = await loop.getnameinfo((ip, 0), 0)
        rdns = resultado[0]
        return rdns if rdns != ip else None
    except Exception:
        return None
