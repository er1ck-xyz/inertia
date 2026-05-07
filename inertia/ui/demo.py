"""
inertia/ui/demo.py
Modo demonstração — simulação visual sem conexões de rede.
"""
from __future__ import annotations

import random
import time
from typing import Optional
from pathlib import Path

from rich.live import Live

from inertia.ui.terminal import (
    console, exibir_banner, criar_barra_progresso,
    exibir_live_hit, exibir_tabela_resultados, exibir_resumo,
)
from inertia.nucleo.modelos import ResultadoPorta, AlvoScan, SessaoScan

_PORTAS_ABERTAS_DEMO = [22, 53, 80, 443, 3306, 5432, 6379, 8080, 9200, 31337]
_PORTAS_DEMO = sorted({
    *_PORTAS_ABERTAS_DEMO,
    21, 23, 25, 69, 110, 111, 135, 137, 139, 143,
    161, 389, 445, 465, 514, 587, 636, 993, 995,
    1080, 1433, 1521, 1723, 2049, 3389, 5000, 5900,
    5985, 7001, 8443, 8888, 9000, 9090, 27017,
})
_BANNERS_DEMO = {
    22:    "SSH-2.0-OpenSSH_9.1p1",
    80:    "HTTP/1.1 200 OK Server: nginx/1.24",
    443:   "",
    3306:  "5.7.39-MySQL Community Server",
    5432:  "PostgreSQL 15.2",
    6379:  "+PONG",
    9200:  '{"name":"node-1","cluster_name":"elasticsearch"}',
}
_SERVICOS_DEMO = {
    22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    3306: "MYSQL", 5432: "POSTGRES", 6379: "REDIS",
    8080: "HTTP-ALT", 9200: "ELASTIC", 31337: "ELITE",
}


def executar_demo(sem_banner: bool = False) -> None:
    """Executa simulação visual completa sem tocar em nenhuma rede."""
    if not sem_banner:
        exibir_banner()

    console.print("\n[dim]demo mode — no network connections are made[/dim]\n")

    alvo    = AlvoScan(host="192.168.1.1", ip_resolvido="192.168.1.1")
    sessao  = SessaoScan(
        alvo=alvo, total_portas=len(_PORTAS_DEMO),
        concorrencia=400, timeout_s=1.5, tcp=True, udp=True,
    )

    rng     = random.Random(42)
    abertas = set(_PORTAS_ABERTAS_DEMO)
    barra   = criar_barra_progresso()
    task_id = barra.add_task(f"[bright_blue]Scanning {alvo.host}", total=len(_PORTAS_DEMO))
    passo   = 4.0 / max(len(_PORTAS_DEMO), 1)

    with barra:
        for porta in _PORTAS_DEMO:
            time.sleep(passo)
            barra.update(task_id, advance=1)

            if porta in abertas:
                resultado = ResultadoPorta(
                    porta      = porta,
                    status     = "open",
                    protocolo  = "tcp",
                    latencia_ms = round(rng.uniform(1.5, 80.0), 1),
                    banner     = _BANNERS_DEMO.get(porta, ""),
                    servico    = _SERVICOS_DEMO.get(porta, "unknown"),
                    cpe        = f"cpe:/a:{_SERVICOS_DEMO.get(porta,'custom').lower()}",
                )
                sessao.resultados.append(resultado)
                barra.stop()
                exibir_live_hit(resultado)
                barra.start()
            else:
                status = "closed" if rng.random() < 0.65 else "filtered"
                sessao.resultados.append(ResultadoPorta(
                    porta=porta, status=status, protocolo="tcp",
                    latencia_ms=round(rng.uniform(0.3, 5.0), 1),
                ))

    import time as _t
    sessao.finalizado_em = _t.monotonic()

    exibir_tabela_resultados(sessao)
    exibir_resumo(sessao)
    console.print("[dim]demo complete — no hosts were scanned[/dim]\n")
