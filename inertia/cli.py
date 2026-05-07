"""
inertia/cli.py
Interface de linha de comando do Inertia.

Usa argparse padrão com --help em inglês (padrão de ferramentas de segurança).
Mensagens de erro de validação em português.

Fluxo principal (_executar):
  1. Resolve o hostname
  2. Calibra o timeout (ou usa o manual)
  3. Resolve a lista de portas (preset ou custom)
  4. Exibe painel de configuração
  5. Inicia a varredura com live hits
  6. Exibe tabela e resumo
  7. Exporta relatório se solicitado
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from typing import Optional

from rich.console import Console
from rich.live import Live

from inertia import __version__
from inertia.nucleo.calibrador import calibrar_timeout
from inertia.nucleo.modelos import AlvoScan, SessaoScan
from inertia.nucleo.resolucao import resolver_host
from inertia.nucleo.scanner import executar_varredura
from inertia.relatorios.exportador import exportar_sessao, FORMATOS_SUPORTADOS
from inertia.ui.terminal import (
    console,
    exibir_banner,
    exibir_info_alvo,
    criar_barra_progresso,
    exibir_live_hit,
    exibir_tabela_resultados,
    exibir_resumo,
)
from inertia.utils.portas import (
    resolver_preset, analisar_portas_customizadas,
    atualizar_cache, ARQUIVO_CACHE,
)

# Presets disponíveis para o argumento --preset
PRESETS_DISPONIVEIS = ["top100", "top1000", "top3000", "top10000", "todas"]


# ─── Parser de argumentos ─────────────────────────────────────────────────────

def _construir_parser() -> argparse.ArgumentParser:
    """
    Constrói o parser de argumentos.
    Help em inglês — padrão para ferramentas de segurança/rede.
    """
    parser = argparse.ArgumentParser(
        prog="inertia",
        description="Inertia — Hybrid Rust+Python Port Scanner (TCP + UDP)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  inertia -t 192.168.1.1
  inertia -t scanme.nmap.org --preset top3000
  inertia -t 10.0.0.1 -p 22,80,443,8000-9000
  inertia -t scanme.nmap.org --preset todas
  inertia -t 10.0.0.1 --udp -p 53,123,161
  inertia -t 10.0.0.1 --preset top1000 -c 500 -o report.json
  inertia -t 10.0.0.1 --rate-limit 300 --no-banner
  inertia --update-ports
  inertia --demo
        """,
    )

    # ── Alvo ──────────────────────────────────────────────────────────────────
    parser.add_argument(
        "-t", "--target",
        metavar="HOST",
        help="Target IP address or hostname",
    )

    # ── Portas ────────────────────────────────────────────────────────────────
    parser.add_argument(
        "-p", "--ports",
        metavar="PORTS",
        help="Custom port list: 22,80,443 or 1-1024 (overrides --preset)",
    )
    parser.add_argument(
        "--preset",
        default="top100",
        choices=PRESETS_DISPONIVEIS,
        help="Named port preset (default: top100)",
    )

    # ── Protocolos ────────────────────────────────────────────────────────────
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Enable UDP scanning in addition to TCP",
    )
    parser.add_argument(
        "--tcp-only",
        action="store_true",
        help="Disable UDP, scan TCP only (default behavior)",
    )

    # ── Temporização ──────────────────────────────────────────────────────────
    parser.add_argument(
        "-c", "--concurrency",
        default=400,
        type=int,
        metavar="N",
        help="Max concurrent probes (default: 400)",
    )
    parser.add_argument(
        "--timeout",
        default=None,
        type=int,
        metavar="MS",
        help="Timeout per probe in ms (default: auto-calibrated)",
    )
    parser.add_argument(
        "--rate-limit",
        default=None,
        type=float,
        metavar="PPS",
        help="Max probes per second (default: unlimited)",
    )

    # ── Saída ─────────────────────────────────────────────────────────────────
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save results to file",
    )
    parser.add_argument(
        "-f", "--format",
        choices=FORMATOS_SUPORTADOS,
        help=f"Output format: {', '.join(FORMATOS_SUPORTADOS)}",
    )

    # ── Comportamento ─────────────────────────────────────────────────────────
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing (faster scan)",
    )
    parser.add_argument(
        "--no-logo",
        action="store_true",
        help="Hide ASCII banner",
    )

    # ── Modos especiais ───────────────────────────────────────────────────────
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a visual simulation without any network connections",
    )
    parser.add_argument(
        "--update-ports",
        action="store_true",
        help="Re-download nmap-services and update local cache (~/.inertia/nmap-services)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"inertia {__version__}",
    )

    return parser


# ─── Validações ───────────────────────────────────────────────────────────────

def _validar_argumentos(args: argparse.Namespace) -> Optional[str]:
    """
    Valida os argumentos e retorna mensagem de erro ou None se tudo ok.
    Mensagens em português — são exibidas ao usuário final.
    """
    if not 1 <= args.concurrency <= 5000:
        return "Concorrência deve estar entre 1 e 5000"

    if args.timeout is not None and args.timeout <= 0:
        return "Timeout deve ser um número positivo"

    if args.rate_limit is not None and args.rate_limit <= 0:
        return "Rate limit deve ser um número positivo"

    return None


def _avisar_cache_antigo() -> None:
    """Avisa se o cache do nmap-services tiver mais de 30 dias."""
    if not ARQUIVO_CACHE.exists():
        return

    import time as _time
    idade_dias = (_time.time() - ARQUIVO_CACHE.stat().st_mtime) / 86400

    if idade_dias > 30:
        console.print(
            f"[yellow]⚠[/yellow]  Cache do nmap-services tem {idade_dias:.0f} dias. "
            "Use [bold]--update-ports[/bold] para atualizar."
        )


# ─── Execução principal ───────────────────────────────────────────────────────

async def _executar(args: argparse.Namespace) -> int:
    """
    Função async principal — orquestra todo o fluxo de varredura.
    Separada de launch() para facilitar testes e reutilização.
    """

    # 1. Resolve o hostname para IP
    console.print(f"\n[dim]Resolving {args.target}…[/dim]")
    try:
        ip, rdns = await resolver_host(args.target)
    except OSError as exc:
        console.print(f"[red]Erro ao resolver host: {exc}[/red]")
        return 1

    # 2. Define o timeout (manual ou calibrado automaticamente)
    if args.timeout:
        timeout_s   = args.timeout / 1000.0
        timeout_note = "[dim](manual)[/dim]"
        console.print(f"[dim]Using manual timeout: {args.timeout} ms[/dim]")
    else:
        console.print(f"[dim]Calibrating timeout against {ip}…[/dim]")
        timeout_s   = await calibrar_timeout(ip)
        timeout_note = "[dim](auto-calibrated)[/dim]"

    # 3. Resolve a lista de portas (custom ou preset)
    try:
        if args.ports:
            portas = analisar_portas_customizadas(args.ports)
        else:
            portas = resolver_preset(args.preset)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 1

    # 4. Monta os objetos de sessão
    alvo = AlvoScan(
        host         = args.target,
        ip_resolvido = ip,
        rdns         = rdns,
    )
    sessao = SessaoScan(
        alvo         = alvo,
        total_portas = len(portas),
        concorrencia = args.concurrency,
        timeout_s    = timeout_s,
        tcp          = True,
        udp          = args.udp,
    )

    # 5. Exibe painel de configuração
    exibir_info_alvo(sessao, timeout_note=timeout_note)
    console.print()

    # 6. Varredura com barra de progresso e live hits
    barra   = criar_barra_progresso()
    task_id = barra.add_task(
        f"[bright_blue]Scanning {args.target}",
        total=len(portas),
    )

    # Contador de portas processadas para atualizar a barra
    processadas = 0

    def ao_encontrar_abertas(resultado):
        """Callback chamado para cada porta aberta — exibe live hit."""
        nonlocal processadas
        barra.stop()
        exibir_live_hit(resultado)
        barra.start()

    # Roda a varredura em thread separada para não bloquear a barra
    import threading
    holder: list = []
    erro_holder: list = []

    def _thread_scan():
        try:
            resultados = executar_varredura(
                sessao       = sessao,
                on_resultado = ao_encontrar_abertas,
                portas       = portas,
            )
            holder.append(resultados)
        except Exception as e:
            erro_holder.append(e)

    thread = threading.Thread(target=_thread_scan, daemon=True)

    with barra:
        thread.start()

        # Anima a barra proporcionalmente ao tempo estimado
        tempo_estimado = (len(portas) * timeout_s) / max(args.concurrency, 1)
        t0 = time.monotonic()
        concluidas = 0

        while thread.is_alive():
            decorrido = time.monotonic() - t0
            fracao    = min(decorrido / max(tempo_estimado, 0.1), 0.97)
            simulado  = int(fracao * len(portas))
            if simulado > concluidas:
                barra.update(task_id, advance=simulado - concluidas)
                concluidas = simulado
            await asyncio.sleep(0.05)

        thread.join()
        barra.update(task_id, completed=len(portas))

    if erro_holder:
        console.print(f"[red]Falha na varredura:[/red] {erro_holder[0]}")
        return 1

    sessao.resultados  = holder[0]
    sessao.finalizado_em = time.monotonic()

    # 7. Exibe tabela de resultados e resumo
    exibir_tabela_resultados(sessao)
    exibir_resumo(sessao)

    # 8. Exporta relatório se solicitado
    if args.output:
        formato = args.format
        if not formato:
            # Tenta inferir pelo sufixo do arquivo
            if "." in args.output:
                formato = args.output.rsplit(".", 1)[-1]
            else:
                console.print(
                    "[red]Não foi possível inferir o formato. "
                    "Use -f/--format para especificar.[/red]"
                )
                return 1

        try:
            destino = exportar_sessao(sessao, args.output, formato)
            console.print(f"\n[green]✓[/green] Salvo em [cyan]{destino}[/cyan]")
        except ValueError as exc:
            console.print(f"[red]Erro ao exportar: {exc}[/red]")
            return 1

    return 0


# ─── Ponto de entrada ─────────────────────────────────────────────────────────

def launch() -> None:
    """
    Ponto de entrada registrado no pyproject.toml.
    Trata modos especiais (--demo, --update-ports) antes de iniciar o scan.
    """
    parser = _construir_parser()
    args   = parser.parse_args()

    # Modo: atualizar cache de portas
    if args.update_ports:
        console.print("[dim]Baixando nmap-services do GitHub…[/dim]")
        try:
            atualizar_cache()
            console.print(f"[green]✓[/green] Cache atualizado em [cyan]{ARQUIVO_CACHE}[/cyan]")
        except Exception as exc:
            console.print(f"[red]Erro ao atualizar: {exc}[/red]")
        return

    # Modo: demonstração visual
    if args.demo:
        if not args.no_logo:
            exibir_banner()
        from inertia.ui.demo import executar_demo
        executar_demo(sem_banner=True)
        return

    # Modo normal: precisa de --target
    if not args.target:
        console.print("[red]--target é obrigatório.[/red]")
        parser.print_usage()
        sys.exit(1)

    # Exibe banner e verifica cache
    if not args.no_logo:
        exibir_banner()

    _avisar_cache_antigo()

    # Valida argumentos
    erro = _validar_argumentos(args)
    if erro:
        console.print(f"[red]Erro:[/red] {erro}")
        sys.exit(1)

    # Executa
    try:
        codigo = asyncio.run(_executar(args))
        sys.exit(codigo)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(0)
