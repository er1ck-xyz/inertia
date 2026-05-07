"""
inertia/ui/terminal.py
Interface visual do Inertia — estética do Pulsar.

Componentes:
  - Banner ASCII em painel azul
  - Painel de informações do alvo
  - Barra de progresso com live hits
  - Tabela de resultados (apenas portas abertas)
  - Painel de resumo final

Todos os textos da UI estão em inglês (padrão para ferramentas de segurança).
Os comentários no código estão em português.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from inertia.nucleo.modelos import ResultadoPorta, SessaoScan
from inertia.utils.servicos import obter_servico

console = Console(highlight=False)

# ─── Estilos por serviço ──────────────────────────────────────────────────────

# Cores para cada tipo de serviço na tabela de resultados
_ESTILOS_SERVICO: dict[str, str] = {
    "http":      "cyan",
    "https":     "bright_cyan",
    "ssh":       "green",
    "ftp":       "yellow",
    "smtp":      "magenta",
    "dns":       "blue",
    "mysql":     "orange1",
    "postgres":  "orange1",
    "oracle":    "orange1",
    "mssql":     "orange1",
    "rdp":       "red",
    "smb":       "red",
    "telnet":    "bright_red",
    "redis":     "bright_yellow",
    "mongodb":   "bright_yellow",
    "elastic":   "bright_yellow",
    "ldap":      "purple",
    "snmp":      "purple",
    "docker":    "bright_red",
    "imap":      "magenta",
    "pop3":      "magenta",
}

_COR_PADRAO = "white"


def _cor_servico(nome_servico: str) -> str:
    """Retorna a cor Rich para um nome de serviço."""
    return _ESTILOS_SERVICO.get(nome_servico.lower(), _COR_PADRAO)


# ─── Banner ───────────────────────────────────────────────────────────────────

_BANNER_ASCII = r"""
 ██╗███╗   ██╗███████╗██████╗ ████████╗██╗ █████╗
 ██║████╗  ██║██╔════╝██╔══██╗╚══██╔══╝██║██╔══██╗
 ██║██╔██╗ ██║█████╗  ██████╔╝   ██║   ██║███████║
 ██║██║╚██╗██║██╔══╝  ██╔══██╗   ██║   ██║██╔══██║
 ██║██║ ╚████║███████╗██║  ██║   ██║   ██║██║  ██║
 ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝
"""


def exibir_banner() -> None:
    """Banner ASCII em painel azul — igual ao Pulsar."""
    console.print(
        Panel(
            Text(_BANNER_ASCII, style="bold bright_blue", justify="center"),
            subtitle="[dim]Hybrid Rust+Python Port Scanner  ·  TCP + UDP  ·  v1.0.0[/dim]",
            border_style="bright_blue",
            padding=(0, 2),
        )
    )


# ─── Informações do alvo ──────────────────────────────────────────────────────

def exibir_info_alvo(
    sessao:        SessaoScan,
    timeout_note:  str = "",
) -> None:
    """
    Painel com as informações da sessão antes de iniciar a varredura.
    Inclui alvo, IP, portas, timeout, concorrência e protocolos.
    """
    alvo      = sessao.alvo
    protos    = " + ".join(p for p, a in [("TCP", sessao.tcp), ("UDP", sessao.udp)] if a)
    iniciado  = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    linhas = [
        f"[bold]Target[/bold]       {alvo.host}",
        f"[bold]Resolved IP[/bold]  [cyan]{alvo.ip_resolvido}[/cyan]",
    ]

    # rDNS só aparece se for diferente do host original
    if alvo.rdns and alvo.rdns != alvo.host:
        linhas.append(f"[bold]rDNS[/bold]         [dim]{alvo.rdns}[/dim]")

    linhas += [
        f"[bold]Ports[/bold]        [yellow]{sessao.total_portas:,}[/yellow]",
        f"[bold]Protocols[/bold]    [magenta]{protos}[/magenta]",
        f"[bold]Concurrency[/bold]  {sessao.concorrencia}",
        f"[bold]Timeout[/bold]      {sessao.timeout_s * 1000:.0f} ms {timeout_note}",
        f"[bold]Started[/bold]      {iniciado}",
    ]

    console.print(
        Panel(
            "\n".join(linhas),
            title="[bold]Scan Target[/bold]",
            border_style="blue",
            padding=(0, 2),
        )
    )


# ─── Barra de progresso ───────────────────────────────────────────────────────

def criar_barra_progresso() -> Progress:
    """
    Barra de progresso no estilo do Pulsar.
    Mostra: spinner, descrição, barra, %, N/M, tempo.
    """
    return Progress(
        SpinnerColumn(style="bright_blue"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="blue", complete_style="bright_blue"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


# ─── Live hit ─────────────────────────────────────────────────────────────────

def exibir_live_hit(resultado: ResultadoPorta) -> None:
    """
    Imprime uma linha para cada porta aberta encontrada durante o scan.
    Exibido em tempo real, intercalado com a barra de progresso.
    """
    cor      = _cor_servico(resultado.servico)
    servico  = (resultado.servico or "unknown").upper()
    proto    = resultado.protocolo.upper()

    # Banner truncado para caber na linha
    trecho_banner = ""
    if resultado.banner:
        banner_curto = resultado.banner[:60].replace("\n", " ").replace("\r", "")
        trecho_banner = f"  [dim]» {banner_curto}[/dim]"

    console.print(
        f"  [bold green]OPEN[/bold green]  "
        f"[bold]{resultado.porta:<6}[/bold]/{proto.lower():<4}  "
        f"[{cor}]{servico:<14}[/{cor}]"
        f"[dim]{resultado.latencia_ms:>7.1f} ms[/dim]"
        f"{trecho_banner}"
    )


# ─── Tabela de resultados ─────────────────────────────────────────────────────

def exibir_tabela_resultados(sessao: SessaoScan) -> None:
    """
    Tabela com todas as portas abertas encontradas.
    Inclui porta, protocolo, estado, serviço, latência, CPE e banner.
    """
    portas_abertas = sessao.portas_abertas

    if not portas_abertas:
        console.print("\n[yellow]No open ports found.[/yellow]")
        return

    tabela = Table(
        box=box.ROUNDED,
        border_style="bright_blue",
        show_header=True,
        header_style="bold bright_blue",
        row_styles=["", "dim"],
        padding=(0, 1),
    )

    tabela.add_column("Port",    style="bold",       width=8)
    tabela.add_column("Proto",   style="dim",         width=6)
    tabela.add_column("State",   style="bold green",  width=8)
    tabela.add_column("Service",                      width=14)
    tabela.add_column("Latency", justify="right",     width=10)
    tabela.add_column("CPE",     style="dim",         width=26)
    tabela.add_column("Banner",                       width=40)

    for r in portas_abertas:
        cor     = _cor_servico(r.servico)
        servico = Text(r.servico or "unknown", style=cor)
        banner  = Text((r.banner or "")[:38], style="dim")

        tabela.add_row(
            str(r.porta),
            r.protocolo,
            r.status,
            servico,
            f"{r.latencia_ms:.1f} ms",
            r.cpe or "—",
            banner,
        )

    console.print()
    console.print(tabela)


# ─── Resumo final ─────────────────────────────────────────────────────────────

def exibir_resumo(sessao: SessaoScan) -> None:
    """
    Painel de resumo no final da varredura.
    Mostra contagens, taxa de scan e tempo total.
    """
    abertas   = len(sessao.portas_abertas)
    fechadas  = sum(1 for r in sessao.resultados if r.status == "closed")
    filtradas = sum(1 for r in sessao.resultados if r.status == "filtered")

    estatisticas = [
        f"[bold green]{abertas}[/bold green] open",
        f"[dim]{fechadas} closed[/dim]",
        f"[dim]{filtradas} filtered[/dim]",
        f"[yellow]{sessao.taxa_scan:.0f} ports/sec[/yellow]",
        f"elapsed [bold]{sessao.tempo_decorrido_s:.2f}s[/bold]",
    ]

    console.print(
        Panel(
            "  ·  ".join(estatisticas),
            title="[bold]Scan Summary[/bold]",
            border_style="blue",
            padding=(0, 1),
        )
    )

    # Mostra erros se houver (máximo 5 para não poluir a saída)
    if sessao.erros:
        console.print(f"[yellow]Warnings: {len(sessao.erros)}[/yellow]")
        for erro in sessao.erros[:5]:
            console.print(f"  [dim]{erro}[/dim]")
