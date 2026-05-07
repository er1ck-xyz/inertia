"""
inertia/utils/portas.py
Carrega presets de portas a partir do nmap-services oficial.

Fluxo:
  1ª execução → baixa de https://raw.githubusercontent.com/nmap/nmap/master/nmap-services
              → salva em ~/.inertia/nmap-services
  Próximas    → lê do cache local (sem internet)
  Manual      → `inertia --atualizar-portas` força novo download

As portas são ordenadas por frequência de uso real (campo do nmap-services),
o que torna o top100 muito mais preciso do que uma lista hardcoded.
"""
from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Final

# ─── Configuração de cache ────────────────────────────────────────────────────

URL_NMAP_SERVICES: Final[str] = (
    "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
)

DIRETORIO_CACHE: Final[Path] = Path.home() / ".inertia"
ARQUIVO_CACHE:   Final[Path] = DIRETORIO_CACHE / "nmap-services"

# ─── Download e cache ─────────────────────────────────────────────────────────

def _obter_conteudo_nmap_services(forcar_download: bool = False) -> str:
    """
    Retorna o conteúdo do nmap-services.

    Usa cache local se disponível (a menos que forcar_download=True).
    Fallback para cache antigo se o download falhar.
    """
    if not forcar_download and ARQUIVO_CACHE.exists():
        return ARQUIVO_CACHE.read_text(encoding="utf-8", errors="replace")

    DIRETORIO_CACHE.mkdir(parents=True, exist_ok=True)

    try:
        req = urllib.request.Request(
            URL_NMAP_SERVICES,
            headers={"User-Agent": "Inertia-Scanner/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            conteudo = resp.read().decode("utf-8", errors="replace")

        ARQUIVO_CACHE.write_text(conteudo, encoding="utf-8")
        return conteudo

    except Exception as exc:
        # Se o download falhar mas tiver cache antigo, usa ele
        if ARQUIVO_CACHE.exists():
            return ARQUIVO_CACHE.read_text(encoding="utf-8", errors="replace")

        raise RuntimeError(
            f"Não foi possível baixar nmap-services e não há cache local.\n"
            f"Verifique sua conexão. Erro: {exc}"
        ) from exc


# ─── Parser do nmap-services ──────────────────────────────────────────────────

def _parsear_portas_tcp(conteudo: str) -> list[tuple[int, float]]:
    """
    Lê o nmap-services e retorna lista de (porta, frequência) para TCP.

    Formato de cada linha do arquivo:
        nome  porta/protocolo  frequência  # comentário
    Exemplo:
        http  80/tcp  0.484143  # World Wide Web HTTP

    Retorna ordenado por frequência decrescente (mais usadas primeiro).
    """
    portas: list[tuple[int, float]] = []

    for linha in conteudo.splitlines():
        linha = linha.strip()

        # Ignora linhas em branco e comentários
        if not linha or linha.startswith("#"):
            continue

        partes = linha.split()
        if len(partes) < 3:
            continue

        try:
            porta_proto = partes[1]          # ex: "80/tcp"
            if not porta_proto.endswith("/tcp"):
                continue

            numero_porta = int(porta_proto.split("/")[0])
            frequencia   = float(partes[2])

            if 1 <= numero_porta <= 65535:
                portas.append((numero_porta, frequencia))

        except (ValueError, IndexError):
            continue

    portas.sort(key=lambda x: x[1], reverse=True)
    return portas


# ─── Construção dos presets ───────────────────────────────────────────────────

def _construir_presets() -> tuple[list[int], list[int], list[int], list[int], list[int]]:
    """
    Constrói os presets TOP100, TOP1000, TOP3000, TOP10000 e TODAS.
    Chamado uma vez no import do módulo.
    """
    conteudo = _obter_conteudo_nmap_services()
    portas_ordenadas = [porta for porta, _ in _parsear_portas_tcp(conteudo)]

    top100   = portas_ordenadas[:100]
    top1000  = portas_ordenadas[:1000]
    top3000  = portas_ordenadas[:3000]
    top10000 = portas_ordenadas[:10000]
    todas    = list(range(1, 65536))   # todas as 65535 portas em ordem sequencial

    return top100, top1000, top3000, top10000, todas


# Carregado uma vez quando o módulo é importado
TOP100, TOP1000, TOP3000, TOP10000, TODAS = _construir_presets()

# ─── API pública ──────────────────────────────────────────────────────────────

def atualizar_cache() -> None:
    """Força novo download do nmap-services e reconstrói os presets."""
    global TOP100, TOP1000, TOP3000, TOP10000, TODAS

    _obter_conteudo_nmap_services(forcar_download=True)
    TOP100, TOP1000, TOP3000, TOP10000, TODAS = _construir_presets()


def resolver_preset(nome: str) -> list[int]:
    """
    Retorna a lista de portas para um preset nomeado.

    Presets disponíveis: top100, top1000, top3000, top10000, todas
    """
    mapa = {
        "top100":   TOP100,
        "top1000":  TOP1000,
        "top3000":  TOP3000,
        "top10000": TOP10000,
        "todas":    TODAS,
    }
    if nome not in mapa:
        raise ValueError(
            f"Preset '{nome}' desconhecido. Opções: {', '.join(mapa.keys())}"
        )
    return list(mapa[nome])


def analisar_portas_customizadas(especificacao: str) -> list[int]:
    """
    Converte uma especificação de portas em lista ordenada de inteiros.

    Formatos aceitos:
      "80"           → [80]
      "22,80,443"    → [22, 80, 443]
      "1-1024"       → [1, 2, ..., 1024]
      "22,80,100-200" → misturado

    Lança ValueError para entradas inválidas.
    """
    portas: set[int] = set()

    for token in especificacao.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            partes = token.split("-", 1)
            try:
                inicio, fim = int(partes[0]), int(partes[1])
            except ValueError:
                raise ValueError(f"Intervalo inválido: '{token}'")
            if inicio < 1 or fim > 65535 or inicio > fim:
                raise ValueError(
                    f"Intervalo '{token}' inválido — valores entre 1-65535, início ≤ fim"
                )
            portas.update(range(inicio, fim + 1))
        else:
            try:
                porta = int(token)
            except ValueError:
                raise ValueError(f"Número de porta inválido: '{token}'")
            if porta < 1 or porta > 65535:
                raise ValueError(f"Porta {porta} fora do intervalo válido (1-65535)")
            portas.add(porta)

    return sorted(portas)
