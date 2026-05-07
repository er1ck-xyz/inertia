"""
inertia/nucleo/modelos.py
Modelos de dados da sessão de varredura.

Mantém separado da lógica de scan e da UI para facilitar manutenção.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ResultadoPorta:
    """Resultado completo de uma porta após a varredura."""
    porta:      int
    status:     str        # "open", "closed", "filtered"
    protocolo:  str        # "tcp", "udp"
    latencia_ms: float
    banner:     str = ""   # texto capturado do serviço (pode estar vazio)
    servico:    str = ""   # nome do serviço detectado (ex: "SSH", "HTTP")
    cpe:        str = ""   # identificador CPE (ex: "cpe:/a:openssh")

    @property
    def esta_aberta(self) -> bool:
        return self.status == "open"

    @property
    def e_interessante(self) -> bool:
        """Porta é interessante se estiver aberta — usado para live hits."""
        return self.esta_aberta


@dataclass
class AlvoScan:
    """Informações sobre o alvo da varredura."""
    host:          str
    ip_resolvido:  Optional[str] = None
    rdns:          Optional[str] = None   # reverse DNS, se disponível


@dataclass
class SessaoScan:
    """Estado completo de uma sessão de varredura."""
    alvo:          AlvoScan
    total_portas:  int
    concorrencia:  int
    timeout_s:     float
    tcp:           bool = True
    udp:           bool = False
    iniciado_em:   float = field(default_factory=time.monotonic)
    finalizado_em: Optional[float] = None
    resultados:    list[ResultadoPorta] = field(default_factory=list)
    erros:         list[str] = field(default_factory=list)

    @property
    def tempo_decorrido_s(self) -> float:
        fim = self.finalizado_em or time.monotonic()
        return fim - self.iniciado_em

    @property
    def portas_abertas(self) -> list[ResultadoPorta]:
        return [r for r in self.resultados if r.esta_aberta]

    @property
    def taxa_scan(self) -> float:
        """Portas por segundo."""
        return self.total_portas / max(self.tempo_decorrido_s, 0.001)
