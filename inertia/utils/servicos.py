"""
inertia/utils/servicos.py
Base de dados de serviços por porta.

Cada registro tem:
  - nome:     string curta para exibição (ex: "SSH")
  - descricao: string longa (ex: "Secure Shell")
  - cpe:      identificador CPE (ex: "cpe:/a:openssh")
  - estilo:   cor Rich para a UI

O fingerprint de banner é feito por regex em engine/scanner.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RegistroServico:
    nome:      str
    descricao: str
    cpe:       str
    estilo:    str   # cor Rich


# ─── Base de dados ────────────────────────────────────────────────────────────

BASE_SERVICOS: dict[int, RegistroServico] = {
    21:    RegistroServico("FTP",         "File Transfer Protocol",      "cpe:/a:ftp",                    "yellow"),
    22:    RegistroServico("SSH",         "Secure Shell",                "cpe:/a:openssh",                "green"),
    23:    RegistroServico("TELNET",      "Telnet",                      "cpe:/a:telnet",                 "bright_red"),
    25:    RegistroServico("SMTP",        "Mail Transfer",               "cpe:/a:smtp",                   "magenta"),
    53:    RegistroServico("DNS",         "Domain Name System",          "cpe:/a:dns",                    "blue"),
    67:    RegistroServico("DHCP",        "DHCP Server",                 "cpe:/a:dhcp",                   "dim white"),
    69:    RegistroServico("TFTP",        "Trivial File Transfer",       "cpe:/a:tftp",                   "dim white"),
    80:    RegistroServico("HTTP",        "Web (HTTP)",                  "cpe:/a:apache:http_server",     "cyan"),
    88:    RegistroServico("KERBEROS",    "Kerberos Auth",               "cpe:/a:kerberos",               "purple"),
    110:   RegistroServico("POP3",        "Mail Retrieval",              "cpe:/a:pop3",                   "magenta"),
    111:   RegistroServico("RPC",         "Remote Procedure Call",       "cpe:/a:rpc",                    "dim white"),
    123:   RegistroServico("NTP",         "Network Time Protocol",       "cpe:/a:ntp",                    "dim white"),
    135:   RegistroServico("MSRPC",       "MS Remote Procedure Call",    "cpe:/a:microsoft:rpc",          "dim white"),
    137:   RegistroServico("NETBIOS",     "NetBIOS Name Service",        "cpe:/a:microsoft:netbios",      "dim white"),
    139:   RegistroServico("NETBIOS",     "NetBIOS Session",             "cpe:/a:microsoft:netbios",      "dim white"),
    143:   RegistroServico("IMAP",        "Internet Mail Access",        "cpe:/a:imap",                   "magenta"),
    161:   RegistroServico("SNMP",        "Network Management",          "cpe:/a:snmp",                   "purple"),
    179:   RegistroServico("BGP",         "Border Gateway Protocol",     "cpe:/a:bgp",                    "dim white"),
    389:   RegistroServico("LDAP",        "Directory Access",            "cpe:/a:ldap",                   "purple"),
    443:   RegistroServico("HTTPS",       "Web (TLS)",                   "cpe:/a:openssl",                "bright_cyan"),
    445:   RegistroServico("SMB",         "Windows File Sharing",        "cpe:/a:microsoft:smb",          "red"),
    465:   RegistroServico("SMTPS",       "SMTP over TLS",               "cpe:/a:smtp",                   "magenta"),
    514:   RegistroServico("SYSLOG",      "System Log",                  "cpe:/a:syslog",                 "dim white"),
    587:   RegistroServico("SUBMISSION",  "Mail Submission",             "cpe:/a:smtp",                   "magenta"),
    636:   RegistroServico("LDAPS",       "LDAP over TLS",               "cpe:/a:ldap",                   "purple"),
    993:   RegistroServico("IMAPS",       "IMAP over TLS",               "cpe:/a:imap",                   "magenta"),
    995:   RegistroServico("POP3S",       "POP3 over TLS",               "cpe:/a:pop3",                   "magenta"),
    1080:  RegistroServico("SOCKS",       "SOCKS Proxy",                 "cpe:/a:socks",                  "dim white"),
    1433:  RegistroServico("MSSQL",       "Microsoft SQL Server",        "cpe:/a:microsoft:sql_server",   "orange1"),
    1521:  RegistroServico("ORACLE",      "Oracle Database",             "cpe:/a:oracle:database",        "orange1"),
    1723:  RegistroServico("PPTP",        "VPN Tunnel",                  "cpe:/a:pptp",                   "dim white"),
    2049:  RegistroServico("NFS",         "Network File System",         "cpe:/a:nfs",                    "dim white"),
    2375:  RegistroServico("DOCKER",      "Docker (sem TLS)",            "cpe:/a:docker",                 "bright_red"),
    2376:  RegistroServico("DOCKER-TLS", "Docker (com TLS)",            "cpe:/a:docker",                 "red"),
    3000:  RegistroServico("DEV-HTTP",   "Dev Server",                  "cpe:/a:node.js",                "cyan"),
    3306:  RegistroServico("MYSQL",       "MySQL / MariaDB",             "cpe:/a:mysql:mysql",            "orange1"),
    3389:  RegistroServico("RDP",         "Remote Desktop",              "cpe:/a:microsoft:rdp",          "red"),
    5000:  RegistroServico("FLASK",       "Flask / UPnP",                "cpe:/a:flask",                  "cyan"),
    5432:  RegistroServico("POSTGRES",    "PostgreSQL",                  "cpe:/a:postgresql",             "orange1"),
    5900:  RegistroServico("VNC",         "Virtual Network Computing",   "cpe:/a:vnc",                    "red"),
    5985:  RegistroServico("WINRM",       "WinRM HTTP",                  "cpe:/a:microsoft:winrm",        "red"),
    5986:  RegistroServico("WINRM-TLS",  "WinRM HTTPS",                 "cpe:/a:microsoft:winrm",        "red"),
    6379:  RegistroServico("REDIS",       "Redis",                       "cpe:/a:redis",                  "bright_yellow"),
    6443:  RegistroServico("K8S-API",    "Kubernetes API",              "cpe:/a:kubernetes",             "cyan"),
    8080:  RegistroServico("HTTP-ALT",   "HTTP Alternate",              "cpe:/a:apache:http_server",     "cyan"),
    8443:  RegistroServico("HTTPS-ALT",  "HTTPS Alternate",             "cpe:/a:openssl",                "bright_cyan"),
    8888:  RegistroServico("DEV-HTTP",   "Dev HTTP / Jupyter",          "cpe:/a:jupyter",                "cyan"),
    9000:  RegistroServico("PHP-FPM",    "PHP-FPM / SonarQube",         "cpe:/a:php",                    "dim white"),
    9090:  RegistroServico("PROMETHEUS", "Prometheus",                  "cpe:/a:prometheus",             "dim white"),
    9200:  RegistroServico("ELASTIC",    "Elasticsearch",               "cpe:/a:elastic:elasticsearch",  "bright_yellow"),
    9929:  RegistroServico("NPING",       "Nping Echo (Nmap)",           "cpe:/a:nmap",                   "dim white"),
    27017: RegistroServico("MONGODB",    "MongoDB",                     "cpe:/a:mongodb",                "bright_yellow"),
    31337: RegistroServico("ELITE",       "Elite / Custom",              "cpe:/a:custom",                 "dim white"),
}

# ─── Fingerprint de banner por regex ─────────────────────────────────────────

# Cada tupla: (padrão regex em bytes, nome do serviço detectado)
PADROES_BANNER: list[tuple[re.Pattern[bytes], str]] = [
    (re.compile(rb"^SSH-"),                               "ssh"),
    (re.compile(rb"^220.*(FTP|FileZilla|vsFTP|ProFTPD)"), "ftp"),
    (re.compile(rb"^220.*(ESMTP|SMTP|smtp)"),             "smtp"),
    (re.compile(rb"^HTTP/"),                              "http"),
    (re.compile(rb"REDIS|^\+PONG|-ERR"),                  "redis"),
    (re.compile(rb"^\* OK"),                              "imap"),
    (re.compile(rb"^\+OK"),                               "pop3"),
    (re.compile(rb"^5\.\d+\.\d+"),                        "mysql"),
]


def obter_servico(porta: int) -> Optional[RegistroServico]:
    """Retorna o registro de serviço para a porta, ou None se desconhecida."""
    return BASE_SERVICOS.get(porta)


def fingerprint_banner(banner_raw: bytes) -> Optional[str]:
    """
    Tenta identificar o serviço a partir dos bytes brutos do banner.
    Retorna o nome do serviço ou None se não reconhecido.
    """
    if not banner_raw:
        return None
    for padrao, nome in PADROES_BANNER:
        if padrao.search(banner_raw):
            return nome
    return None
