<div align="center">

```
 ██╗███╗   ██╗███████╗██████╗ ████████╗██╗ █████╗
 ██║████╗  ██║██╔════╝██╔══██╗╚══██╔══╝██║██╔══██╗
 ██║██╔██╗ ██║█████╗  ██████╔╝   ██║   ██║███████║
 ██║██║╚██╗██║██╔══╝  ██╔══██╗   ██║   ██║██╔══██║
 ██║██║ ╚████║███████╗██║  ██║   ██║   ██║██║  ██║
 ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝
```

**Hybrid Rust + Python port scanner — fast, clean, and built for real recon.**

[![PyPI](https://img.shields.io/pypi/v/inertia-scanner?color=0d1117&labelColor=60a5fa&label=pypi)](https://pypi.org/project/inertia-scanner)
[![Python](https://img.shields.io/badge/python-3.8%2B-0d1117?labelColor=60a5fa)](https://python.org)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-0d1117?labelColor=f97316)](https://rustup.rs)
[![License](https://img.shields.io/badge/license-MIT-0d1117?labelColor=3fb950)](LICENSE)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20only-0d1117?labelColor=f85149)](#-ethical-use)

</div>

---

## Overview

Inertia is a high-performance port scanner that combines a **Rust async core** with a **Python interface**, delivering speed without sacrificing usability. It automatically calibrates timeouts per target, loads port lists from the official Nmap database, supports both TCP and UDP, and displays results in a clean terminal UI with live hits as ports are discovered.

Built for network diagnostics, security auditing, and learning. Not for unauthorized use.

---

## Quick Start

```bash
pip install inertia-scanner
```

```bash
# Scan a host with the top 100 most common ports
inertia -t 192.168.1.1

# Try the visual demo without any network connections
inertia --demo
```

---

## Features

| | Feature | Details |
|---|---|---|
| 🦀 | **Rust async core** | Tokio-powered — thousands of concurrent probes via PyO3 |
| 🎯 | **Auto timeout calibration** | Measures real RTT to the target before scanning |
| 📡 | **TCP + UDP** | Full TCP connect scan + UDP with protocol-specific payloads |
| 🗂️ | **Nmap port presets** | Loaded from official `nmap-services` — top100 to all 65535 |
| 🚦 | **Rate limiting** | Token Bucket algorithm — prevents firewall triggers |
| 🔍 | **Banner grabbing** | Smart per-protocol requests (HTTP HEAD, SMTP CRLF, etc.) |
| ⚡ | **Live hits** | Open ports printed in real time as they're discovered |
| 📊 | **Export formats** | JSON, CSV, HTML report, and plain TXT |
| 🎭 | **Demo mode** | Full visual simulation — no network needed |

---

## Installation

```bash
pip install inertia-scanner
```

> Requires Python 3.8+. The Rust core is pre-compiled — no Rust installation needed.

---

## Usage

```
inertia [options]

Target:
  -t, --target HOST         Target IP address or hostname

Ports:
  -p, --ports PORTS         Custom ports: 22,80,443 or 1-1024
  --preset PRESET           top100 | top1000 | top3000 | top10000 | todas

Protocols:
  --udp                     Enable UDP scanning (in addition to TCP)
  --tcp-only                TCP only (default)

Timing:
  -c, --concurrency N       Max concurrent probes (default: 400)
  --timeout MS              Per-port timeout in ms (default: auto-calibrated)
  --rate-limit PPS          Max probes per second (default: unlimited)

Output:
  -o, --output FILE         Save report to file
  -f, --format FORMAT       json | csv | html | txt

Behavior:
  --no-banner               Skip banner grabbing (faster)
  --no-logo                 Hide ASCII banner
  --demo                    Visual simulation — no network connections
  --update-ports            Re-download nmap-services cache
  --version                 Show version
```

---

## Examples

```bash
# Basic scan — auto-calibrated timeout, top 100 ports
inertia -t 192.168.1.1

# Top 3000 most common ports
inertia -t scanme.nmap.org --preset top3000

# TCP + UDP — detects DNS (53), NTP (123), SNMP (161)
inertia -t 192.168.1.1 --udp

# Custom port range with rate limiting
inertia -t 10.0.0.1 -p 1-10000 --rate-limit 300 -c 500

# Full scan — all 65535 ports
inertia -t 10.0.0.1 --preset todas -c 1000

# Export an HTML report
inertia -t 10.0.0.1 --preset top1000 -o report.html

# Visual demo — no network required
inertia --demo
```

---

## Architecture

Inertia is split into clear, single-responsibility modules:

```
inertia/
│
├── src/lib.rs                 # Rust core — async TCP/UDP, PyO3 bindings
│
└── inertia/
    ├── cli.py                 # Entry point — argument parsing, scan flow
    │
    ├── nucleo/                # Core logic
    │   ├── modelos.py         # Data types: ResultadoPorta, SessaoScan
    │   ├── scanner.py         # Orchestrator — calls Rust, enriches results
    │   ├── calibrador.py      # Auto timeout calibration
    │   ├── limitador.py       # Token Bucket rate limiter
    │   └── resolucao.py       # Hostname resolution + reverse DNS
    │
    ├── ui/
    │   ├── terminal.py        # Rich UI — banner, live hits, table, summary
    │   └── demo.py            # Demo mode (no network)
    │
    ├── utils/
    │   ├── portas.py          # nmap-services loader, presets, port parser
    │   └── servicos.py        # Service database + banner fingerprinting
    │
    └── relatorios/
        └── exportador.py      # JSON, CSV, HTML, TXT exporters
```

### How Python calls Rust

```
CLI (Python)
    │
    ▼
nucleo/scanner.py
    │
    │  from inertia import inertia_core   ← compiled .pyd / .so via PyO3
    │
    ▼
inertia_core.varrer_portas(host, ports, ...)
    │
    │  [Rust / Tokio]
    │  Semaphore → async fan-out → TCP connect / UDP probe → collect
    │
    ▼
ResultadoVarredura { portas: Vec<ResultadoPorta>, ... }
    │
    ▼
Python: enrichment → live hits → table → export
```

---

## Built With

| Technology | Role |
|---|---|
| [Rust](https://www.rust-lang.org/) | Async scan core |
| [Tokio](https://tokio.rs/) | Async runtime inside Rust |
| [PyO3](https://pyo3.rs/) | Rust ↔ Python native bindings |
| [maturin](https://www.maturin.rs/) | Build system for Rust+Python wheels |
| [Rich](https://github.com/Textualize/rich) | Terminal UI |
| [Jinja2](https://jinja.palletsprojects.com/) | HTML report templating |
| [nmap-services](https://github.com/nmap/nmap/blob/master/nmap-services) | Port frequency database |

---

## Ethical Use

Inertia is designed for **authorized** network diagnostics, security auditing, and education.

> **Only scan hosts and networks you own or have explicit written permission to test.**  
> Unauthorized port scanning may be illegal in your jurisdiction.

The `scanme.nmap.org` host is provided by the Nmap project specifically for testing scanners.

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">
<sub>Built with 🦀 Rust + 🐍 Python</sub>
</div>
