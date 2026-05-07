# scripts/compilar.ps1 - Inertia build script (Windows)
param([switch]$Release)
$ErrorActionPreference = "Stop"

Write-Host "Inertia - Compilando..." -ForegroundColor Cyan

if (-not (Get-Command rustup -ErrorAction SilentlyContinue)) {
    Write-Error "Rust nao encontrado. Instale em https://rustup.rs/"
}

if (-not (Test-Path ".venv")) {
    Write-Host "Criando ambiente virtual..." -ForegroundColor Yellow
    python -m venv .venv
}

& .venv\Scripts\Activate.ps1
pip install --upgrade pip maturin rich typer jinja2 pytest -q

Write-Host "Compilando nucleo Rust..." -ForegroundColor Yellow
if ($Release) { maturin develop --release } else { maturin develop }

Write-Host ""
Write-Host "Pronto!" -ForegroundColor Green
Write-Host "  .venv\Scripts\Activate.ps1"
Write-Host "  inertia --help"
