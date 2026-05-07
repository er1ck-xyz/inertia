/// Inertia — Núcleo de varredura assíncrona em Rust.
///
/// Este módulo é compilado como extensão Python nativa via PyO3.
/// O Python chama `varrer_portas()` e recebe de volta uma lista
/// de `ResultadoPorta` com status, latência e banner.
///
/// Fluxo:
///   Python → varrer_portas() → Tokio runtime → N tasks async
///   → probe_tcp() / probe_udp() → ResultadoPorta → Python
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use pyo3::prelude::*;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

// ─────────────────────────────────────────────────────────────────────────────
// Estruturas de dados
// ─────────────────────────────────────────────────────────────────────────────

/// Status de uma porta após a sondagem.
#[derive(Debug, Clone, PartialEq)]
enum StatusPorta {
    Aberta,
    Fechada,
    Filtrada,
}

impl StatusPorta {
    fn como_str(&self) -> &'static str {
        match self {
            StatusPorta::Aberta   => "open",
            StatusPorta::Fechada  => "closed",
            StatusPorta::Filtrada => "filtered",
        }
    }
}

/// Resultado de uma porta — exposto ao Python via atributos `.get`.
#[pyclass]
#[derive(Clone)]
pub struct ResultadoPorta {
    #[pyo3(get)] pub porta:       u16,
    #[pyo3(get)] pub status:      String,
    #[pyo3(get)] pub protocolo:   String,
    #[pyo3(get)] pub latencia_ms: f64,
    #[pyo3(get)] pub banner:      String,
}

#[pymethods]
impl ResultadoPorta {
    fn __repr__(&self) -> String {
        format!(
            "ResultadoPorta(porta={}, protocolo={}, status='{}', latencia={:.1}ms)",
            self.porta, self.protocolo, self.status, self.latencia_ms
        )
    }
}

/// Resultado consolidado de toda a varredura de um alvo.
#[pyclass]
pub struct ResultadoVarredura {
    #[pyo3(get)] pub alvo:      String,
    #[pyo3(get)] pub portas:    Vec<ResultadoPorta>,
    #[pyo3(get)] pub total_ms:  f64,
    #[pyo3(get)] pub abertas:   usize,
    #[pyo3(get)] pub fechadas:  usize,
    #[pyo3(get)] pub filtradas: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sondagem TCP
// ─────────────────────────────────────────────────────────────────────────────

/// Tenta abrir uma conexão TCP completa na porta.
///
/// Se conectar → ABERTA (e tenta capturar banner).
/// Se receber RST → FECHADA.
/// Se timeout ou erro de rede → FILTRADA.
async fn probe_tcp(
    ip:         IpAddr,
    porta:      u16,
    timeout_ms: u64,
) -> (StatusPorta, f64, String) {
    let endereco = SocketAddr::new(ip, porta);
    let prazo    = Duration::from_millis(timeout_ms);
    let inicio   = Instant::now();

    match timeout(prazo, TcpStream::connect(endereco)).await {
        // Conexão estabelecida com sucesso
        Ok(Ok(mut stream)) => {
            let latencia = inicio.elapsed().as_secs_f64() * 1000.0;
            let banner   = capturar_banner_tcp(&mut stream, porta, timeout_ms).await;
            (StatusPorta::Aberta, latencia, banner)
        }

        // Conexão recusada — porta fechada (RST recebido)
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            let latencia = inicio.elapsed().as_secs_f64() * 1000.0;
            (StatusPorta::Fechada, latencia, String::new())
        }

        // Qualquer outro erro de I/O — tratar como filtrada
        Ok(Err(_)) => {
            let latencia = inicio.elapsed().as_secs_f64() * 1000.0;
            (StatusPorta::Filtrada, latencia, String::new())
        }

        // Timeout esgotado — sem resposta
        Err(_timeout_elapsed) => {
            let latencia = inicio.elapsed().as_secs_f64() * 1000.0;
            (StatusPorta::Filtrada, latencia, String::new())
        }
    }
}

/// Tenta capturar o banner de um serviço TCP recém-conectado.
///
/// Estratégia em dois passos:
///   1. Aguarda dados espontâneos (SSH, FTP, SMTP enviam banner sem precisar pedir).
///   2. Se não chegar nada, envia uma requisição mínima adequada à porta
///      (HTTP HEAD para 80/8080, CRLF para SMTP/FTP) e lê a resposta.
async fn capturar_banner_tcp(
    stream:     &mut TcpStream,
    porta:      u16,
    timeout_ms: u64,
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let prazo_banner = Duration::from_millis(timeout_ms.min(1000));
    let mut buf = [0u8; 512];

    // Passo 1: leitura passiva
    let bytes_lidos = match timeout(prazo_banner, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _                   => 0,
    };

    if bytes_lidos > 0 {
        return sanitizar_banner(&buf[..bytes_lidos]);
    }

    // Passo 2: envio de requisição mínima por protocolo
    let requisicao: &[u8] = match porta {
        80 | 8080 | 8000 | 8888 => b"HEAD / HTTP/1.0\r\n\r\n",
        21 | 25 | 110 | 143 | 587 => b"\r\n",
        _ => return String::new(),
    };

    let _ = stream.write_all(requisicao).await;

    let prazo_resposta = Duration::from_millis(timeout_ms.min(1500));
    match timeout(prazo_resposta, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => sanitizar_banner(&buf[..n]),
        _                   => String::new(),
    }
}

/// Converte bytes brutos em string legível, removendo caracteres de controle.
fn sanitizar_banner(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(120)
        .collect::<String>()
        .trim()
        .to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Sondagem UDP
// ─────────────────────────────────────────────────────────────────────────────

/// Retorna o payload UDP mais adequado para uma porta conhecida.
///
/// Serviços como DNS e NTP precisam receber uma requisição válida
/// para enviar resposta. Para portas desconhecidas, enviamos um
/// datagrama vazio — se o host responder com ICMP port unreachable,
/// o Tokio converte em ConnectionRefused → porta FECHADA.
fn payload_udp_para_porta(porta: u16) -> &'static [u8] {
    match porta {
        // DNS — query mínima para "version.bind"
        53 => &[
            0x00, 0x1e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x07, b'v', b'e', b'r',
            b's', b'i', b'o', b'n', 0x04, b'b', b'i', b'n',
            b'd', 0x00, 0x00, 0x10, 0x00, 0x03,
        ],
        // NTP — requisição de cliente modo 3
        123 => &[
            0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        // SNMP — GetRequest comunidade "public"
        161 => &[
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06,
            b'p', b'u', b'b', b'l', b'i', b'c',
            0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b,
            0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02,
            0x01, 0x05, 0x00,
        ],
        _ => &[],
    }
}

/// Sonda uma porta UDP.
///
/// Resultado:
///   Recebeu datagrama de volta → ABERTA
///   ICMP port unreachable      → FECHADA
///   Timeout sem resposta       → FILTRADA (pode estar aberta ou bloqueada)
async fn probe_udp(
    ip:         IpAddr,
    porta:      u16,
    timeout_ms: u64,
) -> (StatusPorta, f64) {
    let prazo  = Duration::from_millis(timeout_ms);
    let inicio = Instant::now();

    // Cria socket UDP efêmero local
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s)  => s,
        Err(_) => return (StatusPorta::Filtrada, 0.0),
    };

    let destino = SocketAddr::new(ip, porta);
    let payload = payload_udp_para_porta(porta);

    if socket.send_to(payload, destino).await.is_err() {
        return (StatusPorta::Filtrada, inicio.elapsed().as_secs_f64() * 1000.0);
    }

    let mut buf = [0u8; 512];
    match timeout(prazo, socket.recv_from(&mut buf)).await {
        // Recebeu resposta UDP — serviço ativo
        Ok(Ok(_)) => {
            (StatusPorta::Aberta, inicio.elapsed().as_secs_f64() * 1000.0)
        }

        // Erro de conexão — provável ICMP port unreachable (porta fechada)
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused
                   || e.raw_os_error() == Some(10054)  // WSAECONNRESET (Windows)
                   || e.raw_os_error() == Some(111) =>  // ECONNREFUSED (Linux)
        {
            (StatusPorta::Fechada, inicio.elapsed().as_secs_f64() * 1000.0)
        }

        // Outros erros ou timeout — sem informação suficiente
        _ => (StatusPorta::Filtrada, inicio.elapsed().as_secs_f64() * 1000.0),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop de varredura
// ─────────────────────────────────────────────────────────────────────────────

/// Executa a varredura assíncrona de todas as portas no alvo.
///
/// Cria N tasks Tokio (limitadas pelo Semaphore) que rodam em paralelo.
/// Cada task processa uma (porta, protocolo) e retorna um ResultadoPorta.
async fn executar_varredura(
    alvo:        String,
    portas:      Vec<u16>,
    timeout_ms:  u64,
    concorrencia: usize,
    delay_ms:    u64,
    tcp:         bool,
    udp:         bool,
) -> PyResult<ResultadoVarredura> {
    // Resolve o hostname para endereço IP
    let ip = resolver_ip(&alvo).await?;

    let semaforo     = Arc::new(Semaphore::new(concorrencia));
    let inicio_total = Instant::now();

    // Monta lista de tarefas: cada porta pode virar 1 ou 2 tarefas (tcp e/ou udp)
    let tarefas: Vec<(u16, &'static str)> = portas
        .iter()
        .flat_map(|&porta| {
            let mut lista = Vec::new();
            if tcp { lista.push((porta, "tcp")); }
            if udp { lista.push((porta, "udp")); }
            lista
        })
        .collect();

    // Executa todas as tarefas em paralelo com limite de concorrência
    let resultados: Vec<ResultadoPorta> = stream::iter(tarefas)
        .map(|(porta, protocolo)| {
            let sem   = Arc::clone(&semaforo);
            let alvo2 = alvo.clone();

            async move {
                // Aguarda uma vaga no semáforo antes de abrir socket
                let _permissao = sem.acquire_owned().await.expect("semáforo fechado");

                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }

                match protocolo {
                    "tcp" => {
                        let (status, latencia, banner) = probe_tcp(ip, porta, timeout_ms).await;
                        ResultadoPorta {
                            porta,
                            status:      status.como_str().to_string(),
                            protocolo:   "tcp".to_string(),
                            latencia_ms: latencia,
                            banner,
                        }
                    }
                    _ => {
                        let (status, latencia) = probe_udp(ip, porta, timeout_ms).await;
                        ResultadoPorta {
                            porta,
                            status:      status.como_str().to_string(),
                            protocolo:   "udp".to_string(),
                            latencia_ms: latencia,
                            banner:      String::new(),
                        }
                    }
                }
            }
        })
        .buffer_unordered(concorrencia)
        .collect()
        .await;

    let total_ms  = inicio_total.elapsed().as_secs_f64() * 1000.0;
    let abertas   = resultados.iter().filter(|r| r.status == "open").count();
    let fechadas  = resultados.iter().filter(|r| r.status == "closed").count();
    let filtradas = resultados.iter().filter(|r| r.status == "filtered").count();

    Ok(ResultadoVarredura { alvo, portas: resultados, total_ms, abertas, fechadas, filtradas })
}

/// Resolve um hostname (ou IP em string) para IpAddr.
async fn resolver_ip(alvo: &str) -> PyResult<IpAddr> {
    if let Ok(ip) = IpAddr::from_str(alvo) {
        return Ok(ip);
    }

    let ip = tokio::net::lookup_host(format!("{}:0", alvo))
        .await
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("Não foi possível resolver '{}': {}", alvo, e)
        ))?
        .next()
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(
            format!("Nenhum endereço encontrado para '{}'", alvo)
        ))?
        .ip();

    Ok(ip)
}

// ─────────────────────────────────────────────────────────────────────────────
// Função pública exposta ao Python
// ─────────────────────────────────────────────────────────────────────────────

/// Varre portas TCP e/ou UDP em um alvo.
///
/// Parâmetros (todos têm valores padrão):
///   alvo         — hostname ou endereço IP
///   portas       — lista de portas a varrer
///   timeout_ms   — timeout por porta em milissegundos
///   concorrencia — máximo de sockets abertos simultaneamente
///   delay_ms     — pausa entre sondagens (0 = sem pausa)
///   tcp          — habilitar varredura TCP
///   udp          — habilitar varredura UDP
#[pyfunction]
#[pyo3(signature = (alvo, portas, timeout_ms=1500, concorrencia=400, delay_ms=0, tcp=true, udp=false))]
pub fn varrer_portas(
    alvo:         String,
    portas:       Vec<u16>,
    timeout_ms:   u64,
    concorrencia: usize,
    delay_ms:     u64,
    tcp:          bool,
    udp:          bool,
) -> PyResult<ResultadoVarredura> {
    if portas.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err("Lista de portas vazia"));
    }
    if !tcp && !udp {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Pelo menos um protocolo (tcp ou udp) deve estar ativo"
        ));
    }
    if concorrencia == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Concorrência deve ser >= 1"));
    }

    // Cada chamada cria seu próprio runtime Tokio — não há estado global
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(
            format!("Falha ao inicializar runtime Tokio: {}", e)
        ))?;

    rt.block_on(executar_varredura(alvo, portas, timeout_ms, concorrencia, delay_ms, tcp, udp))
}

// ─────────────────────────────────────────────────────────────────────────────
// Registro do módulo Python
// ─────────────────────────────────────────────────────────────────────────────

#[pymodule]
fn inertia_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ResultadoPorta>()?;
    m.add_class::<ResultadoVarredura>()?;
    m.add_function(wrap_pyfunction!(varrer_portas, m)?)?;
    Ok(())
}
