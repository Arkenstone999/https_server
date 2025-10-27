use crate::http::{ParseError, Request, Response, StatusCode};
use std::convert::TryFrom;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use std::sync::Arc;
use std::fs::File;
use std::io::BufReader;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio_rustls::TlsAcceptor;

pub trait Handler: Send + Sync + 'static {
    fn handle_request(&self, request: &Request, client_ip: SocketAddr) -> Response;

    fn handle_bad_request(&self, e: &ParseError) -> Response {
        eprintln!("Failed to parse request: {}", e);
        Response::new(StatusCode::BadRequest, Some("Invalid request format".to_string()))
    }

    fn handle_security_violation(&self, reason: &str, client_ip: SocketAddr) -> Response {
        eprintln!("Security violation from {}: {}", client_ip, reason);
        Response::security_error("Request blocked for security reasons")
    }
}

pub struct Server {
    addr: String,
    tls_config: Option<Arc<ServerConfig>>,
}

impl Server {
    pub fn new(addr: String) -> Self {
        Self {
            addr,
            tls_config: None,
        }
    }

    /// Load TLS certificates and create a server with HTTPS support
    pub fn with_tls(
        addr: String,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Load certificate chain
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain = certs(&mut cert_reader)?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

        // Load private key
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let mut keys = pkcs8_private_keys(&mut key_reader)?;

        if keys.is_empty() {
            return Err("No private key found in key file".into());
        }

        let private_key = rustls::PrivateKey(keys.remove(0));

        // Build TLS configuration
        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(Self {
            addr,
            tls_config: Some(Arc::new(tls_config)),
        })
    }

    pub async fn run<H: Handler>(self, handler: H) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.addr).await?;
        let handler = Arc::new(handler);

        let protocol = if self.tls_config.is_some() { "HTTPS" } else { "HTTP" };
        println!("Listening on {} ({})", self.addr, protocol);

        // Create TLS acceptor if TLS is enabled
        let tls_acceptor = self.tls_config.map(TlsAcceptor::from);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let handler = Arc::clone(&handler);
                    let tls_acceptor = tls_acceptor.clone();

                    tokio::spawn(async move {
                        // If TLS is enabled, perform TLS handshake
                        if let Some(acceptor) = tls_acceptor {
                            match acceptor.accept(stream).await {
                                Ok(mut tls_stream) => {
                                    handle_connection(&mut tls_stream, addr, handler).await;
                                }
                                Err(e) => {
                                    eprintln!("TLS handshake failed from {}: {}", addr, e);
                                }
                            }
                        } else {
                            // Plain HTTP connection
                            let mut stream = stream;
                            handle_connection(&mut stream, addr, handler).await;
                        }
                    });
                }
                Err(e) => eprintln!("Failed to establish connection: {}", e),
            }
        }
    }
}

/// Handle a connection (works for both TLS and non-TLS streams)
async fn handle_connection<S>(
    stream: &mut S,
    addr: SocketAddr,
    handler: Arc<dyn Handler>,
) where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut buffer = vec![0; 8192];

    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read(&mut buffer)
    ).await {
        Ok(Ok(size)) => {
            if size == 0 {
                return; // Connection closed
            }

            buffer.truncate(size);

            let response = match Request::try_from(&buffer[..]) {
                Ok(request) => {
                    println!(" {} {} {} ({})",
                        addr,
                        request.method_str(),
                        request.path(),
                        size
                    );
                    handler.handle_request(&request, addr)
                },
                Err(e) => {
                    eprintln!("Parse error from {}: {}", addr, e);
                    handler.handle_bad_request(&e)
                },
            };

            if let Err(e) = response.send(stream).await {
                eprintln!("Failed to send response to {}: {}", addr, e);
            }
        }
        Ok(Err(e)) => eprintln!("Failed to read from {}: {}", addr, e),
        Err(_) => {
            eprintln!("Request timeout from {}", addr);
            let timeout_response = Response::new(
                StatusCode::RequestTimeout,
                Some("Request timeout".to_string())
            );
            let _ = timeout_response.send(stream).await;
        },
    }
}