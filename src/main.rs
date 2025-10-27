#![allow(dead_code)]

use server::Server;
use std::env;
use website_handler::WebsiteHandler;
use security::SecurityConfig;

mod http;
mod server;
mod website_handler;
mod security;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let default_path = format!("{}/public", env!("CARGO_MANIFEST_DIR"));
    let public_path = env::var("PUBLIC_PATH").unwrap_or(default_path);

    let canonical_path = std::fs::canonicalize(&public_path)
        .map_err(|_| format!("Invalid public path: {}", public_path))?;

    // TLS certificate paths
    let cert_path = format!("{}/certs/cert.pem", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{}/certs/key.pem", env!("CARGO_MANIFEST_DIR"));

    println!("=== HTTPS Server Starting ===");
    println!("Address: https://127.0.0.1:8443");
    println!("Serving files from: {}", canonical_path.display());
    println!("TLS Certificate: {}", cert_path);
    println!("TLS Private Key: {}", key_path);
    println!("Security features: TLS 1.2/1.3, Rate limiting, Security headers, File type validation");
    println!("\nAccess the server at:");
    println!("  - https://127.0.0.1:8443/hello");
    println!("  - https://127.0.0.1:8443/api.html");
    println!("\nNote: You'll need to accept the self-signed certificate warning in your browser.");
    println!("==============================\n");

    let security_config = SecurityConfig::default();

    // Create HTTPS server with TLS
    let server = Server::with_tls(
        "127.0.0.1:8443".to_string(),
        &cert_path,
        &key_path,
    )?;

    server.run(WebsiteHandler::new(canonical_path, security_config)).await
}