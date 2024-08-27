mod utils;
use crate::utils::{echo, full, full_framed, get_file_bytes, try_from_pem};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use http_body_util::BodyExt;
use hyper::{
    Request,
    client::conn::http2::handshake,
    server::conn::http2::Builder,
    service::service_fn
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use net::{TcpListener, TcpStream};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::private_key;
use std::{
    io::Cursor,
    sync::Arc,
    time::Duration
};
use tokio::net;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const HTTP2_KEEPALIVE_MILLIS: u64 = 500;
const HTTP2_WINDOW_SIZE: u32 = 2147418112;
const HTTP2_BUF_SIZE: usize = 2147418112;
const HTTP2_FRAME_SIZE: u32 = 16777215;

const CERT_FILE: &str = "repro-ca-cert.pem";
const SERVER_CERT_FILE: &str = "server-cert.pem";
const SERVER_KEY_FILE: &str = "server-key.pem";
const SERVER_CONF_FILE: &str = "server-ext.cnf";
const LARGE_PAYLOAD_SIZE:usize = 16 * 1024 * 1024;
const FRAME_SIZE: usize = 16 * 1024;




#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// The hostname to connect to or serve on.
    ///
    /// If provided, it sets the hostname for the server or client. If not provided, it will try to
    /// read from server-ext.cnf
    #[arg(long)]
    hostname: Option<String>,

    /// Whether to use Streaming frames for HTTP2.
    #[arg(long)]
    use_frames: bool,

    /// http or https
    #[arg(long)]
    use_tls: bool,

    // Whether to use large buffer sizes for the HTTP2 server
    #[arg(long)]
    use_large_buffers: bool,
}

#[derive(Subcommand)]
enum Commands {
    Server,
    Client,
    Combined,
}

async fn run_server(hostname: String, port: u16, use_large_buffers: bool) -> Result<()> { // Server
    // Create a TLS configuration
    let mut cursor = Cursor::new(get_file_bytes(SERVER_CERT_FILE));
    let certs = vec![rustls_pemfile::certs(&mut cursor)
        .next()
        .expect("No certificates found")
        .expect("Failed to parse certificate")];

    let mut key_reader = Cursor::new(get_file_bytes(SERVER_KEY_FILE));
    let private_key = private_key(&mut key_reader)
        .unwrap()
        .ok_or(anyhow!("No private key found".to_string()))?;


    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("bad certificate/key");
    let tls_config = Arc::new(tls_config);

    let listener = TcpListener::bind(&format!("{hostname}:{port}")).await?;
    let server_service = service_fn(echo);

    loop {
        match listener.accept().await {
            Ok((tcp_stream, _)) => {
                let tls_acceptor = TlsAcceptor::from(tls_config.clone());
                match tls_acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);
                        tokio::task::spawn(async move {
                            let mut binding = Builder::new(TokioExecutor::new());
                            let mut builder = binding
                                .keep_alive_interval(Duration::from_millis(HTTP2_KEEPALIVE_MILLIS));
                            if use_large_buffers {
                                 builder = builder.initial_connection_window_size(HTTP2_WINDOW_SIZE)
                                    .initial_stream_window_size(HTTP2_WINDOW_SIZE)
                                    .max_send_buf_size(HTTP2_BUF_SIZE)
                                    .max_frame_size(HTTP2_FRAME_SIZE);
                            }
                            if let Err(err) = builder
                                .timer(TokioTimer::new())
                                .serve_connection(io, server_service).await {
                                eprintln!("Error serving connection: {}", err);
                            }
                        });
                    },
                    Err(e) => eprintln!("TLS acceptance error: {}", e),
                }
            },
            Err(e) => eprintln!("TCP connection acceptance error: {}", e),
        }
    }
}

async fn run_client(hostname: String, port: u16, use_frames: bool, use_tls: bool) -> Result<()> {
    let cert_bytes = get_file_bytes(CERT_FILE);
    // Create the TLS config
    let cert = try_from_pem(&cert_bytes).map_err(|e| anyhow!("Failed to parse PEM certificate: {}", e))?;
    let mut root_store = RootCertStore::empty();
    root_store.add(cert).map_err(|e| anyhow!("Failed to add certificate to root store: {}", e))?;
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp_stream = TcpStream::connect(&format!("{hostname}:{port}")).await.map_err(|e| anyhow!("Failed to connect to server: {}", e))?;

    let domain = ServerName::try_from(hostname.clone()).map_err(|e| anyhow!("Failed to create ServerName: {}", e))?;
    let tls_stream = connector.connect(domain, tcp_stream).await.map_err(|e| anyhow!("Failed to establish TLS connection: {}", e))?;
    let io = TokioIo::new(tls_stream);
    let executor = hyper_util::rt::tokio::TokioExecutor::new();

    let (mut sender, conn) = handshake(executor, io).await?;

    tokio::task::spawn(async move {
        if let Err(e) = conn.await {
            println!("Error: {:?}", e);
        }
    });

    let protocol = if use_tls {
        "https"
    } else
    {
        "http"
    };
    let url = format!("{protocol}://{hostname}:{port}/foo");
    for _i in 0..100 {
        let builder = Request::builder().method("POST").uri(url.clone());
        let request = if use_frames {
            builder.body(full_framed()).unwrap()
        } else {
            builder.body(full()).unwrap()
        };
        let res = sender.send_request(request).await.unwrap();
        let _body = res.collect().await?.to_bytes();
    }
    Ok(())
}
#[tokio::main]
async fn main() ->Result<()> {
    let cli = Cli::parse();
    let hostname = match cli.hostname {
        Some(hostname) => hostname,
        None => utils::extract_host()
            .context("Missing file")?
            .ok_or_else(|| anyhow::anyhow!("Hostname not found in file"))?,
    };
    let port = match hostname.as_str() {
        "localhost" => 3000,
        h if h.ends_with("amazonaws.com") => 443,
        _ => return Err(anyhow::anyhow!("Unsupported: only localhost and EC2 right now are accepted")),
    };


    match cli.command {
        Commands::Server => run_server(hostname, port, cli.use_large_buffers).await?,
        Commands::Client => run_client(hostname, port, cli.use_frames, cli.use_tls).await?,
        Commands::Combined => {
            tokio::task::spawn(run_server(hostname.clone(), port, cli.use_large_buffers));
            run_client(hostname, port, cli.use_frames, cli.use_tls).await?
        }
    }


    Ok(())
}