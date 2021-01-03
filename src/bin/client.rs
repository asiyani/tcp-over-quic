use anyhow::{anyhow, Result};
use clap::{App, Arg, ArgMatches};
use std::{fs, net};
use tcp_over_quic::client;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

pub fn create_options() -> ArgMatches<'static> {
    App::new("client")
        .version("0.1")
        .about("client is a tcp server and it tunnels tcp connections over quic streams towards the concentrator")
        .arg(
            Arg::with_name("tcp_source_port")
                .long("tcp_source_port")
                .help("the tcp source port to use for tcp server")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("quic_serv_addr")
                .long("quic_serv_addr")
                .help("quic server url where tcp traffic will be forwarded")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tcp_dest_addr")
                .long("tcp_dest_addr")
                .help("tcp address sent to quic server as tcp destination")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("quic_serv_cert_path")
                .long("quic_serv_cert_path")
                .help("quic server's CA to trust, in PEM format")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("quic_serv_name")
                .long("quic_serv_name")
                .help("quic server's name used in cert")
                .takes_value(true),
        )
        .get_matches()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // enable logging
    // see https://docs.rs/tracing for more info
    tracing_subscriber::fmt::try_init()?;

    let matches = create_options();
    let tcp_source_port = matches.value_of("tcp_source_port").unwrap();
    let quic_serv_addr = matches.value_of("quic_serv_addr").unwrap();
    let quic_serv_name = matches.value_of("quic_serv_name").unwrap();
    let ca_path = matches
        .value_of("quic_serv_cert_path")
        .unwrap_or("cert/public_cert.der");

    let tcp_dest_addr: net::SocketAddr = matches
        .value_of("tcp_dest_addr")
        .unwrap()
        .parse()
        .expect("invalid tcp destination address");

    let (notify_shutdown, _) = broadcast::channel(1);
    let (shutdown_complete_tx, shutdown_complete_rx) = mpsc::channel(1);

    // QUIC setup
    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();

    client_config.protocols(ALPN_QUIC_HTTP);
    client_config.add_certificate_authority(get_certificate(&ca_path).unwrap())?;

    endpoint.default_client_config(client_config.build());

    let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;

    let new_conn = endpoint
        .connect(&quic_serv_addr.parse().unwrap(), &quic_serv_name)?
        .await
        .map_err(|e| format!("failed to open stream: {}", e))?;

    info!("connected to quic server at {}", quic_serv_addr);

    let quinn::NewConnection {
        connection: conn, ..
    } = { new_conn };

    // TCP
    // Bind a TCP listener
    info!(
        "accepting inbound tcp connection on port {}",
        tcp_source_port
    );
    info!("remote outgoing tcp destination set to {}", tcp_dest_addr);
    let listener = TcpListener::bind(&format!("127.0.0.1:{}", tcp_source_port)).await?;
    // Initialize the listener state
    let mut server = client::Listener {
        listener,
        quic_connection: conn,
        tcp_dest_addr,
        notify_shutdown,
        shutdown_complete_tx,
        shutdown_complete_rx,
    };

    tokio::select! {
        res = server.run() => {
            if let Err(err) = res {
                error!(cause = % err, "failed to accept");
            }
        }
        _ = signal::ctrl_c() => {
            // The shutdown signal has been received.
            info!("shutting down");
        }
    }

    // Extract the `shutdown_complete` receiver and transmitter
    let client::Listener {
        mut shutdown_complete_rx,
        shutdown_complete_tx,
        notify_shutdown,
        ..
    } = server;

    // drop notify_shutdown to indicate shutdown
    drop(notify_shutdown);
    // drop own shutdown_complete_tx and wait for others
    drop(shutdown_complete_tx);
    let _ = shutdown_complete_rx.recv().await;

    Ok(())
}

fn get_certificate(cert_path: &str) -> Result<quinn::Certificate> {
    let cert = fs::read(cert_path)?;

    let certificate: Option<quinn::Certificate>;

    if cert.is_ascii() {
        let cert = quinn::CertificateChain::from_pem(&cert)?
            .iter()
            .next()
            .unwrap()
            .clone();
        certificate = Some(quinn::Certificate::from(cert))
    } else {
        certificate = Some(quinn::Certificate::from_der(&cert)?)
    };

    if certificate.is_some() {
        return Ok(certificate.unwrap());
    };

    Err(anyhow!("unable to parse cert"))
}
