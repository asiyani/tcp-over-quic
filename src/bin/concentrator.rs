use anyhow::{anyhow, Result};
use clap::{App, Arg, ArgMatches};
use core::time::Duration;
use quinn::{Certificate, CertificateChain, PrivateKey};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tcp_over_quic::concentrator;
use tokio::signal;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info};

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

pub fn create_options() -> ArgMatches<'static> {
    App::new("concentrator")
        .version("0.1")
        .about("its a quic server and it converts quic streams from client to tcp connections towards the tcp server")
        .arg(
            Arg::with_name("quic_serv_port")
                .long("quic_serv_port")
                .help("quic server port address to listen on")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("quic_serv_cert_path")
                .long("quic_serv_cert_path")
                .help("quic server cert, in PEM format")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("quic_serv_key_path")
                .long("quic_serv_key_path")
                .help("quic server cert private key, in PEM format")
                .takes_value(true),
        )
        .get_matches()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // enable logging
    tracing_subscriber::fmt::try_init()?;

    let matches = create_options();

    // setup configs
    let quic_serv_port = matches.value_of("quic_serv_port").unwrap_or("4433");
    let quic_serv_cert_path = matches
        .value_of("quic_serv_cert_path")
        .unwrap_or("./cert/cert.pem");
    let quic_serv_key_path = matches
        .value_of("quic_serv_key_path")
        .unwrap_or("./cert/key.pem");

    let (notify_shutdown, _) = broadcast::channel(1);
    let (shutdown_complete_tx, shutdown_complete_rx) = mpsc::channel(1);

    // Get/Create certs
    let (certificate, key) = match get_certificate(quic_serv_cert_path, quic_serv_key_path) {
        Ok((certificate, key)) => (certificate, key),
        Err(e) => {
            error!("unable to parse certificate {}", e);
            generate_self_signed_cert().expect("unable to generate certificate")
        }
    };

    // setup quic server
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .stream_window_uni(0)
        // keep client connection alive package
        // default max idle timeout is 10sec and cant be modified
        .keep_alive_interval(Some(Duration::from_secs(5)));

    let mut server_config = quinn::ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);

    server_config.protocols(ALPN_QUIC_HTTP);
    server_config.certificate(CertificateChain::from_certs(vec![certificate]), key)?;

    let mut endpoint = quinn::Endpoint::builder();
    endpoint.listen(server_config.build());

    let (_, incoming) = endpoint
        .bind(&format!("127.0.0.1:{}", quic_serv_port).parse()?)
        .expect(&format!("unable to bind to local port {}", quic_serv_port));

    info!("listening for quic stream on {}", quic_serv_port);

    let mut server = concentrator::Listener {
        incoming,
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
    let concentrator::Listener {
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

fn get_certificate(cert_path: &str, key_path: &str) -> Result<(Certificate, PrivateKey)> {
    let key = &fs::read(key_path)?;
    let cert = &fs::read(cert_path)?;

    let private_key: Option<PrivateKey>;
    let certificate: Option<Certificate>;

    // check for certificate
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

    // check for key
    if key.is_ascii() {
        private_key = Some(quinn::PrivateKey::from_pem(key)?)
    } else {
        private_key = Some(quinn::PrivateKey::from_der(key)?)
    }

    if certificate.is_some() && private_key.is_some() {
        return Ok((certificate.unwrap(), private_key.unwrap()));
    }

    Err(anyhow!("unable to parse cert or private key"))
}

fn generate_self_signed_cert() -> Result<(Certificate, PrivateKey)> {
    let path = Path::new("./cert");
    let cert_path = path.join("public_cert.der");
    let key_path = path.join("private_key.der");

    info!("generating self signed certificate for server at './cert/public_cert.der'");

    // Generate dummy certificate.
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let serialized_key = certificate.serialize_private_key_der();
    let serialized_certificate = certificate.serialize_der().unwrap();

    // Write to files.
    fs::write(&cert_path, &serialized_certificate).expect("failed to write certificate");
    fs::write(&key_path, &serialized_key).expect("failed to write private key");

    let cert = quinn::Certificate::from_der(&serialized_certificate)?;
    let key = quinn::PrivateKey::from_der(&serialized_key)?;
    Ok((cert, key))
}
