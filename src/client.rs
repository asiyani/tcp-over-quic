use crate::quic_tunnel::connection;
use crate::Shutdown;
use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::time::{self, Duration};
use tracing::{error, trace};

/// TCP Server listener state.
/// which performs the TCP listening and initialization of per-connection state.
pub struct Listener {
    pub listener: TcpListener,

    pub quic_connection: quinn::Connection,

    pub tcp_dest_addr: SocketAddr,

    /// Broadcasts a shutdown signal to all active connections.
    pub notify_shutdown: broadcast::Sender<()>,

    /// Used as part of the graceful shutdown process to wait for client
    /// connections to complete processing.
    pub shutdown_complete_rx: mpsc::Receiver<()>,
    pub shutdown_complete_tx: mpsc::Sender<()>,
}

impl Listener {
    /// Run the server
    pub async fn run(&mut self) -> Result<()> {
        loop {
            let socket = self.accept().await?;

            trace!(
                "new connection accepted opening quic stream {:?}",
                socket.local_addr()
            );

            let (quic_send, quic_recv) = self.quic_connection.open_bi().await?;

            // Create the necessary per-connection handler state.
            let mut conn = connection::Connection {
                shutdown: Shutdown::new(self.notify_shutdown.subscribe()),
                _shutdown_complete: self.shutdown_complete_tx.clone(),
            };
            let addr = self.tcp_dest_addr;
            // Spawn a new task to process each stream.
            tokio::spawn(async move {
                if let Err(err) = conn
                    .run_client_conn(addr, socket, quic_send, quic_recv)
                    .await
                {
                    error!(cause = ? err, "stream error");
                }
            });
        }
    }

    /// Accept an inbound connection.
    async fn accept(&mut self) -> Result<TcpStream> {
        let mut backoff = 1;

        // Try to accept a few times
        loop {
            match self.listener.accept().await {
                Ok((socket, _)) => return Ok(socket),
                Err(err) => {
                    if backoff > 64 {
                        // Accept has failed too many times. Return the error.
                        return Err(err.into());
                    }
                }
            }

            // Pause execution until the back off period elapses.
            // sleep on tokio 0.3
            time::delay_for(Duration::from_secs(backoff)).await;
            backoff *= 2;
        }
    }
}
