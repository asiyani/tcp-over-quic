use crate::quic_tunnel::connection;
use crate::Shutdown;
use anyhow::{anyhow, Result};
use futures::StreamExt;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, trace};

/// TCP Server listener state.
/// which performs the TCP listening and initialization of per-connection state.
pub struct Listener {
    pub incoming: quinn::Incoming,

    /// Broadcasts a shutdown signal to all active connections.
    pub notify_shutdown: broadcast::Sender<()>,

    // Used as part of the graceful shutdown process to wait for client
    // connections to complete processing.
    pub shutdown_complete_rx: mpsc::Receiver<()>,
    pub shutdown_complete_tx: mpsc::Sender<()>,
}

struct ConnectionHandler {
    _connection: quinn::Connection,
    bi_streams: quinn::IncomingBiStreams,
    shutdown: Shutdown,
    _shutdown_complete: mpsc::Sender<()>,
}

impl Listener {
    /// Run the server
    pub async fn run(&mut self) -> Result<()> {
        info!("accepting inbound quic connections");

        loop {
            let conn = self.incoming.next().await;

            if conn.is_none() {
                error!("empty connection received");
                continue;
            }

            let quinn::NewConnection {
                connection,
                bi_streams,
                ..
            } = conn.unwrap().await?;

            trace!("connection established {}", connection.remote_address());

            let mut conn = ConnectionHandler {
                _connection: connection,
                bi_streams,
                shutdown: Shutdown::new(self.notify_shutdown.subscribe()),
                _shutdown_complete: self.shutdown_complete_tx.clone(),
            };

            // Spawn a new task to process the connections.
            tokio::spawn(async move {
                if let Err(err) = conn.run().await {
                    error!(cause = ? err, "connection error");
                }
            });
        }
    }
}

impl ConnectionHandler {
    /// Process a single connection.
    async fn run(&mut self) -> Result<()> {
        // channel to notify all stream handler
        let (notify_shutdown, _) = broadcast::channel(1);
        let (shutdown_complete_tx, mut shutdown_complete_rx) = mpsc::channel(1);

        while !self.shutdown.is_shutdown() {
            tokio::select! {
                stream = self.bi_streams.next() => {

                    if stream.is_none() {
                        debug!("none received from stream!!");
                        continue;
                    }

                    debug!("stream established");

                    let stream = match stream.unwrap() {
                        Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                            debug!("incoming quic connection closed exiting...");
                            drop(notify_shutdown);
                            drop(shutdown_complete_tx);
                            let _ = shutdown_complete_rx.recv().await;
                            return Ok(());
                        }
                        Err(e) => {
                            error!("incoming quic connection error exiting...");
                            drop(notify_shutdown);
                            drop(shutdown_complete_tx);
                            let _ = shutdown_complete_rx.recv().await;
                            return Err(anyhow!("quic stream error: {}", e));
                        }
                        Ok(s) => s,
                    };
                    let ( send,  recv) = stream;

                    let mut conn = connection::Connection{
                        shutdown: Shutdown::new(notify_shutdown.subscribe()),
                        _shutdown_complete: shutdown_complete_tx.clone(),
                    };
                    // Spawn a new task to process each stream.
                    tokio::spawn(async move {
                        if let Err(err) = conn.run_concentrator_conn(send,recv).await {
                            error!(cause = ? err, "stream connection error");
                        }
                    });
                }

                // wait for shutdown signal
                _ = self.shutdown.recv() => {
                    debug!("ConnectionHandler: shutdown signal received indicating connection handler");
                    drop(notify_shutdown);
                    drop(shutdown_complete_tx);
                    let _ = shutdown_complete_rx.recv().await;
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}
