use crate::quic_tunnel::tlv;
use crate::Shutdown;
use anyhow::Result;
use quinn::{RecvStream, SendStream, VarInt};
use std::net::SocketAddr;
use tokio::net::{tcp, TcpStream};
use tokio::prelude::*;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, instrument};

// tcp payload size based on 1500 MTU
const TCP_BUF_SIZE: usize = 1480;
const QUIC_BUF_SIZE: usize = 1480;

pub struct Connection {
    pub shutdown: Shutdown,

    // when `Connection` is dropped it
    // Notifies the main process after shutting stream and tcp connection
    pub _shutdown_complete: mpsc::Sender<()>,
}

struct QuicToTcp {
    pub quic_recv: quinn::RecvStream,
    pub tcp_write: tcp::OwnedWriteHalf,
    pub shutdown: Shutdown,
    pub _shutdown_complete: mpsc::Sender<()>,
}

struct TcpToQuic {
    pub tcp_read: tcp::OwnedReadHalf,
    pub quic_send: quinn::SendStream,
    pub shutdown: Shutdown,
    pub _shutdown_complete: mpsc::Sender<()>,
}

impl Connection {
    pub async fn run_client_conn(
        &mut self,
        tcp_dest_addr: SocketAddr,
        tcp_streamer: TcpStream,
        mut quic_send: SendStream,
        mut quic_recv: RecvStream,
    ) -> Result<()> {
        let (notify_shutdown, _) = broadcast::channel(1);
        let (shutdown_complete_tx, mut shutdown_complete_rx) = mpsc::channel(1);

        let mut buf = [0; 20];
        // send TCP Connect TLV
        let n = tlv::new_tcp_connect(&mut buf, &tcp_dest_addr);
        if let Err(e) = n {
            error!("error while creating tcp connect tlv {}", e);
            return Ok(());
        }
        if let Err(e) = quic_send.write_all(&buf[..n.unwrap()]).await {
            error!("error sending tcp connect data to quic stream {}", e);
        };

        //  End TLV
        let n = tlv::new_tcp_connect_ok(&mut buf);
        if let Err(e) = n {
            error!("error while creating tcp ok connect tlv {}", e);
            return Ok(());
        }
        if let Err(e) = quic_send.write_all(&buf[..n.unwrap()]).await {
            error!("error sending tcp connect data to quic stream {}", e);
        };

        // wait for TCP Connect OK TLV
        let quic_read_count = quic_recv.read(&mut buf).await;
        if let Err(ref e) = quic_read_count {
            error!("error reading quic stream {}", e);
            tcp_streamer.shutdown(std::net::Shutdown::Both)?;
            return Ok(());
        }
        let quic_read_count = quic_read_count.unwrap();

        if quic_read_count.is_none() {
            tcp_streamer.shutdown(std::net::Shutdown::Both)?;
            return Ok(());
        }

        let n = quic_read_count.unwrap();

        if !tlv::is_tcp_connect_ok(&buf[..n]) {
            tcp_streamer.shutdown(std::net::Shutdown::Both)?;
            return Ok(());
        }

        let (tcp_read, tcp_write) = tcp_streamer.into_split();

        let mut quic_to_tcp = QuicToTcp {
            quic_recv,
            tcp_write,
            shutdown: Shutdown::new(notify_shutdown.subscribe()),
            _shutdown_complete: shutdown_complete_tx.clone(),
        };

        let mut tcp_to_quic = TcpToQuic {
            tcp_read,
            quic_send,
            shutdown: Shutdown::new(notify_shutdown.subscribe()),
            _shutdown_complete: shutdown_complete_tx.clone(),
        };

        // Spawn a new tasks to handle bidirectional communication.
        tokio::spawn(async move {
            if let Err(err) = quic_to_tcp.handle().await {
                error!(cause = ? err, "stream error");
            }
        });
        tokio::spawn(async move {
            if let Err(err) = tcp_to_quic.handle().await {
                error!(cause = ? err, "stream error");
            }
        });

        drop(shutdown_complete_tx);
        tokio::select! {
           _ =  self.shutdown.recv() => {
                    drop(notify_shutdown);
                    let _ = shutdown_complete_rx.recv().await;
                }
           _ = shutdown_complete_rx.recv() => {}
        };
        Ok(())
    }

    pub async fn run_concentrator_conn(
        &mut self,
        mut quic_send: SendStream,
        mut quic_recv: RecvStream,
    ) -> Result<()> {
        let (notify_shutdown, _) = broadcast::channel(1);
        let (shutdown_complete_tx, mut shutdown_complete_rx) = mpsc::channel(1);

        // wait for quic tunnel tlv
        let mut buf = [0; 1024];
        let n = quic_recv.read(&mut buf).await;
        // TODO:parse tlv
        if let Err(ref e) = n {
            error!("error reading quic tlv stream close TCP connection?{}", e);
            return Ok(());
        }
        let remote_addr = match n.unwrap() {
            Some(_) => tlv::parse_tcp_connect(&buf),
            None => {
                // the quic stream is finished close TCP connection
                return Ok(());
            }
        };

        if let Err(e) = remote_addr {
            error!(" TCP Connect TLV parse error  {}", e);
            return Ok(());
        }
        // initiate tcp connection
        let remote_addr = remote_addr.unwrap();
        let dest_tcp = TcpStream::connect(&remote_addr).await;

        // If unable to connect to remote tcp destination return error tlv
        if let Err(e) = dest_tcp {
            error!(
                "unable to establish tcp connection to {} err: {}",
                remote_addr, e
            );
            let n = tlv::new_error_tlv(&mut buf).unwrap();
            quic_send.write(&mut buf[..n]).await?;
            return Ok(());
        }

        // send TCP Connect OK TLV
        let n = tlv::new_tcp_connect_ok(&mut buf).unwrap();
        quic_send.write(&mut buf[..n]).await?;

        let (tcp_read, tcp_write) = dest_tcp.unwrap().into_split();

        let mut quic_to_tcp = QuicToTcp {
            quic_recv,
            tcp_write,
            shutdown: Shutdown::new(notify_shutdown.subscribe()),
            _shutdown_complete: shutdown_complete_tx.clone(),
        };

        let mut tcp_to_quic = TcpToQuic {
            tcp_read,
            quic_send,
            shutdown: Shutdown::new(notify_shutdown.subscribe()),
            _shutdown_complete: shutdown_complete_tx.clone(),
        };

        // Spawn a new tasks to handle bidirectional communication.
        tokio::spawn(async move {
            if let Err(err) = quic_to_tcp.handle().await {
                error!(cause = ? err, "stream error");
            }
        });
        tokio::spawn(async move {
            if let Err(err) = tcp_to_quic.handle().await {
                error!(cause = ? err, "stream error");
            }
        });

        drop(shutdown_complete_tx);
        tokio::select! {
           _ =  self.shutdown.recv() => {
                    drop(notify_shutdown);
                    let _ = shutdown_complete_rx.recv().await;
                }
           _ = shutdown_complete_rx.recv() => {}
        };
        Ok(())
    }
}

impl TcpToQuic {
    #[instrument(skip(self))]
    async fn handle(&mut self) -> Result<()> {
        let mut tcp_buf = [0; TCP_BUF_SIZE];

        while !self.shutdown.is_shutdown() {
            tokio::select! {
                // wait for data from tcp and send to quic
                count = self.tcp_read.read(&mut tcp_buf) => {
                    match count {
                        Ok(0) => {
                            // graceful TCP->QUIC shutdown
                            debug!("graceful TCP->QUIC shutdown");
                            if let Err(e) = self.quic_send.finish().await {
                                debug!("error closing quic write stream {}",e);
                            }
                            return Ok(());
                        },
                        Ok(n) => {
                            debug!("tcp data size {}\n", n);
                            if let Err(e) = self.quic_send.write_all(&tcp_buf[..n]).await {
                                // handle remote TCP RST
                                // forced QUIC->TCP shutdown
                                debug!("error in writing to quic stream forced QUIC->TCP shutdown - {}", e);
                                return Ok(());
                            };
                        },
                        Err(err) => {
                            // handle TCP RST
                            // forced TCP->QUIC shutdown
                            debug!("error in reading tcp stream forced TCP->QUIC shutdown - {}", err);
                            let err_code:VarInt = VarInt::from_u32(0);
                            self.quic_send.reset(err_code);
                            return Ok(());
                        },
                    }
                },

                // wait for shutdown signal
                _ = self.shutdown.recv() => {
                    debug!("shutdown down TcpToQuic");
                    if let Err(e) = self.quic_send.finish().await {
                        debug!("error gracefully shutting send stream {}",e);
                    }
                    return Ok(());
                }
            };
        }
        Ok(())
    }
}

impl QuicToTcp {
    #[instrument(skip(self))]
    async fn handle(&mut self) -> Result<()> {
        let mut quic_buf = [0; QUIC_BUF_SIZE];

        while !self.shutdown.is_shutdown() {
            tokio::select! {
                // wait for data from quic and send to tcp
                count = self.quic_recv.read(&mut quic_buf) => {
                    if let Err(ref e) = count {
                        // handle REMOTE TCP RST
                        // forced QUIC->TCP shutdown
                        debug!("error reading quic stream forced QUIC->TCP shutdown - {}",e);
                        if let Err(e) =  self.tcp_write.shutdown().await {
                            debug!("error closing tcp write stream {}",e);
                        };
                        return Ok(());
                    }

                    match count.unwrap() {
                        Some(n) => {
                            if let Err(err) = self.tcp_write.write_all(&quic_buf[..n]).await {
                                // handle TCP RST
                                // forced TCP->QUIC shutdown
                                debug!("error in writing data to tcp stream forced TCP->QUIC shutdown - {}", err);
                                // TODO: Fix this in future update
                                // https://github.com/tokio-rs/tokio/issues/2968
                                // Since in tokio there is no way to check if socket is closed without
                                // writing it. if there is in error we will act as connection is RST
                                let err_code = VarInt::from_u32(0);
                                if let Err(e) = self.quic_recv.stop(err_code) {
                                    debug!("error closing quic write stream {:?}",e);
                                }
                                return Ok(());
                            };
                        },
                        None => {
                            // graceful QUIC->TCP shutdown
                            debug!("graceful QUIC->TCP shutdown");
                            if let Err(e) =  self.tcp_write.shutdown().await {
                                debug!("error closing tcp write stream {}",e);
                            };
                            return Ok(());

                        }
                    }
                },

                // wait for shutdown signal
                _ = self.shutdown.recv() => {
                    debug!("shutdown down QuicToTcp");
                    let err_code = VarInt::from_u32(0);
                    if let Err(e) = self.quic_recv.stop(err_code) {
                        debug!("error closing quic write stream {:?}",e);
                    }
                    return Ok(());
                }
            };
        }
        Ok(())
    }
}
