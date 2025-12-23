use std::{net::SocketAddr, pin::Pin, sync::Arc};

use bytes::{BufMut, Bytes, BytesMut};
use msquic::{
    BufferRef, CertificateFile, CertificateHash, Configuration, ConnectionEvent, ConnectionRef,
    ConnectionShutdownFlags, Credential, CredentialConfig, DatagramSendState, ListenerEvent,
    ListenerRef, ReceiveFlags, Registration, RegistrationConfig, SendFlags, Settings, Status,
    StatusCode, StreamEvent, StreamOpenFlags, StreamRef, StreamShutdownFlags, StreamStartFlags,
};

use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    init_tracing();
    let cfg = match EchoServerConfig::from_env_and_args() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("Configuration error: {err}");
            EchoServerConfig::print_usage();
            std::process::exit(1);
        }
    };

    if let Err(err) = run_server(cfg).await {
        eprintln!("Server failed: {err}");
        std::process::exit(1);
    }
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}

#[derive(Debug, Clone)]
struct EchoServerConfig {
    bind_addr: SocketAddr,
    alpn: String,
    cert: ServerCert,
}

#[derive(Debug, Clone)]
enum ServerCert {
    Thumbprint(String),
    CertFile {
        cert: String,
        key: String,
        generated: bool,
    },
}

impl EchoServerConfig {
    fn from_env_and_args() -> Result<Self, String> {
        let mut bind = std::env::var("ECHO_BIND").ok();
        let mut alpn = std::env::var("ECHO_ALPN").ok();
        let mut cert = std::env::var("ECHO_CERT").ok();
        let mut key = std::env::var("ECHO_KEY").ok();
        let mut thumbprint = std::env::var("ECHO_CERT_THUMBPRINT").ok();
        let mut self_signed = std::env::var("ECHO_SELF_SIGNED")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--bind" => bind = Some(args.next().ok_or("--bind requires a value")?),
                "--alpn" => alpn = Some(args.next().ok_or("--alpn requires a value")?),
                "--cert" => cert = Some(args.next().ok_or("--cert requires a value")?),
                "--key" => key = Some(args.next().ok_or("--key requires a value")?),
                "--thumbprint" => {
                    thumbprint = Some(args.next().ok_or("--thumbprint requires a value")?)
                }
                "--self-signed" => self_signed = true,
                "--help" | "-h" => {
                    Self::print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("Unknown argument: {other}")),
            }
        }

        let bind_addr: SocketAddr = bind
            .unwrap_or_else(|| "127.0.0.1:4568".to_string())
            .parse()
            .map_err(|e| format!("Invalid bind address: {e}"))?;
        let alpn = alpn.unwrap_or_else(|| "echo".to_string());
        let cert = if let Some(tp) = thumbprint {
            ServerCert::Thumbprint(tp)
        } else if cert.is_some() || key.is_some() {
            let cert_path =
                cert.ok_or("Missing --cert (or ECHO_CERT) when using certificate files")?;
            let key_path = key.ok_or("Missing --key (or ECHO_KEY) when using certificate files")?;
            ServerCert::CertFile {
                cert: cert_path,
                key: key_path,
                generated: false,
            }
        } else if self_signed {
            Self::generate_self_signed_cert()?
        } else {
            eprintln!(
                "Certificate details missing; generating self-signed cert (set --thumbprint or --cert/--key to override)."
            );
            Self::generate_self_signed_cert()?
        };

        Ok(Self {
            bind_addr,
            alpn,
            cert,
        })
    }

    fn print_usage() {
        eprintln!(
            "Usage: msquic-echo-rs [--bind ip:port] [--alpn token] [--self-signed] (--thumbprint HASH | --cert CERT_PEM --key KEY_PEM)"
        );
        eprintln!(
            "Environment overrides: ECHO_BIND, ECHO_ALPN, ECHO_CERT_THUMBPRINT, ECHO_CERT, ECHO_KEY, ECHO_SELF_SIGNED"
        );
        eprintln!(
            "Windows: --self-signed installs to CurrentUser cert store and uses its thumbprint."
        );
        eprintln!("Non-Windows: --self-signed uses `openssl` to generate temporary PEM files.");
    }

    fn credential_config(&self) -> Result<CredentialConfig, Box<dyn std::error::Error>> {
        let cred_cfg = match &self.cert {
            ServerCert::Thumbprint(tp) => {
                #[cfg(windows)]
                {
                    let hash = CertificateHash::from_str(tp)?;
                    CredentialConfig::new().set_credential(Credential::CertificateHash(hash))
                }

                #[cfg(not(windows))]
                {
                    return Err("Thumbprint credentials are only supported on Windows".into());
                }
            }
            ServerCert::CertFile { cert, key, .. } => {
                let cred =
                    Credential::CertificateFile(CertificateFile::new(key.clone(), cert.clone()));
                CredentialConfig::new().set_credential(cred)
            }
        };
        Ok(cred_cfg)
    }

    fn generate_self_signed_cert() -> Result<ServerCert, String> {
        #[cfg(windows)]
        return Self::generate_self_signed_cert_windows();
        #[cfg(not(windows))]
        return Self::generate_self_signed_cert_pem()
    }

    #[cfg(windows)]
    fn generate_self_signed_cert_windows() -> Result<ServerCert, String> {
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-Command",
                "New-SelfSignedCertificate -DnsName \"localhost\",\"127.0.0.1\",\"::1\" -CertStoreLocation Cert:\\CurrentUser\\My -FriendlyName msquic-echo-rs | Select-Object -ExpandProperty Thumbprint",
            ])
            .output()
            .map_err(|e| format!("Failed to run powershell to generate cert: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "powershell self-signed certificate generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let mut thumbprint = String::from_utf8_lossy(&output.stdout).to_string();
        thumbprint.retain(|c| !c.is_whitespace());
        if thumbprint.is_empty() {
            return Err("Failed to read thumbprint from self-signed certificate generation".into());
        }
        Ok(ServerCert::Thumbprint(thumbprint))
    }

    #[cfg(not(windows))]
    fn generate_self_signed_cert_pem() -> Result<ServerCert, String> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("System clock error: {e}"))?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "msquic-echo-self-signed-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("Failed to create temp cert dir {}: {e}", dir.display()))?;

        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let openssl_cfg_path = dir.join("openssl.cnf");
        let openssl_cfg = r#"[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = localhost

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
"#;
        std::fs::write(&openssl_cfg_path, openssl_cfg).map_err(|e| {
            format!(
                "Failed to write openssl config {}: {e}",
                openssl_cfg_path.display()
            )
        })?;

        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "365",
                "-keyout",
            ])
            .arg(&key_path)
            .args(["-out"])
            .arg(&cert_path)
            .args(["-config"])
            .arg(&openssl_cfg_path)
            .args(["-extensions", "v3_req"])
            .output()
            .map_err(|e| {
                format!(
                    "Failed to run openssl to generate a self-signed certificate: {e} (install openssl or pass --cert/--key)"
                )
            })?;
        if !output.status.success() {
            return Err(format!(
                "openssl self-signed certificate generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(ServerCert::CertFile {
            cert: cert_path.display().to_string(),
            key: key_path.display().to_string(),
            generated: true,
        })
    }
}

async fn run_server(cfg: EchoServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let reg = Registration::new(&RegistrationConfig::default())?;
    let alpn = [BufferRef::from(cfg.alpn.as_str())];
    let settings = Settings::new()
        .set_ServerResumptionLevel(msquic::ServerResumptionLevel::ResumeAndZerortt)
        .set_DatagramReceiveEnabled()
        .set_PeerBidiStreamCount(16)
        .set_IdleTimeoutMs(30_000);
    let config = Configuration::open(&reg, &alpn, Some(&settings))?;
    config.load_credential(&cfg.credential_config()?)?;
    let config = Arc::new(config);
    let listener = EchoListener::new(&reg, config.clone(), &alpn, Some(cfg.bind_addr))?;

    if let ServerCert::CertFile {
        cert,
        key,
        generated: true,
    } = &cfg.cert
    {
        println!(
            "Using self-signed cert at {} and key at {} (generated)",
            cert, key
        );
    }

    println!(
        "Echo server listening on {} using ALPN \"{}\"",
        cfg.bind_addr, cfg.alpn
    );

    let mut listener = listener;
    loop {
        let next_conn = tokio::select! {
            conn = listener.accept() => conn,
            _ = tokio::signal::ctrl_c() => {
                println!("Ctrl-C received, shutting down listener");
                break;
            }
        };

        match next_conn? {
            Some(conn) => {
                tokio::spawn(async move {
                    if let Err(err) = echo_connection(conn).await {
                        tracing::warn!("connection handler exited: {:?}", err);
                    }
                });
            }
            None => break,
        }
    }

    listener.shutdown().await;
    Ok(())
}

#[derive(Debug)]
pub struct Connection {
    conn: Arc<msquic::Connection>,
    ctx: ConnCtxReceiver,
    opener: StreamOpener,
}

/// Clonable handle for sending datagrams from multiple tasks.
#[derive(Debug, Clone)]
pub struct DatagramSender {
    conn: Arc<msquic::Connection>,
    datagram_sends: Arc<std::sync::Mutex<std::collections::HashMap<usize, Box<DatagramSendCtx>>>>,
}

impl DatagramSender {
    pub async fn send(&self, payload: Bytes) -> Result<DatagramSendState, Status> {
        let (tx, rx) = oneshot::channel();
        let mut send_ctx = Box::new(DatagramSendCtx {
            buffer: payload,
            completion: Some(tx),
        });
        let ctx_ptr = send_ctx.as_mut() as *mut DatagramSendCtx as *const std::ffi::c_void;
        {
            let buffer_ref = BufferRef::from(send_ctx.buffer.as_ref());
            {
                let mut pending = self.datagram_sends.lock().unwrap();
                pending.insert(ctx_ptr as usize, send_ctx);
            }

            if let Err(status) = unsafe {
                self.conn
                    .datagram_send(std::slice::from_ref(&buffer_ref), SendFlags::NONE, ctx_ptr)
            } {
                let mut pending = self.datagram_sends.lock().unwrap();
                pending.remove(&(ctx_ptr as usize));
                return Err(status);
            }
        }

        rx.await
            .map_err(|_| Status::new(StatusCode::QUIC_STATUS_ABORTED))
    }
}

/// responsible for open streams on a connection.
#[derive(Debug)]
pub struct StreamOpener {
    conn: Arc<msquic::Connection>,
    bidi_temp: Option<EchoStream>,
    uni_temp: Option<EchoStream>,
}

impl StreamOpener {
    fn new(conn: Arc<msquic::Connection>) -> Self {
        Self {
            conn,
            bidi_temp: None,
            uni_temp: None,
        }
    }

    /// open a stream and poll it in the holder.
    fn poll_open_inner(
        conn: &Arc<msquic::Connection>,
        uni: bool,
        stream_holder: &mut Option<EchoStream>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<EchoStream, Status>> {
        if stream_holder.is_none() {
            // create new stream
            let s = match EchoStream::open_and_start(conn, uni) {
                Ok(s) => s,
                Err(e) => {
                    return std::task::Poll::Ready(Err(e));
                }
            };
            *stream_holder = Some(s);
        }

        // poll stream start.
        let res = {
            let s = stream_holder.as_mut().unwrap();
            let rx = s.send.sctx.start.as_mut().unwrap();
            let p = Pin::new(rx);
            futures::ready!(std::future::Future::poll(p, cx))
        };
        // Mark start as consumed so wait_for_start knows it's done
        stream_holder.as_mut().unwrap().send.sctx.start = None;
        // current stream is either ready or error. So ready to be returned or dropped.
        let s = stream_holder.take().unwrap();
        let res = res.expect("cannot receive").map(|_| s);
        std::task::Poll::Ready(res)
    }
}

impl Clone for StreamOpener {
    fn clone(&self) -> Self {
        Self {
            conn: self.conn.clone(),
            bidi_temp: None,
            uni_temp: None,
        }
    }
}

impl StreamOpener {
    fn poll_open_bidi(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<EchoStream, Status>> {
        Self::poll_open_inner(&self.conn, false, &mut self.bidi_temp, cx)
    }

    fn poll_open_uni(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<EchoStream, Status>> {
        Self::poll_open_inner(&self.conn, true, &mut self.uni_temp, cx)
    }
}

/// ctx for receiving data on frontend.
#[derive(Debug)]
struct RecvStreamReceiveCtx {
    receive: mpsc::UnboundedReceiver<Bytes>,
}
/// ctx for sending data on frontend.
#[derive(Debug)]
struct SendStreamReceiveCtx {
    start: Option<oneshot::Receiver<Result<(), Status>>>,
    // cancelled, client_context
    send: mpsc::UnboundedReceiver<(bool, BufPtr)>,
    send_inprogress: bool,
    shutdown: Option<oneshot::Receiver<()>>,
}
struct BufPtr(*const std::ffi::c_void);
unsafe impl Send for BufPtr {}
unsafe impl Sync for BufPtr {}

struct SendBufCtx {
    data: Bytes,
    buffers: Box<[BufferRef]>,
}
// BufferRef holds a raw pointer to the Bytes' data; Bytes keeps that alive and is Send/Sync.
unsafe impl Send for SendBufCtx {}

#[derive(Debug)]
struct DatagramSendCtx {
    buffer: Bytes,
    completion: Option<oneshot::Sender<DatagramSendState>>,
}

fn datagram_send_state_is_final(state: DatagramSendState) -> bool {
    matches!(
        state,
        DatagramSendState::LostDiscarded
            | DatagramSendState::Acknowledged
            | DatagramSendState::AcknowledgedSpurious
            | DatagramSendState::Canceled
    )
}

/// from callback send to fount end.
#[derive(Debug)]
struct ConnCtxSender {
    connected: Option<oneshot::Sender<()>>,
    shutdown: Option<oneshot::Sender<()>>,
    bidi: Option<mpsc::UnboundedSender<Option<crate::EchoStream>>>,
    uni: Option<mpsc::UnboundedSender<Option<crate::EchoStream>>>,
    datagram: Option<mpsc::UnboundedSender<Option<Bytes>>>,
    datagram_sends: Arc<std::sync::Mutex<std::collections::HashMap<usize, Box<DatagramSendCtx>>>>,
}

/// front end receive.
#[derive(Debug)]
struct ConnCtxReceiver {
    connected: Option<oneshot::Receiver<()>>,
    shutdown: Option<oneshot::Receiver<()>>,
    bidi: mpsc::UnboundedReceiver<Option<crate::EchoStream>>,
    uni: mpsc::UnboundedReceiver<Option<crate::EchoStream>>,
    datagram: mpsc::UnboundedReceiver<Option<Bytes>>,
    datagram_sends: Arc<std::sync::Mutex<std::collections::HashMap<usize, Box<DatagramSendCtx>>>>,
}

/// Msquic Stream.
#[derive(Debug)]
pub struct EchoStream {
    send: EchoSendStream,
    recv: EchoRecvStream,
}
#[derive(Debug)]
pub struct EchoSendStream {
    stream: Arc<msquic::Stream>,
    sctx: SendStreamReceiveCtx,
}
#[derive(Debug)]
pub struct EchoRecvStream {
    stream: Arc<msquic::Stream>,
    rctx: RecvStreamReceiveCtx,
}
struct StreamSendCtx {
    start: Option<oneshot::Sender<Result<(), Status>>>,
    // cancelled, client_context
    send: Option<mpsc::UnboundedSender<(bool, BufPtr)>>,
    shutdown: Option<oneshot::Sender<()>>,
    receive: Option<mpsc::UnboundedSender<Bytes>>,
}

impl EchoRecvStream {
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rctx.receive.next().await
    }
}

impl EchoSendStream {
    async fn wait_for_start(&mut self) -> Result<(), Status> {
        if let Some(start) = self.sctx.start.take() {
            start
                .await
                .unwrap_or_else(|_| Err(Status::new(StatusCode::QUIC_STATUS_ABORTED)))?;
        }
        Ok(())
    }

    async fn await_send_complete(&mut self) -> Result<(), Status> {
        tracing::debug!(
            "await_send_complete: send_inprogress={}",
            self.sctx.send_inprogress
        );
        if !self.sctx.send_inprogress {
            return Ok(());
        }
        tracing::debug!("await_send_complete: waiting on channel...");
        let result = self.sctx.send.next().await;
        tracing::debug!(
            "await_send_complete: channel returned {:?}",
            result.is_some()
        );
        let (cancelled, buf_ptr) =
            result.ok_or_else(|| Status::new(StatusCode::QUIC_STATUS_ABORTED))?;
        unsafe {
            let _ = Box::from_raw(buf_ptr.0 as *mut SendBufCtx);
        }
        self.sctx.send_inprogress = false;
        if cancelled {
            Err(Status::new(StatusCode::QUIC_STATUS_ABORTED))
        } else {
            Ok(())
        }
    }

    pub async fn send(&mut self, payload: Bytes, fin: bool) -> Result<(), Status> {
        tracing::debug!("send: wait_for_start");
        self.wait_for_start().await?;
        tracing::debug!("send: first await_send_complete");
        // Only support a single in-flight send to keep buffer management simple.
        self.await_send_complete().await?;
        tracing::debug!("send: creating buffers");

        let buffers = vec![BufferRef::from(payload.as_ref())].into_boxed_slice();
        let ctx = Box::new(SendBufCtx {
            data: payload,
            buffers,
        });
        let ptr = ctx.as_ref() as *const _ as *const std::ffi::c_void;
        let flags = if fin { SendFlags::FIN } else { SendFlags::NONE };

        tracing::debug!("send: calling msquic send");
        if let Err(e) = unsafe { self.stream.send(ctx.buffers.as_ref(), flags, ptr) } {
            // free the buffers before returning error
            tracing::debug!("send: msquic send failed: {:?}", e);
            drop(ctx);
            return Err(e);
        }
        tracing::debug!("send: msquic send succeeded, waiting for completion");

        let _ = Box::into_raw(ctx);
        self.sctx.send_inprogress = true;
        self.await_send_complete().await
    }

    pub async fn shutdown(&mut self) -> Result<(), Status> {
        self.stream.shutdown(StreamShutdownFlags::GRACEFUL, 0)?;
        if let Some(shutdown) = self.sctx.shutdown.take() {
            let _ = shutdown.await;
        }
        Ok(())
    }
}

impl EchoStream {
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.recv.recv().await
    }

    pub async fn send(&mut self, payload: Bytes, fin: bool) -> Result<(), Status> {
        self.send.send(payload, fin).await
    }

    pub fn split_mut(&mut self) -> (&mut EchoSendStream, &mut EchoRecvStream) {
        (&mut self.send, &mut self.recv)
    }

    pub async fn shutdown(&mut self) -> Result<(), Status> {
        self.send.shutdown().await
    }
}

fn stream_ctx_channel() -> (StreamSendCtx, SendStreamReceiveCtx, RecvStreamReceiveCtx) {
    let (start_tx, start_rx) = oneshot::channel::<Result<(), Status>>();
    let (send_tx, send_rx) = mpsc::unbounded();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (receive_tx, receive_rx) = mpsc::unbounded();
    (
        StreamSendCtx {
            start: Some(start_tx),
            send: Some(send_tx),
            shutdown: Some(shutdown_tx),
            receive: Some(receive_tx),
        },
        SendStreamReceiveCtx {
            start: Some(start_rx),
            send: send_rx,
            send_inprogress: false,
            shutdown: Some(shutdown_rx),
        },
        RecvStreamReceiveCtx {
            receive: receive_rx,
        },
    )
}

fn stream_callback(prefix: &str, ctx: &mut StreamSendCtx, ev: StreamEvent) -> Result<(), Status> {
    tracing::debug!("{} stream_callback: {:?}", prefix, ev);
    match ev {
        StreamEvent::StartComplete { status, .. } => {
            let tx = ctx.start.take().unwrap();
            if status.is_ok() {
                tx.send(Ok(())).expect("cannot send");
            } else {
                tx.send(Err(status)).expect("cannot send")
            }
        }
        StreamEvent::SendComplete {
            cancelled,
            client_context,
        } => {
            if let Some(send) = ctx.send.as_ref() {
                send.unbounded_send((cancelled, BufPtr(client_context)))
                    .expect("cannot send");
            } else {
                debug_assert!(false, "mem leak");
            }
        }
        StreamEvent::Receive { buffers, flags, .. } => {
            if let Some(receive) = ctx.receive.as_ref() {
                let mut b = BytesMut::new();
                for br in buffers {
                    // skip empty buffs.
                    if !br.as_bytes().is_empty() {
                        b.put_slice(br.as_bytes());
                    }
                }
                let b = b.freeze();
                if !b.is_empty() {
                    receive.unbounded_send(b).expect("cannot send");
                }
            }
            if flags.contains(ReceiveFlags::FIN) {
                // close
                ctx.receive.take();
            }
        }
        StreamEvent::SendShutdownComplete { graceful: _ } => {
            // Peer acknowledged shutdown.
            if let Some(shutdown) = ctx.shutdown.take() {
                // Receiver may be dropped if the stream was already dropped
                let _ = shutdown.send(());
            }
        }
        StreamEvent::ShutdownComplete { .. } => {
            // close all channels
            ctx.receive.take();
            ctx.send.take();
            ctx.shutdown.take();
            ctx.start.take();
        }
        _ => {}
    }
    Ok(())
}

impl EchoStream {
    /// attach to accepted stream
    pub(crate) fn attach(stream: msquic::Stream) -> Self {
        let (mut ctx, mut rtx, rrtx) = stream_ctx_channel();
        let handler = move |_: StreamRef, ev: StreamEvent| stream_callback("SERVER", &mut ctx, ev);

        stream.set_callback_handler(handler);
        let s = Arc::new(stream);
        // For server-side streams, the stream is already started by the peer.
        // Mark start as complete so wait_for_start doesn't block.
        rtx.start = None;
        Self {
            send: EchoSendStream {
                stream: s.clone(),
                sctx: rtx,
            },
            recv: EchoRecvStream {
                stream: s,
                rctx: rrtx,
            },
        }
    }

    fn open_and_start(conn: &msquic::Connection, uni: bool) -> Result<Self, Status> {
        let (mut ctx, rtx, rrtx) = stream_ctx_channel();
        let handler = move |_: StreamRef, ev: StreamEvent| stream_callback("CLIENT", &mut ctx, ev);

        let flag = match uni {
            true => StreamOpenFlags::UNIDIRECTIONAL,
            false => StreamOpenFlags::NONE,
        };

        let s = msquic::Stream::open(conn, flag, handler)?;
        s.start(StreamStartFlags::NONE)?;
        let s = Arc::new(s);
        Ok(Self {
            send: EchoSendStream {
                stream: s.clone(),
                sctx: rtx,
            },
            recv: EchoRecvStream {
                stream: s,
                rctx: rrtx,
            },
        })
    }
}

fn conn_ctx_channel() -> (ConnCtxSender, ConnCtxReceiver) {
    let (conn_tx, conn_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (bidi_tx, bidi_rx) = mpsc::unbounded();
    let (uni_tx, uni_rx) = mpsc::unbounded();
    let (datagram_tx, datagram_rx) = mpsc::unbounded();
    let datagram_sends = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    (
        ConnCtxSender {
            connected: Some(conn_tx),
            shutdown: Some(shutdown_tx),
            bidi: Some(bidi_tx),
            uni: Some(uni_tx),
            datagram: Some(datagram_tx),
            datagram_sends: datagram_sends.clone(),
        },
        ConnCtxReceiver {
            connected: Some(conn_rx),
            shutdown: Some(shutdown_rx),
            bidi: bidi_rx,
            uni: uni_rx,
            datagram: datagram_rx,
            datagram_sends,
        },
    )
}

fn connection_callback(ctx: &mut ConnCtxSender, ev: msquic::ConnectionEvent) -> Result<(), Status> {
    tracing::debug!("connection_callback: {:?}", ev);
    match ev {
        ConnectionEvent::Connected { .. } => {
            ctx.connected.take().unwrap().send(()).unwrap();
        }
        ConnectionEvent::DatagramReceived { buffer, .. } => {
            if let Some(datagram) = ctx.datagram.as_ref() {
                let _ = datagram.unbounded_send(Some(Bytes::copy_from_slice(buffer.as_bytes())));
            }
        }
        ConnectionEvent::DatagramSendStateChanged {
            client_context,
            state,
        } => {
            if datagram_send_state_is_final(state) {
                let mut sends = ctx.datagram_sends.lock().unwrap();
                if let Some(mut send_ctx) = sends.remove(&(client_context as usize)) {
                    if let Some(done) = send_ctx.completion.take() {
                        let _ = done.send(state);
                    }
                }
            }
        }
        ConnectionEvent::PeerStreamStarted { stream, flags } => {
            let s = unsafe { msquic::Stream::from_raw(stream.as_raw()) };
            if flags.contains(StreamOpenFlags::UNIDIRECTIONAL) {
                if let Some(uni) = ctx.uni.as_ref() {
                    uni.unbounded_send(Some(crate::EchoStream::attach(s)))
                        .expect("cannot send");
                }
            } else if let Some(bidi) = ctx.bidi.as_ref() {
                bidi.unbounded_send(Some(crate::EchoStream::attach(s)))
                    .expect("cannot send");
            }
        }
        ConnectionEvent::ShutdownComplete { .. } => {
            // clear all channels.
            ctx.connected.take();
            ctx.uni.take();
            ctx.bidi.take();
            if let Some(datagram) = ctx.datagram.take() {
                let _ = datagram.unbounded_send(None);
            }
            let mut sends = ctx.datagram_sends.lock().unwrap();
            for (_, mut send_ctx) in sends.drain() {
                if let Some(done) = send_ctx.completion.take() {
                    let _ = done.send(DatagramSendState::Canceled);
                }
            }
            if let Some(shutdown) = ctx.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
        _ => {}
    }
    Ok(())
}

impl Connection {
    /// Connects to the server
    /// Note: Registration must be kept outside of connection
    /// and must wait for all connections to finish before closing,
    /// else registration close will wait on system lock, and block
    /// rust runtime.
    pub async fn connect(
        reg: &Registration,
        config: &Configuration,
        server_name: &str,
        server_port: u16,
    ) -> Result<Self, Status> {
        let (mut ctx, mut crx) = conn_ctx_channel();
        let handler = move |_: ConnectionRef, ev: ConnectionEvent| {
            tracing::debug!("CLIENT connection_callback: {:?}", ev);
            connection_callback(&mut ctx, ev)
        };
        let conn = msquic::Connection::open(reg, handler)?;
        conn.start(config, server_name, server_port)?;
        // wait for connection.
        crx.connected
            .take()
            .unwrap()
            .await
            .map_err(|_| Status::new(StatusCode::QUIC_STATUS_ABORTED))?;

        let conn = Arc::new(conn);

        let opener = StreamOpener::new(conn.clone());

        Ok(Self {
            conn,
            ctx: crx,
            opener,
        })
    }

    pub async fn open_bidi_stream(&mut self) -> Result<EchoStream, Status> {
        std::future::poll_fn(|cx| self.opener.poll_open_bidi(cx)).await
    }

    pub async fn open_uni_stream(&mut self) -> Result<EchoStream, Status> {
        std::future::poll_fn(|cx| self.opener.poll_open_uni(cx)).await
    }

    pub async fn accept_bidi_stream(&mut self) -> Result<Option<EchoStream>, Status> {
        Ok(self.ctx.bidi.next().await.flatten())
    }

    pub async fn accept_uni_stream(&mut self) -> Result<Option<EchoStream>, Status> {
        Ok(self.ctx.uni.next().await.flatten())
    }

    pub async fn recv_datagram(&mut self) -> Option<Bytes> {
        self.ctx.datagram.next().await.flatten()
    }

    pub async fn send_datagram(&self, payload: Bytes) -> Result<DatagramSendState, Status> {
        let (tx, rx) = oneshot::channel();
        let mut send_ctx = Box::new(DatagramSendCtx {
            buffer: payload,
            completion: Some(tx),
        });
        let ctx_ptr = send_ctx.as_mut() as *mut DatagramSendCtx as *const std::ffi::c_void;
        {
            let buffer_ref = BufferRef::from(send_ctx.buffer.as_ref());
            {
                let mut pending = self.ctx.datagram_sends.lock().unwrap();
                pending.insert(ctx_ptr as usize, send_ctx);
            }

            if let Err(status) = unsafe {
                self.conn
                    .datagram_send(std::slice::from_ref(&buffer_ref), SendFlags::NONE, ctx_ptr)
            } {
                let mut pending = self.ctx.datagram_sends.lock().unwrap();
                pending.remove(&(ctx_ptr as usize));
                return Err(status);
            }
            // buffer_ref drops here before the await below.
        }

        rx.await
            .map_err(|_| Status::new(StatusCode::QUIC_STATUS_ABORTED))
    }

    pub fn shutdown(&self, flags: ConnectionShutdownFlags) {
        self.conn.shutdown(flags, 0);
    }

    /// Get a clonable handle for sending datagrams from multiple tasks.
    pub fn datagram_sender(&self) -> DatagramSender {
        DatagramSender {
            conn: self.conn.clone(),
            datagram_sends: self.ctx.datagram_sends.clone(),
        }
    }

    /// attach to an accepted connection
    pub(crate) fn attach(
        inner: msquic::ConnectionRef,
        config: Arc<Configuration>,
    ) -> Result<Self, Status> {
        tracing::debug!("Connection::attach - setting up callback handler");
        let (mut ctx, crx) = conn_ctx_channel();
        let handler = move |_: ConnectionRef, ev: ConnectionEvent| {
            tracing::debug!("SERVER connection_callback: {:?}", ev);
            connection_callback(&mut ctx, ev)
        };
        inner.set_callback_handler(handler);
        tracing::debug!("Connection::attach - setting configuration");
        inner.set_configuration(&config)?;
        tracing::debug!("Connection::attach - done");
        // Use into_raw to prevent drop, then reconstruct with from_raw
        // This matches the pattern from msquic's own tests
        let conn = Arc::new(unsafe { msquic::Connection::from_raw(inner.as_raw()) });

        let opener = StreamOpener::new(conn.clone());

        Ok(Self {
            conn,
            ctx: crx,
            opener,
        })
    }

    /// Can only be called once after construction.
    pub fn get_shutdown_waiter(&mut self) -> ConnectionShutdownWaiter {
        ConnectionShutdownWaiter {
            rx: self.ctx.shutdown.take().unwrap(),
        }
    }
}

/// wait for connection to be fully shutdown.
pub struct ConnectionShutdownWaiter {
    rx: oneshot::Receiver<()>,
}
impl ConnectionShutdownWaiter {
    /// wait for connection to be fully shutdown.
    pub async fn wait(self) {
        self.rx
            .await
            .expect("failed to wait for connection shutdown");
    }
}

fn listener_callback(
    ctx: &ListenerCtxSender,
    ev: ListenerEvent,
    config: &Arc<msquic::Configuration>,
) -> Result<(), Status> {
    tracing::debug!("listener_callback: {:?}", std::mem::discriminant(&ev));
    match ev {
        ListenerEvent::NewConnection {
            info: _,
            connection,
        } => {
            tracing::debug!("listener_callback: NewConnection - calling attach");
            // connection is already owned by ListenerEvent - use it directly
            let conn = crate::Connection::attach(connection, config.clone())?;
            tracing::debug!("listener_callback: NewConnection - attach done, sending to channel");
            if let Some(tx) = ctx.conn.as_ref() {
                tx.unbounded_send(Some(conn)).expect("cannot send");
                tracing::debug!("listener_callback: NewConnection - sent to channel");
            }
        }
        ListenerEvent::StopComplete { .. } => {
            // none means end of connections
            if let Some(tx) = ctx.conn.as_ref() {
                tx.unbounded_send(None).expect("cannot send");
            }
            let mut lk = ctx.shutdown.lock().unwrap();
            let tx = lk.take();
            if let Some(tx) = tx {
                tx.send(()).expect("cannot send");
            }
        }
    }
    Ok(())
}

struct EchoListener {
    inner: msquic::Listener,
    conn: ListenerCtxReceiver,
}

impl EchoListener {
    pub fn new(
        reg: &msquic::Registration,
        config: Arc<Configuration>,
        alpn: &[BufferRef],
        local_addr: Option<SocketAddr>,
    ) -> Result<Self, Status> {
        let (tx, rx) = listener_ctx_channel();
        let handler = move |_: ListenerRef, ev: ListenerEvent| listener_callback(&tx, ev, &config);
        let inner = msquic::Listener::open(reg, handler)?;
        let addr = local_addr.map(msquic::Addr::from);
        inner.start(alpn, addr.as_ref())?;
        Ok(Self { inner, conn: rx })
    }

    /// Get the inner listener ref.
    pub fn get_ref(&self) -> &msquic::Listener {
        &self.inner
    }

    // #[cfg_attr(
    //     feature = "tracing",
    //     tracing::instrument(skip_all, level = "trace", ret)
    // )]
    pub fn poll_accept(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<crate::Connection>, Status>> {
        let s = std::task::ready!(self.conn.conn.poll_next_unpin(cx)).unwrap_or(None);
        std::task::Poll::Ready(Ok(s))
    }

    pub async fn accept(&mut self) -> Result<Option<crate::Connection>, Status> {
        std::future::poll_fn(|cx| self.poll_accept(cx)).await
    }

    /// shutdown is made immutable to enable it to be called from another thread.
    pub async fn shutdown(&self) {
        let opt_rx = {
            let mut lk = self.conn.shutdown.lock().unwrap();
            lk.take()
        };
        if let Some(rx) = opt_rx {
            self.inner.stop();
            rx.await.expect("cannot receive");
        }
    }
}

struct ListenerCtxSender {
    conn: Option<mpsc::UnboundedSender<Option<crate::Connection>>>,
    shutdown: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}
struct ListenerCtxReceiver {
    conn: mpsc::UnboundedReceiver<Option<crate::Connection>>,
    /// mutex used to make shutdown immutable
    shutdown: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
}

fn listener_ctx_channel() -> (ListenerCtxSender, ListenerCtxReceiver) {
    let (tx, rx) = mpsc::unbounded();
    let (sh_tx, sh_rx) = oneshot::channel();
    (
        ListenerCtxSender {
            conn: Some(tx),
            shutdown: std::sync::Mutex::new(Some(sh_tx)),
        },
        ListenerCtxReceiver {
            conn: rx,
            shutdown: std::sync::Mutex::new(Some(sh_rx)),
        },
    )
}

async fn echo_stream(mut stream: EchoStream) -> Result<(), Status> {
    // Handle length-prefixed echo protocol:
    // - First byte: message length
    // - Following bytes: message data
    // Echo each message immediately after receiving it completely

    let mut buf = BytesMut::with_capacity(1024);

    while let Some(chunk) = stream.recv.recv().await {
        info!("stream echo chunk: {:?}", chunk);
        buf.put(chunk);

        // Process all complete messages in the buffer
        while !buf.is_empty() {
            let len = buf[0] as usize;

            // Check if we have the complete message
            if buf.len() < 1 + len {
                // Need more data, wait for next chunk
                break;
            }

            // Extract and echo the message immediately
            let message = buf.split_to(1 + len);
            info!(
                "stream echo message: {:?}",
                String::from_utf8_lossy(&message[1..])
            );

            // Echo back with same length-prefix format
            stream.send.send(message.freeze(), false).await?;
        }
    }

    debug!("stream echo complete");
    // The peer may have gracefully finished its send direction (FIN). Make sure we also
    // gracefully finish our send direction so the peer doesn't observe an abort when
    // this task drops the stream handle.
    stream.shutdown().await?;
    Ok(())
}

async fn echo_connection(mut conn: Connection) -> Result<(), Status> {
    loop {
        let next_stream = conn.ctx.bidi.next();
        let next_datagram = conn.ctx.datagram.next();
        tokio::pin!(next_stream);
        tokio::pin!(next_datagram);

        tokio::select! {
            datagram = &mut next_datagram => {
                match datagram {
                    Some(Some(payload)) => {
                        info!("datagram echo: {:?}", payload);
                        match conn.send_datagram(payload.clone()).await {
                            Ok(DatagramSendState::Acknowledged | DatagramSendState::AcknowledgedSpurious) => {}
                            Ok(state) => tracing::warn!("datagram echo completed with {:?}", state),
                            Err(err) => return Err(err),
                        }
                    }
                    _ => break,
                }
            }
            stream = &mut next_stream => {
                match stream {
                    Some(Some(stream)) => {
                        tokio::spawn(async move {
                            if let Err(err) = echo_stream(stream).await {
                                tracing::warn!("stream echo failed: {:?}", err);
                            }
                        });
                    }
                    _ => break,
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use bytes::Bytes;
    use msquic::{
        BufferRef, Configuration, CredentialConfig, CredentialFlags, DatagramSendState,
        Registration, RegistrationConfig, Settings,
    };
    use tracing::info;

    use crate::{Connection, EchoListener};

    #[test]
    fn basic_server_test() {
        crate::test::util::try_setup_tracing();
        info!("Test start");
        let cred = crate::test::util::get_test_cred();

        let reg = Registration::new(&RegistrationConfig::default()).unwrap();
        let alpn = [BufferRef::from("echo")];
        let settings = Settings::new()
            .set_ServerResumptionLevel(msquic::ServerResumptionLevel::ResumeAndZerortt)
            .set_PeerBidiStreamCount(1)
            .set_IdleTimeoutMs(1000);

        let config = Configuration::open(&reg, &alpn, Some(&settings)).unwrap();

        let cred_config = CredentialConfig::new()
            .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION)
            .set_credential(cred);
        config.load_credential(&cred_config).unwrap();

        let config = Arc::new(config);

        let l = EchoListener::new(
            &reg,
            config,
            &alpn,
            Some(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                4568,
            )),
        )
        .unwrap();

        let (sht_tx, mut sht_rx) = tokio::sync::oneshot::channel::<()>();
        let th = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .unwrap();
            rt.block_on(async {
                let mut l = l;
                let mut i = 0;
                loop {
                    let conn_id = i;
                    info!("server accept conn {}", i);
                    i += 1;
                    let conn = tokio::select! {
                        val = l.accept() => val.unwrap(),
                        _ = &mut sht_rx => {
                            info!("server accepted interrupted.");
                            None // stop accept and break.
                        }
                    };
                    if conn.is_none() {
                        info!("server accepted conn end");
                        break;
                    }
                    tokio::spawn(async move {
                        let conn = conn.unwrap();
                        info!("server accepted conn id={}", conn_id);
                        if let Err(err) = crate::echo_connection(conn).await {
                            info!("server connection error: {:?}", err);
                        }
                    });
                }
                info!("server listener stop");
                l.shutdown().await;
                info!("server listner stop finish");
            });
            info!("tokio server end.");
        });

        let client_msg = Bytes::from_static(b"hello from client");

        let echoed = {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .unwrap();
            rt.block_on(async {
                let client_settings = Settings::new()
                    .set_IdleTimeoutMs(5_000)
                    .set_PeerBidiStreamCount(1);
                let client_config =
                    Configuration::open(&reg, &alpn, Some(&client_settings)).unwrap();
                let cred_config = CredentialConfig::new_client()
                    .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION);
                client_config.load_credential(&cred_config).unwrap();

                let mut conn = crate::Connection::connect(&reg, &client_config, "127.0.0.1", 4568)
                    .await
                    .expect("client failed to connect");
                let mut stream = conn
                    .open_bidi_stream()
                    .await
                    .expect("client failed to open stream");
                stream
                    .send(client_msg.clone(), true)
                    .await
                    .expect("client failed to send");
                let echoed = stream.recv().await.expect("missing echo");
                conn.shutdown(msquic::ConnectionShutdownFlags::NONE);
                echoed
            })
        };

        assert_eq!(echoed, client_msg);

        sht_tx.send(()).unwrap();
        th.join().unwrap();
    }

    #[test]
    fn datagram_echo_test() {
        crate::test::util::try_setup_tracing();
        info!("Datagram test start");
        let cred = crate::test::util::get_test_cred();

        let reg = Registration::new(&RegistrationConfig::default()).unwrap();
        let alpn = [BufferRef::from("echo")];
        let settings = Settings::new()
            .set_ServerResumptionLevel(msquic::ServerResumptionLevel::ResumeAndZerortt)
            .set_PeerBidiStreamCount(1)
            .set_DatagramReceiveEnabled()
            .set_IdleTimeoutMs(1000);

        let config = Configuration::open(&reg, &alpn, Some(&settings)).unwrap();

        let cred_config = CredentialConfig::new()
            .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION)
            .set_credential(cred);
        config.load_credential(&cred_config).unwrap();

        let config = Arc::new(config);

        let l = EchoListener::new(
            &reg,
            config,
            &alpn,
            Some(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                4569,
            )),
        )
        .unwrap();

        let (sht_tx, mut sht_rx) = tokio::sync::oneshot::channel::<()>();
        let th = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut l = l;
                loop {
                    let conn = tokio::select! {
                        val = l.accept() => val.unwrap(),
                        _ = &mut sht_rx => {
                            info!("datagram server accept interrupted.");
                            None // stop accept and break.
                        }
                    };
                    let Some(mut conn) = conn else {
                        break;
                    };
                    let mut shutdown = conn.get_shutdown_waiter();
                    tokio::spawn(async move {
                        while let Some(dgram) = conn.recv_datagram().await {
                            if let Err(err) = conn.send_datagram(dgram.clone()).await {
                                tracing::warn!("datagram echo failed: {:?}", err);
                                break;
                            }
                        }
                    });
                    // Only handle a single connection for this test; exit after it shuts down.
                    shutdown.wait().await;
                    break;
                }
                l.shutdown().await;
            });
        });

        let client_msg = Bytes::from_static(b"hello from datagram");
        let expected = client_msg.clone();

        let echoed = {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_time()
                .build()
                .unwrap();
            rt.block_on(async move {
                let client_settings = Settings::new()
                    .set_IdleTimeoutMs(5_000)
                    .set_PeerBidiStreamCount(1)
                    .set_DatagramReceiveEnabled();
                let client_config =
                    Configuration::open(&reg, &alpn, Some(&client_settings)).unwrap();
                let cred_config = CredentialConfig::new_client()
                    .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION);
                client_config.load_credential(&cred_config).unwrap();

                let mut conn = Connection::connect(&reg, &client_config, "127.0.0.1", 4569)
                    .await
                    .expect("client failed to connect");
                let send_state = conn
                    .send_datagram(client_msg.clone())
                    .await
                    .expect("client failed to send datagram");
                assert!(
                    matches!(
                        send_state,
                        DatagramSendState::Acknowledged | DatagramSendState::AcknowledgedSpurious
                    ),
                    "unexpected datagram send state: {:?}",
                    send_state
                );
                let echoed = conn.recv_datagram().await.expect("missing datagram echo");
                conn.shutdown(msquic::ConnectionShutdownFlags::NONE);
                echoed
            })
        };

        assert_eq!(echoed, expected);

        let _ = sht_tx.send(());
        th.join().unwrap();
    }

    pub mod util {
        use msquic::Credential;
        #[cfg(target_os = "windows")]
        use std::process::Command;
        // used for debugging
        pub const DEVEL_TRACE_LEVEL: tracing::Level = tracing::Level::TRACE;

        pub fn try_setup_tracing() {
            let _ = tracing_subscriber::fmt()
                .with_max_level(DEVEL_TRACE_LEVEL)
                .try_init();
        }

        /// Use powershell/pwsh to get or create a test cert hash
        #[cfg(target_os = "windows")]
        pub fn get_test_cred() -> Credential {
            use msquic::CertificateHash;

            const FRIENDLY: &str = "MsQuic-Test";

            fn run_ps(cmd: &str) -> std::io::Result<std::process::Output> {
                for exe in ["pwsh.exe", "powershell.exe"] {
                    if let Ok(out) = Command::new(exe).args(["-Command", cmd]).output() {
                        return Ok(out);
                    }
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "powershell not found",
                ))
            }

            fn read_thumbprint() -> Option<String> {
                let cmd = format!(
                    "Get-ChildItem Cert:\\CurrentUser\\My | Where-Object -Property FriendlyName -EQ -Value '{FRIENDLY}' | Select-Object -ExpandProperty Thumbprint -First 1"
                );
                let out = run_ps(&cmd).ok()?;
                if !out.status.success() {
                    return None;
                }
                let mut s = String::from_utf8_lossy(&out.stdout).to_string();
                s.retain(|c| !c.is_whitespace());
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            }

            let thumbprint = read_thumbprint().or_else(|| {
                let cmd = format!("New-SelfSignedCertificate -DnsName \"localhost\",\"127.0.0.1\",\"::1\" -CertStoreLocation Cert:\\CurrentUser\\My -FriendlyName '{FRIENDLY}' | Select-Object -ExpandProperty Thumbprint");
                let out = run_ps(&cmd).ok()?;
                if !out.status.success() {
                    return None;
                }
                let mut s = String::from_utf8_lossy(&out.stdout).to_string();
                s.retain(|c| !c.is_whitespace());
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            });

            let thumbprint = thumbprint.expect("Failed to create/read self-signed certificate for tests; ensure PowerShell is available.");
            Credential::CertificateHash(CertificateHash::from_str(&thumbprint).unwrap())
        }

        /// Generate a test cert if not present using openssl cli.
        #[cfg(not(target_os = "windows"))]
        pub fn get_test_cred() -> Credential {
            use msquic::CertificateFile;

            let cert_dir = std::env::temp_dir().join("msquic_h3_test_rs");
            let key = "key.pem";
            let cert = "cert.pem";
            let key_path = cert_dir.join(key);
            let cert_path = cert_dir.join(cert);
            if !key_path.exists() || !cert_path.exists() {
                // remove the dir
                let _ = std::fs::remove_dir_all(&cert_dir);
                std::fs::create_dir_all(&cert_dir).expect("cannot create cert dir");
                // generate test cert using openssl cli
                let output = std::process::Command::new("openssl")
                    .args([
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:4096",
                        "-keyout",
                        "key.pem",
                        "-out",
                        "cert.pem",
                        "-sha256",
                        "-days",
                        "3650",
                        "-nodes",
                        "-subj",
                        "/CN=localhost",
                    ])
                    .current_dir(cert_dir)
                    .stderr(std::process::Stdio::inherit())
                    .stdout(std::process::Stdio::inherit())
                    .output()
                    .expect("cannot generate cert");
                if !output.status.success() {
                    panic!("generate cert failed");
                }
            }
            Credential::CertificateFile(CertificateFile::new(
                key_path.display().to_string(),
                cert_path.display().to_string(),
            ))
        }
    }
}
