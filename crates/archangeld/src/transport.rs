//! Production [`ExecTransport`]: the boundary-B client over a Unix socket.
//!
//! The orchestrator builds a signed, length-prefixed frame; this connects
//! to `archangel-execd`'s socket, sends it, and reads back the response
//! frame. The reply length is bounded *before* allocation (reusing
//! `archangel-ipc`'s frame cap) so a hostile/buggy executor cannot make the
//! daemon allocate unboundedly. It performs no signing or verification —
//! that is the protocol crate's job; this is just the wire.

use std::path::PathBuf;

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
};

use archangel_ipc::{response_from_frame_body, SignedEnvelope};

use crate::orchestrator::{ExecTransport, OrchestratorError};

/// Connects to the executor socket per request (the executor processes
/// serially in v0.1; a fresh short-lived connection keeps the client
/// trivially correct and stateless).
#[derive(Debug, Clone)]
pub struct SocketExecTransport {
    socket_path: PathBuf,
}

impl SocketExecTransport {
    /// Target the executor at `socket_path` (e.g. `/run/archangel/exec.sock`).
    #[must_use]
    pub const fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

fn transport_err(context: &str, e: &impl core::fmt::Display) -> OrchestratorError {
    OrchestratorError::Transport(format!("{context}: {e}"))
}

impl ExecTransport for SocketExecTransport {
    async fn send(
        &self,
        frame: Vec<u8>,
    ) -> Result<archangel_ipc::ExecResponse, OrchestratorError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| transport_err("connect exec socket", &e))?;

        stream
            .write_all(&frame)
            .await
            .map_err(|e| transport_err("write request", &e))?;
        stream
            .flush()
            .await
            .map_err(|e| transport_err("flush request", &e))?;

        let mut prefix = [0u8; 4];
        stream
            .read_exact(&mut prefix)
            .await
            .map_err(|e| transport_err("read response length", &e))?;
        // Reuse the protocol's pre-allocation cap on the reply, too.
        let len = SignedEnvelope::frame_len(prefix)
            .map_err(|e| transport_err("response frame length", &e))?;
        let mut body = vec![0u8; len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| transport_err("read response body", &e))?;

        response_from_frame_body(&body)
            .map_err(|e| transport_err("decode response", &e))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::UnixListener,
    };

    use archangel_core::ActionId;
    use archangel_ipc::{response_to_frame, ExecOutcome, ExecResponse};

    use crate::orchestrator::ExecTransport;

    use super::SocketExecTransport;

    fn tmp_sock() -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "archangeld-xport-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn round_trips_over_a_real_unix_socket() {
        let path = tmp_sock();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");

        let action = ActionId::new();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            // Read the request frame (4-byte prefix + body) like execd.
            let mut p = [0u8; 4];
            s.read_exact(&mut p).await.expect("prefix");
            let len = u32::from_be_bytes(p) as usize;
            let mut body = vec![0u8; len];
            s.read_exact(&mut body).await.expect("body");
            // Reply with a canned response frame.
            let resp = ExecResponse {
                action_id: action,
                outcome: ExecOutcome::Completed {
                    exit_code: 0,
                    duration_ms: 2,
                    stdout: "socket-ok".to_owned(),
                    stderr: String::new(),
                    output_truncated: false,
                },
            };
            let frame = response_to_frame(&resp).expect("frame");
            s.write_all(&frame).await.expect("write");
            s.flush().await.expect("flush");
            action
        });

        let transport = SocketExecTransport::new(path.clone());
        // Body content is irrelevant to the transport; send a dummy frame.
        let dummy = {
            let payload = b"hello-executor";
            let n = u32::try_from(payload.len()).expect("tiny");
            let mut f = n.to_be_bytes().to_vec();
            f.extend_from_slice(payload);
            f
        };
        let resp = transport.send(dummy).await.expect("transport send");
        let expected_action = server.await.expect("server task");

        assert_eq!(resp.action_id, expected_action);
        assert!(
            matches!(
                &resp.outcome,
                ExecOutcome::Completed { stdout, exit_code: 0, .. }
                    if stdout == "socket-ok"
            ),
            "got {:?}",
            resp.outcome
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn connect_failure_is_a_transport_error() {
        let transport = SocketExecTransport::new(tmp_sock()); // nothing listening
        let r = transport.send(vec![0, 0, 0, 0]).await;
        assert!(r.is_err(), "connecting to a dead socket must error, not hang");
    }
}
