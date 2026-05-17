//! Executor error types.

/// Errors that prevent the executor from even forming a verdict.
///
/// These are *infrastructure* failures (cannot bind the socket, cannot read
/// the bundle directory). A rejected request is NOT an error — it is a
/// normal signed [`archangel_ipc::ExecResponse`] with an
/// [`archangel_ipc::RejectStage`]. Anything here is fatal-ish and must
/// never be interpreted as "allow".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExecdError {
    /// Socket / filesystem I/O failure.
    #[error("executor I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration was unusable (bad key, missing bundle dir, etc.).
    #[error("executor configuration error: {0}")]
    Config(String),
}
