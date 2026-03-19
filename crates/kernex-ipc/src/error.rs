use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur in the Kernex IPC layer.
#[derive(Debug, Error)]
pub enum IpcError {
    /// An underlying I/O error from the OS or tokio.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A message could not be serialized or deserialized.
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),

    /// An incoming message exceeds the maximum allowed size.
    ///
    /// This prevents a malicious or misbehaving peer from causing unbounded
    /// memory allocation on the receiving side.
    #[error("message too large: {size} bytes (limit: {limit} bytes)")]
    MessageTooLarge { size: usize, limit: usize },

    /// The remote peer closed the connection before sending a complete message.
    #[error("connection closed by peer")]
    ConnectionClosed,

    /// A socket file already exists at the expected path.
    ///
    /// Kernex refuses to overwrite an existing socket to prevent a TOCTOU
    /// attack where a malicious process places a socket at a predictable path
    /// to intercept IPC traffic.
    #[error("socket already exists at {}: refusing to overwrite", path.display())]
    SocketAlreadyExists { path: PathBuf },
}
