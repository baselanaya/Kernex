//! Unix Domain Socket IPC between the Kernex CLI and the core engine.
//!
//! # Protocol
//!
//! Messages are framed as a 4-byte little-endian `u32` length prefix followed
//! by a UTF-8 JSON body. The maximum body size is 4 MiB
//! ([`codec::MAX_MESSAGE_BYTES`]).
//!
//! # Message flow
//!
//! ```text
//! CLI                          Core engine
//!  |-- PolicyQuery ----------->|
//!  |<-- PolicyDecision --------|   (Allow / Deny / Prompt)
//!  |
//!  |   [if Prompt:]
//!  |<-- JitPrompt -------------|
//!  |-- JitResponse ----------->|
//!  |
//!  |<-- SessionSummary --------|   (on agent exit)
//! ```
//!
//! # Security
//!
//! The IPC socket is created in a user-owned temporary directory with mode
//! `0700`, and the socket file itself is set to mode `0600`. See
//! [`socket::IpcServer::bind`] for details.

pub mod codec;
pub mod error;
pub mod message;
pub mod socket;

pub use error::IpcError;
pub use message::{
    IpcMessage, JitDecision, JitPrompt, JitResponse, Operation, PolicyDecision, PolicyQuery,
    Resource, RiskTier, SessionSummary, Verdict,
};
pub use socket::{IpcClient, IpcConnection, IpcServer};
