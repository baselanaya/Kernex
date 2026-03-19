//! JIT deduplication state for a single enforcement session.
//!
//! # Deduplication rules
//!
//! After a JIT prompt is shown and the user responds, the decision is recorded
//! so that future identical queries (same operation + resource) do not re-prompt:
//!
//! | User decision   | Future identical queries              |
//! |-----------------|---------------------------------------|
//! | `AllowOnce`     | Show the prompt again (no dedup)      |
//! | `AddToPolicy`   | Auto-allow for the rest of the session|
//! | `Deny`          | Silently re-deny without prompting    |
//!
//! Queries that were denied by the **policy** itself (without a prompt) are
//! also added to the silent-deny set so that repeated blocked operations do
//! not generate redundant log noise.

use std::collections::HashSet;

use kernex_ipc::{Operation, Resource};

// ---------------------------------------------------------------------------
// DedupeKey
// ---------------------------------------------------------------------------

/// A hashable, string-encoded key uniquely identifying an operation+resource pair.
///
/// We encode as a string rather than deriving `Hash` on the IPC types to avoid
/// coupling `kernex-core` internals to the wire-protocol representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DedupeKey(String);

impl DedupeKey {
    /// Construct a `DedupeKey` from an IPC operation + resource pair.
    pub fn from_parts(op: &Operation, resource: &Resource) -> Self {
        let op_str = match op {
            Operation::FileRead => "read",
            Operation::FileWrite => "write",
            Operation::FileExec => "exec",
            Operation::NetworkConnect => "net",
            Operation::EnvRead => "env",
            Operation::Syscall => "sys",
        };
        let res_str = match resource {
            Resource::Path(p) => format!("path:{}", p.display()),
            Resource::Network { host, port } => format!("net:{host}:{port}"),
            Resource::EnvVar(name) => format!("env:{name}"),
            Resource::Syscall { nr, .. } => format!("syscall:{nr}"),
        };
        DedupeKey(format!("{op_str}:{res_str}"))
    }

    /// Return the raw key string (for logging/debugging).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// JitDedupeState
// ---------------------------------------------------------------------------

/// Per-session JIT deduplication state.
///
/// Holds two disjoint sets of keys:
/// - `silent_denies`: future identical queries are denied without prompting
/// - `session_allows`: future identical queries are auto-allowed
///
/// # Invariant
///
/// A key should never appear in both sets simultaneously. Callers that add to
/// one set should ensure the key is not in the other, though this is not
/// enforced at runtime for performance reasons.
#[derive(Debug, Default)]
pub struct JitDedupeState {
    silent_denies: HashSet<DedupeKey>,
    session_allows: HashSet<DedupeKey>,
}

impl JitDedupeState {
    /// Create an empty deduplication state for a new session.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if this key has been silently denied in this session.
    pub fn is_silent_deny(&self, key: &DedupeKey) -> bool {
        self.silent_denies.contains(key)
    }

    /// Returns `true` if the user chose `AddToPolicy` for this key earlier in
    /// the session — auto-allow for the rest of the session.
    pub fn is_session_allow(&self, key: &DedupeKey) -> bool {
        self.session_allows.contains(key)
    }

    /// Record that an operation was denied (by policy or by the user via JIT).
    ///
    /// Future queries with the same key will be silently re-denied.
    pub fn record_deny(&mut self, key: DedupeKey) {
        self.silent_denies.insert(key);
    }

    /// Record that the user chose `AddToPolicy` for this key.
    ///
    /// Future queries with the same key will be auto-allowed for this session.
    pub fn record_session_allow(&mut self, key: DedupeKey) {
        self.session_allows.insert(key);
    }

    /// Total number of distinct keys in the silent-deny set.
    pub fn unique_denies(&self) -> usize {
        self.silent_denies.len()
    }

    /// Total number of distinct keys in the session-allow set.
    pub fn unique_allows(&self) -> usize {
        self.session_allows.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kernex_ipc::{Operation, Resource};

    use super::*;

    fn read_key(path: &str) -> DedupeKey {
        DedupeKey::from_parts(&Operation::FileRead, &Resource::Path(PathBuf::from(path)))
    }

    fn net_key(host: &str, port: u16) -> DedupeKey {
        DedupeKey::from_parts(
            &Operation::NetworkConnect,
            &Resource::Network {
                host: host.to_string(),
                port,
            },
        )
    }

    fn env_key(name: &str) -> DedupeKey {
        DedupeKey::from_parts(&Operation::EnvRead, &Resource::EnvVar(name.to_string()))
    }

    // -- DedupeKey construction ----------------------------------------------

    #[test]
    fn test_dedupe_key_same_op_same_path_are_equal() {
        let a = read_key("/tmp/data.csv");
        let b = read_key("/tmp/data.csv");
        assert_eq!(a, b);
    }

    #[test]
    fn test_dedupe_key_different_paths_are_not_equal() {
        let a = read_key("/tmp/a.csv");
        let b = read_key("/tmp/b.csv");
        assert_ne!(a, b);
    }

    #[test]
    fn test_dedupe_key_same_path_different_ops_are_not_equal() {
        let read = DedupeKey::from_parts(
            &Operation::FileRead,
            &Resource::Path(PathBuf::from("/tmp/file")),
        );
        let write = DedupeKey::from_parts(
            &Operation::FileWrite,
            &Resource::Path(PathBuf::from("/tmp/file")),
        );
        assert_ne!(read, write);
    }

    #[test]
    fn test_dedupe_key_network_encodes_host_and_port() {
        let a = net_key("api.example.com", 443);
        let b = net_key("api.example.com", 80);
        assert_ne!(a, b, "different ports must produce different keys");
    }

    #[test]
    fn test_dedupe_key_env_var_is_case_sensitive() {
        let a = env_key("PATH");
        let b = env_key("path");
        assert_ne!(a, b, "env var keys are case-sensitive");
    }

    // -- JitDedupeState operations -------------------------------------------

    #[test]
    fn test_new_state_has_no_denies_or_allows() {
        let state = JitDedupeState::new();
        let key = read_key("/tmp/file");
        assert!(!state.is_silent_deny(&key));
        assert!(!state.is_session_allow(&key));
    }

    #[test]
    fn test_record_deny_makes_key_a_silent_deny() {
        let mut state = JitDedupeState::new();
        let key = read_key("/tmp/blocked");
        state.record_deny(key.clone());
        assert!(state.is_silent_deny(&key));
    }

    #[test]
    fn test_record_session_allow_makes_key_auto_allowed() {
        let mut state = JitDedupeState::new();
        let key = net_key("api.example.com", 443);
        state.record_session_allow(key.clone());
        assert!(state.is_session_allow(&key));
    }

    #[test]
    fn test_unique_denies_counts_distinct_keys() {
        let mut state = JitDedupeState::new();
        state.record_deny(read_key("/tmp/a"));
        state.record_deny(read_key("/tmp/b"));
        state.record_deny(read_key("/tmp/a")); // duplicate
        assert_eq!(state.unique_denies(), 2);
    }

    #[test]
    fn test_unrecorded_key_is_not_silent_deny() {
        let mut state = JitDedupeState::new();
        state.record_deny(read_key("/tmp/a"));
        assert!(!state.is_silent_deny(&read_key("/tmp/b")));
    }
}
