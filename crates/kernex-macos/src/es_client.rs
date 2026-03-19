//! Real Endpoint Security client implementation.
//!
//! This module is macOS-only. It wraps the `endpoint-sec` crate to:
//!
//! 1. Create an ES client subscribed to the required `AUTH_*` event types.
//! 2. Pre-warm an audit thread so no threads are created on the hot event path.
//! 3. Respond to every `AUTH` event before the kernel timeout (~30 s).
//!
//! # Thread model
//!
//! The ES framework delivers `AUTH` events on its own internal thread. The
//! event handler closure is called synchronously — the monitored process is
//! blocked until `respond_auth_result` returns. The critical path must be
//! non-blocking:
//!
//! ```text
//! ES framework thread → handle_auth_event()
//!     1. Atomic PID load           — O(1), no lock
//!     2. evaluate_event()          — O(n) path-prefix scan, no I/O
//!     3. respond_auth_result()     — kernel call, must not be skipped
//!     4. try_send(AuditRecord)     — non-blocking, drops if channel full
//! ```
//!
//! The pre-warmed audit thread drains the bounded channel and logs decisions
//! without blocking the ES callback thread.
//!
//! # Safety
//!
//! `EsHandle` carries a `Client<'static>` behind a manual `Send` impl.
//! See the `// SAFETY:` comment on that impl for the upheld invariants.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::Arc;

use endpoint_sec::sys::{es_auth_result_t, es_event_type_t};
use endpoint_sec::{Event, EventCreateDestinationFile, EventRenameDestinationFile};
use kernex_policy::FilesystemPolicy;

use crate::error::MacosError;
use crate::policy::PolicyEvaluator;
use crate::spawn::EsMonitorActive;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capacity of the bounded audit channel (records, not bytes).
///
/// Events that overflow the channel are silently dropped — audit loss is
/// acceptable, enforcement loss is not.
const AUDIT_QUEUE_CAP: usize = 1_024;

/// Sentinel meaning "no agent PID has been assigned yet".
///
/// While set, the handler allows all events from every PID unconditionally.
const NO_AGENT_PID: i32 = -1;

/// `PROT_WRITE` from `<sys/mman.h>` — writable mmap protection flag (0x02).
///
/// Defined here to avoid a libc dependency in this crate.
const PROT_WRITE: i32 = 0x02;

/// `O_WRONLY` from `<fcntl.h>` — write-only open flag (1).
const O_WRONLY: i32 = 1;

/// `O_RDWR` from `<fcntl.h>` — read-write open flag (2).
const O_RDWR: i32 = 2;

// ---------------------------------------------------------------------------
// AuditRecord — sent to the pre-warmed audit thread after each decision
// ---------------------------------------------------------------------------

/// A single ES auth decision, posted asynchronously to the audit thread.
struct AuditRecord {
    pid: i32,
    path: PathBuf,
    writable: bool,
    allowed: bool,
}

// ---------------------------------------------------------------------------
// EsHandle
// ---------------------------------------------------------------------------

/// Owns the live Endpoint Security client and the pre-warmed audit thread.
///
/// Dropping this value:
/// 1. Calls `es_delete_client()` via the `Client` destructor.
/// 2. Closes the audit channel, causing the audit thread to drain its
///    backlog and exit.
pub(crate) struct EsHandle {
    /// The ES client — keeps the ES registration alive.
    ///
    /// The ES framework calls our handler from its own internal thread;
    /// `Client` does not need to be called from the CLI thread after creation.
    _client: endpoint_sec::Client<'static>,

    /// The agent PID being monitored.
    ///
    /// Initially `NO_AGENT_PID`. Set to the real PID by `activate_for_pid`.
    /// The handler reads this with `Ordering::Acquire` on every event.
    agent_pid: Arc<AtomicI32>,

    /// Keeps the audit channel open until the handle is dropped.
    _audit_tx: SyncSender<AuditRecord>,

    /// Pre-warmed audit thread (kept alive for the duration of monitoring).
    _audit_thread: std::thread::JoinHandle<()>,
}

// SAFETY: `_client: Client<'static>` wraps an `es_client_t` opaque C pointer.
// The ES framework owns the thread that calls our handler — no Rust-side
// concurrent access to `Client` methods occurs. `EsHandle` is created on the
// CLI thread and held there (inside `EsMonitorActive`) until the agent exits.
// The handler closure receives `&mut Client<'_>` from the framework thread,
// not from any Rust-managed thread. Therefore moving `EsHandle` between
// threads (e.g. from the creation thread to the one that polls agent exit)
// is safe: the handle is accessed by at most one Rust thread at a time.
unsafe impl Send for EsHandle {}

impl std::fmt::Debug for EsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EsHandle")
            .field("agent_pid", &self.agent_pid.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// build_client
// ---------------------------------------------------------------------------

/// Create a new ES client subscribed to the required `AUTH_*` event types.
///
/// Pre-warms the audit thread before registering with the ES framework so
/// that no thread creation occurs on the hot event path.
///
/// # Errors
///
/// - [`MacosError::EntitlementMissing`] — `es_new_client()` returned
///   `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` (or similar entitlement error).
/// - [`MacosError::ClientCreate`] — any other `es_new_client()` failure.
/// - [`MacosError::Subscribe`] — `es_subscribe()` failed.
pub(crate) fn build_client(policy: &FilesystemPolicy) -> Result<EsHandle, MacosError> {
    // ── Step 1: pre-warm the audit thread ────────────────────────────────────
    //
    // Created BEFORE the ES client so that the thread is ready before the
    // first event arrives.
    let (audit_tx, audit_rx) = mpsc::sync_channel::<AuditRecord>(AUDIT_QUEUE_CAP);
    let audit_thread = std::thread::Builder::new()
        .name("kernex-macos-audit".to_string())
        .spawn(move || {
            // Drains the channel. Exits when the sender (EsHandle) is dropped.
            for record in audit_rx {
                tracing::debug!(
                    pid        = record.pid,
                    path       = %record.path.display(),
                    writable   = record.writable,
                    allowed    = record.allowed,
                    "kernex ES auth decision",
                );
            }
        })
        .map_err(|e| MacosError::ClientCreate(format!("audit thread spawn failed: {e}")))?;

    // ── Step 2: build in-memory policy evaluator ─────────────────────────────
    //
    // Immutable after construction; shared via Arc without locking.
    let evaluator = Arc::new(PolicyEvaluator::from_policy(policy));
    let agent_pid = Arc::new(AtomicI32::new(NO_AGENT_PID));

    let eval_ref = Arc::clone(&evaluator);
    let pid_ref = Arc::clone(&agent_pid);
    let tx = audit_tx.clone();

    // ── Step 3: create the ES client ─────────────────────────────────────────
    //
    // The handler closure captures Arc<T> values ('static) so the client
    // has lifetime 'static.  The framework calls the handler from its own
    // internal thread on every subscribed AUTH event.
    let mut client = endpoint_sec::Client::new(
        move |client: &mut endpoint_sec::Client<'_>, msg: endpoint_sec::Message| {
            handle_auth_event(client, &msg, &eval_ref, &pid_ref, &tx);
        },
    )
    .map_err(map_client_error)?;

    // ── Step 4: subscribe to AUTH event types ────────────────────────────────
    //
    // ES_EVENT_TYPE_AUTH_WRITE does not exist — writes are NOTIFY-only in the
    // ES API.  Write access control is enforced via AUTH_OPEN with the
    // O_WRONLY / O_RDWR flags in the `fflag` field.
    client
        .subscribe(&[
            es_event_type_t::ES_EVENT_TYPE_AUTH_OPEN,
            es_event_type_t::ES_EVENT_TYPE_AUTH_CREATE,
            es_event_type_t::ES_EVENT_TYPE_AUTH_UNLINK,
            es_event_type_t::ES_EVENT_TYPE_AUTH_RENAME,
            es_event_type_t::ES_EVENT_TYPE_AUTH_EXEC,
            es_event_type_t::ES_EVENT_TYPE_AUTH_MMAP,
        ])
        .map_err(|e| MacosError::Subscribe(e.to_string()))?;

    Ok(EsHandle {
        _client: client,
        agent_pid,
        _audit_tx: audit_tx,
        _audit_thread: audit_thread,
    })
}

// ---------------------------------------------------------------------------
// activate_for_pid
// ---------------------------------------------------------------------------

/// Assign the agent PID to a built `EsHandle` and return the live monitor.
///
/// After this call the handler starts applying `FilesystemPolicy` rules to
/// every AUTH event from `agent_pid`. Events from all other PIDs continue to
/// be allowed unconditionally.
///
/// # Errors
///
/// Currently infallible. The `Result` return matches the `SandboxBackend`
/// trait signature to allow future failure paths.
pub(crate) fn activate_for_pid(
    handle: EsHandle,
    agent_pid: u32,
) -> Result<EsMonitorActive, MacosError> {
    // SAFETY: macOS PIDs are always in [1, 99998], well within i32::MAX.
    #[allow(clippy::cast_possible_wrap)]
    let pid_i32 = agent_pid as i32;

    // Release store: the handler thread will see the PID via Acquire load.
    handle.agent_pid.store(pid_i32, Ordering::Release);

    Ok(EsMonitorActive::from_handle(handle))
}

// ---------------------------------------------------------------------------
// handle_auth_event — hot-path ES event handler
// ---------------------------------------------------------------------------

/// Respond to a single Endpoint Security `AUTH` event.
///
/// Called synchronously from the ES framework's internal thread. The monitored
/// process is blocked until `respond_auth_result` returns — this function
/// **must** complete well within the ~30 s kernel deadline.
fn handle_auth_event(
    client: &mut endpoint_sec::Client<'_>,
    msg: &endpoint_sec::Message,
    evaluator: &Arc<PolicyEvaluator>,
    agent_pid: &Arc<AtomicI32>,
    audit_tx: &SyncSender<AuditRecord>,
) {
    let event_pid = msg.process().audit_token().pid();
    let monitored = agent_pid.load(Ordering::Acquire);

    // Fast path: events from non-agent PIDs (or before the agent starts).
    // cache=false: never cache allow decisions for non-agent PIDs; the ES
    // cache uses the path as the key and the same path may later warrant a
    // deny for the actual agent.
    if monitored == NO_AGENT_PID || event_pid != monitored {
        if let Err(e) =
            client.respond_auth_result(msg, es_auth_result_t::ES_AUTH_RESULT_ALLOW, false)
        {
            tracing::error!("ES respond failed for non-agent event: {e}");
        }
        return;
    }

    // Evaluate the event against the filesystem policy.
    let (allowed, path_opt, writable) = evaluate_event(msg, evaluator);

    let result = if allowed {
        es_auth_result_t::ES_AUTH_RESULT_ALLOW
    } else {
        es_auth_result_t::ES_AUTH_RESULT_DENY
    };

    // Respond BEFORE any logging — the kernel is waiting.
    // A failed respond is critical: the framework will fail-open after the
    // deadline, which is a security regression.
    if let Err(e) = client.respond_auth_result(msg, result, false) {
        tracing::error!("ES respond_auth_result failed — framework may fail-open: {e}");
    }

    // Post-response: push audit record to the pre-warmed thread.
    // try_send never blocks; records are dropped if the channel is full.
    if let Some(path) = path_opt {
        let _ = audit_tx.try_send(AuditRecord {
            pid: event_pid,
            path,
            writable,
            allowed,
        });
    }
}

// ---------------------------------------------------------------------------
// evaluate_event
// ---------------------------------------------------------------------------

/// Evaluate a single ES AUTH event against the filesystem policy.
///
/// Returns `(allowed, Option<path>, is_write_operation)`.
///
/// Unknown or unhandled event types fail-open (`allowed = true`) — we only
/// enforce what we explicitly understand.
fn evaluate_event(
    msg: &endpoint_sec::Message,
    evaluator: &PolicyEvaluator,
) -> (bool, Option<PathBuf>, bool) {
    let Some(event) = msg.event() else {
        return (true, None, false); // unknown event type: fail-open
    };

    match event {
        // AUTH_OPEN — file open.
        //
        // `fflag` encodes the open mode: O_RDONLY=0, O_WRONLY=1, O_RDWR=2.
        // Any non-zero write bit means the open requests write access.
        Event::AuthOpen(e) => {
            let path = Path::new(e.file().path()).to_path_buf();
            let wants_write = (e.fflag() & (O_WRONLY | O_RDWR)) != 0;
            let allowed = if wants_write {
                evaluator.allows_write(&path)
            } else {
                evaluator.allows_read(&path)
            };
            (allowed, Some(path), wants_write)
        }

        // AUTH_CREATE — file or directory creation.
        //
        // Both overwriting an existing path and creating a new path require
        // write permission on the destination.
        Event::AuthCreate(e) => match e.destination() {
            Some(EventCreateDestinationFile::ExistingFile(f)) => {
                let path = Path::new(f.path()).to_path_buf();
                (evaluator.allows_write(&path), Some(path), true)
            }
            Some(EventCreateDestinationFile::NewPath {
                directory,
                filename,
                ..
            }) => {
                let path = build_path(directory.path(), filename);
                (evaluator.allows_write(&path), Some(path), true)
            }
            None => (true, None, true), // no destination info: fail-open
        },

        // AUTH_UNLINK — deletion (requires write permission).
        Event::AuthUnlink(e) => {
            let path = Path::new(e.target().path()).to_path_buf();
            (evaluator.allows_write(&path), Some(path), true)
        }

        // AUTH_RENAME — move or rename.
        //
        // Both source and destination require write permission. Deny if
        // either is denied (take the more restrictive result).
        Event::AuthRename(e) => {
            let src = Path::new(e.source().path()).to_path_buf();
            let dst_opt: Option<PathBuf> = match e.destination() {
                Some(EventRenameDestinationFile::ExistingFile(f)) => {
                    Some(Path::new(f.path()).to_path_buf())
                }
                Some(EventRenameDestinationFile::NewPath {
                    directory,
                    filename,
                }) => Some(build_path(directory.path(), filename)),
                None => None,
            };
            let src_ok = evaluator.allows_write(&src);
            let dst_ok = dst_opt.as_ref().map_or(true, |p| evaluator.allows_write(p));
            (src_ok && dst_ok, Some(src), true)
        }

        // AUTH_EXEC — process execution (read permission on the binary).
        Event::AuthExec(e) => {
            let path = Path::new(e.target().executable().path()).to_path_buf();
            (evaluator.allows_read(&path), Some(path), false)
        }

        // AUTH_MMAP — memory-mapped file access.
        //
        // `protection` encodes the requested memory protection.
        // PROT_WRITE (0x02) indicates a writable mapping.
        Event::AuthMmap(e) => {
            let path = Path::new(e.source().path()).to_path_buf();
            let wants_write = (e.protection() & PROT_WRITE) != 0;
            let allowed = if wants_write {
                evaluator.allows_write(&path)
            } else {
                evaluator.allows_read(&path)
            };
            (allowed, Some(path), wants_write)
        }

        // NOTIFY_* variants and future unhandled AUTH types: fail-open.
        _ => (true, None, false),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a [`PathBuf`] from a directory path (`OsStr`) and a filename (`OsStr`).
fn build_path(directory: &OsStr, filename: &OsStr) -> PathBuf {
    let mut path = Path::new(directory).to_path_buf();
    path.push(filename);
    path
}

/// Map `endpoint_sec::NewClientError` to [`MacosError`].
///
/// Detects entitlement failures by inspecting the `Display` string.
/// This is the most robust approach given that `NewClientError` may be opaque
/// or vary between `endpoint-sec` versions.
///
/// Error codes that map to entitlement errors:
/// - `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` (missing entitlement)
/// - `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED` (SIP prevents non-Apple ES)
/// - `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED` (unsigned / wrong sandbox)
fn map_client_error(e: endpoint_sec::sys::NewClientError) -> MacosError {
    // `NewClientError` may Display as an enum variant name like
    // "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED" (underscores) or as a
    // human-readable string like "not entitled" (spaces). Check both forms.
    let msg = e.to_string().to_ascii_lowercase();
    let is_entitlement_error = msg.contains("entit")
        || msg.contains("not_permit")
        || msg.contains("not permit")
        || msg.contains("not_privil")
        || msg.contains("not privil");
    if is_entitlement_error {
        MacosError::EntitlementMissing
    } else {
        MacosError::ClientCreate(e.to_string())
    }
}
