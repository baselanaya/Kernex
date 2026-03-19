//! Shared helpers for kernex end-to-end integration tests.
//!
//! All integration test files in `tests/tests/` import from this crate.

use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Binary location
// ---------------------------------------------------------------------------

/// Returns the path to the compiled `kernex` binary.
///
/// Resolution order:
/// 1. `KERNEX_BIN` environment variable — set this in CI when building with a
///    non-default target (e.g. musl) so integration tests find the right binary.
/// 2. musl target debug build: `target/x86_64-unknown-linux-musl/debug/kernex`
///    (Linux only — present when `.cargo/config.toml` defaults to musl).
/// 3. Native target debug build: `target/debug/kernex` (fallback for macOS and
///    any environment that overrides the default target).
///
/// `cargo test --workspace` builds all workspace members before running tests,
/// so the binary is guaranteed to exist when any test in this crate runs.
pub fn kernex_bin() -> PathBuf {
    // 1. Explicit override — highest priority.
    if let Ok(bin) = std::env::var("KERNEX_BIN") {
        return PathBuf::from(bin);
    }

    // CARGO_MANIFEST_DIR is `<workspace>/tests/`
    let workspace_root = {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p
    };

    // 2. musl target (Linux default from .cargo/config.toml).
    #[cfg(target_os = "linux")]
    {
        let musl = workspace_root
            .join("target")
            .join("x86_64-unknown-linux-musl")
            .join("debug")
            .join("kernex");
        if musl.exists() {
            return musl;
        }
    }

    // 3. Native target fallback.
    workspace_root.join("target").join("debug").join("kernex")
}

// ---------------------------------------------------------------------------
// Policy fixtures
// ---------------------------------------------------------------------------

/// Minimal kernex.yaml for Linux: allows the system paths required to exec
/// standard binaries like `true`, `cat`, `sh`.
///
/// Used by tests that run `kernex run` on Linux, where Landlock is active and
/// restricts the binary's ability to open any file not in allow_read.
pub const LINUX_EXEC_POLICY: &str = "\
agent_name: test-agent
filesystem:
  allow_read:
    - /usr
    - /bin
    - /lib
    - /lib64
    - /lib32
    - /usr/lib
    - /etc
  block_hidden: true
";

/// Minimal kernex.yaml with no filesystem policy — suitable for schema tests
/// where enforcement behaviour is not under test.
pub const MINIMAL_POLICY: &str = "agent_name: test-agent\n";

// ---------------------------------------------------------------------------
// Command builder helpers
// ---------------------------------------------------------------------------

/// Build a `std::process::Command` for `kernex` with `--quiet` and the given
/// config path pre-populated.
///
/// Pass additional arguments with `.arg()` / `.args()` on the returned
/// `Command`.
pub fn kernex_cmd(config: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(kernex_bin());
    cmd.args(["--quiet", "--config", config]);
    // Pipe stdin so `confirm()` reads EOF and accepts the default.
    cmd.stdin(std::process::Stdio::null());
    cmd
}
