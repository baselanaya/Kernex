//! `kernex run -- <cmd>` — full sandbox enforcement.
//!
//! # Enforcement model
//!
//! On Linux, enforcement is applied in the child process between `fork()` and
//! `execve()` via `std::process::Command::pre_exec`. The kernel-mandated
//! ordering is preserved inside [`kernex_linux::setup_sandbox`]:
//!
//! 1. Build Landlock ruleset.
//! 2. Install seccomp BPF filter.
//! 3. `restrict_self()` — lock Landlock.
//! 4. `execve` — inherit sandbox.
//!
//! In non-strict mode, Kernex degrades to seccomp-only if Landlock is
//! unsupported or the depth limit is reached. Seccomp failure is always fatal.

use std::process::Command;

use crate::cli::{GlobalArgs, RunArgs};
use crate::output::{EnforcementInfo, Output, RunJsonOutput, RunSummary};
use crate::policy_io::{load_policy, score_warning};

/// Run `kernex run -- <cmd>`.
pub async fn run(out: &Output, global: &GlobalArgs, args: RunArgs) -> anyhow::Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("No command specified. Usage: kernex run -- <cmd>");
    }

    // Load and validate policy.
    let policy = load_policy(&global.config)?;

    if let Err(e) = policy.validate() {
        if global.strict {
            anyhow::bail!("Policy validation failed: {e}");
        }
        out.warn(&format!("Policy validation warning: {e}"));
    }

    // Pre-flight score warning (silent if >= 60).
    if let Some(warning) = score_warning(&policy) {
        out.warn(&warning);
    }

    let cmd_str = args.command.join(" ");
    let result = spawn_with_enforcement(&policy, global.strict, &args.command, out)?;

    // Session summary output.
    let summary = RunSummary {
        total_blocks: 0,
        unique_blocks: 0,
        prompts_shown: 0,
        prompts_allowed: 0,
        prompts_denied: 0,
        injection_signals: 0,
    };

    if out.json {
        out.emit_json(&RunJsonOutput {
            command: "run",
            agent: cmd_str,
            policy_score: policy.score().total,
            enforcement: result.info,
            exit_code: result.exit_code,
            summary,
        });
    } else {
        let blocks = summary.total_blocks;
        let unique = summary.unique_blocks;
        let prompts = summary.prompts_shown;
        let denied = summary.prompts_denied;
        out.print(&format!(
            "Session summary: {blocks} requests blocked ({unique} unique), \
             {prompts} prompted ({denied} denied)"
        ));
    }

    // Propagate non-zero exit codes.
    if let Some(code) = result.exit_code {
        if code != 0 {
            std::process::exit(code);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Platform-specific enforcement
// ---------------------------------------------------------------------------

struct SpawnResult {
    info: EnforcementInfo,
    exit_code: Option<i32>,
}

#[cfg(target_os = "linux")]
fn spawn_with_enforcement(
    policy: &kernex_policy::KernexPolicy,
    strict: bool,
    command: &[String],
    out: &Output,
) -> anyhow::Result<SpawnResult> {
    use std::os::unix::process::CommandExt as _;

    use kernex_linux::{setup_sandbox, LinuxSandboxBackend, SandboxBackend as _};

    // Pre-fork: probe Landlock support WITHOUT calling restrict_self.
    // This tells us which enforcement tier to report and whether to fail fast.
    let landlock_available = LinuxSandboxBackend
        .build_landlock_ruleset(&policy.filesystem)
        .is_ok();

    if !landlock_available && strict {
        anyhow::bail!(
            "Enforcement failed: Landlock LSM is not supported on this kernel. \
             Remove --strict to fall back to seccomp-only enforcement."
        );
    }

    if !landlock_available {
        out.warn(
            "Landlock LSM is not available on this kernel; \
             falling back to seccomp-only enforcement.",
        );
    }

    let fs_policy = policy.filesystem.clone();
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    // SAFETY: This closure runs in the forked child process before execve().
    // We apply Landlock + seccomp as the first action so the sandbox is active
    // before the agent takes any action. setup_sandbox only makes kernel
    // syscalls — no parent allocator locks are held in this window.
    unsafe {
        cmd.pre_exec(move || {
            setup_sandbox(&LinuxSandboxBackend, &fs_policy, strict)
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string()))
        });
    }

    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to launch '{}': {e}", command[0]))?;

    // Report enforcement based on the pre-fork probe.
    // setup_sandbox in non-strict mode always succeeds (SeccompOnly if Landlock
    // is unavailable), so we can infer enforcement quality from landlock_available.
    let (landlock, seccomp, degraded) = if landlock_available {
        (true, true, false)
    } else {
        (false, true, true)
    };

    Ok(SpawnResult {
        info: EnforcementInfo {
            landlock,
            seccomp,
            endpoint_security: false,
            degraded,
        },
        exit_code: status.code(),
    })
}

#[cfg(target_os = "macos")]
fn spawn_with_enforcement(
    policy: &kernex_policy::KernexPolicy,
    strict: bool,
    command: &[String],
    out: &Output,
) -> anyhow::Result<SpawnResult> {
    use kernex_macos::{setup_sandbox, MacosSandboxBackend};

    // On macOS, Endpoint Security monitors externally — the ES client observes
    // the agent process from outside rather than being applied pre-exec. So we:
    // 1. Spawn the child first.
    // 2. Activate ES monitoring for its PID via setup_sandbox.
    // 3. Wait for the child to exit, keeping the monitor alive throughout.
    //
    // There is an inherent race window between spawn and ES activation, handled
    // by the NO_AGENT_PID sentinel in es_client: all events are allowed until
    // the PID is set via the atomic store in activate_for_pid.
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to launch '{}': {e}", command[0]))?;

    let agent_pid = child.id();

    let ready = match setup_sandbox(&MacosSandboxBackend, &policy.filesystem, agent_pid, strict) {
        Ok(r) => r,
        Err(e) => {
            // Kill the child so we don't leave an unsandboxed process running.
            let _ = child.kill();
            anyhow::bail!("Endpoint Security setup failed: {e}");
        }
    };

    if ready.is_degraded() {
        out.warn(
            "Endpoint Security entitlement missing; running without macOS sandboxing. \
             Obtain com.apple.developer.endpoint-security.client to enable enforcement.",
        );
    }

    let degraded = ready.is_degraded();

    // Keep the monitor alive until the child exits.
    let status = child
        .wait()
        .map_err(|e| anyhow::anyhow!("Failed to wait for child process: {e}"))?;

    // Dropping `ready` signals the ES client destructor to call es_delete_client().
    drop(ready);

    Ok(SpawnResult {
        info: EnforcementInfo {
            landlock: false,
            seccomp: false,
            endpoint_security: !degraded,
            degraded,
        },
        exit_code: status.code(),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn spawn_with_enforcement(
    _policy: &kernex_policy::KernexPolicy,
    _strict: bool,
    command: &[String],
    out: &Output,
) -> anyhow::Result<SpawnResult> {
    out.warn("Enforcement is not supported on this platform — running without sandboxing.");

    let status = Command::new(&command[0])
        .args(&command[1..])
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to launch '{}': {e}", command[0]))?;

    Ok(SpawnResult {
        info: EnforcementInfo {
            landlock: false,
            seccomp: false,
            endpoint_security: false,
            degraded: true,
        },
        exit_code: status.code(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{GlobalArgs, RunArgs};

    fn quiet_out() -> Output {
        Output {
            json: false,
            color: false,
            quiet: true,
        }
    }

    fn global(config: &str) -> GlobalArgs {
        GlobalArgs {
            output_format: None,
            strict: false,
            config: config.to_string(),
            quiet: true,
            mcp: false,
        }
    }

    #[tokio::test]
    async fn test_run_fails_for_missing_policy() {
        let g = global("/nonexistent/kernex.yaml");
        let args = RunArgs {
            command: vec!["true".to_string()],
            accept_expansions: false,
        };
        let result = run(&quiet_out(), &g, args).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("kernex init") || msg.contains("not found") || msg.contains("audit"));
    }

    #[tokio::test]
    async fn test_run_empty_command_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml");
        std::fs::write(&path, "agent_name: test").unwrap();
        let g = global(&path.to_string_lossy());
        let args = RunArgs {
            command: vec![],
            accept_expansions: false,
        };
        let result = run(&quiet_out(), &g, args).await;
        assert!(result.is_err());
    }

    // macOS: requires com.apple.developer.endpoint-security.client entitlement — not
    // available on GitHub Actions runners. Skip on macOS to prevent CI failures.
    #[cfg_attr(target_os = "macos", ignore)]
    #[tokio::test]
    async fn test_run_valid_command_with_policy_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml");
        // Policy must include system paths so Landlock allows the binary to execute.
        let yaml = "agent_name: test\nfilesystem:\n  allow_read:\n    - /usr\n    - /lib\n    - /lib64\n    - /etc\n  block_hidden: true\n";
        std::fs::write(&path, yaml).unwrap();
        let g = global(&path.to_string_lossy());
        let args = RunArgs {
            command: vec!["true".to_string()],
            accept_expansions: false,
        };
        let result = run(&quiet_out(), &g, args).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_run_score_check_passes_for_high_score_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml");
        std::fs::write(&path, "agent_name: test\n").unwrap();
        let policy = kernex_policy::KernexPolicy::from_file(&path).unwrap();
        // Default policy scores >= 60 (no resource limits deduction only).
        let warning = score_warning(&policy);
        assert!(warning.is_none());
    }
}
