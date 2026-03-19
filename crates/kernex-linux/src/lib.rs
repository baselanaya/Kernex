//! Linux sandbox adapter — Landlock LSM + seccomp BPF enforcement for Kernex.
//!
//! # Security architecture
//!
//! This crate applies two complementary enforcement layers before `execve`:
//!
//! 1. **Landlock LSM** — filesystem path-scoped access control.
//!    Cannot restrict syscalls, `/proc` fd-based access, or network (v1).
//!
//! 2. **seccomp BPF** — syscall-level filtering with a mandatory blocklist
//!    covering `ptrace`, `io_uring`, `memfd_create`, namespace creation,
//!    and kernel-takeover syscalls.
//!
//! Together they provide defence-in-depth: Landlock covers what seccomp
//! cannot (file path specificity), and seccomp covers what Landlock cannot
//! (kernel-level syscall blocking).
//!
//! # Enforcement ordering
//!
//! ```text
//! 1. build_landlock_ruleset()  → LandlockBuilt
//! 2. apply_seccomp()           → SeccompApplied
//! 3. LandlockBuilt::restrict_self() → LandlockApplied
//! 4. SandboxedSpawn::new(landlock, seccomp) — proof both layers are active
//! 5. execve(agent)
//! ```
//!
//! The type system enforces this ordering: [`SandboxedSpawn`] can only be
//! constructed when both [`LandlockApplied`] and [`SeccompApplied`] exist.
//!
//! # Graceful degradation
//!
//! If the process already has 16 stacked Landlock rulesets (`E2BIG` from
//! `restrict_self`), and `strict = false`, Kernex falls back to
//! seccomp-only enforcement and returns [`SandboxReady::SeccompOnly`].
//!
//! # Platform support
//!
//! All Linux-specific implementation code is in [`landlock`], [`seccomp`],
//! and [`tty`], gated by `#[cfg(target_os = "linux")]`.
//! The trait and marker types in [`backend`] and [`spawn`] compile on all
//! platforms so that downstream crates can reference them without platform gates.

pub mod backend;
pub mod error;
pub mod spawn;

#[cfg(target_os = "linux")]
pub mod landlock;

#[cfg(target_os = "linux")]
pub mod seccomp;

#[cfg(target_os = "linux")]
pub mod tty;

pub use backend::{setup_sandbox, SandboxBackend};
pub use error::{LandlockError, LinuxError, SeccompError};
pub use spawn::{LandlockApplied, LandlockBuilt, SandboxReady, SandboxedSpawn, SeccompApplied};

#[cfg(target_os = "linux")]
pub use backend::LinuxSandboxBackend;

#[cfg(target_os = "linux")]
pub use tty::close_tty_fds;
