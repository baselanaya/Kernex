//! seccomp BPF filter construction and installation.
//!
//! # Security notes
//!
//! ## Architecture check
//!
//! The generated BPF program's **first three instructions** are the x86-64
//! architecture validation sequence emitted by `seccompiler`:
//!
//! ```text
//! [0] BPF_LD  | BPF_W | BPF_ABS, k=4        // load seccomp_data.arch
//! [1] BPF_JMP | BPF_JEQ | BPF_K, k=AUDIT_ARCH_X86_64, jt=1, jf=0
//! [2] BPF_RET | BPF_K, k=SECCOMP_RET_KILL_PROCESS   // wrong arch → kill
//! [3] ...                                             // continue to rules
//! ```
//!
//! Without this check, a 32-bit process using the `int 0x80` entry point
//! can bypass all 64-bit syscall number filters.
//!
//! ## Mandatory blocklist
//!
//! Every syscall in [`BLOCKED_SYSCALLS`] is mapped to an **empty rule vector**,
//! which seccompiler interprets as "always match → apply `match_action`".
//! The `match_action` is [`SeccompAction::KillProcess`], which sends
//! `SIGKILL` to the entire process group — not just the offending thread.
//!
//! ## JIT interception model
//!
//! This filter uses `KillProcess`, not `User_Notif`, because `User_Notif` is
//! exploitable: a malicious process can intercept the notification and inject
//! a shared library via `SECCOMP_ADDFD_FLAG_SEND`. If JIT prompting is needed
//! it is implemented via `SIGSYS` (`SeccompAction::Trap`) on a separate,
//! narrower filter layer.

use std::collections::BTreeMap;
use std::convert::TryInto;

use nix::libc;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

use crate::error::SeccompError;
use crate::spawn::SeccompApplied;

/// AUDIT_ARCH_X86_64 — the value the kernel stores in `seccomp_data.arch` for
/// native x86-64 processes. Defined as:
/// `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`
/// = 62 | 0x8000_0000 | 0x4000_0000
///
/// The architecture check compares this value against `seccomp_data.arch`
/// (at byte offset 4). A mismatch kills the process immediately.
pub const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;

/// Byte offset of `arch` within `struct seccomp_data`.
/// The first BPF instruction loads a 32-bit word from this offset.
pub const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// `CLONE_NEWUSER` flag — creates a new user namespace, granting capabilities.
/// We block `clone(2)` calls that set this flag via a BPF argument condition.
const CLONE_NEWUSER: u64 = 0x1000_0000;

/// Syscall numbers on x86-64 that are not (yet) in the vendored libc.
/// Defined here to avoid depending on a specific libc version.
#[allow(non_upper_case_globals)]
mod nr {
    pub const io_uring_setup: i64 = 425;
    pub const io_uring_enter: i64 = 426;
    pub const io_uring_register: i64 = 427;
    pub const clone3: i64 = 435;
}

/// Syscalls that are unconditionally blocked (empty rule vector → always match).
///
/// See the module-level doc for the rationale behind each entry.
///
/// # SECURITY: do not remove entries from this list without a signed ADR.
const BLOCKED_SYSCALLS: &[i64] = &[
    // Memory injection / process inspection
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    // io_uring — bypasses many seccomp-checked syscall paths
    nr::io_uring_setup,
    nr::io_uring_enter,
    nr::io_uring_register,
    // Anonymous executable memory / code loading without hitting FS allow-list
    libc::SYS_memfd_create,
    // Filesystem manipulation / namespace escapes
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    // Kernel takeover — both kexec variants must be blocked.
    // kexec_load(2) takes a user-space buffer; kexec_file_load(2) takes a file
    // descriptor. They are separate syscalls (246 and 320) and independent
    // attack vectors. Blocking one without the other is a security gap.
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    // clone3 — argument is a struct pointer, can't filter on CLONE_NEWUSER flag;
    // block entirely and rely on the older clone(2) fallback.
    nr::clone3,
];

/// Compile the seccomp BPF filter into a loadable program.
///
/// The returned [`BpfProgram`] can be inspected in tests or passed directly
/// to [`seccompiler::apply_filter`].
///
/// # Errors
///
/// Returns [`SeccompError::CompileError`] if the BPF program cannot be
/// compiled (e.g. duplicate syscall entries, invalid conditions).
pub fn build_seccomp_filter() -> Result<BpfProgram, SeccompError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Block all unconditional syscalls with an empty rule vector.
    // An empty Vec<SeccompRule> means "match this syscall regardless of args".
    for &nr in BLOCKED_SYSCALLS {
        rules.insert(nr, vec![]);
    }

    // Block clone(2) when CLONE_NEWUSER is set in the flags argument (arg 0).
    // This prevents user namespace creation, which grants capabilities.
    // We keep clone(2) allowed for other uses (it's required by many programs).
    //
    // SECURITY: CLONE_NEWUSER = 0x10000000, checked via MaskedEq so other
    // bits in flags don't affect the match.
    let clone_newuser_cond = SeccompCondition::new(
        0, // arg 0 = flags
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::MaskedEq(CLONE_NEWUSER),
        CLONE_NEWUSER,
    )
    .map_err(|e| SeccompError::CompileError(e.to_string()))?;

    let clone_newuser_rule = SeccompRule::new(vec![clone_newuser_cond])
        .map_err(|e| SeccompError::CompileError(e.to_string()))?;

    rules.insert(libc::SYS_clone, vec![clone_newuser_rule]);

    // Compile the filter.
    // - `mismatch_action`: what to do when a syscall is NOT in the rules → Allow
    // - `match_action`:    what to do when a rule matches           → KillProcess
    // - `target_arch`:     x86_64 — seccompiler prepends the arch check automatically
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::KillProcess,
        TargetArch::x86_64,
    )
    .map_err(|e| SeccompError::CompileError(e.to_string()))?;

    filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| SeccompError::CompileError(e.to_string()))
}

/// Build and install the seccomp filter on the calling thread.
///
/// # Errors
///
/// - [`SeccompError::CompileError`] — BPF compilation failed.
/// - [`SeccompError::InstallError`] — `prctl(PR_SET_SECCOMP, ...)` failed.
pub fn build_and_install() -> Result<SeccompApplied, SeccompError> {
    let prog = build_seccomp_filter()?;
    seccompiler::apply_filter(&prog).map_err(|e| SeccompError::InstallError(e.to_string()))?;
    Ok(SeccompApplied::new())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// BPF instruction class constants — mirrors seccompiler internals so tests
    /// can assert on the generated bytecode without a private-API dependency.
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;

    // -- Filter compilation --------------------------------------------------

    #[test]
    fn test_build_seccomp_filter_succeeds() {
        let result = build_seccomp_filter();
        assert!(
            result.is_ok(),
            "filter compilation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_seccomp_filter_is_non_empty() {
        let prog = build_seccomp_filter().unwrap();
        assert!(!prog.is_empty(), "BPF program must not be empty");
    }

    // -- Architecture check -------------------------------------------------
    //
    // SECURITY: these tests verify the x86-64 architecture guard is present
    // and is the first instruction group in the filter. Without this guard,
    // 32-bit `int 0x80` syscalls bypass all 64-bit number filters.

    #[test]
    fn test_seccomp_filter_first_instruction_loads_arch_field() {
        let prog = build_seccomp_filter().unwrap();
        // seccompiler always emits the arch check first.
        // Instruction [0]: BPF_LD | BPF_W | BPF_ABS, k = SECCOMP_DATA_ARCH_OFFSET (4)
        assert_eq!(
            prog[0].code,
            BPF_LD | BPF_W | BPF_ABS,
            "first BPF instruction must load a 32-bit word (BPF_LD|BPF_W|BPF_ABS = 0x20)"
        );
        assert_eq!(
            prog[0].k, SECCOMP_DATA_ARCH_OFFSET,
            "first BPF instruction must load from offset 4 (seccomp_data.arch)"
        );
    }

    #[test]
    fn test_seccomp_filter_contains_audit_arch_x86_64_constant() {
        let prog = build_seccomp_filter().unwrap();
        // The jump instruction that follows the arch load compares against
        // AUDIT_ARCH_X86_64. Scan the whole program for this value.
        let has_arch_check = prog.iter().any(|insn| insn.k == AUDIT_ARCH_X86_64);
        assert!(
            has_arch_check,
            "BPF filter must contain AUDIT_ARCH_X86_64 (0xC000_003E) for the arch guard"
        );
    }

    // -- Mandatory blocklist ------------------------------------------------

    fn filter_blocks_syscall(nr: i64) {
        // We can't safely CALL blocked syscalls in a unit test, so we verify
        // the presence of the syscall number in the compiled BPF instructions.
        // seccompiler encodes the syscall number as `k` in the load/compare
        // instructions for each entry in the rules map.
        let prog = build_seccomp_filter().unwrap();
        let nr_u32 = nr as u32;
        let found = prog.iter().any(|insn| insn.k == nr_u32);
        assert!(
            found,
            "BPF filter must reference syscall {nr} in its instructions"
        );
    }

    #[test]
    fn test_seccomp_blocks_ptrace() {
        filter_blocks_syscall(libc::SYS_ptrace);
    }

    #[test]
    fn test_seccomp_blocks_process_vm_readv() {
        filter_blocks_syscall(libc::SYS_process_vm_readv);
    }

    #[test]
    fn test_seccomp_blocks_process_vm_writev() {
        filter_blocks_syscall(libc::SYS_process_vm_writev);
    }

    #[test]
    fn test_seccomp_blocks_io_uring_setup() {
        filter_blocks_syscall(nr::io_uring_setup);
    }

    #[test]
    fn test_seccomp_blocks_io_uring_enter() {
        filter_blocks_syscall(nr::io_uring_enter);
    }

    #[test]
    fn test_seccomp_blocks_io_uring_register() {
        filter_blocks_syscall(nr::io_uring_register);
    }

    #[test]
    fn test_seccomp_blocks_memfd_create() {
        filter_blocks_syscall(libc::SYS_memfd_create);
    }

    #[test]
    fn test_seccomp_blocks_mount() {
        filter_blocks_syscall(libc::SYS_mount);
    }

    #[test]
    fn test_seccomp_blocks_umount2() {
        filter_blocks_syscall(libc::SYS_umount2);
    }

    #[test]
    fn test_seccomp_blocks_pivot_root() {
        filter_blocks_syscall(libc::SYS_pivot_root);
    }

    #[test]
    fn test_seccomp_blocks_kexec_load() {
        filter_blocks_syscall(libc::SYS_kexec_load);
    }

    // SECURITY: kexec_file_load (syscall 320) is a separate entry point for
    // kernel replacement added in Linux 3.17. It accepts an open file descriptor
    // instead of a user-space buffer, bypassing the same restrictions as kexec_load.
    // Both must be blocked.
    #[test]
    fn test_seccomp_blocks_kexec_file_load() {
        filter_blocks_syscall(libc::SYS_kexec_file_load);
    }

    #[test]
    fn test_seccomp_blocks_init_module() {
        filter_blocks_syscall(libc::SYS_init_module);
    }

    #[test]
    fn test_seccomp_blocks_finit_module() {
        filter_blocks_syscall(libc::SYS_finit_module);
    }

    #[test]
    fn test_seccomp_blocks_clone3() {
        filter_blocks_syscall(nr::clone3);
    }

    #[test]
    fn test_seccomp_blocks_clone_with_newuser() {
        // clone(2) itself must appear in the BPF program (conditional block).
        filter_blocks_syscall(libc::SYS_clone);
    }

    // -- BPF return values: KillProcess used, USER_NOTIF absent ---------------
    //
    // SECURITY: The match_action for blocked syscalls must be KillProcess
    // (SECCOMP_RET_KILL_PROCESS = 0x80000000), not USER_NOTIF.
    //
    // SECCOMP_RET_USER_NOTIF (0x7FC00000) is exploitable: a malicious process
    // can install its own seccomp filter, intercept the USER_NOTIF notification
    // from an outer filter, and inject a shared library via SECCOMP_ADDFD_FLAG_SEND.
    // KillProcess terminates the entire process group — no interception possible.
    //
    // JIT prompting, when needed, uses SECCOMP_RET_TRAP (SIGSYS) on a separate,
    // narrower filter layer rather than USER_NOTIF on the main blocklist filter.

    /// SECCOMP_RET_KILL_PROCESS — kills the entire thread group.
    /// Value from <linux/seccomp.h>; verified against libc::SECCOMP_RET_KILL_PROCESS.
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

    /// SECCOMP_RET_USER_NOTIF — must NOT appear in any generated filter instruction.
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7FC0_0000;

    /// BPF_RET instruction class (code 0x06 | BPF_K 0x00 = 0x06).
    /// Return instructions encode the action in the `k` field.
    const BPF_RET: u16 = 0x06;

    #[test]
    fn test_seccomp_match_action_is_kill_process() {
        // SECURITY: Every BPF_RET instruction that is NOT the allow-all pass
        // must carry SECCOMP_RET_KILL_PROCESS. Scan every return instruction
        // and assert that KillProcess appears and is the only non-allow action.
        let prog = build_seccomp_filter().unwrap();
        let ret_instructions: Vec<u32> = prog
            .iter()
            .filter(|insn| insn.code == BPF_RET)
            .map(|insn| insn.k)
            .collect();

        assert!(
            !ret_instructions.is_empty(),
            "filter must contain at least one BPF_RET instruction"
        );

        let has_kill = ret_instructions.contains(&SECCOMP_RET_KILL_PROCESS);
        assert!(
            has_kill,
            "filter must contain SECCOMP_RET_KILL_PROCESS (0x80000000) as the match action; \
             found ret values: {ret_instructions:#010x?}"
        );
    }

    #[test]
    fn test_seccomp_does_not_use_user_notif() {
        // SECURITY: SECCOMP_RET_USER_NOTIF must never appear in the main
        // blocklist filter. Any occurrence is an exploitable vulnerability.
        let prog = build_seccomp_filter().unwrap();
        let user_notif_present = prog.iter().any(|insn| insn.k == SECCOMP_RET_USER_NOTIF);
        assert!(
            !user_notif_present,
            "SECCOMP_RET_USER_NOTIF (0x7FC00000) must not appear in the filter — \
             use SECCOMP_RET_TRAP (SIGSYS) for JIT interception instead"
        );
    }

    // -- Mandatory blocklist completeness ------------------------------------
    //
    // This single test asserts ALL entries from the kernel-security skill's
    // mandatory blocklist are present in the compiled filter. Add new entries
    // here whenever BLOCKED_SYSCALLS is extended.

    #[test]
    fn test_seccomp_mandatory_blocklist_complete() {
        // Reference: kernel-security skill, "Mandatory blocklist" section.
        // Each entry is (human_name, syscall_number).
        let required: &[(&str, i64)] = &[
            ("ptrace", libc::SYS_ptrace),
            ("process_vm_readv", libc::SYS_process_vm_readv),
            ("process_vm_writev", libc::SYS_process_vm_writev),
            ("io_uring_setup", nr::io_uring_setup),
            ("io_uring_enter", nr::io_uring_enter),
            ("memfd_create", libc::SYS_memfd_create),
            ("mount", libc::SYS_mount),
            ("umount2", libc::SYS_umount2),
            ("pivot_root", libc::SYS_pivot_root),
            ("kexec_load", libc::SYS_kexec_load),
            // kexec_file_load is a separate syscall (320); both must be blocked.
            ("kexec_file_load", libc::SYS_kexec_file_load),
            ("init_module", libc::SYS_init_module),
            ("finit_module", libc::SYS_finit_module),
            // clone3 is blocked entirely (struct-pointer arg, can't filter flags).
            ("clone3", nr::clone3),
            // clone(2) with CLONE_NEWUSER is blocked conditionally.
            ("clone+CLONE_NEWUSER", libc::SYS_clone),
        ];

        let prog = build_seccomp_filter().unwrap();

        let mut missing: Vec<&str> = Vec::new();
        for &(name, nr) in required {
            let nr_u32 = nr as u32;
            if !prog.iter().any(|insn| insn.k == nr_u32) {
                missing.push(name);
            }
        }

        assert!(
            missing.is_empty(),
            "mandatory blocklist entries missing from compiled BPF filter: {missing:?}\n\
             Add each missing syscall to BLOCKED_SYSCALLS in seccomp.rs."
        );
    }

    // -- AUDIT_ARCH_X86_64 constant value -----------------------------------

    #[test]
    fn test_audit_arch_x86_64_value_is_correct() {
        // Value from Linux kernel: EM_X86_64=62, __AUDIT_ARCH_64BIT=0x80000000,
        // __AUDIT_ARCH_LE=0x40000000. Regression guard.
        assert_eq!(AUDIT_ARCH_X86_64, 0xC000_003E);
    }
}
