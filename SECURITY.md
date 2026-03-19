# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| latest `main` | Yes |
| older releases | No — please upgrade |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Kernex is a security-critical tool that runs at the kernel level. A vulnerability could directly compromise the machines of users who rely on it for isolation. We take this seriously.

To report a vulnerability, email: **security@maximlabs.co**

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept
- The affected crate(s) and version(s)
- Any suggested remediation, if you have one

We will acknowledge receipt within 48 hours and aim to provide a fix or remediation plan within 14 days for critical issues.

## Security Design Invariants

The following invariants are enforced in code and must never be violated:

1. **No root requirement.** The CLI exits with an error if `geteuid() == 0` unless `--allow-root` is explicitly passed.
2. **IPC socket is private.** The Unix Domain Socket is created in a user-owned temp directory with mode `0600`. Never world-readable.
3. **Rules applied before exec.** Landlock and seccomp filters are installed _before_ `execve()`. The ordering is enforced in `kernex-linux`.
4. **Block hidden by default.** `block_hidden: true` is the default. It is opt-out, never opt-in.
5. **32-bit syscall protection.** The seccomp BPF filter includes an architecture check on x86-64 to block the `int 0x80` 32-bit syscall entry point.
6. **No network in core.** `kernex-core` and the adapter crates make no network calls. Telemetry is opt-in and lives only in `kernex-cli`.

## Scope

Issues in scope:
- Sandbox escape (a sandboxed process accessing paths/hosts it should not)
- Privilege escalation via the IPC channel
- Policy bypass through malformed `kernex.yaml`
- Insecure defaults that weaken isolation

Out of scope:
- Issues requiring physical access to the machine
- Social engineering
- Vulnerabilities in third-party dependencies (report those upstream; we'll track them via `cargo audit`)
