# Contributing to Kernex

Thank you for your interest in contributing to Kernex. This is a security-critical systems project — we hold contributions to a high standard to protect the users who depend on it.

## Before You Start

- **Security issues:** Do not open a public issue. See [SECURITY.md](SECURITY.md).
- **Large features:** Open an issue first to discuss the design. Unsolicited large PRs risk being closed if the approach conflicts with the architecture.
- **Breaking changes:** Require an ADR (Architecture Decision Record) in `docs/adr/`.

## Development Setup

```bash
# Prerequisites: Rust 1.75+, musl-tools (Linux)
git clone https://github.com/baselanaya/Kernex.git
cd Kernex

# Check everything compiles
cargo build --workspace

# Run tests
cargo test --workspace

# Lint (must pass with zero warnings)
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --all -- --check
```

On Linux, some tests require kernel 5.13+ for Landlock support.

## Architecture Overview

Kernex is a Rust workspace. Each crate has a single responsibility:

| Crate | Responsibility |
|---|---|
| `kernex-cli` | CLI entrypoint, argument parsing, user-facing output |
| `kernex-core` | Platform-agnostic policy evaluation engine |
| `kernex-policy` | Policy types, YAML parsing, validation, scoring |
| `kernex-linux` | Linux adapter — Landlock LSM + seccomp BPF |
| `kernex-macos` | macOS adapter — Endpoint Security API |
| `kernex-audit` | Audit mode — observation and policy generation |
| `kernex-ipc` | Unix Domain Socket IPC |

Keep `kernex-core` platform-agnostic. No `#[cfg(target_os)]` in core.

## Coding Standards

- **Error handling:** `thiserror` in library crates, `anyhow` only in `kernex-cli`.
- **No `.unwrap()`** in non-test code. Use `?` or `.expect("meaningful reason")`.
- **Unsafe blocks** require a `// SAFETY:` comment explaining the invariant.
- **Security implications** require a `// SECURITY:` comment.
- All new OS-level code belongs in `kernex-linux` or `kernex-macos` — never in core.

## Testing

- Unit tests go in `#[cfg(test)]` modules within each file.
- Integration tests go in `tests/` at workspace root.
- Platform-specific tests must use `#[cfg(target_os = "linux")]` or `#[cfg(target_os = "macos")]`.
- Use `tempfile::tempdir()` for all temp paths — no real filesystem writes.
- Never make real Landlock/seccomp calls in unit tests — mock the syscall interface.

## Pull Request Checklist

Before opening a PR, confirm:

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes with zero warnings
- [ ] `cargo test --workspace` passes
- [ ] No new `.unwrap()` calls in non-test code
- [ ] Any new unsafe block has a `// SAFETY:` comment
- [ ] Any security-relevant change has a `// SECURITY:` comment
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) with crate scope (e.g., `feat(linux): add seccomp architecture check`)
- [ ] Each commit leaves the build green

## Commit Message Format

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`
**Scopes:** `cli`, `core`, `linux`, `macos`, `policy`, `audit`, `ipc`

**Examples:**
```
feat(linux): enforce Landlock ABI v3 truncate access
fix(policy): reject kernex.yaml with empty agent_name
docs(cli): update kernex run usage in README
```

## Dependency Policy

Every new dependency increases attack surface. Before adding one:

1. Check it is actively maintained and not yanked.
2. Prefer crates with `#![forbid(unsafe_code)]` for non-kernel-interface code.
3. Run `cargo audit` and confirm zero advisories.
4. Justify the addition in the PR description.

## Questions

Open a [GitHub Discussion](https://github.com/baselanaya/Kernex/discussions) for design questions or general help. Use [Issues](https://github.com/baselanaya/Kernex/issues) for confirmed bugs and actionable feature requests only.
