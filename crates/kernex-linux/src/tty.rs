//! TTY file descriptor cleanup before exec.
//!
//! # Security rationale
//!
//! On kernels before 6.2, the `TIOCSTI` ioctl on a TTY file descriptor can
//! inject keystrokes into the parent terminal session. Even though Landlock
//! can restrict `LANDLOCK_ACCESS_FS_IOCTL_DEV`, closing inherited TTY fds
//! is a defence-in-depth measure that works at any kernel version.
//!
//! # Approach
//!
//! We enumerate `/proc/self/fd`, call `isatty(3)` on each, and close any
//! that refer to a terminal. The directory fd used for enumeration is not
//! closed (it would invalidate the iterator).

use std::fs;
use std::os::fd::BorrowedFd;
use std::os::unix::io::RawFd;

use nix::unistd::isatty;

use crate::error::LinuxError;

/// Close all file descriptors in the current process that refer to a TTY.
///
/// Reads `/proc/self/fd` to enumerate open fds, checks each with `isatty`,
/// and closes any that are terminals.
///
/// # Errors
///
/// Returns [`LinuxError::Io`] if `/proc/self/fd` cannot be read. Individual
/// close failures are silently ignored (the fd may have been closed already).
///
/// # Safety
///
/// This function must be called from a single-threaded context (before the
/// child process has forked additional threads), because closing fds from
/// multiple threads simultaneously is a data race.
pub fn close_tty_fds() -> Result<(), LinuxError> {
    // Collect fd numbers first; closing while iterating the directory would
    // be a TOCTOU hazard.
    let tty_fds: Vec<RawFd> = enumerate_open_fds()?
        .into_iter()
        .filter(|&fd| {
            // SAFETY: fd was just read from /proc/self/fd and is owned by
            // this process. We borrow it transiently only to call isatty.
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
            isatty(borrowed).unwrap_or(false)
        })
        .collect();

    for fd in tty_fds {
        // SAFETY: `fd` was read from `/proc/self/fd` moments ago and is
        // owned by this process. A concurrent close is possible if this is
        // called from a multi-threaded context — see the Safety doc above.
        // We intentionally ignore `close` errors: EINTR means the fd was
        // already closed; EBADF means the same.
        let _ = nix::unistd::close(fd);
    }

    Ok(())
}

/// Enumerate the raw fd numbers visible in `/proc/self/fd`.
fn enumerate_open_fds() -> Result<Vec<RawFd>, LinuxError> {
    let mut fds = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        if let Some(nr) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<RawFd>().ok())
        {
            fds.push(nr);
        }
    }
    Ok(fds)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- enumerate_open_fds -------------------------------------------------

    #[test]
    fn test_enumerate_open_fds_returns_at_least_stdin_stdout_stderr() {
        let fds = enumerate_open_fds().unwrap();
        // stdin (0), stdout (1), stderr (2) must always be open.
        assert!(fds.contains(&0), "stdin fd must be present");
        assert!(fds.contains(&1), "stdout fd must be present");
        assert!(fds.contains(&2), "stderr fd must be present");
    }

    #[test]
    fn test_enumerate_open_fds_returns_no_negative_values() {
        let fds = enumerate_open_fds().unwrap();
        assert!(fds.iter().all(|&fd| fd >= 0));
    }

    // -- close_tty_fds ------------------------------------------------------

    #[test]
    fn test_close_tty_fds_does_not_error_in_test_environment() {
        // In CI and test runs stdin/stdout/stderr are typically not a TTY,
        // so this should be a no-op that succeeds cleanly.
        let result = close_tty_fds();
        assert!(result.is_ok(), "close_tty_fds failed: {:?}", result.err());
    }

    #[test]
    fn test_close_tty_fds_non_tty_fds_remain_open() {
        use std::fs::File;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let path = dir.path().join("probe.txt");

        // Open a regular file — it must survive close_tty_fds.
        let file = File::create(&path).unwrap();
        let fd = {
            use std::os::unix::io::AsRawFd;
            file.as_raw_fd()
        };

        close_tty_fds().unwrap();

        // Verify the file fd is still valid by checking isatty (should be false).
        // SAFETY: fd was obtained from file.as_raw_fd() above and file is still alive.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        assert!(
            !isatty(borrowed).unwrap_or(true),
            "non-TTY fd should still be open after close_tty_fds"
        );

        // Keep `file` alive until here so the fd isn't double-closed.
        drop(file);
    }
}
