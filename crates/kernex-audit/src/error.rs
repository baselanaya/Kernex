use thiserror::Error;

/// Errors that can occur in the Kernex audit layer.
#[derive(Debug, Error)]
pub enum AuditError {
    /// `merge` was called with an empty slice — there is nothing to merge.
    #[error("cannot merge an empty candidate list")]
    EmptyCandidateList,

    /// An underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
