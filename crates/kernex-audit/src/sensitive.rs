use std::path::Path;

/// Filesystem path suffixes that indicate sensitive credential or system files.
///
/// Matching is case-insensitive and works against both `~/`-prefixed paths
/// and absolute paths (e.g. `/home/user/.ssh` and `~/.ssh` both match `.ssh`).
///
/// Tuple fields: `(path_segment, human_readable_reason)`.
const SENSITIVE_FS_PATTERNS: &[(&str, &str)] = &[
    (".ssh", "SSH private keys and configuration"),
    (".aws", "AWS credentials and configuration"),
    (".gnupg", "GPG keys and configuration"),
    (".config/gcloud", "Google Cloud credentials"),
    (".config/gh", "GitHub CLI credentials"),
    (".kube", "Kubernetes configuration and credentials"),
    (".netrc", "netrc credentials (FTP/HTTP passwords)"),
    ("etc/passwd", "system user account database"),
    ("etc/shadow", "system password hash database"),
    ("etc/sudoers", "sudo privilege configuration"),
];

/// Environment variable name prefixes/tokens that indicate sensitive values.
///
/// Matching is case-insensitive prefix or exact match on the uppercased name.
///
/// Tuple fields: `(pattern, human_readable_reason)`.
const SENSITIVE_ENV_PATTERNS: &[(&str, &str)] = &[
    ("AWS_", "AWS credentials or configuration"),
    ("GOOGLE_", "Google Cloud credentials or configuration"),
    ("GITHUB_TOKEN", "GitHub API token"),
    ("NPM_TOKEN", "NPM authentication token"),
    (
        "DATABASE_URL",
        "database connection string (may contain credentials)",
    ),
    ("SECRET", "secret or sensitive value"),
    ("PASSWORD", "password"),
    ("PRIVATE_KEY", "private key material"),
];

/// Returns `true` if `path` matches any known sensitive filesystem pattern.
pub fn is_sensitive_path(path: &Path) -> bool {
    sensitive_path_reason(path).is_some()
}

/// Returns `true` if `name` matches any known sensitive environment variable pattern.
pub fn is_sensitive_env_var(name: &str) -> bool {
    sensitive_env_reason(name).is_some()
}

/// Returns the human-readable reason why `path` is considered sensitive,
/// or `None` if the path is not sensitive.
pub fn sensitive_path_reason(path: &Path) -> Option<&'static str> {
    let s = path.to_string_lossy().to_lowercase();
    // Normalise: strip the leading `~/` or `/` so that both `~/.ssh/id_rsa`
    // and `/home/user/.ssh/id_rsa` are matched by the `.ssh` segment.
    let normalised = s.trim_start_matches("~/").trim_start_matches('/');

    SENSITIVE_FS_PATTERNS
        .iter()
        .find(|(pattern, _)| {
            normalised.starts_with(pattern) || normalised.contains(&format!("/{}", pattern))
        })
        .map(|(_, reason)| *reason)
}

/// Returns the human-readable reason why `name` is considered a sensitive
/// environment variable, or `None` if it is not sensitive.
pub fn sensitive_env_reason(name: &str) -> Option<&'static str> {
    let upper = name.to_uppercase();
    SENSITIVE_ENV_PATTERNS
        .iter()
        .find(|(pattern, _)| upper.starts_with(pattern) || upper == *pattern)
        .map(|(_, reason)| *reason)
}

// ---------------------------------------------------------------------------
// Tests — Red phase: written first to describe required detection behaviour.
//         Every sensitive pattern must have a test. Missing a pattern here
//         is a security gap.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Filesystem: should detect -------------------------------------------

    #[test]
    fn test_sensitive_path_detects_ssh_tilde() {
        assert!(is_sensitive_path(Path::new("~/.ssh")));
    }

    #[test]
    fn test_sensitive_path_detects_ssh_file_absolute() {
        assert!(is_sensitive_path(Path::new("/home/alice/.ssh/id_rsa")));
    }

    #[test]
    fn test_sensitive_path_detects_aws_tilde() {
        assert!(is_sensitive_path(Path::new("~/.aws")));
    }

    #[test]
    fn test_sensitive_path_detects_aws_credentials_absolute() {
        assert!(is_sensitive_path(Path::new("/home/alice/.aws/credentials")));
    }

    #[test]
    fn test_sensitive_path_detects_gnupg_tilde() {
        assert!(is_sensitive_path(Path::new("~/.gnupg")));
    }

    #[test]
    fn test_sensitive_path_detects_gnupg_absolute() {
        assert!(is_sensitive_path(Path::new("/root/.gnupg/secring.gpg")));
    }

    #[test]
    fn test_sensitive_path_detects_config_gcloud() {
        assert!(is_sensitive_path(Path::new("~/.config/gcloud")));
    }

    #[test]
    fn test_sensitive_path_detects_config_gcloud_nested() {
        assert!(is_sensitive_path(Path::new(
            "/home/user/.config/gcloud/credentials.db"
        )));
    }

    #[test]
    fn test_sensitive_path_detects_config_gh() {
        assert!(is_sensitive_path(Path::new("~/.config/gh")));
    }

    #[test]
    fn test_sensitive_path_detects_kube() {
        assert!(is_sensitive_path(Path::new("~/.kube")));
    }

    #[test]
    fn test_sensitive_path_detects_kube_config_absolute() {
        assert!(is_sensitive_path(Path::new("/home/user/.kube/config")));
    }

    #[test]
    fn test_sensitive_path_detects_netrc_tilde() {
        assert!(is_sensitive_path(Path::new("~/.netrc")));
    }

    #[test]
    fn test_sensitive_path_detects_netrc_absolute() {
        assert!(is_sensitive_path(Path::new("/home/user/.netrc")));
    }

    #[test]
    fn test_sensitive_path_detects_etc_passwd() {
        assert!(is_sensitive_path(Path::new("/etc/passwd")));
    }

    #[test]
    fn test_sensitive_path_detects_etc_shadow() {
        assert!(is_sensitive_path(Path::new("/etc/shadow")));
    }

    #[test]
    fn test_sensitive_path_detects_etc_sudoers() {
        assert!(is_sensitive_path(Path::new("/etc/sudoers")));
    }

    // -- Filesystem: should NOT detect ---------------------------------------

    #[test]
    fn test_sensitive_path_does_not_flag_project_src() {
        assert!(!is_sensitive_path(Path::new("./src/main.rs")));
    }

    #[test]
    fn test_sensitive_path_does_not_flag_tmp_file() {
        assert!(!is_sensitive_path(Path::new("/tmp/output.txt")));
    }

    #[test]
    fn test_sensitive_path_does_not_flag_project_data() {
        assert!(!is_sensitive_path(Path::new("./data/train.csv")));
    }

    // -- Filesystem: reasons -------------------------------------------------

    #[test]
    fn test_sensitive_path_reason_is_some_for_ssh() {
        let reason = sensitive_path_reason(Path::new("~/.ssh"));
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("SSH"));
    }

    #[test]
    fn test_sensitive_path_reason_is_none_for_regular_file() {
        assert!(sensitive_path_reason(Path::new("./src/lib.rs")).is_none());
    }

    // -- Environment variables: should detect --------------------------------

    #[test]
    fn test_sensitive_env_detects_aws_access_key() {
        assert!(is_sensitive_env_var("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn test_sensitive_env_detects_aws_secret() {
        assert!(is_sensitive_env_var("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn test_sensitive_env_detects_google_credentials() {
        assert!(is_sensitive_env_var("GOOGLE_APPLICATION_CREDENTIALS"));
    }

    #[test]
    fn test_sensitive_env_detects_github_token() {
        assert!(is_sensitive_env_var("GITHUB_TOKEN"));
    }

    #[test]
    fn test_sensitive_env_detects_github_token_backup() {
        // Any var starting with GITHUB_TOKEN should be flagged.
        assert!(is_sensitive_env_var("GITHUB_TOKEN_BACKUP"));
    }

    #[test]
    fn test_sensitive_env_detects_npm_token() {
        assert!(is_sensitive_env_var("NPM_TOKEN"));
    }

    #[test]
    fn test_sensitive_env_detects_database_url() {
        assert!(is_sensitive_env_var("DATABASE_URL"));
    }

    #[test]
    fn test_sensitive_env_detects_secret_prefix() {
        assert!(is_sensitive_env_var("SECRET_KEY"));
    }

    #[test]
    fn test_sensitive_env_detects_password_prefix() {
        assert!(is_sensitive_env_var("PASSWORD_HASH"));
    }

    #[test]
    fn test_sensitive_env_detects_private_key_prefix() {
        assert!(is_sensitive_env_var("PRIVATE_KEY_PEM"));
    }

    // -- Environment variables: should NOT detect ----------------------------

    #[test]
    fn test_sensitive_env_does_not_flag_anthropic_api_key() {
        // ANTHROPIC_ is not in the sensitive prefix list.
        assert!(!is_sensitive_env_var("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn test_sensitive_env_does_not_flag_path() {
        assert!(!is_sensitive_env_var("PATH"));
    }

    #[test]
    fn test_sensitive_env_does_not_flag_home() {
        assert!(!is_sensitive_env_var("HOME"));
    }

    #[test]
    fn test_sensitive_env_does_not_flag_my_password_mid_name() {
        // "MY_PASSWORD" does not START with "PASSWORD" — must be a prefix match.
        assert!(!is_sensitive_env_var("MY_PASSWORD"));
    }

    // -- Environment variables: reasons --------------------------------------

    #[test]
    fn test_sensitive_env_reason_is_some_for_aws() {
        let reason = sensitive_env_reason("AWS_SECRET");
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("AWS"));
    }

    #[test]
    fn test_sensitive_env_reason_is_none_for_path() {
        assert!(sensitive_env_reason("PATH").is_none());
    }
}
