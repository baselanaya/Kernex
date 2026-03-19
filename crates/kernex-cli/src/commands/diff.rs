//! `kernex diff [OLD] [NEW]` — compare two `kernex.yaml` files.

use kernex_policy::DiffEntry;

use crate::cli::{DiffArgs, GlobalArgs};
use crate::output::{DiffJsonEntry, DiffJsonOutput, Output};
use crate::policy_io::load_policy;

/// Run `kernex diff`.
///
/// Argument handling:
/// - `kernex diff old.yaml new.yaml` — compare the two named files.
/// - `kernex diff new.yaml`          — compare the active config vs `new.yaml`.
/// - `kernex diff`                   — error: must specify at least one file.
pub async fn run(out: &Output, global: &GlobalArgs, args: DiffArgs) -> anyhow::Result<()> {
    let (old_path, new_path) = resolve_paths(global, &args)?;

    let old_policy = load_policy(&old_path)?;
    let new_policy = load_policy(&new_path)?;

    let diff = old_policy.diff(&new_policy);

    if out.json {
        let entries: Vec<DiffJsonEntry> = diff
            .entries
            .iter()
            .map(|e| match e {
                DiffEntry::Added { field, value } => DiffJsonEntry {
                    kind: "added",
                    field: field.clone(),
                    value: Some(value.clone()),
                    old_value: None,
                    new_value: None,
                    is_scope_expansion: true,
                },
                DiffEntry::Removed { field, value } => DiffJsonEntry {
                    kind: "removed",
                    field: field.clone(),
                    value: Some(value.clone()),
                    old_value: None,
                    new_value: None,
                    is_scope_expansion: false,
                },
                DiffEntry::Changed {
                    field,
                    old_value,
                    new_value,
                    is_scope_expansion,
                } => DiffJsonEntry {
                    kind: "changed",
                    field: field.clone(),
                    value: None,
                    old_value: Some(old_value.clone()),
                    new_value: Some(new_value.clone()),
                    is_scope_expansion: *is_scope_expansion,
                },
            })
            .collect();

        out.emit_json(&DiffJsonOutput {
            command: "diff",
            old: old_path,
            new: new_path,
            entries,
            has_scope_expansions: diff.has_scope_expansions(),
        });
        return Ok(());
    }

    if diff.is_empty() {
        out.info("No differences.");
        return Ok(());
    }

    for entry in &diff.entries {
        match entry {
            DiffEntry::Added { field, value } => {
                out.print(&format!("+ added:   {field}: [\"{value}\"]"));
            }
            DiffEntry::Removed { field, value } => {
                out.print(&format!("- removed: {field}: [\"{value}\"]"));
            }
            DiffEntry::Changed {
                field,
                old_value,
                new_value,
                is_scope_expansion,
            } => {
                let marker = if *is_scope_expansion {
                    "  ⚠ scope expansion"
                } else {
                    ""
                };
                out.print(&format!(
                    "~ changed: {field}: {old_value} → {new_value}{marker}"
                ));
            }
        }
    }

    if diff.has_scope_expansions() {
        out.print("\n! WARNING: scope expansion detected — requires --accept-expansions to apply");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

fn resolve_paths(global: &GlobalArgs, args: &DiffArgs) -> anyhow::Result<(String, String)> {
    match (&args.old, &args.new) {
        (Some(old), Some(new)) => Ok((old.clone(), new.clone())),
        (Some(new), None) => {
            // Single argument: treat it as the "new" file, active config is "old".
            Ok((global.config.clone(), new.clone()))
        }
        (None, None) => {
            anyhow::bail!(
                "Usage: kernex diff [OLD] NEW\n  \
                 Provide two files to compare, or one file to compare against the active config."
            )
        }
        (None, Some(_)) => unreachable!("clap fills positional args left-to-right"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::cli::{DiffArgs, GlobalArgs};

    fn quiet_out() -> Output {
        Output {
            json: false,
            color: false,
            quiet: true,
        }
    }

    fn write_policy_yaml(dir: &tempfile::TempDir, name: &str, yaml: &str) -> String {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{yaml}").unwrap();
        path.to_string_lossy().to_string()
    }

    fn base_yaml() -> &'static str {
        "agent_name: test-agent\n"
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
    async fn test_diff_no_args_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_policy_yaml(&dir, "kernex.yaml", base_yaml());
        let g = global(&config);
        let args = DiffArgs {
            old: None,
            new: None,
        };
        let result = run(&quiet_out(), &g, args).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_diff_identical_files_reports_no_differences() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = write_policy_yaml(&dir, "a.yaml", base_yaml());
        let p2 = write_policy_yaml(&dir, "b.yaml", base_yaml());
        let g = global(&p1);
        let args = DiffArgs {
            old: Some(p1.clone()),
            new: Some(p2),
        };
        // No error, should succeed even though output goes to stdout.
        let result = run(&quiet_out(), &g, args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_diff_two_files_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = write_policy_yaml(&dir, "old.yaml", base_yaml());
        let p2 = write_policy_yaml(
            &dir,
            "new.yaml",
            "agent_name: test-agent\nfilesystem:\n  allow_read:\n    - ./logs\n",
        );
        let g = global(&p1);
        let args = DiffArgs {
            old: Some(p1),
            new: Some(p2),
        };
        let result = run(&quiet_out(), &g, args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_diff_single_arg_uses_active_config_as_old() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_policy_yaml(&dir, "kernex.yaml", base_yaml());
        let new_file = write_policy_yaml(
            &dir,
            "new.yaml",
            "agent_name: test-agent\nfilesystem:\n  allow_read:\n    - ./logs\n",
        );
        let g = global(&config);
        let args = DiffArgs {
            old: Some(new_file),
            new: None,
        };
        let result = run(&quiet_out(), &g, args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_diff_json_output_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = write_policy_yaml(&dir, "old.yaml", base_yaml());
        let p2 = write_policy_yaml(&dir, "new.yaml", base_yaml());
        let g = global(&p1);
        let out = Output {
            json: true,
            color: false,
            quiet: false,
        };
        let args = DiffArgs {
            old: Some(p1),
            new: Some(p2),
        };
        let result = run(&out, &g, args).await;
        assert!(result.is_ok());
    }
}
