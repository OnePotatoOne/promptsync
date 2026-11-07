//! Client adapters: put the synced prompt where each installed coding agent
//! reads its global instructions.
//!
//! One authoritative prompt is copied to every detected client file. The old
//! file is backed up next to itself (`<name>.<UTC stamp>.bak`) before it is
//! replaced, so a wrong guess is always recoverable.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;

use crate::config::SyncConfig;
use crate::util::{atomic_write, expand_tilde};

#[derive(Debug, Clone)]
pub struct Adapter {
    /// Short client id used in logs and `status` ("codex", "claude", ...).
    pub id: String,
    /// Instruction file the client reads.
    pub path: PathBuf,
}

#[derive(Debug, Default, Clone)]
pub struct AdaptReport {
    /// `(id, path, backup)` for every file that actually changed.
    pub written: Vec<(String, PathBuf, Option<PathBuf>)>,
    /// Files that already contained the prompt.
    pub unchanged: Vec<(String, PathBuf)>,
    /// Files that could not be written; sync itself still succeeds.
    pub failed: Vec<(String, PathBuf, String)>,
}

impl AdaptReport {
    pub fn is_empty(&self) -> bool {
        self.written.is_empty() && self.unchanged.is_empty() && self.failed.is_empty()
    }

    /// True when a file was written or failed; `unchanged` alone is quiet.
    pub fn has_changes(&self) -> bool {
        !self.written.is_empty() || !self.failed.is_empty()
    }

    /// Compact one-line summary for logs and Feishu acknowledgements.
    pub fn summary(&self) -> String {
        let names = |items: &[(String, PathBuf, Option<PathBuf>)]| {
            items
                .iter()
                .map(|(id, _, _)| id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut parts = Vec::new();
        if !self.written.is_empty() {
            parts.push(format!(
                "{} updated ({})",
                self.written.len(),
                names(&self.written)
            ));
        }
        if !self.unchanged.is_empty() {
            parts.push(format!("{} unchanged", self.unchanged.len()));
        }
        if !self.failed.is_empty() {
            parts.push(format!("{} failed", self.failed.len()));
        }
        if parts.is_empty() {
            "no client config".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Detect the clients installed on this machine plus any `sync.adapt_paths`.
pub fn detect(config: &SyncConfig) -> Vec<Adapter> {
    match dirs::home_dir() {
        Some(home) => detect_with_home(config, &home),
        None => Vec::new(),
    }
}

fn detect_with_home(config: &SyncConfig, home: &Path) -> Vec<Adapter> {
    let mut adapters = Vec::new();
    let mut seen = BTreeSet::new();

    // Kimi Code (`~/.kimi-code/AGENTS.md`).
    push_client(
        &mut adapters,
        &mut seen,
        "kimi",
        env_dir("KIMI_CODE_HOME").unwrap_or_else(|| home.join(".kimi-code")),
        "AGENTS.md",
    );
    // DeepSeek Harness (`~/.dsh/AGENTS.md`).
    push_client(
        &mut adapters,
        &mut seen,
        "deepseek",
        env_dir("DSH_HOME").unwrap_or_else(|| home.join(".dsh")),
        "AGENTS.md",
    );
    // Codex CLI (`~/.codex/AGENTS.md`).
    push_client(
        &mut adapters,
        &mut seen,
        "codex",
        env_dir("CODEX_HOME").unwrap_or_else(|| home.join(".codex")),
        "AGENTS.md",
    );
    // Claude Code (`~/.claude/CLAUDE.md`).
    push_client(
        &mut adapters,
        &mut seen,
        "claude",
        env_dir("CLAUDE_CONFIG_DIR").unwrap_or_else(|| home.join(".claude")),
        "CLAUDE.md",
    );
    // Cindy desktop: the prompt of the local bot.
    if let Some(path) = cindy_prompt() {
        push_unique(&mut adapters, &mut seen, "cindy".to_string(), path);
    }

    for raw in &config.adapt_paths {
        let path = expand_tilde(raw);
        if path.file_name().is_none() {
            continue;
        }
        let id = path
            .file_stem()
            .map(|name| name.to_string_lossy().to_lowercase())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "custom".to_string());
        push_unique(&mut adapters, &mut seen, id, path);
    }

    adapters
}

fn env_dir(name: &str) -> Option<PathBuf> {
    let value = std::env::var_os(name)?;
    let value = value.to_string_lossy();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(expand_tilde(trimmed))
    }
}

fn push_client(
    adapters: &mut Vec<Adapter>,
    seen: &mut BTreeSet<PathBuf>,
    id: &str,
    dir: PathBuf,
    file: &str,
) {
    let path = dir.join(file);
    if dir.is_dir() || path.is_file() {
        push_unique(adapters, seen, id.to_string(), path);
    }
}

fn push_unique(
    adapters: &mut Vec<Adapter>,
    seen: &mut BTreeSet<PathBuf>,
    id: String,
    path: PathBuf,
) {
    if seen.insert(path.clone()) {
        adapters.push(Adapter { id, path });
    }
}

/// Cindy keeps one prompt per bot under `owners/<owner>/bots/<bot>/SOUL.md`.
/// Prefer the local `cindy-default` bot, then the newest prompt.
fn cindy_prompt() -> Option<PathBuf> {
    cindy_prompt_under(&crate::config::cindy_owners_root())
}

fn cindy_prompt_under(root: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    for owner in fs::read_dir(root).ok()?.flatten() {
        let bots = owner.path().join("bots");
        for bot in fs::read_dir(&bots).into_iter().flatten().flatten() {
            let soul = bot.path().join("SOUL.md");
            if soul.is_file() {
                candidates.push(soul);
            }
        }
    }
    candidates.sort_by(|left, right| {
        let default_left = is_default_bot(left);
        let default_right = is_default_bot(right);
        default_right
            .cmp(&default_left)
            .then_with(|| modified(right).cmp(&modified(left)))
            .then_with(|| left.cmp(right))
    });
    candidates.into_iter().next()
}

fn is_default_bot(path: &Path) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .map(|name| name == "cindy-default")
        .unwrap_or(false)
}

fn modified(path: &Path) -> u64 {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Choose the one prompt from a bundle that should become the clients'
/// instruction file.
///
/// Priority: `sync.target`, then the largest `SOUL.md`, then the largest
/// `system_prompt.md`, then a single entry, then the largest markdown file.
pub fn canonical_prompt<'a>(
    entries: &'a BTreeMap<String, Vec<u8>>,
    target: &str,
) -> Option<(String, &'a [u8])> {
    let target = target.trim();
    if !target.is_empty() {
        // A configured target is authoritative: never guess another file when
        // this agent does not sync it.
        return entries
            .get(target)
            .map(|content| (target.to_string(), content.as_slice()));
    }

    for suffix in ["/SOUL.md", "/system_prompt.md"] {
        let best = entries
            .iter()
            .filter(|(key, _)| key.ends_with(suffix))
            .max_by(|(left_key, left), (right_key, right)| {
                left.len()
                    .cmp(&right.len())
                    .then_with(|| right_key.cmp(left_key))
            });
        if let Some((key, content)) = best {
            return Some((key.clone(), content.as_slice()));
        }
    }

    if entries.len() == 1 {
        let (key, content) = entries.iter().next()?;
        return Some((key.clone(), content.as_slice()));
    }

    entries
        .iter()
        .filter(|(key, _)| key.ends_with(".md"))
        .max_by(|(left_key, left), (right_key, right)| {
            left.len()
                .cmp(&right.len())
                .then_with(|| right_key.cmp(left_key))
        })
        .map(|(key, content)| (key.clone(), content.as_slice()))
}

/// Adapt every detected client to the prompt selected from a pulled bundle.
/// `target` is the server's `sync.target` when it is known; the local config is
/// used as a fallback.
pub fn apply_bundle(
    config: &SyncConfig,
    entries: &BTreeMap<String, Vec<u8>>,
    target: &str,
) -> AdaptReport {
    if !config.adapt_clients {
        return AdaptReport::default();
    }
    let target = if target.trim().is_empty() {
        config.target.as_str()
    } else {
        target
    };
    let Some((_, content)) = canonical_prompt(entries, target) else {
        return AdaptReport::default();
    };
    apply_content(config, content)
}

/// Adapt every detected client to one prompt (also used by the Feishu control
/// channel, where the prompt comes from a private message).
pub fn apply_content(config: &SyncConfig, content: &[u8]) -> AdaptReport {
    let mut report = AdaptReport::default();
    if !config.adapt_clients {
        return report;
    }
    for adapter in detect(config) {
        match write_one(&adapter.path, content, config.keep_backups) {
            Ok(WriteOutcome::Written(backup)) => {
                report.written.push((adapter.id, adapter.path, backup));
            }
            Ok(WriteOutcome::Unchanged) => {
                report.unchanged.push((adapter.id, adapter.path));
            }
            Err(err) => report
                .failed
                .push((adapter.id, adapter.path, format!("{err:#}"))),
        }
    }
    report
}

#[derive(Debug)]
enum WriteOutcome {
    /// The file already contained exactly this prompt.
    Unchanged,
    /// The file was created or replaced; the backup is `None` for a new file.
    Written(Option<PathBuf>),
}

/// Write one client file.
fn write_one(path: &Path, content: &[u8], keep_backups: usize) -> Result<WriteOutcome> {
    let existing = match fs::read(path) {
        Ok(existing) => Some(existing),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("reading {}", path.display()));
        }
    };
    if existing.as_deref() == Some(content) {
        return Ok(WriteOutcome::Unchanged);
    }

    let backup = match existing.as_ref() {
        Some(old) => Some(backup_existing(path, old, keep_backups)?),
        None => None,
    };

    #[cfg(unix)]
    let previous_mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path)
            .ok()
            .map(|metadata| metadata.permissions().mode() & 0o777)
    };
    #[cfg(not(unix))]
    let previous_mode: Option<u32> = None;

    atomic_write(path, content, false).with_context(|| format!("writing {}", path.display()))?;

    #[cfg(unix)]
    if let Some(mode) = previous_mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = previous_mode;

    Ok(WriteOutcome::Written(backup))
}

fn backup_existing(path: &Path, content: &[u8], keep_backups: usize) -> Result<PathBuf> {
    let stamp = Utc::now().format("%Y%m%dT%H%M%S%.9fZ");
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "prompt".to_string());
    let backup = path.with_file_name(format!("{name}.{stamp}.bak"));
    fs::write(&backup, content).with_context(|| format!("writing backup {}", backup.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&backup, fs::Permissions::from_mode(0o600));
    }
    prune_sibling_backups(path, keep_backups);
    Ok(backup)
}

/// Keep the newest `keep` `<name>.<stamp>.bak` siblings; 0 keeps all.
fn prune_sibling_backups(path: &Path, keep: usize) {
    if keep == 0 {
        return;
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let prefix = format!("{}.", name.to_string_lossy());
    let mut backups: Vec<PathBuf> = fs::read_dir(parent)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.starts_with(&prefix) && file_name.ends_with(".bak") {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();
    backups.sort();
    while backups.len() > keep {
        let victim = backups.remove(0);
        let _ = fs::remove_file(victim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn entry(key: &str, content: &str) -> (String, Vec<u8>) {
        (key.to_string(), content.as_bytes().to_vec())
    }

    #[test]
    fn detects_installed_clients_and_explicit_paths() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path();
        for dir in [".kimi-code", ".dsh", ".codex", ".claude"] {
            fs::create_dir_all(home.join(dir)).unwrap();
        }
        let extra = home.join("custom/AGENTS.md");
        let config = SyncConfig {
            adapt_paths: vec![extra.display().to_string()],
            ..SyncConfig::default()
        };
        let adapters = detect_with_home(&config, home);
        let ids: Vec<&str> = adapters.iter().map(|adapter| adapter.id.as_str()).collect();
        for expected in ["kimi", "deepseek", "codex", "claude", "agents"] {
            assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
        }
        assert!(adapters.iter().any(|adapter| adapter.path == extra));
    }

    #[test]
    fn picks_the_configured_target_first() {
        let entries = BTreeMap::from([
            entry("cindy/a/SOUL.md", "soul"),
            entry("cindy/a/system_prompt.md", "system"),
            entry("shared/prompt.md", "shared"),
        ]);
        let (key, content) = canonical_prompt(&entries, "shared/prompt.md").unwrap();
        assert_eq!(key, "shared/prompt.md");
        assert_eq!(content, b"shared");
    }

    #[test]
    fn a_missing_target_does_not_guess_another_file() {
        let entries = BTreeMap::from([
            entry("cindy/a/SOUL.md", "soul"),
            entry("cindy/a/system_prompt.md", "system"),
        ]);
        assert!(canonical_prompt(&entries, "cindy/missing/SOUL.md").is_none());
    }

    #[test]
    fn falls_back_to_soul_then_single_then_markdown() {
        let entries = BTreeMap::from([
            entry("cindy/a/SOUL.md", "soul"),
            entry("cindy/b/SOUL.md", "the larger soul"),
            entry("cindy/a/system_prompt.md", "system"),
        ]);
        let (key, _) = canonical_prompt(&entries, "").unwrap();
        assert_eq!(key, "cindy/b/SOUL.md");

        let entries = BTreeMap::from([entry("shared/only.txt", "only")]);
        assert_eq!(canonical_prompt(&entries, "").unwrap().0, "shared/only.txt");

        let entries = BTreeMap::from([
            entry("shared/a.md", "a"),
            entry("shared/b.md", "bb"),
            entry("shared/c.txt", "cc"),
        ]);
        assert_eq!(canonical_prompt(&entries, "").unwrap().0, "shared/b.md");
    }

    #[test]
    fn backs_up_before_overwriting_and_skips_identical_content() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("CLAUDE.md");
        fs::write(&path, "old prompt\n").unwrap();

        let backup = match write_one(&path, b"new prompt\n", 5).unwrap() {
            WriteOutcome::Written(Some(backup)) => backup,
            other => panic!("expected a written file with a backup, got {other:?}"),
        };
        assert_eq!(fs::read_to_string(&path).unwrap(), "new prompt\n");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "old prompt\n");
        assert!(backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("CLAUDE.md."));

        assert!(matches!(
            write_one(&path, b"new prompt\n", 5).unwrap(),
            WriteOutcome::Unchanged
        ));
    }

    #[test]
    fn creates_missing_files_without_a_backup() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("nested/AGENTS.md");
        assert!(matches!(
            write_one(&path, b"first\n", 5).unwrap(),
            WriteOutcome::Written(None)
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1,
            "no backup for a file that did not exist"
        );
    }

    #[test]
    fn prunes_old_backups_but_keeps_the_newest() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("AGENTS.md");
        fs::write(&path, "v0").unwrap();
        for index in 1..=5 {
            fs::write(
                temp.path()
                    .join(format!("AGENTS.md.20260101T00000{index}Z.bak")),
                format!("v{index}"),
            )
            .unwrap();
        }
        let backup = backup_existing(&path, b"v0", 2).unwrap();
        let backups: Vec<String> = fs::read_dir(temp.path())
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".bak"))
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(backups.len(), 2);
        assert!(backups.contains(&backup.file_name().unwrap().to_string_lossy().to_string()));
    }

    #[test]
    fn finds_only_cindy_default_as_the_default_bot() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owners");
        for (owner, bot) in [("acme", "cindy-default"), ("acme", "other")] {
            let dir = root.join(owner).join("bots").join(bot);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("SOUL.md"), "soul").unwrap();
        }
        let chosen = cindy_prompt_under(&root).unwrap();
        assert_eq!(chosen, root.join("acme/bots/cindy-default/SOUL.md"));
    }
}
