//! Prompt bundle handling: scanning configured sources, hashing and applying a
//! pull to the local disk (atomic writes, backups, managed-file tracking).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::SyncConfig;
use crate::globpat;
use crate::logx::Logger;
use crate::util::{atomic_write, expand_tilde, safe_relative_path, secure_join};

pub const MAX_FILE_BYTES: u64 = 512 * 1024;
pub const MAX_FILES: usize = 1024;
const MAX_DEPTH: usize = 16;
const HASH_DOMAIN: &[u8] = b"promptsync-bundle-v1\n";

#[derive(Debug, Clone)]
pub struct SourceSpec {
    pub id: String,
    pub root: PathBuf,
    pub globs: Vec<String>,
}

pub fn resolve_sources(config: &SyncConfig) -> Vec<SourceSpec> {
    config
        .sources
        .iter()
        .map(|source| SourceSpec {
            id: source.id.clone(),
            root: expand_tilde(&source.root),
            globs: source.globs.clone(),
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_bundle_bytes: u64,
    pub follow_symlinks: bool,
}

impl From<&SyncConfig> for ScanOptions {
    fn from(config: &SyncConfig) -> Self {
        Self {
            max_bundle_bytes: config.max_bundle_bytes,
            follow_symlinks: config.follow_symlinks,
        }
    }
}

fn walk(
    root: &Path,
    current: &Path,
    depth: usize,
    options: &ScanOptions,
    out: &mut Vec<String>,
    logger: Option<&Logger>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) => {
            if let Some(logger) = logger {
                logger.warn(format!("cannot read {}: {err}", current.display()));
            }
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".DS_Store" || name.ends_with(".psync.tmp") {
            continue;
        }
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        let is_symlink = file_type.is_symlink();
        if is_symlink && !options.follow_symlinks {
            continue;
        }
        let metadata = if is_symlink {
            fs::metadata(&path)
        } else {
            entry.metadata()
        };
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            if name.starts_with('.') && name != "." {
                continue;
            }
            walk(root, &path, depth + 1, options, out, logger);
        } else if metadata.is_file() {
            if name.starts_with('.') {
                continue;
            }
            if let Ok(relative) = path.strip_prefix(root) {
                let relative = relative.to_string_lossy().replace('\\', "/");
                out.push(relative);
            }
        }
    }
}

/// Whether `relative` (a path below `source.root`, `/`-separated) is a file
/// this machine would sync itself.
///
/// Mirrors `scan`: the path must match one of the source's globs and must not
/// contain hidden components. Agents use it to reject bundle entries that are
/// inside a configured root but outside its globs, so a server (or anyone who
/// holds the shared cluster secret and can impersonate it) cannot drop
/// arbitrary files such as Cindy skills or memories next to the prompts.
pub fn source_accepts(source: &SourceSpec, relative: &str) -> bool {
    if relative
        .split('/')
        .any(|part| part.is_empty() || part.starts_with('.'))
    {
        return false;
    }
    source
        .globs
        .iter()
        .any(|pattern| globpat::matches(pattern, relative))
}

/// Collect every managed prompt file, keyed by `<source id>/<relative path>`.
pub fn scan(
    sources: &[SourceSpec],
    options: &ScanOptions,
    logger: Option<&Logger>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut total: u64 = 0;
    for source in sources {
        if !source.root.is_dir() {
            if let Some(logger) = logger {
                logger.debug(format!(
                    "source {} root does not exist yet: {}",
                    source.id,
                    source.root.display()
                ));
            }
            continue;
        }
        let mut relative_files = Vec::new();
        walk(
            &source.root,
            &source.root,
            0,
            options,
            &mut relative_files,
            logger,
        );
        relative_files.sort();
        for relative in relative_files {
            if !source
                .globs
                .iter()
                .any(|pattern| globpat::matches(pattern, &relative))
            {
                continue;
            }
            if entries.len() >= MAX_FILES {
                if let Some(logger) = logger {
                    logger.warn(format!(
                        "bundle reached the {} file limit, ignoring the rest",
                        MAX_FILES
                    ));
                }
                break;
            }
            let full = source.root.join(&relative);
            let metadata =
                fs::metadata(&full).with_context(|| format!("stat {}", full.display()))?;
            if metadata.len() > MAX_FILE_BYTES {
                if let Some(logger) = logger {
                    logger.warn(format!(
                        "skipping {} ({} bytes > {} limit)",
                        full.display(),
                        metadata.len(),
                        MAX_FILE_BYTES
                    ));
                }
                continue;
            }
            if total + metadata.len() > options.max_bundle_bytes {
                bail!(
                    "bundle exceeds sync.max_bundle_bytes ({}), raise the limit",
                    options.max_bundle_bytes
                );
            }
            let key = format!("{}/{}", source.id, relative);
            if !source.id.is_empty() && safe_relative_path(&key).is_none() {
                continue;
            }
            let content = fs::read(&full).with_context(|| format!("reading {}", full.display()))?;
            total += content.len() as u64;
            entries.insert(key, content);
        }
    }
    Ok(entries)
}

/// SHA-256 over a canonical serialisation of all bundle entries.
pub fn canonical_hash(entries: &BTreeMap<String, Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    for (path, content) in entries {
        hasher.update(path.as_bytes());
        hasher.update([0u8]);
        hasher.update((content.len() as u64).to_be_bytes());
        hasher.update(Sha256::digest(content));
    }
    hex::encode(hasher.finalize())
}

pub fn total_bytes(entries: &BTreeMap<String, Vec<u8>>) -> u64 {
    entries.values().map(|content| content.len() as u64).sum()
}

#[derive(Debug, Default, Clone)]
pub struct ApplyReport {
    pub written: Vec<String>,
    pub deleted: Vec<String>,
    pub unchanged: usize,
    pub backup_dir: Option<PathBuf>,
}

impl ApplyReport {
    pub fn summary(&self) -> String {
        format!(
            "{} written, {} deleted, {} unchanged",
            self.written.len(),
            self.deleted.len(),
            self.unchanged
        )
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ManagedState {
    #[serde(default)]
    updated_unix: u64,
    #[serde(default)]
    files: Vec<String>,
}

fn managed_path(data_dir: &Path) -> PathBuf {
    data_dir.join("managed.json")
}

fn load_managed(data_dir: &Path) -> ManagedState {
    let path = managed_path(data_dir);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(_) => return ManagedState::default(),
    };
    serde_json::from_str(&text).unwrap_or_default()
}

/// Resolve `<source id>/<relative>` to a path that cannot follow symlinks below
/// the configured root. `create_root` is only enabled for writes, not deletes.
fn resolve_entry<'a>(
    roots: &'a BTreeMap<String, PathBuf>,
    key: &str,
    create_root: bool,
) -> Result<(&'a PathBuf, PathBuf)> {
    let (id, rest) = key
        .split_once('/')
        .with_context(|| format!("bundle entry {key:?} has no source id"))?;
    let root = roots
        .get(id)
        .with_context(|| format!("bundle entry {key:?} does not map to a local source"))?;
    let relative = safe_relative_path(rest)
        .with_context(|| format!("bundle entry {key:?} has an unsafe path"))?;
    let target = secure_join(root, &relative, create_root)
        .with_context(|| format!("resolving target for {key}"))?;
    Ok((root, target))
}

struct StagedWrite {
    temp: PathBuf,
    target: PathBuf,
    backup: Option<PathBuf>,
    previous_mode: Option<u32>,
}

/// Write a pulled bundle to disk. Server data is authoritative: files recorded
/// in the previous managed set but missing from the bundle are removed.
pub fn apply(
    entries: &BTreeMap<String, Vec<u8>>,
    sources: &[SourceSpec],
    data_dir: &Path,
    keep_backups: usize,
    delete_removed: bool,
    logger: &Logger,
) -> Result<ApplyReport> {
    let roots: BTreeMap<String, PathBuf> = sources
        .iter()
        .map(|source| (source.id.clone(), source.root.clone()))
        .collect();

    // Validate the whole bundle before touching the filesystem.
    let mut plan: Vec<(String, PathBuf, &[u8])> = Vec::new();
    for (key, content) in entries {
        let (_, target) = resolve_entry(&roots, key, true)?;
        plan.push((key.clone(), target, content.as_slice()));
    }

    let previous = load_managed(data_dir);
    let mut report = ApplyReport::default();
    let backup_root = data_dir
        .join("backups")
        .join(chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ").to_string());

    // Read and back up every changed file before replacing any of them. A read
    // or backup failure aborts the update rather than silently losing the only
    // copy of a local prompt.
    let mut staged: Vec<StagedWrite> = Vec::new();
    let staging = (|| -> Result<()> {
        for (key, target, content) in &plan {
            let existing = match fs::read(target) {
                Ok(existing) => Some(existing),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(err).with_context(|| format!("reading {}", target.display()))
                }
            };
            if existing.as_deref() == Some(*content) {
                report.unchanged += 1;
                continue;
            }
            #[cfg(unix)]
            let previous_mode = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(target)
                    .ok()
                    .map(|metadata| metadata.permissions().mode() & 0o777)
            };
            #[cfg(not(unix))]
            let previous_mode: Option<u32> = None;
            let backup = if let Some(existing) = existing.as_ref() {
                let backup = backup_root.join(key);
                fs::create_dir_all(backup.parent().unwrap_or(&backup_root))
                    .with_context(|| format!("creating backup dir for {key}"))?;
                fs::write(&backup, existing)
                    .with_context(|| format!("backing up {}", target.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&backup, fs::Permissions::from_mode(0o600));
                }
                report.backup_dir = Some(backup_root.clone());
                Some(backup)
            } else {
                None
            };
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let temp = target.with_file_name(format!(
                ".{}.psync.tmp",
                target
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| "prompt".to_string())
            ));
            fs::write(&temp, content).with_context(|| format!("writing {}", temp.display()))?;
            staged.push(StagedWrite {
                temp,
                target: target.clone(),
                backup,
                previous_mode,
            });
            report.written.push(key.clone());
        }
        Ok(())
    })();
    if let Err(err) = staging {
        for item in &staged {
            let _ = fs::remove_file(&item.temp);
        }
        return Err(err);
    }

    for (index, item) in staged.iter().enumerate() {
        if let Err(err) = crate::util::replace_file(&item.temp, &item.target) {
            for item in &staged {
                let _ = fs::remove_file(&item.temp);
            }
            let rollback_errors = rollback_writes(&staged, index);
            let err =
                anyhow::Error::new(err).context(format!("installing {}", item.target.display()));
            if rollback_errors.is_empty() {
                return Err(err);
            }
            return Err(err.context(format!(
                "rollback also failed: {}",
                rollback_errors.join("; ")
            )));
        }
        // Keep the mode of an existing file, default new prompts to owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = item.previous_mode.unwrap_or(0o600);
            let _ = fs::set_permissions(&item.target, fs::Permissions::from_mode(mode));
        }
        #[cfg(not(unix))]
        let _ = &item.previous_mode;
    }

    let current: BTreeSet<&String> = entries.keys().collect();
    for old in &previous.files {
        if !delete_removed {
            if !current.contains(old) {
                logger.info(format!(
                    "keeping {old} (no longer synced; sync.delete_removed = false)"
                ));
            }
            continue;
        }
        if current.contains(old) {
            continue;
        }
        match resolve_entry(&roots, old, false) {
            Ok((_, path)) => {
                if path.is_file() {
                    match fs::remove_file(&path) {
                        Ok(()) => {
                            logger.info(format!("removed {}", path.display()));
                            report.deleted.push(old.clone());
                        }
                        Err(err) => logger.warn(format!("cannot remove {}: {err}", path.display())),
                    }
                }
            }
            Err(err) => logger.warn(format!(
                "cannot remove stale managed entry {old:?}: {err:#}"
            )),
        }
    }

    let state = ManagedState {
        updated_unix: crate::util::now_unix(),
        files: entries.keys().cloned().collect(),
    };
    let serialized = serde_json::to_vec_pretty(&state)?;
    atomic_write(&managed_path(data_dir), &serialized, true).context("writing managed.json")?;

    prune_backups(data_dir, keep_backups, logger);
    Ok(report)
}

fn rollback_writes(staged: &[StagedWrite], installed: usize) -> Vec<String> {
    let mut errors = Vec::new();
    for item in staged[..installed].iter().rev() {
        let result = (|| -> std::io::Result<()> {
            if let Some(backup) = &item.backup {
                let content = fs::read(backup)?;
                atomic_write(&item.target, &content, false)?;
            } else if item.target.exists() {
                fs::remove_file(&item.target)?;
            }
            #[cfg(unix)]
            if let Some(mode) = item.previous_mode {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&item.target, fs::Permissions::from_mode(mode))?;
            }
            Ok(())
        })();
        if let Err(err) = result {
            errors.push(format!("{}: {err}", item.target.display()));
        }
    }
    errors
}

fn prune_backups(data_dir: &Path, keep: usize, logger: &Logger) {
    if keep == 0 {
        return;
    }
    let root = data_dir.join("backups");
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.path())
        .collect();
    // Timestamped names sort chronologically.
    dirs.sort();
    while dirs.len() > keep {
        let victim = dirs.remove(0);
        if let Err(err) = fs::remove_dir_all(&victim) {
            logger.warn(format!("cannot prune backup {}: {err}", victim.display()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logx::{Level, Logger};
    use std::fs;

    fn logger(dir: &Path) -> Logger {
        Logger::new(dir, "test.log", Level::Debug, 1_000_000, 2, false).unwrap()
    }

    fn write(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    #[test]
    fn scans_matches_and_hashes_stably() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cindy");
        write(&root.join("owner1/bots/default/SOUL.md"), "soul");
        write(&root.join("owner1/bots/default/system_prompt.md"), "system");
        write(&root.join("owner1/bots/default/notes.txt"), "ignored");
        let sources = vec![SourceSpec {
            id: "cindy-bots".to_string(),
            root: root.clone(),
            globs: vec![
                "*/bots/*/system_prompt.md".to_string(),
                "*/bots/*/SOUL.md".to_string(),
            ],
        }];
        let options = ScanOptions {
            max_bundle_bytes: 1024 * 1024,
            follow_symlinks: false,
        };
        let entries = scan(&sources, &options, None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries
                .get("cindy-bots/owner1/bots/default/SOUL.md")
                .unwrap(),
            b"soul"
        );
        assert_eq!(canonical_hash(&entries), canonical_hash(&entries));

        let mut changed = entries.clone();
        changed.insert(
            "cindy-bots/owner1/bots/default/SOUL.md".into(),
            b"soul2".to_vec(),
        );
        assert_ne!(canonical_hash(&entries), canonical_hash(&changed));
    }

    #[test]
    fn applies_bundle_writes_and_removes_stale_files() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("state");
        let root = temp.path().join("target");
        let sources = vec![SourceSpec {
            id: "shared".to_string(),
            root: root.clone(),
            globs: vec!["**/*.md".to_string()],
        }];
        write(&root.join("old.md"), "old");
        let mut entries = BTreeMap::new();
        entries.insert("shared/new.md".to_string(), b"new".to_vec());
        let log = logger(&data);

        let report = apply(&entries, &sources, &data, 3, true, &log).unwrap();
        assert_eq!(report.written, vec!["shared/new.md".to_string()]);
        assert_eq!(fs::read_to_string(root.join("new.md")).unwrap(), "new");

        // Pretend old.md was managed before.
        let state =
            serde_json::json!({ "updated_unix": 0, "files": ["shared/new.md", "shared/old.md"] });
        fs::write(managed_path(&data), serde_json::to_vec(&state).unwrap()).unwrap();

        let report = apply(&entries, &sources, &data, 3, true, &log).unwrap();
        assert_eq!(report.deleted, vec!["shared/old.md".to_string()]);
        assert!(!root.join("old.md").exists());
        assert!(root.join("new.md").exists());
    }

    #[test]
    fn keeps_old_files_when_delete_removed_is_off() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("state");
        let root = temp.path().join("target");
        let sources = vec![SourceSpec {
            id: "shared".to_string(),
            root: root.clone(),
            globs: vec!["**/*.md".to_string()],
        }];
        write(&root.join("old.md"), "old");
        let log = logger(&data);
        let state = serde_json::json!({ "updated_unix": 0, "files": ["shared/old.md"] });
        fs::write(managed_path(&data), serde_json::to_vec(&state).unwrap()).unwrap();

        let mut entries = BTreeMap::new();
        entries.insert("shared/new.md".to_string(), b"new".to_vec());
        let report = apply(&entries, &sources, &data, 3, false, &log).unwrap();
        assert!(report.deleted.is_empty());
        assert!(root.join("old.md").exists());
        assert!(root.join("new.md").exists());
    }

    #[test]
    fn backup_retention_zero_keeps_every_generation() {
        let temp = tempfile::tempdir().unwrap();
        let backups = temp.path().join("backups");
        for name in ["20260101T000000Z", "20260102T000000Z"] {
            fs::create_dir_all(backups.join(name)).unwrap();
        }
        prune_backups(temp.path(), 0, &logger(temp.path()));
        assert_eq!(fs::read_dir(backups).unwrap().count(), 2);
        prune_backups(temp.path(), 1, &logger(temp.path()));
        assert_eq!(
            fs::read_dir(temp.path().join("backups")).unwrap().count(),
            1
        );
    }

    #[test]
    fn rollback_restores_old_files_and_removes_new_files() {
        let temp = tempfile::tempdir().unwrap();
        let old_target = temp.path().join("old.md");
        let new_target = temp.path().join("new.md");
        let old_backup = temp.path().join("old.bak");
        fs::write(&old_target, "new content").unwrap();
        fs::write(&old_backup, "original content").unwrap();
        fs::write(&new_target, "created by failed update").unwrap();
        let staged = vec![
            StagedWrite {
                temp: temp.path().join("old.tmp"),
                target: old_target.clone(),
                backup: Some(old_backup),
                previous_mode: None,
            },
            StagedWrite {
                temp: temp.path().join("new.tmp"),
                target: new_target.clone(),
                backup: None,
                previous_mode: None,
            },
        ];
        assert!(rollback_writes(&staged, 2).is_empty());
        assert_eq!(fs::read_to_string(old_target).unwrap(), "original content");
        assert!(!new_target.exists());
    }

    #[test]
    fn backup_failure_does_not_replace_the_prompt() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("target");
        let data = temp.path().join("state");
        write(&root.join("prompt.md"), "local original");
        fs::write(&data, "state is unexpectedly a file").unwrap();
        let sources = vec![SourceSpec {
            id: "shared".to_string(),
            root,
            globs: vec!["**/*.md".to_string()],
        }];
        let entries = BTreeMap::from([(
            "shared/prompt.md".to_string(),
            b"server replacement".to_vec(),
        )]);
        let log = logger(&temp.path().join("logs"));
        assert!(apply(&entries, &sources, &data, 3, true, &log).is_err());
        assert_eq!(
            fs::read_to_string(sources[0].root.join("prompt.md")).unwrap(),
            "local original"
        );
    }

    #[cfg(unix)]
    #[test]
    fn writes_and_deletes_do_not_follow_source_symlinks() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("target");
        let outside = temp.path().join("outside");
        let data = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("old.md"), "do not delete").unwrap();
        symlink(&outside, root.join("linked")).unwrap();
        let sources = vec![SourceSpec {
            id: "shared".to_string(),
            root,
            globs: vec!["**/*.md".to_string()],
        }];
        let log = logger(&data);
        let entries = BTreeMap::from([(
            "shared/linked/new.md".to_string(),
            b"must not escape".to_vec(),
        )]);
        assert!(apply(&entries, &sources, &data, 3, true, &log).is_err());
        assert!(!outside.join("new.md").exists());

        fs::create_dir_all(&data).unwrap();
        let state = serde_json::json!({"files": ["shared/linked/old.md"]});
        fs::write(managed_path(&data), serde_json::to_vec(&state).unwrap()).unwrap();
        apply(&BTreeMap::new(), &sources, &data, 3, true, &log).unwrap();
        assert_eq!(
            fs::read_to_string(outside.join("old.md")).unwrap(),
            "do not delete"
        );
    }

    #[test]
    fn source_accepts_only_glob_matches_without_hidden_parts() {
        let source = SourceSpec {
            id: "cindy-bots".to_string(),
            root: PathBuf::from("/nowhere"),
            globs: vec!["*/bots/*/SOUL.md".to_string()],
        };
        assert!(source_accepts(&source, "owner/bots/cindy/SOUL.md"));
        assert!(!source_accepts(&source, "owner/bots/cindy/skills/run.js"));
        assert!(!source_accepts(&source, "owner/memories/SOUL.md"));
        assert!(!source_accepts(&source, ".hidden/bots/cindy/SOUL.md"));
        assert!(!source_accepts(&source, "owner//bots/cindy/SOUL.md"));
    }

    #[test]
    fn rejects_bundle_paths_outside_known_sources() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("state");
        let sources = vec![SourceSpec {
            id: "shared".to_string(),
            root: temp.path().join("target"),
            globs: vec!["**/*.md".to_string()],
        }];
        let log = logger(&data);
        let mut entries = BTreeMap::new();
        entries.insert("unknown/escape.md".to_string(), b"x".to_vec());
        assert!(apply(&entries, &sources, &data, 3, true, &log).is_err());

        let mut entries = BTreeMap::new();
        entries.insert("shared/../../escape.md".to_string(), b"x".to_vec());
        assert!(apply(&entries, &sources, &data, 3, true, &log).is_err());
    }
}
