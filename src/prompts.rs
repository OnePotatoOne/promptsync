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
use crate::util::{atomic_write, expand_tilde, safe_relative_path};

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

/// Resolve `<source id>/<relative>` to an absolute path inside a known root.
fn resolve_entry<'a>(
    roots: &'a BTreeMap<String, PathBuf>,
    key: &str,
) -> Option<(&'a PathBuf, PathBuf)> {
    let (id, rest) = key.split_once('/')?;
    let root = roots.get(id)?;
    let relative = safe_relative_path(rest)?;
    Some((root, relative))
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
        let (root, relative) = resolve_entry(&roots, key).ok_or_else(|| {
            anyhow::anyhow!("bundle entry {key:?} does not map to a local source")
        })?;
        plan.push((key.clone(), root.join(relative), content.as_slice()));
    }

    let previous = load_managed(data_dir);
    let mut report = ApplyReport::default();
    let backup_root = data_dir
        .join("backups")
        .join(chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string());

    // Stage everything first so a failure cannot leave a half-written bundle.
    let mut staged: Vec<(PathBuf, PathBuf, Option<u32>)> = Vec::new();
    for (key, target, content) in &plan {
        let existing = fs::read(target).ok();
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
        if let Some(existing) = existing.as_ref() {
            let backup = backup_root.join(key);
            if let Err(err) = fs::create_dir_all(backup.parent().unwrap_or(&backup_root)) {
                logger.warn(format!("cannot create backup dir: {err}"));
            } else if let Err(err) = fs::write(&backup, existing) {
                logger.warn(format!("cannot back up {}: {err}", target.display()));
            } else {
                report.backup_dir = Some(backup_root.clone());
            }
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let temp = target.with_file_name(format!(
            ".{}.psync.tmp",
            target
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| "prompt".to_string())
        ));
        fs::write(&temp, content).with_context(|| format!("writing {}", temp.display()))?;
        staged.push((temp, target.clone(), previous_mode));
        report.written.push(key.clone());
    }

    for (temp, target, previous_mode) in &staged {
        if let Err(err) = crate::util::replace_file(temp, target) {
            for (temp, _, _) in &staged {
                let _ = fs::remove_file(temp);
            }
            return Err(err).with_context(|| format!("installing {}", target.display()));
        }
        // Keep the mode of an existing file, default new prompts to owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = previous_mode.unwrap_or(0o600);
            let _ = fs::set_permissions(target, fs::Permissions::from_mode(mode));
        }
        #[cfg(not(unix))]
        let _ = previous_mode;
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
        match resolve_entry(&roots, old) {
            Some((root, relative)) => {
                let path = root.join(relative);
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
            None => logger.warn(format!("cannot remove stale managed entry {old:?}")),
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

fn prune_backups(data_dir: &Path, keep: usize, logger: &Logger) {
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
    while dirs.len() > keep.max(1) {
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
