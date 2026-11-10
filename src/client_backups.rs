//! 客户端指令文件的集中备份库。
//!
//! agent 把同步的 prompt 写进各个客户端（Claude Code、Codex、Cindy 等）的全局
//! 指令文件之前，会把旧内容备份到这里，而不是在每个客户端目录旁边生成
//! `<文件名>.<时间>.bak`。目录结构：
//!
//! ```text
//! <状态目录>/client-backups/
//! ├── index.json            # 清单：每条备份来自哪个文件、什么时间、哪一类
//! └── blobs/<sha256>.md     # 备份内容，按内容去重（同一版本只存一份）
//! ```
//!
//! 备份分三类：
//! - `original`：promptsync 第一次接管某个文件前，用户自己的原始内容，**永不自动清理**；
//! - `replaced`：之后每次覆盖前的旧内容，每个文件保留最新 `keep` 份；
//! - `retired`：为避免重复加载而移走的旧同步副本，同样按文件保留 `keep` 份。
//!
//! 旧版本留在客户端目录里的 `<文件名>.<时间>.bak` 会通过 [`BackupStore::import_legacy`]
//! 导入这里并从原处删除（内容先写进备份库，再删原文件，不会丢）。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::util::atomic_write;

/// 备份库目录名（位于状态目录 `<配置目录>/state/` 下）。
pub const DIR_NAME: &str = "client-backups";
/// 清单文件名。
const INDEX_FILE: &str = "index.json";
/// 内容文件所在的子目录名。
const BLOB_DIR: &str = "blobs";
/// 清单格式版本，以后改格式时用来判断是否需要升级。
const INDEX_VERSION: u32 = 1;

/// 同一进程内对清单做“读-改-写”时加锁，避免两个线程互相覆盖
/// （server 的飞书通道和 agent 可能在同一进程里先后写入）。
static INDEX_LOCK: Mutex<()> = Mutex::new(());

/// 备份的类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// promptsync 第一次接管前的原始内容，永不自动清理。
    Original,
    /// 覆盖写入前的旧内容。
    Replaced,
    /// 为避免重复加载而移走的旧同步副本。
    Retired,
}

impl Kind {
    /// 给人看的中文名称；用于 `promptsync backups` 输出。
    pub fn label(self) -> &'static str {
        match self {
            Kind::Original => "原始文件",
            Kind::Replaced => "被替换",
            Kind::Retired => "移走的重复",
        }
    }
}

/// 清单里的一条备份记录。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// 备份时间（UTC，格式 `20261110T025110.895271000Z`，可直接按字符串排序）。
    pub time: String,
    /// 客户端 id（`claude`、`codex`、`cindy-pi` ...）。
    pub id: String,
    /// 原文件的绝对路径。
    pub path: String,
    /// 内容的 SHA-256（十六进制），对应 `blobs/<sha256>.md`。
    pub sha256: String,
    /// 内容字节数。
    pub bytes: u64,
    /// 备份类别。
    pub kind: Kind,
}

/// 清单文件的内容。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Index {
    /// 清单格式版本。
    version: u32,
    /// promptsync 已经接管过的文件路径（接管时不存在的文件也记在这里，
    /// 这样之后的覆盖就不会被误认为“原始文件”）。
    managed: BTreeSet<String>,
    /// 全部备份记录，按时间先后排列。
    entries: Vec<Entry>,
}

/// 一次旧备份迁移的结果：`(原 .bak 路径, 导入后的记录)`。
pub type Imported = Vec<(PathBuf, Entry)>;

/// 集中备份库。
#[derive(Debug, Clone)]
pub struct BackupStore {
    /// 备份库根目录 `<状态目录>/client-backups`。
    root: PathBuf,
}

impl BackupStore {
    /// 打开状态目录下的备份库（只计算路径，不创建任何文件）。
    ///
    /// 参数 `data_dir` 为状态目录（`Paths::data_dir()`，默认 `<配置目录>/state`）。
    /// 调用示例：`let store = BackupStore::new(&paths.data_dir());`
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join(DIR_NAME),
        }
    }

    /// 备份库根目录；用于日志和 `status` 输出。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 某条记录对应的内容文件路径；参数 `entry` 为清单里的记录。
    pub fn blob_path(&self, entry: &Entry) -> PathBuf {
        self.blob_for(&entry.sha256)
    }

    /// 按 SHA-256 计算内容文件路径；参数 `sha256` 为十六进制摘要。
    fn blob_for(&self, sha256: &str) -> PathBuf {
        self.root.join(BLOB_DIR).join(format!("{sha256}.md"))
    }

    /// 读取全部备份记录（按时间先后）；备份库不存在时返回空列表。
    pub fn entries(&self) -> Vec<Entry> {
        self.load().entries
    }

    /// 备份即将被覆盖的旧内容。
    ///
    /// 参数：`id` 客户端 id；`path` 原文件；`content` 覆盖前的旧内容；
    /// `keep` 每个文件保留的非原始备份份数（0 = 全部保留）。
    /// `synced_copy` 表示旧内容是已知的同步 prompt 版本：这种内容一定不是用户的原始文件。
    /// 否则第一次接管这个文件时记为 `original`（永不清理），之后记为 `replaced`。
    /// 返回内容文件路径。调用示例：`store.backup("claude", &path, &old, 10, false)?`
    pub fn backup(
        &self,
        id: &str,
        path: &Path,
        content: &[u8],
        keep: usize,
        synced_copy: bool,
    ) -> Result<PathBuf> {
        // 已知同步版本直接记为 replaced，其余交给 record 按“是否第一次接管”判断。
        let kind = synced_copy.then_some(Kind::Replaced);
        self.record(id, path, content, kind, keep, None)
    }

    /// 备份即将移走的旧同步副本（类别 `retired`）；参数含义同 [`BackupStore::backup`]。
    /// 调用方确认写入成功后再删除原文件。
    pub fn retire(&self, id: &str, path: &Path, content: &[u8], keep: usize) -> Result<PathBuf> {
        self.record(id, path, content, Some(Kind::Retired), keep, None)
    }

    /// 记录 promptsync 新建了一个原本不存在的文件：以后覆盖它时不再算“原始文件”。
    ///
    /// 参数 `path` 为新建的文件。已经记录过时不写盘。
    pub fn mark_created(&self, path: &Path) -> Result<()> {
        // 加锁，保证读-改-写完整。
        let _guard = INDEX_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut index = self.load();
        // 已经接管过就什么都不做，避免每轮同步都重写清单。
        if index.managed.insert(path_key(path)) {
            self.save(&index)?;
        }
        Ok(())
    }

    /// 把旧版本留在客户端目录里的 `<文件名>.<时间>.bak` 导入备份库，并删除原处的文件。
    ///
    /// 参数：`id` 客户端 id；`path` 客户端文件（在它的同目录里找旧备份）；
    /// `known` 已知的同步 prompt 版本（用来区分原始文件）；`keep` 保留份数。
    /// 这个文件还没有任何记录时，最早的那份旧备份如果不是已知的同步版本，
    /// 就记为 `original`；其余记为 `replaced`。`dry_run = true` 时只返回将要导入的内容。
    /// 调用示例：`store.import_legacy("codex", &codex_md, &known, 10, false)?`
    pub fn import_legacy(
        &self,
        id: &str,
        path: &Path,
        known: &[Vec<u8>],
        keep: usize,
        dry_run: bool,
    ) -> Result<Imported> {
        // 找出同目录里属于这个文件的旧备份，按时间先后排序。
        let legacy = legacy_backups(path);
        if legacy.is_empty() {
            return Ok(Vec::new());
        }
        // 这个文件以前是否已被接管（有记录 = 最早的旧备份也不是原始文件）。
        let already_managed = {
            let index = self.load();
            let key = path_key(path);
            index.managed.contains(&key) || index.entries.iter().any(|entry| entry.path == key)
        };
        let mut imported = Vec::new();
        for (position, (backup, stamp)) in legacy.into_iter().enumerate() {
            // 读取旧备份内容；读不了就跳过，留在原处等下次。
            let Ok(content) = fs::read(&backup) else {
                continue;
            };
            // 只有最早的一份、且不是已知同步版本时，才认定为用户的原始文件。
            let kind = if position == 0 && !already_managed && !known.contains(&content) {
                Kind::Original
            } else {
                Kind::Replaced
            };
            // 要写入清单的记录（时间沿用旧备份文件名里的时间）。
            let entry = make_entry(id, path, &content, kind, stamp.clone());
            if !dry_run {
                // 先把内容写进备份库……
                self.record(id, path, &content, Some(kind), keep, Some(stamp))?;
                // ……确认写入后才删除原处的旧备份。
                fs::remove_file(&backup)
                    .with_context(|| format!("removing migrated {}", backup.display()))?;
            }
            imported.push((backup, entry));
        }
        Ok(imported)
    }

    /// 写入一条备份记录（内部公共实现）。
    ///
    /// 参数：`kind` 为 `None` 时按“是否第一次接管”自动判断 original / replaced；
    /// `time` 为 `None` 时使用当前时间（迁移旧备份时传入旧文件名里的时间）。
    fn record(
        &self,
        id: &str,
        path: &Path,
        content: &[u8],
        kind: Option<Kind>,
        keep: usize,
        time: Option<String>,
    ) -> Result<PathBuf> {
        // 加锁，保证读-改-写完整。
        let _guard = INDEX_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut index = self.load();
        index.version = INDEX_VERSION;
        // 清单里统一使用的路径写法。
        let key = path_key(path);
        // 第一次接管：清单里既没有接管记录、也没有任何备份。
        let first_takeover =
            !index.managed.contains(&key) && !index.entries.iter().any(|entry| entry.path == key);
        let kind = kind.unwrap_or(if first_takeover {
            Kind::Original
        } else {
            Kind::Replaced
        });
        // 生成记录（时间缺省为现在）。
        let entry = make_entry(id, path, content, kind, time.unwrap_or_else(now_stamp));
        // 内容文件：同样的内容只写一次。
        let blob = self.blob_for(&entry.sha256);
        if !blob.is_file() {
            atomic_write(&blob, content, true)
                .with_context(|| format!("writing backup {}", blob.display()))?;
        }
        index.managed.insert(key);
        index.entries.push(entry);
        // 保持时间顺序（迁移的旧备份时间可能早于已有记录）。
        index
            .entries
            .sort_by(|left, right| left.time.cmp(&right.time));
        prune(&mut index, keep);
        self.save(&index)?;
        // 清掉已经没有任何记录引用的内容文件。
        self.collect_garbage(&index);
        Ok(blob)
    }

    /// 读取清单；不存在或损坏时返回空清单（损坏的清单会在下次写入时被替换，
    /// 内容文件仍然留在 blobs/ 里，不会丢）。
    fn load(&self) -> Index {
        fs::read_to_string(self.root.join(INDEX_FILE))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// 原子写入清单（权限 0600）；参数 `index` 为完整清单。
    fn save(&self, index: &Index) -> Result<()> {
        let text = serde_json::to_string_pretty(index)?;
        let path = self.root.join(INDEX_FILE);
        atomic_write(&path, text.as_bytes(), true)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// 删除没有被任何记录引用的内容文件；参数 `index` 为最新清单。
    fn collect_garbage(&self, index: &Index) {
        // 仍被引用的摘要集合。
        let referenced: BTreeSet<&str> = index
            .entries
            .iter()
            .map(|entry| entry.sha256.as_str())
            .collect();
        let Ok(blobs) = fs::read_dir(self.root.join(BLOB_DIR)) else {
            return;
        };
        for blob in blobs.flatten() {
            let name = blob.file_name().to_string_lossy().to_string();
            // 只处理我们自己的 <sha256>.md，其他文件一律不动。
            let Some(sha) = name.strip_suffix(".md") else {
                continue;
            };
            if sha.len() == 64 && !referenced.contains(sha) {
                let _ = fs::remove_file(blob.path());
            }
        }
    }
}

/// 生成一条记录；参数含义见 [`Entry`] 各字段。
fn make_entry(id: &str, path: &Path, content: &[u8], kind: Kind, time: String) -> Entry {
    Entry {
        time,
        id: id.to_string(),
        path: path_key(path),
        sha256: hex::encode(Sha256::digest(content)),
        bytes: content.len() as u64,
        kind,
    }
}

/// 按文件清理多余的备份：每个文件只保留最新 `keep` 条非原始记录（0 = 全部保留）。
/// 参数 `index` 为要修改的清单。
fn prune(index: &mut Index, keep: usize) {
    if keep == 0 {
        return;
    }
    // 从新到旧统计每个文件已保留的非原始记录数。
    let mut kept: std::collections::BTreeMap<String, usize> = Default::default();
    let mut retain = vec![true; index.entries.len()];
    for (position, entry) in index.entries.iter().enumerate().rev() {
        // 原始文件永不清理。
        if entry.kind == Kind::Original {
            continue;
        }
        let count = kept.entry(entry.path.clone()).or_default();
        *count += 1;
        if *count > keep {
            retain[position] = false;
        }
    }
    // 按标记删除记录。
    let mut flags = retain.into_iter();
    index.entries.retain(|_| flags.next().unwrap_or(true));
}

/// 当前 UTC 时间，格式 `20261110T025110.895271000Z`（与旧备份文件名一致）。
fn now_stamp() -> String {
    Utc::now().format("%Y%m%dT%H%M%S%.9fZ").to_string()
}

/// 清单里使用的路径写法（绝对路径的字符串形式）；参数 `path` 为文件路径。
fn path_key(path: &Path) -> String {
    path.display().to_string()
}

/// 找出 `path` 同目录里属于它的旧备份 `<文件名>.<时间>.bak`。
///
/// 返回 `(备份路径, 统一格式的时间)`，按时间先后排序。只认 promptsync 生成的
/// 时间格式（`YYYYMMDDTHHMMSS[.纳秒]Z`），其他 `.bak` 文件（例如用户自己的）不动。
pub fn legacy_backups(path: &Path) -> Vec<(PathBuf, String)> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Vec::new();
    };
    // 旧备份的文件名前缀，例如 `CLAUDE.md.`。
    let prefix = format!("{}.", name.to_string_lossy());
    let mut found: Vec<(PathBuf, String)> = fs::read_dir(parent)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let file_name = entry.file_name().to_string_lossy().to_string();
            // 去掉前缀和 .bak 后缀，剩下的必须是时间戳。
            let stamp = file_name.strip_prefix(&prefix)?.strip_suffix(".bak")?;
            let stamp = normalize_stamp(stamp)?;
            entry.path().is_file().then(|| (entry.path(), stamp))
        })
        .collect();
    found.sort_by(|left, right| left.1.cmp(&right.1));
    found
}

/// 把旧备份文件名里的时间统一成带 9 位纳秒的格式，便于排序；不是合法时间戳时返回 `None`。
///
/// 参数 `stamp` 例如 `20261108T122841Z` 或 `20261108T150221.673343000Z`。
fn normalize_stamp(stamp: &str) -> Option<String> {
    // 必须以 Z 结尾。
    let body = stamp.strip_suffix('Z')?;
    // 拆出秒以下的小数部分（可选）。
    let (main, fraction) = match body.split_once('.') {
        Some((main, fraction)) => (main, fraction),
        None => (body, ""),
    };
    // 主体：8 位日期 + T + 6 位时间。
    let bytes = main.as_bytes();
    let valid_main = bytes.len() == 15
        && bytes[8] == b'T'
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[9..].iter().all(u8::is_ascii_digit);
    // 小数部分最多 9 位数字。
    let valid_fraction = fraction.len() <= 9 && fraction.bytes().all(|byte| byte.is_ascii_digit());
    if !valid_main || !valid_fraction {
        return None;
    }
    Some(format!("{main}.{fraction:0<9}Z"))
}

/// 收集状态目录 `backups/` 里保存过的同步 prompt 版本（agent 每次拉取前的旧同步文件）。
///
/// 参数 `data_dir` 为状态目录。这些内容一定是同步过的 prompt，用来判断旧备份
/// 是否为用户原始文件。只读取 1 MiB 以内的文件。
pub fn synced_versions(data_dir: &Path) -> Vec<Vec<u8>> {
    let mut versions = Vec::new();
    // 用栈做非递归遍历，避免深层目录。
    let mut pending = vec![data_dir.join("backups")];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if entry
                .metadata()
                .map(|meta| meta.len() <= 1 << 20)
                .unwrap_or(false)
            {
                if let Ok(content) = fs::read(&path) {
                    if !versions.contains(&content) {
                        versions.push(content);
                    }
                }
            }
        }
    }
    versions
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 第一次覆盖记为原始文件，之后记为被替换；同样内容只存一份。
    #[test]
    fn first_backup_is_the_original_and_content_is_deduplicated() {
        let temp = tempfile::tempdir().unwrap();
        let store = BackupStore::new(&temp.path().join("state"));
        let file = temp.path().join("CLAUDE.md");
        store
            .backup("claude", &file, b"my own rules\n", 2, false)
            .unwrap();
        store
            .backup("claude", &file, b"prompt v1\n", 2, false)
            .unwrap();
        // 另一个客户端备份同一版本：内容文件不重复。
        let other = temp.path().join("AGENTS.md");
        store.mark_created(&other).unwrap();
        store
            .backup("codex", &other, b"prompt v1\n", 2, false)
            .unwrap();

        let entries = store.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].kind, Kind::Original);
        assert_eq!(entries[1].kind, Kind::Replaced);
        assert_eq!(
            entries[2].kind,
            Kind::Replaced,
            "created file has no original"
        );
        let blobs = fs::read_dir(store.root().join(BLOB_DIR)).unwrap().count();
        assert_eq!(blobs, 2, "one blob per distinct content");
    }

    /// 轮换只清理被替换的备份，原始文件永远保留；没人引用的内容文件被删除。
    #[test]
    fn pruning_never_drops_the_original() {
        let temp = tempfile::tempdir().unwrap();
        let store = BackupStore::new(temp.path());
        let file = temp.path().join("CLAUDE.md");
        store
            .backup("claude", &file, b"original\n", 2, false)
            .unwrap();
        for version in 1..=5 {
            store
                .backup(
                    "claude",
                    &file,
                    format!("v{version}\n").as_bytes(),
                    2,
                    false,
                )
                .unwrap();
        }
        let entries = store.entries();
        let kinds: Vec<Kind> = entries.iter().map(|entry| entry.kind).collect();
        assert_eq!(kinds, vec![Kind::Original, Kind::Replaced, Kind::Replaced]);
        assert_eq!(
            fs::read_to_string(store.blob_path(&entries[0])).unwrap(),
            "original\n"
        );
        assert_eq!(
            fs::read_to_string(store.blob_path(&entries[2])).unwrap(),
            "v5\n"
        );
        let blobs = fs::read_dir(store.root().join(BLOB_DIR)).unwrap().count();
        assert_eq!(blobs, 3, "unreferenced blobs are collected");
    }

    /// 迁移旧的同目录备份：最早且不是同步版本的那份记为原始文件，原处文件被删除。
    #[test]
    fn imports_legacy_sibling_backups() {
        let temp = tempfile::tempdir().unwrap();
        let store = BackupStore::new(&temp.path().join("state"));
        let dir = temp.path().join("claude");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("CLAUDE.md");
        fs::write(&file, "current\n").unwrap();
        fs::write(dir.join("CLAUDE.md.20261108T122841Z.bak"), "mine\n").unwrap();
        fs::write(dir.join("CLAUDE.md.20261109T021650.969695000Z.bak"), "v1\n").unwrap();
        // 不是 promptsync 格式的 .bak，必须原样保留。
        fs::write(dir.join("CLAUDE.md.old.bak"), "user backup\n").unwrap();

        let known = vec![b"v1\n".to_vec()];
        let preview = store
            .import_legacy("claude", &file, &known, 10, true)
            .unwrap();
        assert_eq!(preview.len(), 2);
        assert!(
            dir.join("CLAUDE.md.20261108T122841Z.bak").exists(),
            "dry run"
        );

        let imported = store
            .import_legacy("claude", &file, &known, 10, false)
            .unwrap();
        assert_eq!(imported.len(), 2);
        let entries = store.entries();
        assert_eq!(entries[0].kind, Kind::Original);
        assert_eq!(entries[0].time, "20261108T122841.000000000Z");
        assert_eq!(entries[1].kind, Kind::Replaced);
        assert!(!dir.join("CLAUDE.md.20261108T122841Z.bak").exists());
        assert!(
            dir.join("CLAUDE.md.old.bak").exists(),
            "foreign .bak untouched"
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), "current\n");
    }

    /// 最早的旧备份是同步过的 prompt（文件由 promptsync 新建）时，不算原始文件。
    #[test]
    fn a_synced_version_is_not_mistaken_for_the_original() {
        let temp = tempfile::tempdir().unwrap();
        let store = BackupStore::new(temp.path());
        let file = temp.path().join("AGENTS.md");
        fs::write(
            temp.path().join("AGENTS.md.20261109T021650.980501000Z.bak"),
            "v1\n",
        )
        .unwrap();
        let known = vec![b"v1\n".to_vec()];
        store
            .import_legacy("cindy-pi", &file, &known, 10, false)
            .unwrap();
        assert_eq!(store.entries()[0].kind, Kind::Replaced);
    }

    /// 时间戳格式校验与统一。
    #[test]
    fn normalizes_backup_stamps() {
        assert_eq!(
            normalize_stamp("20261108T122841Z").as_deref(),
            Some("20261108T122841.000000000Z")
        );
        assert_eq!(
            normalize_stamp("20261108T150221.6733Z").as_deref(),
            Some("20261108T150221.673300000Z")
        );
        assert_eq!(normalize_stamp("old"), None);
        assert_eq!(normalize_stamp("20261108T1228Z"), None);
        assert_eq!(normalize_stamp("20261108T122841.1234567890Z"), None);
    }

    /// 从状态目录的 backups/ 收集同步过的版本。
    #[test]
    fn collects_synced_versions_from_the_state_dir() {
        let temp = tempfile::tempdir().unwrap();
        let nested = temp.path().join("backups/20261109T021650Z/shared");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("prompt.md"), "v1\n").unwrap();
        assert_eq!(synced_versions(temp.path()), vec![b"v1\n".to_vec()]);
    }
}
