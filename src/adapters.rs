//! Client adapters: put the synced prompt where each installed coding agent
//! reads its global instructions.
//!
//! One authoritative prompt is copied to every detected client file. The old
//! file is backed up next to itself (`<name>.<UTC stamp>.bak`) before it is
//! replaced, so a wrong guess is always recoverable.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};

use crate::client_backups::{synced_versions, BackupStore, Imported};
use crate::config::SyncConfig;
use crate::util::{atomic_write, expand_tilde};

#[derive(Debug, Clone)]
pub struct Adapter {
    /// Short client id used in logs and `status` ("codex", "claude", ...).
    pub id: String,
    /// Instruction file the client reads.
    pub path: PathBuf,
    /// `Some(目标)` 时这个文件不写 prompt 正文，而是写一行 Claude Code 导入语句
    /// `@目标`（目前只有旧版 Cindy 场景下的 `claude` 会用到，目标为 `~/AGENTS.md`）。
    /// Claude Code 会把导入的文件按路径去重，所以同一份 prompt 只加载一次。
    pub import: Option<String>,
}

/// 一次适配要做的全部事情：要写入的客户端文件，以及要移走的旧副本。
#[derive(Debug, Default, Clone)]
pub struct Plan {
    /// 需要写入同步 prompt（或导入语句）的客户端文件。
    pub adapters: Vec<Adapter>,
    /// 以前由 promptsync 写入、现在会造成重复加载的旧位置；
    /// 只有内容确实是同步副本时才会备份后移走，用户自己写的文件保持不动。
    pub retire: Vec<Adapter>,
    /// 旧版本 promptsync 写过、但现在没有任何引擎读取的过期副本
    /// （例如 `CindyGlobal/pi-agent-home/AGENTS.md`）；是同步副本就归档，否则不动也不告警。
    pub stale: Vec<Adapter>,
}

/// `sync.cindy_pi` 的取值：决定 Cindy 的 Pi 任务从哪个文件读取同步的 prompt。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CindyPiMode {
    /// 检查本机 Cindy 应用是否支持 Pi 全局指令目录，再自动选择。
    Auto,
    /// 强制写 `<PI_CODING_AGENT_DIR|~/.pi/agent>/AGENTS.md`。
    PiAgent,
    /// 强制写 `~/AGENTS.md`。
    Home,
}

impl CindyPiMode {
    /// 解析配置值。
    ///
    /// 参数 `raw` 是配置文件里 `sync.cindy_pi` 的原文，忽略大小写和首尾空格，
    /// 空字符串按 `auto` 处理；无法识别时返回 `None`（`Config::validate` 据此报错）。
    /// 调用示例：`CindyPiMode::parse("pi-agent") == Some(CindyPiMode::PiAgent)`。
    pub fn parse(raw: &str) -> Option<Self> {
        // 统一转成小写后再比较，允许用户写成 "Auto" / " HOME " 等形式。
        match raw.trim().to_ascii_lowercase().as_str() {
            // 空值和 auto 都表示自动检测。
            "" | "auto" => Some(Self::Auto),
            // pi-agent 表示 Pi 的全局 agent 目录。
            "pi-agent" => Some(Self::PiAgent),
            // home 表示家目录下的 AGENTS.md。
            "home" => Some(Self::Home),
            // 其他取值一律视为配置错误。
            _ => None,
        }
    }
}

/// Cindy 的 Pi 任务最终从哪里读取同步的 prompt。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiPlacement {
    /// 新版 Cindy（0.1.129 实测）启动 Pi 任务时，会把
    /// `<PI_CODING_AGENT_DIR|~/.pi/agent>/AGENTS.md` 复制进任务的临时 agent 目录。
    AgentDir,
    /// 旧版 Cindy 不读 Pi 全局目录，只能靠 Pi 读取工作目录及所有父目录的
    /// AGENTS.md，也就是写 `~/AGENTS.md`。
    HomeAncestor,
}

#[derive(Debug, Default, Clone)]
pub struct AdaptReport {
    /// `(id, path, backup)` for every file that actually changed.
    pub written: Vec<(String, PathBuf, Option<PathBuf>)>,
    /// Files that already contained the prompt.
    pub unchanged: Vec<(String, PathBuf)>,
    /// Files that could not be written; sync itself still succeeds.
    pub failed: Vec<(String, PathBuf, String)>,
    /// `(id, 旧路径, 备份路径)`：被备份后移走的旧同步副本（避免重复加载）。
    pub retired: Vec<(String, PathBuf, PathBuf)>,
    /// `(id, 旧路径)`：旧位置上有文件，但内容不是同步副本，所以没有动它；
    /// 对应的引擎可能会读到两份指令，需要用户自己确认。
    pub kept: Vec<(String, PathBuf)>,
    /// 从客户端目录迁入集中备份库的旧 `.bak` 文件：`(原路径, 导入后的记录)`。
    pub migrated: Imported,
}

impl AdaptReport {
    pub fn is_empty(&self) -> bool {
        self.written.is_empty()
            && self.unchanged.is_empty()
            && self.failed.is_empty()
            && self.retired.is_empty()
            && self.kept.is_empty()
            && self.migrated.is_empty()
    }

    /// True when a file was written, retired, migrated or failed; `unchanged` alone is quiet.
    pub fn has_changes(&self) -> bool {
        !self.written.is_empty()
            || !self.failed.is_empty()
            || !self.retired.is_empty()
            || !self.migrated.is_empty()
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
        if !self.retired.is_empty() {
            // 列出被移走的旧路径，方便用户知道哪个文件去了哪里。
            let retired = self
                .retired
                .iter()
                .map(|(id, path, _)| format!("{id}: {}", path.display()))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!(
                "{} duplicate retired ({retired})",
                self.retired.len()
            ));
        }
        if !self.kept.is_empty() {
            parts.push(format!("{} duplicate kept", self.kept.len()));
        }
        if !self.migrated.is_empty() {
            // 旧的同目录备份迁入了集中备份库。
            parts.push(format!(
                "{} old backup file(s) moved into the backup store",
                self.migrated.len()
            ));
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

/// Detect the clients installed on this machine plus any `sync.adapt_paths`,
/// minus the ids listed in `sync.adapt_exclude`.
pub fn detect(config: &SyncConfig) -> Vec<Adapter> {
    plan(config).adapters
}

/// 计算本机的完整适配计划（要写哪些文件、要移走哪些旧副本）。
///
/// 参数 `config` 是 `[sync]` 配置；只读取文件系统，不做任何修改。
/// 调用示例：`let plan = adapters::plan(&config.sync);`
pub fn plan(config: &SyncConfig) -> Plan {
    match dirs::home_dir() {
        Some(home) => {
            // Cindy 的 owners 目录，用来找伙伴的 SOUL.md。
            let owners = crate::config::cindy_owners_root();
            // 只有在真的需要自动判断时才去检查 Cindy 应用（读一个大文件）。
            let supported = || cindy_reads_pi_agent_dir(&home);
            plan_with_roots(config, &home, owners.parent(), Some(&owners), supported)
        }
        None => Plan::default(),
    }
}

/// Detection with explicit roots so tests never touch the real machine.
///
/// `home` is the user's home directory, `cindy_global` the `CindyGlobal`
/// directory (None = Cindy not considered) and `cindy_owners` its `owners`
/// directory used to find bot `SOUL.md` files. `pi_agent_supported` answers
/// whether the installed Cindy copies the Pi global agent dir into its tasks;
/// it is only called for `sync.cindy_pi = "auto"` when Cindy is installed.
fn plan_with_roots(
    config: &SyncConfig,
    home: &Path,
    cindy_global: Option<&Path>,
    cindy_owners: Option<&Path>,
    pi_agent_supported: impl FnOnce() -> bool,
) -> Plan {
    let mut adapters = Vec::new();
    let mut seen = BTreeSet::new();
    // 需要检查并可能移走的旧副本。
    let mut retire = Vec::new();
    // 不再被任何引擎读取的过期副本。
    let mut stale = Vec::new();

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
    // Gemini CLI (`~/.gemini/GEMINI.md`).
    push_client(
        &mut adapters,
        &mut seen,
        "gemini",
        home.join(".gemini"),
        "GEMINI.md",
    );
    // Qwen Code (`~/.qwen/QWEN.md`).
    push_client(
        &mut adapters,
        &mut seen,
        "qwen",
        home.join(".qwen"),
        "QWEN.md",
    );
    // opencode (`$XDG_CONFIG_HOME/opencode/AGENTS.md`, default ~/.config).
    push_client(
        &mut adapters,
        &mut seen,
        "opencode",
        env_dir("XDG_CONFIG_HOME")
            .unwrap_or_else(|| home.join(".config"))
            .join("opencode"),
        "AGENTS.md",
    );

    // Cindy runs Codex with CODEX_HOME=CindyGlobal/codex-home and copies
    // ~/.codex/AGENTS.md there only when the app starts. Writing the copy too
    // lets new Cindy Codex tasks see an update without restarting Cindy.
    if let Some(global) = cindy_global {
        push_client(
            &mut adapters,
            &mut seen,
            "cindy-codex",
            global.join("codex-home"),
            "AGENTS.md",
        );
    }

    // Pi 的全局 agent 目录：`$PI_CODING_AGENT_DIR` 或 `~/.pi/agent`。
    // 在 Cindy 任务里运行时这个变量指向一次性的 run-tmp 目录，不能用。
    let pi_agent_file = env_dir("PI_CODING_AGENT_DIR")
        .filter(|dir| !dir.to_string_lossy().contains("CindyGlobal"))
        .unwrap_or_else(|| home.join(".pi").join("agent"))
        .join("AGENTS.md");
    // 家目录下的 AGENTS.md：Pi、Claude Code、opencode 等都会沿父目录读到它。
    let home_agents = home.join("AGENTS.md");
    // 有 pi-agent-home 目录说明本机 Cindy 跑过 Pi 任务。
    let cindy_pi = cindy_global
        .map(|global| global.join("pi-agent-home").is_dir())
        .unwrap_or(false);
    // 记录 Cindy Pi 最终采用的位置，后面决定是否给 Claude Code 写导入语句。
    let mut placement = None;
    if cindy_pi {
        // 配置无效时按 auto 处理（validate 已经拦截过，这里只是兜底）。
        let mode = CindyPiMode::parse(&config.cindy_pi).unwrap_or(CindyPiMode::Auto);
        let chosen = match mode {
            CindyPiMode::PiAgent => PiPlacement::AgentDir,
            CindyPiMode::Home => PiPlacement::HomeAncestor,
            // 自动模式：Cindy 支持 Pi 全局目录就用它，否则退回家目录。
            CindyPiMode::Auto if pi_agent_supported() => PiPlacement::AgentDir,
            CindyPiMode::Auto => PiPlacement::HomeAncestor,
        };
        // 选中的位置写 prompt，另一个位置上的同步旧副本要移走：
        // Pi 两处都会读，留着就会加载两份。
        let (target, legacy) = match chosen {
            PiPlacement::AgentDir => (pi_agent_file.clone(), home_agents.clone()),
            PiPlacement::HomeAncestor => (home_agents.clone(), pi_agent_file.clone()),
        };
        push_unique(&mut adapters, &mut seen, "cindy-pi".to_string(), target);
        retire.push(Adapter {
            id: "cindy-pi".to_string(),
            path: legacy,
            import: None,
        });
        placement = Some(chosen);
        // promptsync 0.4.0 及更早版本写过 pi-agent-home/AGENTS.md，但 Cindy 的 Pi 任务
        // 使用每个任务单独的临时目录，从来不读它；留着只会让人误以为它在生效。
        if let Some(global) = cindy_global {
            stale.push(Adapter {
                id: "cindy-pi".to_string(),
                path: global.join("pi-agent-home").join("AGENTS.md"),
                import: None,
            });
        }
    } else {
        // Standalone Pi (`$PI_CODING_AGENT_DIR` or ~/.pi/agent).
        if let Some(dir) = pi_agent_file.parent() {
            push_client(
                &mut adapters,
                &mut seen,
                "pi",
                dir.to_path_buf(),
                "AGENTS.md",
            );
        }
    }

    // Cindy bot persona (used by teammate/IM conversations).
    if let Some(path) = cindy_owners.and_then(cindy_prompt_under) {
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

    // 判断某个 id 是否被 `sync.adapt_exclude` 关掉（忽略大小写和空格）。
    let excluded = |id: &str| {
        config
            .adapt_exclude
            .iter()
            .any(|excluded| excluded.trim().eq_ignore_ascii_case(id))
    };
    // `sync.adapt_exclude` switches individual clients off by id.
    adapters.retain(|adapter| !excluded(&adapter.id));
    // 被排除的客户端连旧副本也不碰；仍然要写入的路径（例如 adapt_paths
    // 显式列出的文件）当然也不能移走。
    retire.retain(|old| !excluded(&old.id) && !seen_in(&adapters, &old.path));
    stale.retain(|old| !excluded(&old.id) && !seen_in(&adapters, &old.path));

    // 旧版 Cindy 只能写 ~/AGENTS.md，而 Claude Code 在项目没有 CLAUDE.md 时
    // 也会读父目录的 AGENTS.md。让 ~/.claude/CLAUDE.md 导入同一个文件：
    // Claude Code 按路径去重，最终只加载一份；项目自带 CLAUDE.md、或者
    // 工作目录不在家目录下时，也照样能通过导入读到 prompt。
    let home_pi_active = placement == Some(PiPlacement::HomeAncestor)
        && adapters
            .iter()
            .any(|adapter| adapter.id == "cindy-pi" && adapter.path == home_agents);
    if home_pi_active {
        for adapter in adapters.iter_mut().filter(|adapter| adapter.id == "claude") {
            adapter.import = Some("~/AGENTS.md".to_string());
        }
    }

    Plan {
        adapters,
        retire,
        stale,
    }
}

/// 判断 `path` 是否已经在写入列表里；参数 `adapters` 为写入列表。
fn seen_in(adapters: &[Adapter], path: &Path) -> bool {
    adapters.iter().any(|adapter| adapter.path == path)
}

/// 新版 Cindy 应用代码里才有的函数名：它读取 Pi 全局指令目录
/// （`AGENTS.override.md` / `AGENTS.md` / `CLAUDE.md` 取第一个）并复制进每个 Pi 任务。
const CINDY_PI_GLOBAL_CONTEXT_MARKER: &[u8] = b"readPiGlobalContext";

/// 本机安装的 Cindy 是否会把 Pi 全局 agent 目录的指令带进任务。
///
/// 参数 `home` 为家目录（用于 `~/Applications`）。找不到 Cindy 应用、或读取失败时
/// 返回 false，此时退回 `~/AGENTS.md` + Claude Code 导入的方式，依旧不会重复加载。
/// 调用示例：`if cindy_reads_pi_agent_dir(&home) { ... }`
fn cindy_reads_pi_agent_dir(home: &Path) -> bool {
    cindy_app_archives(home)
        .iter()
        // 只看第一个真实存在的应用包。
        .find(|archive| archive.is_file())
        .and_then(|archive| archive_has_marker(archive))
        .unwrap_or(false)
}

/// 各平台 Cindy 应用代码包（Electron `app.asar`）的常见安装位置。
///
/// 参数 `home` 为家目录；返回按优先级排列的候选路径，不保证存在。
fn cindy_app_archives(home: &Path) -> Vec<PathBuf> {
    let mut archives = Vec::new();
    if cfg!(target_os = "macos") {
        // 系统级和用户级 Applications 目录。
        for apps in [PathBuf::from("/Applications"), home.join("Applications")] {
            archives.push(apps.join("Cindy.app/Contents/Resources/app.asar"));
        }
    } else if cfg!(windows) {
        // 用户级安装（默认）与全局安装。
        for (var, sub) in [
            ("LOCALAPPDATA", "Programs/Cindy"),
            ("ProgramFiles", "Cindy"),
        ] {
            if let Some(base) = env_dir(var) {
                archives.push(base.join(sub).join("resources").join("app.asar"));
            }
        }
    } else {
        // Linux 安装包的常见目录。
        for dir in [
            "/opt/Cindy",
            "/opt/cindy",
            "/usr/lib/cindy",
            "/usr/share/cindy",
        ] {
            archives.push(Path::new(dir).join("resources/app.asar"));
        }
    }
    archives
}

/// 检查结果缓存：`(路径, 大小, 修改时间, 是否包含标识)`。
/// 应用包约 200 MB，只在 Cindy 升级（大小或修改时间变化）后重新扫描。
type MarkerCache = Vec<(PathBuf, u64, Option<std::time::SystemTime>, bool)>;

/// 判断应用包里是否有 `CINDY_PI_GLOBAL_CONTEXT_MARKER`。
///
/// 参数 `archive` 为 `app.asar` 路径；无法读取时返回 `None`。结果按大小和修改时间缓存。
fn archive_has_marker(archive: &Path) -> Option<bool> {
    // 进程内共享的缓存（agent 常驻，每次适配都会用到）。
    static CACHE: OnceLock<Mutex<MarkerCache>> = OnceLock::new();
    // 读取文件元数据，作为缓存是否有效的依据。
    let metadata = fs::metadata(archive).ok()?;
    // 文件大小。
    let len = metadata.len();
    // 修改时间（个别文件系统不支持时为 None）。
    let modified = metadata.modified().ok();
    // 取出缓存；锁中毒时继续使用里面的数据。
    let cache = CACHE.get_or_init(|| Mutex::new(Vec::new()));
    if let Some(hit) = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|(path, size, time, _)| path == archive && *size == len && *time == modified)
    {
        // 应用包没变，直接返回上次的结论。
        return Some(hit.3);
    }
    // 流式扫描整个文件，不一次性读进内存。
    let found = fs::File::open(archive)
        .and_then(|file| stream_contains(file, CINDY_PI_GLOBAL_CONTEXT_MARKER))
        .ok()?;
    // 写回缓存：同一路径只保留最新一条。
    let mut entries = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.retain(|(path, _, _, _)| path != archive);
    entries.push((archive.to_path_buf(), len, modified, found));
    Some(found)
}

/// 在数据流里查找一段字节，找到即返回 true。
///
/// 参数 `reader` 为任意可读对象，`needle` 为要找的字节串（非空）。按 1 MiB 分块读取，
/// 块与块之间保留 `needle.len() - 1` 字节，跨块的匹配也不会漏掉。
/// 调用示例：`stream_contains(File::open(p)?, b"marker")?`
fn stream_contains(mut reader: impl Read, needle: &[u8]) -> std::io::Result<bool> {
    // 空串视为总能找到，避免下面的 windows(0) 出错。
    if needle.is_empty() {
        return Ok(true);
    }
    // 分块大小再加上重叠区。
    let mut buffer = vec![0u8; (1 << 20) + needle.len()];
    // 缓冲区开头保留的上一块尾部字节数。
    let mut carry = 0usize;
    loop {
        // 读到缓冲区的剩余部分。
        let read = reader.read(&mut buffer[carry..])?;
        // 读完了还没找到。
        if read == 0 {
            return Ok(false);
        }
        // 当前缓冲区中有效数据的长度。
        let filled = carry + read;
        // 在有效数据里查找。
        if buffer[..filled]
            .windows(needle.len())
            .any(|window| window == needle)
        {
            return Ok(true);
        }
        // 把末尾 needle.len()-1 字节挪到开头，与下一块拼接。
        let keep = (needle.len() - 1).min(filled);
        buffer.copy_within(filled - keep..filled, 0);
        carry = keep;
    }
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
        adapters.push(Adapter {
            id,
            path,
            import: None,
        });
    }
}

/// Cindy keeps one prompt per bot under `owners/<owner>/bots/<bot>/SOUL.md`.
/// Prefer the local `cindy-default` bot, then the newest prompt. `root` is the
/// `owners` directory.
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
/// used as a fallback. `data_dir` is the state directory that holds the central
/// backup store (`<data_dir>/client-backups`).
pub fn apply_bundle(
    config: &SyncConfig,
    entries: &BTreeMap<String, Vec<u8>>,
    target: &str,
    data_dir: &Path,
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
    apply_content(config, content, data_dir)
}

/// Adapt every detected client to one prompt (also used by the Feishu control
/// channel, where the prompt comes from a private message).
///
/// 参数 `data_dir` 为状态目录，旧内容统一备份到 `<data_dir>/client-backups`。
/// 写完全部客户端文件、且没有任何失败后，再把会造成重复加载的旧同步副本
/// 备份移走（先写后移，任何一步失败都不会让某个引擎丢掉 prompt）。
pub fn apply_content(config: &SyncConfig, content: &[u8], data_dir: &Path) -> AdaptReport {
    if !config.adapt_clients {
        return AdaptReport::default();
    }
    // 先算好本机的适配计划，再按计划执行。
    apply_plan(config, plan(config), content, data_dir)
}

/// 预览迁移：列出客户端目录里还留着的旧 `<文件名>.<时间>.bak`，以及导入后的类别。
///
/// 参数：`config` 为 `[sync]` 配置；`data_dir` 为状态目录。只读，不改动任何文件。
/// 调用示例：`for (old, entry) in adapters::pending_migration(&config.sync, &dir) { ... }`
pub fn pending_migration(config: &SyncConfig, data_dir: &Path) -> Imported {
    let plan = plan(config);
    let store = BackupStore::new(data_dir);
    // 判定“原始文件”用的已知同步版本（演练时没有本次 prompt，用现有客户端内容代替）。
    let known = known_versions(&plan, None, data_dir);
    let mut pending = Vec::new();
    for (id, path) in migration_targets(&plan) {
        if let Ok(found) = store.import_legacy(&id, &path, &known, config.keep_backups, true) {
            pending.extend(found);
        }
    }
    pending
}

/// 需要检查旧备份的全部文件：要写入的、要移走的和过期的。参数 `plan` 为适配计划。
fn migration_targets(plan: &Plan) -> Vec<(String, PathBuf)> {
    plan.adapters
        .iter()
        .chain(&plan.retire)
        .chain(&plan.stale)
        .map(|adapter| (adapter.id.clone(), adapter.path.clone()))
        .collect()
}

/// 已知的同步 prompt 版本：本次 prompt、各客户端文件当前（写入前）的内容、
/// 以及状态目录 `backups/` 里保存过的同步文件。
///
/// 参数：`plan` 适配计划；`content` 本次 prompt（预览时为 None）；`data_dir` 状态目录。
fn known_versions(plan: &Plan, content: Option<&[u8]>, data_dir: &Path) -> Vec<Vec<u8>> {
    let mut known: Vec<Vec<u8>> = content.map(<[u8]>::to_vec).into_iter().collect();
    for adapter in &plan.adapters {
        // 导入语句文件里没有 prompt 正文，不作为判定依据。
        if adapter.import.is_some() {
            continue;
        }
        // 读不到（不存在等）就跳过；空文件不算副本。
        if let Ok(previous) = fs::read(&adapter.path) {
            if !previous.is_empty() && !known.contains(&previous) {
                known.push(previous);
            }
        }
    }
    for version in synced_versions(data_dir) {
        if !known.contains(&version) {
            known.push(version);
        }
    }
    known
}

/// 按给定计划写入客户端文件并移走旧副本（测试可直接传入临时目录里的计划）。
///
/// 参数：`config` 提供备份保留份数；`plan` 为 `plan()` 的结果；`content` 为 prompt 正文；
/// `data_dir` 为状态目录（集中备份库所在位置）。
fn apply_plan(config: &SyncConfig, plan: Plan, content: &[u8], data_dir: &Path) -> AdaptReport {
    let mut report = AdaptReport::default();
    // 集中备份库。
    let store = BackupStore::new(data_dir);
    // “同步副本”的判定依据（见 known_versions）。
    let known = known_versions(&plan, Some(content), data_dir);

    // 第一步：把旧版本留在客户端目录里的 .bak 迁入备份库。
    for (id, path) in migration_targets(&plan) {
        match store.import_legacy(&id, &path, &known, config.keep_backups, false) {
            Ok(found) => report.migrated.extend(found),
            Err(err) => report.failed.push((id, path, format!("{err:#}"))),
        }
    }

    // 第二步：写入各客户端文件。
    for adapter in plan.adapters {
        // 普通客户端写 prompt 正文，需要导入的写导入语句。
        let body = match &adapter.import {
            Some(target) => import_body(target),
            None => content.to_vec(),
        };
        match write_one(
            &adapter.id,
            &adapter.path,
            &body,
            &known,
            &store,
            config.keep_backups,
        ) {
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
    // 有写入失败时先不移旧副本：旧位置可能是某个引擎此刻唯一能读到的 prompt。
    if !report.failed.is_empty() {
        return report;
    }

    // 第三步：移走会造成重复加载的旧同步副本，以及不再被读取的过期副本。
    let retire = plan.retire.into_iter().map(|old| (old, true));
    let stale = plan.stale.into_iter().map(|old| (old, false));
    for (old, loaded_by_engine) in retire.chain(stale) {
        match retire_one(&old.id, &old.path, &known, &store, config.keep_backups) {
            // 旧副本已备份移走。
            Ok(RetireOutcome::Retired(backup)) => {
                report.retired.push((old.id, old.path, backup));
            }
            // 用户自己的文件，保持不动；只有会被引擎读到的才需要提示。
            Ok(RetireOutcome::Kept) if loaded_by_engine => report.kept.push((old.id, old.path)),
            Ok(RetireOutcome::Kept) | Ok(RetireOutcome::Absent) => {}
            Err(err) => report.failed.push((old.id, old.path, format!("{err:#}"))),
        }
    }
    report
}

/// 生成 Claude Code 导入语句文件的内容。
///
/// 参数 `target` 为被导入的文件（如 `~/AGENTS.md`）。第一行是给人看的说明
/// （HTML 注释），第二行 `@目标` 是 Claude Code 的导入语法。
fn import_body(target: &str) -> Vec<u8> {
    format!(
        "<!-- promptsync: Cindy 的 Pi 任务读取 {target}，Claude Code 也会读到它；这里只导入同一个文件，避免同一份 prompt 加载两次。 -->\n@{target}\n"
    )
    .into_bytes()
}

/// 移走旧副本的结果。
#[derive(Debug)]
enum RetireOutcome {
    /// 旧位置没有文件。
    Absent,
    /// 内容是同步副本，已存入备份库并删除原文件（值为备份库里的内容文件）。
    Retired(PathBuf),
    /// 内容不是同步副本（用户自己写的），没有改动。
    Kept,
}

/// 把会造成重复加载（或已经过期）的旧同步副本存入备份库后删除。
///
/// 参数：`id` 客户端 id；`path` 旧位置；`known` 视为同步副本的内容列表；
/// `store` 集中备份库；`keep_backups` 每个文件保留的备份份数（0 = 全部保留）。
fn retire_one(
    id: &str,
    path: &Path,
    known: &[Vec<u8>],
    store: &BackupStore,
    keep_backups: usize,
) -> Result<RetireOutcome> {
    // 读取旧文件内容；不存在就什么都不做。
    let existing = match fs::read(path) {
        Ok(existing) => existing,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RetireOutcome::Absent);
        }
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    // 不是 promptsync 写入的内容，绝不动用户文件。
    if !known.contains(&existing) {
        return Ok(RetireOutcome::Kept);
    }
    // 先存进备份库……
    let backup = store.retire(id, path, &existing, keep_backups)?;
    // ……确认备份成功后再删除原文件。
    fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    Ok(RetireOutcome::Retired(backup))
}

#[derive(Debug)]
enum WriteOutcome {
    /// The file already contained exactly this prompt.
    Unchanged,
    /// The file was created or replaced; the backup (a file in the central
    /// store) is `None` for a new file.
    Written(Option<PathBuf>),
}

/// 写入一个客户端文件，覆盖前把旧内容存进集中备份库。
///
/// 参数：`id` 客户端 id；`path` 目标文件；`content` 要写入的内容；
/// `known` 已知的同步 prompt 版本（旧内容在其中时不算原始文件）；
/// `store` 集中备份库；`keep_backups` 每个文件保留的备份份数。
fn write_one(
    id: &str,
    path: &Path,
    content: &[u8],
    known: &[Vec<u8>],
    store: &BackupStore,
    keep_backups: usize,
) -> Result<WriteOutcome> {
    let existing = match fs::read(path) {
        Ok(existing) => Some(existing),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("reading {}", path.display()));
        }
    };
    if existing.as_deref() == Some(content) {
        // 内容相同也记一次“已接管”（只在第一次写清单），以后覆盖时不会误判为原始文件。
        store.mark_created(path)?;
        return Ok(WriteOutcome::Unchanged);
    }

    let backup = match existing.as_ref() {
        // 旧文件存在：先备份进备份库。
        Some(old) => Some(store.backup(id, path, old, keep_backups, known.contains(old))?),
        // 旧文件不存在：记下这是 promptsync 新建的文件。
        None => {
            store.mark_created(path)?;
            None
        }
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
        let adapters = plan_with_roots(&config, home, None, None, || false).adapters;
        let ids: Vec<&str> = adapters.iter().map(|adapter| adapter.id.as_str()).collect();
        for expected in ["kimi", "deepseek", "codex", "claude", "agents"] {
            assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
        }
        assert!(adapters.iter().any(|adapter| adapter.path == extra));
    }

    /// 测试用的状态目录（集中备份库所在位置），与 home 并列；参数 `home` 为临时家目录。
    fn state_dir(home: &Path) -> PathBuf {
        home.parent().unwrap().join("state")
    }

    /// 列出某目录里所有 `.bak` 文件名；参数 `dir` 为要检查的目录。
    fn sibling_baks(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.ends_with(".bak"))
            .collect()
    }

    /// 建一套临时的家目录 + CindyGlobal 目录；返回 (临时目录守卫, home, CindyGlobal)。
    /// 参数 `client_dirs` 为家目录下要创建的客户端目录（表示这些客户端已安装）。
    fn cindy_fixture(client_dirs: &[&str]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let global = temp.path().join("CindyGlobal");
        for dir in client_dirs {
            fs::create_dir_all(home.join(dir)).unwrap();
        }
        // pi-agent-home 表示 Cindy 跑过 Pi 任务；codex-home 表示 Cindy 的 Codex 任务。
        for dir in [
            "codex-home",
            "pi-agent-home",
            "owners/o1/bots/cindy-default",
        ] {
            fs::create_dir_all(global.join(dir)).unwrap();
        }
        fs::write(global.join("owners/o1/bots/cindy-default/SOUL.md"), "soul").unwrap();
        (temp, home, global)
    }

    /// 新版 Cindy：Pi 任务读 ~/.pi/agent/AGENTS.md，家目录的旧副本要移走，
    /// Claude Code 继续写完整 prompt，独立 Pi 与 Cindy Pi 共用同一个文件。
    #[test]
    fn new_cindy_reads_the_pi_agent_dir_and_retires_home_agents() {
        let (_temp, home, global) =
            cindy_fixture(&[".claude", ".gemini", ".qwen", ".config/opencode"]);
        let config = SyncConfig::default();
        let plan = plan_with_roots(
            &config,
            &home,
            Some(&global),
            Some(&global.join("owners")),
            || true,
        );
        let find = |id: &str| plan.adapters.iter().find(|adapter| adapter.id == id);
        assert_eq!(
            find("cindy-pi").unwrap().path,
            home.join(".pi/agent/AGENTS.md")
        );
        assert!(
            find("claude").unwrap().import.is_none(),
            "claude keeps the full prompt"
        );
        assert!(
            find("pi").is_none(),
            "standalone pi shares the cindy-pi file"
        );
        assert_eq!(
            find("cindy-codex").unwrap().path,
            global.join("codex-home/AGENTS.md")
        );
        assert_eq!(find("gemini").unwrap().path, home.join(".gemini/GEMINI.md"));
        assert_eq!(find("qwen").unwrap().path, home.join(".qwen/QWEN.md"));
        assert!(find("opencode").is_some());
        assert!(find("cindy").is_some());
        assert!(!plan
            .adapters
            .iter()
            .any(|adapter| adapter.path == home.join("AGENTS.md")));
        let retire: Vec<&PathBuf> = plan.retire.iter().map(|old| &old.path).collect();
        assert_eq!(retire, vec![&home.join("AGENTS.md")]);
    }

    /// 旧版 Cindy：只能写 ~/AGENTS.md，Claude Code 改为导入它（按路径去重，只加载一次）。
    #[test]
    fn old_cindy_writes_home_agents_and_claude_imports_it() {
        let (_temp, home, global) = cindy_fixture(&[".claude", ".pi/agent"]);
        let config = SyncConfig::default();
        let plan = plan_with_roots(&config, &home, Some(&global), None, || false);
        let find = |id: &str| plan.adapters.iter().find(|adapter| adapter.id == id);
        assert_eq!(find("cindy-pi").unwrap().path, home.join("AGENTS.md"));
        assert_eq!(
            find("claude").unwrap().import.as_deref(),
            Some("~/AGENTS.md")
        );
        assert!(
            find("pi").is_none(),
            "standalone pi would read the prompt twice"
        );
        let retire: Vec<&PathBuf> = plan.retire.iter().map(|old| &old.path).collect();
        assert_eq!(retire, vec![&home.join(".pi/agent/AGENTS.md")]);
    }

    /// 没装 Cindy：独立 Pi 写自己的全局文件，不检测 Cindy 应用，也没有旧副本要移。
    #[test]
    fn without_cindy_standalone_pi_keeps_its_own_file() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(home.join(".pi/agent")).unwrap();
        fs::create_dir_all(home.join(".claude")).unwrap();
        let plan = plan_with_roots(&SyncConfig::default(), &home, None, None, || {
            panic!("Cindy app must not be inspected when Cindy is not installed")
        });
        assert!(plan
            .adapters
            .iter()
            .any(|adapter| adapter.id == "pi" && adapter.path == home.join(".pi/agent/AGENTS.md")));
        assert!(!plan.adapters.iter().any(|adapter| adapter.id == "cindy-pi"));
        assert!(plan.adapters.iter().all(|adapter| adapter.import.is_none()));
        assert!(plan.retire.is_empty());
    }

    /// `sync.cindy_pi` 显式指定时不再自动检测。
    #[test]
    fn cindy_pi_setting_overrides_detection() {
        let (_temp, home, global) = cindy_fixture(&[".claude"]);
        let forced = |mode: &str| SyncConfig {
            cindy_pi: mode.to_string(),
            ..SyncConfig::default()
        };
        let plan = plan_with_roots(&forced("home"), &home, Some(&global), None, || {
            panic!("detection must be skipped for an explicit mode")
        });
        let pi = plan
            .adapters
            .iter()
            .find(|adapter| adapter.id == "cindy-pi");
        assert_eq!(pi.unwrap().path, home.join("AGENTS.md"));

        let plan = plan_with_roots(&forced(" Pi-Agent "), &home, Some(&global), None, || {
            panic!("detection must be skipped for an explicit mode")
        });
        let pi = plan
            .adapters
            .iter()
            .find(|adapter| adapter.id == "cindy-pi");
        assert_eq!(pi.unwrap().path, home.join(".pi/agent/AGENTS.md"));

        assert_eq!(CindyPiMode::parse(""), Some(CindyPiMode::Auto));
        assert_eq!(CindyPiMode::parse("AUTO"), Some(CindyPiMode::Auto));
        assert_eq!(CindyPiMode::parse("both"), None);
    }

    #[test]
    fn adapt_exclude_switches_clients_off() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let global = temp.path().join("CindyGlobal");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::create_dir_all(global.join("pi-agent-home")).unwrap();
        let config = SyncConfig {
            adapt_exclude: vec!["Cindy-Pi".to_string()],
            ..SyncConfig::default()
        };
        let plan = plan_with_roots(&config, &home, Some(&global), None, || false);
        let ids: Vec<String> = plan
            .adapters
            .iter()
            .map(|adapter| adapter.id.clone())
            .collect();
        assert!(ids.contains(&"claude".to_string()));
        assert!(!ids.contains(&"cindy-pi".to_string()), "{ids:?}");
        // 被排除的客户端：旧副本不碰，Claude Code 也不改成导入一个不再维护的文件。
        assert!(plan.retire.is_empty());
        assert!(plan.adapters.iter().all(|adapter| adapter.import.is_none()));
    }

    /// 端到端：从旧布局（~/AGENTS.md）迁移到新版 Cindy 布局。
    /// 同步副本被备份移走，Claude Code 文件从导入语句恢复成完整 prompt。
    #[test]
    fn migrating_moves_the_synced_home_copy_away() {
        let (_temp, home, global) = cindy_fixture(&[".claude"]);
        let config = SyncConfig::default();
        // 旧布局：~/AGENTS.md 是上一版 prompt，CLAUDE.md 是导入语句。
        fs::write(home.join("AGENTS.md"), "old prompt\n").unwrap();
        fs::write(home.join(".claude/CLAUDE.md"), import_body("~/AGENTS.md")).unwrap();
        // .pi/agent 里留着上一版的副本：写入前的旧内容，用于判定 ~/AGENTS.md 是同步副本。
        fs::create_dir_all(home.join(".pi/agent")).unwrap();
        fs::write(home.join(".pi/agent/AGENTS.md"), "old prompt\n").unwrap();

        let plan = plan_with_roots(&config, &home, Some(&global), None, || true);
        let report = apply_plan(&config, plan, b"new prompt\n", &state_dir(&home));
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert_eq!(
            fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap(),
            "new prompt\n"
        );
        assert_eq!(
            fs::read_to_string(home.join(".pi/agent/AGENTS.md")).unwrap(),
            "new prompt\n"
        );
        assert!(
            !home.join("AGENTS.md").exists(),
            "duplicate must be moved away"
        );
        let (_, old, backup) = &report.retired[0];
        assert_eq!(old, &home.join("AGENTS.md"));
        assert_eq!(fs::read_to_string(backup).unwrap(), "old prompt\n");
        assert!(report.summary().contains("duplicate retired"));
        // 备份全部在集中备份库里，客户端目录和家目录不再出现 .bak。
        assert!(backup.starts_with(state_dir(&home).join(crate::client_backups::DIR_NAME)));
        assert!(sibling_baks(&home).is_empty(), "{:?}", sibling_baks(&home));
        assert!(sibling_baks(&home.join(".claude")).is_empty());
        assert!(sibling_baks(&home.join(".pi/agent")).is_empty());

        // 再跑一次：一切不变，不会再产生备份。
        let plan = plan_with_roots(&config, &home, Some(&global), None, || true);
        let report = apply_plan(&config, plan, b"new prompt\n", &state_dir(&home));
        assert!(!report.has_changes(), "{}", report.summary());
    }

    /// 旧位置是用户自己写的文件：保持原样，只报告。
    #[test]
    fn a_user_written_duplicate_is_kept() {
        let (_temp, home, global) = cindy_fixture(&[".claude"]);
        let config = SyncConfig::default();
        fs::write(home.join("AGENTS.md"), "my own notes\n").unwrap();
        let plan = plan_with_roots(&config, &home, Some(&global), None, || true);
        let report = apply_plan(&config, plan, b"prompt\n", &state_dir(&home));
        assert_eq!(
            fs::read_to_string(home.join("AGENTS.md")).unwrap(),
            "my own notes\n"
        );
        assert_eq!(
            report.kept,
            vec![("cindy-pi".to_string(), home.join("AGENTS.md"))]
        );
        assert!(report.retired.is_empty());
    }

    /// 旧版 Cindy：CLAUDE.md 写成导入语句，~/AGENTS.md 写正文。
    #[test]
    fn old_cindy_layout_is_written_with_an_import() {
        let (_temp, home, global) = cindy_fixture(&[".claude"]);
        let config = SyncConfig::default();
        let plan = plan_with_roots(&config, &home, Some(&global), None, || false);
        let report = apply_plan(&config, plan, b"prompt\n", &state_dir(&home));
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert_eq!(
            fs::read_to_string(home.join("AGENTS.md")).unwrap(),
            "prompt\n"
        );
        let claude = fs::read_to_string(home.join(".claude/CLAUDE.md")).unwrap();
        assert!(claude.ends_with("\n@~/AGENTS.md\n"), "{claude}");
        assert!(!claude.contains("prompt\n@"), "no prompt body in CLAUDE.md");
    }

    /// 跨分块边界的标识也能找到。
    #[test]
    fn finds_a_marker_across_chunk_boundaries() {
        let needle = CINDY_PI_GLOBAL_CONTEXT_MARKER;
        // 让标识正好跨过第一次读取的缓冲区末尾。
        let split = (1 << 20) + needle.len() - 3;
        let mut data = vec![b'x'; split];
        data.extend_from_slice(needle);
        data.extend_from_slice(b"tail");
        assert!(stream_contains(std::io::Cursor::new(&data), needle).unwrap());
        let missing = vec![b'x'; 3 << 20];
        assert!(!stream_contains(std::io::Cursor::new(&missing), needle).unwrap());
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

    /// 覆盖前把旧内容存进集中备份库（第一次接管记为原始文件），内容相同则跳过。
    #[test]
    fn backs_up_into_the_store_and_skips_identical_content() {
        let temp = tempfile::tempdir().unwrap();
        let store = BackupStore::new(&temp.path().join("state"));
        let path = temp.path().join("CLAUDE.md");
        fs::write(&path, "my own rules\n").unwrap();

        let backup = match write_one("claude", &path, b"new prompt\n", &[], &store, 5).unwrap() {
            WriteOutcome::Written(Some(backup)) => backup,
            other => panic!("expected a written file with a backup, got {other:?}"),
        };
        assert_eq!(fs::read_to_string(&path).unwrap(), "new prompt\n");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "my own rules\n");
        assert!(backup.starts_with(store.root()));
        assert!(
            sibling_baks(temp.path()).is_empty(),
            "no .bak next to the file"
        );
        assert_eq!(
            store.entries()[0].kind,
            crate::client_backups::Kind::Original
        );

        assert!(matches!(
            write_one("claude", &path, b"new prompt\n", &[], &store, 5).unwrap(),
            WriteOutcome::Unchanged
        ));
        // 再次覆盖：记为被替换，原始文件仍在。
        write_one("claude", &path, b"newer prompt\n", &[], &store, 5).unwrap();
        let kinds: Vec<_> = store.entries().iter().map(|entry| entry.kind).collect();
        assert_eq!(
            kinds,
            vec![
                crate::client_backups::Kind::Original,
                crate::client_backups::Kind::Replaced
            ]
        );
    }

    /// 新建的文件没有备份，之后的覆盖也不会被当作原始文件。
    #[test]
    fn creates_missing_files_without_a_backup() {
        let temp = tempfile::tempdir().unwrap();
        let store = BackupStore::new(&temp.path().join("state"));
        let path = temp.path().join("nested/AGENTS.md");
        assert!(matches!(
            write_one("codex", &path, b"first\n", &[], &store, 5).unwrap(),
            WriteOutcome::Written(None)
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1,
            "no backup for a file that did not exist"
        );
        write_one("codex", &path, b"second\n", &[], &store, 5).unwrap();
        assert_eq!(
            store.entries()[0].kind,
            crate::client_backups::Kind::Replaced
        );
    }

    /// 端到端：旧版本留下的同目录 .bak 和过期的 pi-agent-home/AGENTS.md 都被迁入备份库。
    #[test]
    fn migrates_old_sibling_backups_and_archives_the_stale_pi_agent_home_file() {
        let (_temp, home, global) = cindy_fixture(&[".claude"]);
        let config = SyncConfig::default();
        let claude = home.join(".claude/CLAUDE.md");
        fs::write(&claude, "prompt\n").unwrap();
        // 用户原始文件 + 一份同步过的旧版本，按旧规则放在 CLAUDE.md 旁边。
        fs::write(
            home.join(".claude/CLAUDE.md.20261108T122841Z.bak"),
            "mine\n",
        )
        .unwrap();
        fs::write(
            home.join(".claude/CLAUDE.md.20261109T021650.969695000Z.bak"),
            "old prompt\n",
        )
        .unwrap();
        // 状态目录 backups/ 里存着同步过的旧版本，证明 "old prompt" 不是用户原始文件。
        let synced = state_dir(&home).join("backups/20261109T021650Z/shared");
        fs::create_dir_all(&synced).unwrap();
        fs::write(synced.join("prompt.md"), "old prompt\n").unwrap();
        // 过期副本：Cindy 从来不读的 pi-agent-home/AGENTS.md。
        let stale = global.join("pi-agent-home/AGENTS.md");
        fs::write(&stale, "old prompt\n").unwrap();

        let plan = plan_with_roots(&config, &home, Some(&global), None, || true);
        let report = apply_plan(&config, plan, b"prompt\n", &state_dir(&home));
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert_eq!(report.migrated.len(), 2);
        assert!(sibling_baks(&home.join(".claude")).is_empty());
        assert!(!stale.exists(), "stale copy archived");
        assert!(report.kept.is_empty(), "stale files never warn");

        let store = BackupStore::new(&state_dir(&home));
        let entries = store.entries();
        let original = entries
            .iter()
            .find(|entry| entry.kind == crate::client_backups::Kind::Original)
            .unwrap();
        assert_eq!(original.path, claude.display().to_string());
        assert_eq!(
            fs::read_to_string(store.blob_path(original)).unwrap(),
            "mine\n"
        );
        assert!(entries.iter().any(|entry| {
            entry.kind == crate::client_backups::Kind::Retired
                && entry.path == stale.display().to_string()
        }));
    }

    /// 过期位置上是用户自己的内容：不动，也不告警。
    #[test]
    fn a_user_file_in_a_stale_location_is_left_alone_quietly() {
        let (_temp, home, global) = cindy_fixture(&[".claude"]);
        let config = SyncConfig::default();
        let stale = global.join("pi-agent-home/AGENTS.md");
        fs::write(&stale, "hand written\n").unwrap();
        let plan = plan_with_roots(&config, &home, Some(&global), None, || true);
        let report = apply_plan(&config, plan, b"prompt\n", &state_dir(&home));
        assert_eq!(fs::read_to_string(&stale).unwrap(), "hand written\n");
        assert!(report.kept.is_empty());
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
