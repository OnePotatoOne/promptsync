//! Feishu control channel: first-start binding and the ingest loop that turns
//! private-chat text messages into the one managed prompt file.
//!
//! Messages that start with `--` are commands (see [`crate::commands`]): they
//! are answered with a status view and never touch the managed file.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{set_source_globs, set_value, Config};
use crate::feishu::{self, message_text, FeishuClient};
use crate::globpat;
use crate::logx::Logger;
use crate::paths::Paths;
use crate::prompts::SourceSpec;
use crate::util::{atomic_write, now_unix, safe_relative_path, secure_join};

pub const BINDING_FILE: &str = "feishu-binding.json";
pub const CURSOR_FILE: &str = "feishu-cursor.json";
const SEEN_IDS_LIMIT: usize = 200;
/// A message that cannot be applied (disk full, read-only mount, ...) is
/// retried on the next poll instead of being dropped. After this many failed
/// attempts it is recorded anyway so one stuck message cannot block the chat
/// forever.
const MAX_DELIVERY_ATTEMPTS: u8 = 3;
const MAX_TRACKED_FAILURES: usize = 256;

/// The recipient used for offline alerts. Binding can happen after startup, so
/// the server keeps this in memory and every alert re-reads it.
pub type OwnerCell = Arc<Mutex<Option<String>>>;

/// Builds the read-only view answered by `--commands`. The server passes a
/// closure so every command sees live state (epoch, online agents, binding).
pub type StatusProvider = Arc<dyn Fn() -> crate::commands::Status + Send + Sync>;

pub fn owner_cell(owner: &str) -> OwnerCell {
    let trimmed = owner.trim();
    Arc::new(Mutex::new(if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub chat_id: String,
    pub open_id: String,
    /// Bindings belong to one app and one explicitly authorised recipient.
    /// Older files without this field are deliberately not reused.
    #[serde(default)]
    pub app_id: String,
    pub bound_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cursor {
    last_create_time_ms: u64,
    #[serde(default)]
    seen_ids: Vec<String>,
    /// Failed delivery attempts per message id. Older cursor files simply
    /// start with an empty map.
    #[serde(default)]
    failures: BTreeMap<String, u8>,
}

impl Cursor {
    fn load(data_dir: &Path, default_ms: u64) -> Self {
        let path = data_dir.join(CURSOR_FILE);
        fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or(Self {
                last_create_time_ms: default_ms,
                seen_ids: Vec::new(),
                failures: BTreeMap::new(),
            })
    }

    fn save(&self, data_dir: &Path) -> Result<()> {
        let serialized = serde_json::to_vec_pretty(self)?;
        atomic_write(&data_dir.join(CURSOR_FILE), &serialized, true)
            .context("writing feishu-cursor.json")
    }

    fn seen(&self, id: &str) -> bool {
        self.seen_ids.iter().any(|seen| seen == id)
    }

    fn record(&mut self, id: &str, create_time_ms: u64) {
        if !id.is_empty() && !self.seen(id) {
            self.seen_ids.push(id.to_string());
            if self.seen_ids.len() > SEEN_IDS_LIMIT {
                let excess = self.seen_ids.len() - SEEN_IDS_LIMIT;
                self.seen_ids.drain(0..excess);
            }
        }
        self.failures.remove(id);
        self.last_create_time_ms = self.last_create_time_ms.max(create_time_ms);
    }

    /// Count one failed delivery attempt for `id` and return the new count.
    fn note_failure(&mut self, id: &str) -> u8 {
        if id.is_empty() {
            return MAX_DELIVERY_ATTEMPTS;
        }
        if self.failures.len() >= MAX_TRACKED_FAILURES && !self.failures.contains_key(id) {
            if let Some(first) = self.failures.keys().next().cloned() {
                self.failures.remove(&first);
            }
        }
        let attempts = self.failures.entry(id.to_string()).or_insert(0);
        *attempts = attempts.saturating_add(1);
        *attempts
    }
}

#[derive(Debug, Clone)]
pub struct TargetFile {
    /// Logical key shared with agents: `<source id>/<relative path>`.
    pub key: String,
    /// Absolute path on this machine.
    pub path: PathBuf,
}

/// Resolve `sync.target` against the configured sources and make sure the path
/// stays inside that source and is covered by one of its globs.
pub fn resolve_target(config: &Config, sources: &[SourceSpec]) -> Result<TargetFile> {
    let target = config.sync.target.trim();
    if target.is_empty() {
        bail!(
            "sync.target is not set; the Feishu control channel needs one managed file. \
             Set [sync] target = \"<source id>/<relative path>\" in the config file \
             (or run `promptsync server` in a terminal and use wizard step 2)"
        );
    }
    let (id, rest) = target
        .split_once('/')
        .context("sync.target must be <source id>/<relative path>")?;
    let source = sources
        .iter()
        .find(|source| source.id == id)
        .with_context(|| format!("sync.target references unknown source {id:?}"))?;
    let relative = safe_relative_path(rest)
        .with_context(|| format!("sync.target {target:?} is not a safe path"))?;
    if !source
        .globs
        .iter()
        .any(|pattern| globpat::matches(pattern, rest))
    {
        bail!("sync.target {target:?} is not covered by the source globs of {id:?}");
    }
    let path = secure_join(&source.root, &relative, true)
        .with_context(|| format!("resolving sync.target {target:?}"))?;
    Ok(TargetFile {
        key: target.to_string(),
        path,
    })
}

pub fn load_binding(data_dir: &Path) -> Option<Binding> {
    let path = data_dir.join(BINDING_FILE);
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

pub fn binding_matches(config: &Config, binding: &Binding) -> bool {
    let app_id = config.feishu.app.app_id.trim();
    let owner = config.feishu.app.owner_open_id.trim();
    !app_id.is_empty()
        && binding.app_id == app_id
        && !binding.chat_id.trim().is_empty()
        && !binding.open_id.trim().is_empty()
        && (owner.is_empty() || binding.open_id == owner)
}

fn save_binding(data_dir: &Path, binding: &Binding) -> Result<()> {
    fs::create_dir_all(data_dir)?;
    let serialized = serde_json::to_vec_pretty(binding)?;
    atomic_write(&data_dir.join(BINDING_FILE), &serialized, true)
        .context("writing feishu-binding.json")
}

/// Reject bindings that cannot drive the control channel. Feishu sometimes
/// answers a send without a `chat_id`; storing that would make the poll loop
/// query an empty container forever and the user would never know why.
fn checked_binding(config: &Config, binding: Binding) -> Result<Binding> {
    if binding.chat_id.trim().is_empty() {
        bail!(
            "Feishu accepted the message for {} but returned no chat_id; the prompt control channel needs the private chat id (check im:message:send_as_bot and that the app is published)",
            binding.open_id
        );
    }
    if binding.open_id.trim().is_empty() {
        bail!("Feishu returned no open_id for the bound private chat");
    }
    if binding.app_id != config.feishu.app.app_id.trim() {
        bail!(
            "binding belongs to app {:?}, but the config uses {:?}",
            binding.app_id,
            config.feishu.app.app_id.trim()
        );
    }
    Ok(binding)
}

/// What the binding is used for. The server reads the private chat as its prompt
/// control channel; an agent only needs the owner open_id for offline alerts.
/// The purpose only changes the wording, never the binding logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingPurpose {
    Server,
    Agent,
}

/// Where the message recipient came from. Reported in the log so an unexpected
/// recipient is one grep away from the config value that caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerSource {
    Configured,
    Contact,
    AppOwner,
}

impl OwnerSource {
    fn label(self) -> &'static str {
        match self {
            OwnerSource::Configured => "configured owner_open_id",
            OwnerSource::Contact => "bind_contact",
            OwnerSource::AppOwner => "app owner",
        }
    }
}

impl BindingPurpose {
    /// The one message the bot sends while binding. Its response carries the
    /// private chat id, so binding and confirming are the same API call and
    /// nothing has to be answered by hand.
    fn success_message(self) -> &'static str {
        match self {
            BindingPurpose::Server => concat!(
                "promptsync 绑定成功。以后把纯文本 prompt 发给我就会覆盖服务端的那个文件；",
                "发 --help 看我支持的状态命令（--status / --agents / --config）。"
            ),
            BindingPurpose::Agent => concat!(
                "promptsync agent 绑定成功。之后离线告警会发到这个私聊；",
                "server 和 agent 用的是同一个飞书应用，-- 开头的命令由服务端应答。"
            ),
        }
    }
}

/// Resolve who receives messages without asking anyone to send one:
/// an explicitly configured recipient wins, then a configured email/mobile,
/// then the account that owns the app.
pub fn resolve_owner(config: &Config, client: &FeishuClient) -> Result<(String, OwnerSource)> {
    let configured = config.feishu.app.owner_open_id.trim();
    if !configured.is_empty() {
        return Ok((configured.to_string(), OwnerSource::Configured));
    }
    let contact = config.feishu.control.bind_contact.trim();
    if !contact.is_empty() {
        let open_id = if contact.starts_with("ou_") {
            contact.to_string()
        } else {
            client.lookup_open_id(contact)?
        };
        return Ok((open_id, OwnerSource::Contact));
    }
    Ok((client.app_owner_open_id()?, OwnerSource::AppOwner))
}

/// Message the recipient and learn the private chat id from the response. That
/// is the whole binding step: no one-time code, nothing for the user to send,
/// and the same code path for both roles.
fn bind_once(
    config: &Config,
    client: &FeishuClient,
    message: &str,
) -> Result<(Binding, OwnerSource)> {
    let (open_id, source) = resolve_owner(config, client)?;
    let sent = client.send_text_to_owner(&open_id, message)?;
    let binding = checked_binding(
        config,
        Binding {
            chat_id: sent.chat_id,
            open_id,
            app_id: config.feishu.app.app_id.trim().to_string(),
            bound_unix: now_unix(),
        },
    )?;
    Ok((binding, source))
}

/// First-start binding, fully automatic.
///
/// 1. A binding on disk that still matches the app/owner is reused.
/// 2. Otherwise the recipient is resolved (config, `bind_contact`, then the app
///    owner) and messaged once; the response carries the private chat id.
///
/// Nothing waits for a message from a human, so the wizard and the background
/// retry loop share the same code path.
pub fn ensure_binding(
    config: &mut Config,
    paths: &Paths,
    logger: &Logger,
    force: bool,
    purpose: BindingPurpose,
) -> Result<Option<Binding>> {
    if !config.feishu.enabled {
        return Ok(None);
    }
    if !config.feishu_app_configured() {
        logger.warn(
            "Feishu is enabled but feishu.app.app_id / app_secret are empty; control channel and alerts are off",
        );
        return Ok(None);
    }
    let data_dir = paths.data_dir();
    fs::create_dir_all(&data_dir)?;
    if !force {
        if let Some(binding) = load_binding(&data_dir) {
            if binding_matches(config, &binding) {
                return Ok(Some(binding));
            }
        }
    }

    let client = FeishuClient::from_config(config)?;
    client.check().context("verifying Feishu app credentials")?;
    match bind_once(config, &client, purpose.success_message()) {
        Ok((binding, source)) => {
            store_binding(&data_dir, &paths.config_file, &binding)?;
            // Keep the in-memory copy in step with the file so callers can
            // print what was just learned without re-reading the config.
            config.feishu.app.owner_open_id = binding.open_id.clone();
            logger.info(format!(
                "Feishu bound ({}): chat {} owner {}",
                source.label(),
                binding.chat_id,
                binding.open_id
            ));
            Ok(Some(binding))
        }
        Err(err) => {
            logger.warn(format!(
                "Feishu 自动绑定失败：{err:#}；可在 config.toml 的 [feishu.app] 填写 owner_open_id 指定接收人"
            ));
            Ok(None)
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCandidate {
    pub key: String,
    pub bytes: usize,
}

/// Candidate prompt files (`system_prompt.md` / `SOUL.md`) from the sources.
/// Non-empty files come first so the wizard can default to them.
pub fn target_candidates(config: &Config) -> Result<Vec<TargetCandidate>> {
    let sources = crate::prompts::resolve_sources(&config.sync);
    let options = crate::prompts::ScanOptions::from(&config.sync);
    let entries = crate::prompts::scan(&sources, &options, None)?;
    let mut candidates: Vec<TargetCandidate> = entries
        .iter()
        .filter(|(key, _)| key.ends_with("/system_prompt.md") || key.ends_with("/SOUL.md"))
        .map(|(key, content)| TargetCandidate {
            key: key.clone(),
            bytes: content.len(),
        })
        .collect();
    candidates.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.key.cmp(&right.key))
    });
    Ok(candidates)
}

/// Persist `sync.target` and optionally narrow the source globs to that file.
pub fn set_target(config: &mut Config, config_file: &Path, key: &str, narrow: bool) -> Result<()> {
    let previous = config.sync.target.clone();
    config.sync.target = key.to_string();
    if let Err(err) = || -> Result<()> {
        let sources = crate::prompts::resolve_sources(&config.sync);
        resolve_target(config, &sources)?;
        Ok(())
    }() {
        config.sync.target = previous;
        return Err(err);
    }
    set_value(config_file, Some("sync"), "target", &format!("\"{key}\""))?;
    if narrow {
        let (id, relative) = key
            .split_once('/')
            .context("sync.target has no source id")?;
        set_source_globs(config_file, id, &[relative.to_string()])?;
        if let Some(source) = config
            .sync
            .sources
            .iter_mut()
            .find(|source| source.id == id)
        {
            source.globs = vec![relative.to_string()];
        }
    }
    Ok(())
}

/// Fill `sync.target` when it is empty and exactly one candidate exists.
///
/// The server also calls this before starting the control channel, so a
/// non-interactive start (systemd/launchd/`--port ...`) still gets a managed
/// file instead of silently running without the Feishu control channel.
pub fn ensure_target(
    config: &mut Config,
    config_file: &Path,
    logger: &Logger,
    narrow: bool,
) -> Result<Option<String>> {
    if !config.sync.target.trim().is_empty() {
        return Ok(Some(config.sync.target.trim().to_string()));
    }
    let candidates = target_candidates(config)?;
    let non_empty: Vec<&TargetCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.bytes > 0)
        .collect();
    let chosen = if non_empty.len() == 1 {
        Some(non_empty[0].key.clone())
    } else if candidates.len() == 1 {
        Some(candidates[0].key.clone())
    } else {
        None
    };
    let Some(key) = chosen else {
        if candidates.is_empty() {
            logger.warn(
                "Feishu control needs sync.target, but no system_prompt.md / SOUL.md was found in the configured sources; set [sync] target = \"<source id>/<relative path>\" or run `promptsync server` in a terminal",
            );
        } else {
            logger.warn(format!(
                "Feishu control needs sync.target; several candidates exist: {}. Set [sync] target or run `promptsync server` in a terminal",
                candidates
                    .iter()
                    .map(|candidate| candidate.key.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        return Ok(None);
    };
    set_target(config, config_file, &key, narrow)?;
    logger.info(format!("sync.target auto-detected: {key}"));
    Ok(Some(key))
}

fn qr_art(link: &str) -> Option<String> {
    let code = qrcode::QrCode::new(link.as_bytes()).ok()?;
    Some(
        code.render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .build(),
    )
}

pub fn print_qr(link: &str) {
    match qr_art(link) {
        Some(art) => println!("{art}\n"),
        None => println!("（二维码生成失败，请直接使用上面的链接）\n"),
    }
}

/// Ingest loop (runs on the server).
#[allow(clippy::too_many_arguments)]
pub async fn run(
    config: Config,
    data_dir: PathBuf,
    config_file: PathBuf,
    target: TargetFile,
    binding: Option<Binding>,
    owner: OwnerCell,
    logger: Logger,
    status: StatusProvider,
) -> Result<()> {
    let client = Arc::new(FeishuClient::from_config(&config)?);
    let poll_secs = config.feishu.control.poll_secs.max(2);
    let binding = binding.and_then(|binding| {
        if binding_matches(&config, &binding) {
            Some(binding)
        } else {
            logger
                .warn("Feishu binding does not match the current app/owner; rebinding is required");
            None
        }
    });
    let binding = match binding {
        Some(binding) => binding,
        None => {
            bind_loop(
                &config,
                &client,
                &data_dir,
                &config_file,
                poll_secs,
                &logger,
                BindingPurpose::Server,
            )
            .await?
        }
    };
    // Binding may have happened after the server started; alerts must use the
    // fresh recipient without waiting for a restart.
    publish_owner(&owner, &binding.open_id);
    let poll = Duration::from_secs(poll_secs);
    let mut cursor = Cursor::load(&data_dir, (binding.bound_unix + 2) * 1000);

    loop {
        let started = Instant::now();
        let client = client.clone();
        let binding = binding.clone();
        let target = target.clone();
        let config = config.clone();
        let snapshot = cursor.clone();
        let status = Arc::clone(&status);
        // 状态目录：客户端适配时的集中备份库放在这里。
        let state_dir = data_dir.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            poll_once(
                &config, &client, &binding, &target, &snapshot, &status, &state_dir,
            )
        })
        .await;
        match outcome {
            Ok(Ok(outcome)) => {
                cursor = outcome.cursor;
                if let Err(err) = cursor.save(&data_dir) {
                    logger.warn(format!("cannot persist Feishu cursor: {err:#}"));
                }
                if let Some(message) = outcome.log_message {
                    logger.info(message);
                }
            }
            Ok(Err(err)) => logger.warn(format!("Feishu control poll failed: {err:#}")),
            Err(err) => logger.warn(format!("Feishu control task panicked: {err}")),
        }
        let elapsed = started.elapsed();
        if elapsed < poll {
            tokio::time::sleep(poll - elapsed).await;
        }
    }
}

/// Make the recipient known to the process that sends alerts.
fn publish_owner(owner: &OwnerCell, open_id: &str) {
    let open_id = open_id.trim();
    if open_id.is_empty() {
        return;
    }
    if let Ok(mut guard) = owner.lock() {
        if guard.as_deref() != Some(open_id) {
            *guard = Some(open_id.to_string());
        }
    }
}

/// Persist a binding in the state dir and write the recipient back to the
/// config file (best effort: the binding file is authoritative at runtime).
fn store_binding(data_dir: &Path, config_file: &Path, binding: &Binding) -> Result<()> {
    save_binding(data_dir, binding)?;
    let _ = set_value(
        config_file,
        Some("feishu.app"),
        "owner_open_id",
        &format!("\"{}\"", binding.open_id),
    );
    Ok(())
}

/// Background binding used by both roles: retry the automatic binding until it
/// works (network hiccup, app just created, ...) and log each distinct error
/// once instead of on every attempt.
async fn bind_loop(
    config: &Config,
    client: &Arc<FeishuClient>,
    data_dir: &Path,
    config_file: &Path,
    poll_secs: u64,
    logger: &Logger,
    purpose: BindingPurpose,
) -> Result<Binding> {
    let message = purpose.success_message();
    let mut last_error: Option<String> = None;
    loop {
        let task_config = config.clone();
        let client_for_task = Arc::clone(client);
        let attempt =
            tokio::task::spawn_blocking(move || bind_once(&task_config, &client_for_task, message))
                .await;
        match attempt {
            Ok(Ok((binding, source))) => {
                store_binding(data_dir, config_file, &binding)?;
                logger.info(format!(
                    "Feishu bound ({}): chat {} owner {}",
                    source.label(),
                    binding.chat_id,
                    binding.open_id
                ));
                return Ok(binding);
            }
            Ok(Err(err)) => {
                let message = format!("{err:#}");
                if last_error.as_deref() != Some(&message) {
                    logger.warn(format!(
                        "Feishu 自动绑定失败（{poll_secs} 秒后重试）：{message}"
                    ));
                    last_error = Some(message);
                }
            }
            Err(err) => logger.warn(format!("Feishu binding task panicked: {err}")),
        }
        tokio::time::sleep(Duration::from_secs(poll_secs)).await;
    }
}

/// Background binding used by an agent: it keeps retrying until the alert
/// recipient is known, then writes both `feishu-binding.json` and
/// `feishu.app.owner_open_id`.
pub async fn bind_agent(
    config: &Config,
    data_dir: &Path,
    config_file: &Path,
    logger: &Logger,
) -> Result<Binding> {
    let client = Arc::new(FeishuClient::from_config(config)?);
    let poll_secs = config.feishu.control.poll_secs.max(2);
    bind_loop(
        config,
        &client,
        data_dir,
        config_file,
        poll_secs,
        logger,
        BindingPurpose::Agent,
    )
    .await
}

struct PollOutcome {
    cursor: Cursor,
    log_message: Option<String>,
}

fn poll_once(
    config: &Config,
    client: &FeishuClient,
    binding: &Binding,
    target: &TargetFile,
    cursor: &Cursor,
    status: &StatusProvider,
    data_dir: &Path,
) -> Result<PollOutcome> {
    let mut cursor = cursor.clone();
    let now = now_unix();
    let start = (cursor.last_create_time_ms / 1000).saturating_sub(5);
    let messages = client.list_messages(&binding.chat_id, start, now + 60)?;
    let mut log_message = None;

    for message in messages {
        if cursor.seen(&message.id) {
            continue;
        }
        // Never treat messages that predate the binding (including the one
        // that triggered it) as prompt content.
        if message.create_time_ms / 1000 <= binding.bound_unix {
            cursor.record(&message.id, message.create_time_ms);
            continue;
        }
        if message.chat_id != binding.chat_id || message.sender_type != "user" {
            cursor.record(&message.id, message.create_time_ms);
            continue;
        }
        if message.sender_id != binding.open_id {
            cursor.record(&message.id, message.create_time_ms);
            continue;
        }

        // A `--command` is a query, not prompt content: answer it and leave the
        // managed file alone. Unknown verbs get the manual, never a write.
        let text = message_text(&message);
        if let Some(command) = text
            .as_deref()
            .and_then(|text| crate::commands::handle(text, &status()))
        {
            cursor.record(&message.id, message.create_time_ms);
            log_message = Some(format!(
                "Feishu command: {}",
                text.as_deref().unwrap_or_default().trim()
            ));
            if let Err(err) = client.send_text_to_chat(&binding.chat_id, &command) {
                log_message = Some(format!("Feishu command reply failed: {err:#}"));
            }
            continue;
        }

        let reply = match apply_message(config, client, binding, target, &message, data_dir) {
            Ok(Applied::Ignored { reason }) => {
                cursor.record(&message.id, message.create_time_ms);
                reason
            }
            Ok(Applied::Rejected { reason }) => {
                cursor.record(&message.id, message.create_time_ms);
                log_message = Some(format!("Feishu update rejected: {reason}"));
                Some(format!("❌ 未更新：{reason}"))
            }
            Ok(Applied::Written {
                bytes,
                hash,
                backup,
                adapted,
                adapt_errors,
            }) => {
                cursor.record(&message.id, message.create_time_ms);
                log_message = Some(format!(
                    "Feishu update: {} ({} B, sha256 {}, backup {}{}{})",
                    target.key,
                    bytes,
                    &hash[..8.min(hash.len())],
                    backup
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    if adapted.is_empty() {
                        String::new()
                    } else {
                        format!(", clients {}", adapted.join(", "))
                    },
                    if adapt_errors.is_empty() {
                        String::new()
                    } else {
                        format!(", client errors: {}", adapt_errors.join("; "))
                    }
                ));
                let mut reply = format!(
                    "✅ 已更新 {}（{bytes} B，sha256 {}）",
                    target.key,
                    &hash[..8.min(hash.len())]
                );
                if !adapted.is_empty() {
                    reply.push_str(&format!("；已适配 {}", adapted.join(", ")));
                }
                if !adapt_errors.is_empty() {
                    reply.push_str(&format!(
                        "；{} 个客户端写入失败（详见日志）",
                        adapt_errors.len()
                    ));
                }
                Some(reply)
            }
            Ok(Applied::DryRun { bytes, hash }) => {
                cursor.record(&message.id, message.create_time_ms);
                Some(format!(
                    "🧪 dry-run：将更新 {}（{bytes} B，sha256 {}），未写入",
                    target.key,
                    &hash[..8.min(hash.len())]
                ))
            }
            // Do not advance past a message we could not deliver: a transient
            // write failure must not silently drop the prompt. Retry on the
            // next poll and give up only after MAX_DELIVERY_ATTEMPTS.
            Err(err) => {
                let attempt = cursor.note_failure(&message.id);
                let detail = format!("{err:#}");
                if attempt >= MAX_DELIVERY_ATTEMPTS {
                    cursor.record(&message.id, message.create_time_ms);
                    log_message = Some(format!(
                        "Feishu update failed after {attempt} attempts: {detail}"
                    ));
                    Some(format!(
                        "❌ 未更新（已重试 {MAX_DELIVERY_ATTEMPTS} 次）：{detail}"
                    ))
                } else {
                    log_message = Some(format!(
                        "Feishu update failed (attempt {attempt}/{MAX_DELIVERY_ATTEMPTS}), will retry: {detail}"
                    ));
                    if attempt == 1 {
                        Some(format!("❌ 未更新：{detail}；稍后自动重试"))
                    } else {
                        None
                    }
                }
            }
        };
        if let Some(reply) = reply {
            if let Err(err) = client.send_text_to_chat(&binding.chat_id, &reply) {
                log_message = Some(format!("Feishu ack failed: {err:#}"));
            }
        }
    }

    Ok(PollOutcome {
        cursor,
        log_message,
    })
}

enum Applied {
    Ignored {
        reason: Option<String>,
    },
    /// The message was understood but refused (too large / unsupported). It is
    /// deliberately not retried.
    Rejected {
        reason: String,
    },
    Written {
        bytes: usize,
        hash: String,
        backup: Option<PathBuf>,
        adapted: Vec<String>,
        adapt_errors: Vec<String>,
    },
    DryRun {
        bytes: usize,
        hash: String,
    },
}

fn apply_message(
    config: &Config,
    _client: &FeishuClient,
    _binding: &Binding,
    target: &TargetFile,
    message: &feishu::Message,
    data_dir: &Path,
) -> Result<Applied> {
    let text = match message_text(message) {
        Some(text) => text,
        None => {
            return Ok(Applied::Ignored {
                reason: Some("只接受纯文本消息（不要用富文本/图片/附件）".to_string()),
            })
        }
    };
    if text.is_empty() {
        return Ok(Applied::Ignored {
            reason: Some("消息内容为空".to_string()),
        });
    }
    if text.len() > config.feishu.control.max_message_bytes {
        return Ok(Applied::Rejected {
            reason: format!(
                "内容 {} B 超过上限 {} B",
                text.len(),
                config.feishu.control.max_message_bytes
            ),
        });
    }
    // The message ends up on disk exactly as written; make sure the newline at
    // the very end is normalised so repeated messages do not churn the hash.
    let content = text.trim_end_matches('\n').to_string() + "\n";
    let bytes = content.len();
    let hash = sha256_hex(content.as_bytes());

    if let Ok(existing) = fs::read_to_string(&target.path) {
        if existing == content {
            return Ok(Applied::Ignored {
                reason: Some("内容与现有文件一致，无需更新".to_string()),
            });
        }
    }
    if config.feishu.control.dry_run {
        return Ok(Applied::DryRun { bytes, hash });
    }

    let mut backup = None;
    if let Ok(existing) = fs::read(&target.path) {
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.9fZ").to_string();
        let name = target
            .path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "prompt".to_string());
        let backup_path = target.path.with_file_name(format!("{name}.{stamp}.bak"));
        fs::write(&backup_path, existing)
            .with_context(|| format!("writing backup {}", backup_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600));
        }
        backup = Some(backup_path);
        prune_backups(&target.path, config.feishu.control.keep_backups);
    }
    if let Some(parent) = target.path.parent() {
        fs::create_dir_all(parent)?;
    }
    atomic_write(&target.path, content.as_bytes(), true)
        .with_context(|| format!("writing {}", target.path.display()))?;
    // 服务端本机的客户端也立即适配；旧内容备份到状态目录的集中备份库。
    let adapted = crate::adapters::apply_content(&config.sync, content.as_bytes(), data_dir);
    Ok(Applied::Written {
        bytes,
        hash,
        backup,
        // 已更新的客户端，加上被移走旧副本的客户端（标注“移走重复”）。
        adapted: adapted
            .written
            .into_iter()
            .map(|(client, _, _)| client)
            .chain(
                adapted
                    .retired
                    .into_iter()
                    .map(|(client, path, _)| format!("{client}(移走重复 {})", path.display())),
            )
            .collect(),
        adapt_errors: adapted
            .failed
            .into_iter()
            .map(|(client, path, err)| format!("{client} ({}): {err}", path.display()))
            .collect(),
    })
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Keep the newest `keep` `<file>.<stamp>.bak` siblings; 0 keeps everything.
fn prune_backups(path: &Path, keep: usize) {
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
    use serde_json::json;
    use std::sync::Mutex;
    use tiny_http::{Header, Response, Server};

    struct MockFeishu {
        base: String,
        messages: Arc<Mutex<Vec<serde_json::Value>>>,
        sent: Arc<Mutex<Vec<String>>>,
    }

    impl MockFeishu {
        fn start() -> Self {
            let server = Server::http("127.0.0.1:0").expect("mock server");
            let port = server.server_addr().to_ip().expect("ip addr").port();
            let messages = Arc::new(Mutex::new(Vec::new()));
            let sent = Arc::new(Mutex::new(Vec::new()));
            let (m, s) = (messages.clone(), sent.clone());
            std::thread::spawn(move || {
                for mut request in server.incoming_requests() {
                    let path = request.url().split('?').next().unwrap_or("").to_string();
                    let method = request.method().as_str().to_string();
                    let mut body = String::new();
                    if method == "POST" {
                        let mut reader = request.as_reader();
                        let _ = std::io::Read::read_to_string(&mut reader, &mut body);
                    }
                    let payload = match (method.as_str(), path.as_str()) {
                        ("POST", "/open-apis/auth/v3/tenant_access_token/internal") => {
                            json!({ "code": 0, "tenant_access_token": "test-token", "expire": 7200 })
                        }
                        ("GET", "/open-apis/im/v1/messages") => {
                            json!({ "code": 0, "data": { "items": *m.lock().unwrap(), "has_more": false } })
                        }
                        ("POST", "/open-apis/im/v1/messages") => {
                            s.lock().unwrap().push(body);
                            json!({ "code": 0, "data": { "message_id": "ack-1", "chat_id": "oc_p2p" } })
                        }
                        ("POST", "/open-apis/contact/v3/users/batch_get_id") => {
                            json!({ "code": 0, "data": { "user_list": [ { "user_id": "ou_owner" } ] } })
                        }
                        ("GET", path)
                            if path.starts_with("/open-apis/application/v6/applications/") =>
                        {
                            json!({
                                "code": 0,
                                "data": { "app": {
                                    "app_id": "cli_test",
                                    "creator_id": "ou_app_owner",
                                    "owner": { "owner_id": "ou_app_owner", "type": 2 }
                                }}
                            })
                        }
                        _ => json!({ "code": 99999, "msg": "not mocked" }),
                    };
                    let response = Response::from_string(payload.to_string()).with_header(
                        Header::from_bytes("Content-Type", "application/json").unwrap(),
                    );
                    let _ = request.respond(response);
                }
            });
            Self {
                base: format!("http://127.0.0.1:{port}"),
                messages,
                sent,
            }
        }

        fn push_text(&self, text: &str, sender: &str) {
            let message_id = {
                let messages = self.messages.lock().unwrap();
                format!("m-{}", messages.len())
            };
            self.messages.lock().unwrap().push(json!({
                "message_id": message_id,
                "create_time": (now_unix() * 1000).to_string(),
                "msg_type": "text",
                "body": { "content": json!({ "text": text }).to_string() },
                "sender": { "id": sender, "sender_type": "user" },
                "chat_id": "oc_p2p",
            }));
        }

        fn acks(&self) -> Vec<String> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .map(|body| {
                    let value: serde_json::Value =
                        serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
                    let content = value
                        .get("content")
                        .and_then(|content| content.as_str())
                        .unwrap_or("");
                    serde_json::from_str::<serde_json::Value>(content)
                        .ok()
                        .and_then(|content| {
                            content
                                .get("text")
                                .and_then(|text| text.as_str())
                                .map(str::to_string)
                        })
                        .unwrap_or_default()
                })
                .collect()
        }
    }

    /// Commands are not exercised by most tests; they get an empty status.
    fn no_status() -> StatusProvider {
        Arc::new(crate::commands::Status::default)
    }

    fn fixture(mock: &MockFeishu) -> (Config, tempfile::TempDir, TargetFile, Binding, Cursor) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owners");
        let target_path = root.join("acme/bots/cindy/system_prompt.md");
        fs::create_dir_all(target_path.parent().unwrap()).unwrap();
        fs::write(&target_path, "old prompt\n").unwrap();

        let mut config = Config::default();
        config.feishu.enabled = true;
        config.feishu.app.app_id = "cli_test".to_string();
        config.feishu.app.app_secret = "secret".to_string();
        config.feishu.app.api_base = mock.base.clone();
        config.feishu.app.owner_open_id = "ou_owner".to_string();
        config.feishu.timeout_secs = 5;
        config.sync.target = "cindy/acme/bots/cindy/system_prompt.md".to_string();
        config.sync.adapt_clients = false;
        config.sync.sources = vec![crate::config::SourceConfig {
            id: "cindy".to_string(),
            root: root.display().to_string(),
            globs: vec!["*/bots/*/system_prompt.md".to_string()],
        }];
        let sources = crate::prompts::resolve_sources(&config.sync);
        let target = resolve_target(&config, &sources).unwrap();
        let binding = Binding {
            chat_id: "oc_p2p".to_string(),
            open_id: "ou_owner".to_string(),
            app_id: "cli_test".to_string(),
            // 0 lets the fixture messages (created "now") count as new.
            bound_unix: 0,
        };
        let cursor = Cursor {
            last_create_time_ms: now_unix() * 1000 - 5000,
            seen_ids: Vec::new(),
            failures: BTreeMap::new(),
        };
        (config, temp, target, binding, cursor)
    }

    #[test]
    fn renders_a_terminal_qr_code() {
        let art = qr_art("https://applink.feishu.cn/client/bot/open?appId=cli_test").unwrap();
        assert!(art.lines().count() > 5);
        assert!(art.contains('█') || art.contains('▀'));
    }

    #[test]
    fn binds_to_the_app_owner_without_any_message_from_the_user() {
        let mock = MockFeishu::start();
        let mut config = Config::default();
        config.feishu.app.app_id = "cli_test".to_string();
        config.feishu.app.app_secret = "secret".to_string();
        config.feishu.app.api_base = mock.base.clone();
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();

        assert_eq!(client.app_owner_open_id().unwrap(), "ou_app_owner");
        let (binding, source) = bind_once(&config, &client, "绑定成功").unwrap();
        assert_eq!(source, OwnerSource::AppOwner);
        assert_eq!(binding.open_id, "ou_app_owner");
        assert_eq!(binding.chat_id, "oc_p2p");
        assert_eq!(binding.app_id, "cli_test");
        assert!(mock.acks().iter().any(|text| text == "绑定成功"));
        // The user never had to send anything.
        assert!(mock.messages.lock().unwrap().is_empty());
    }

    #[test]
    fn a_configured_recipient_wins_over_the_app_owner() {
        let mock = MockFeishu::start();
        let mut config = Config::default();
        config.feishu.app.app_id = "cli_test".to_string();
        config.feishu.app.app_secret = "secret".to_string();
        config.feishu.app.api_base = mock.base.clone();
        config.feishu.app.owner_open_id = "ou_configured".to_string();
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let (binding, source) = bind_once(&config, &client, "hi").unwrap();
        assert_eq!(source, OwnerSource::Configured);
        assert_eq!(binding.open_id, "ou_configured");
    }

    #[test]
    fn binding_must_match_the_current_app_and_owner() {
        let mut config = Config::default();
        config.feishu.app.app_id = "cli_new".to_string();
        config.feishu.app.owner_open_id = "ou_new".to_string();
        let binding = Binding {
            chat_id: "oc_chat".to_string(),
            open_id: "ou_old".to_string(),
            app_id: "cli_old".to_string(),
            bound_unix: 1,
        };
        assert!(!binding_matches(&config, &binding));
        let binding = Binding {
            open_id: "ou_new".to_string(),
            app_id: "cli_new".to_string(),
            ..binding
        };
        assert!(binding_matches(&config, &binding));
        let legacy = Binding {
            app_id: String::new(),
            ..binding
        };
        assert!(!binding_matches(&config, &legacy));
    }

    #[test]
    fn applies_owner_text_and_creates_a_suffix_backup() {
        let mock = MockFeishu::start();
        mock.push_text("new prompt\nsecond line", "ou_owner");
        let (config, _temp, target, binding, cursor) = fixture(&mock);
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let outcome = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &cursor,
            &no_status(),
            target.path.parent().unwrap(),
        )
        .unwrap();

        let content = fs::read_to_string(&target.path).unwrap();
        assert_eq!(content, "new prompt\nsecond line\n");
        assert!(outcome.log_message.unwrap().contains("Feishu update"));
        let backup = fs::read_dir(target.path.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .find(|name| name.ends_with(".bak"))
            .expect("backup file");
        assert!(backup.starts_with("system_prompt.md."));
        assert_eq!(
            fs::read_to_string(target.path.with_file_name(backup)).unwrap(),
            "old prompt\n"
        );
        let acks = mock.acks();
        assert_eq!(acks.len(), 1);
        assert!(acks[0].contains("已更新"));
        assert!(outcome.cursor.last_create_time_ms > cursor.last_create_time_ms);
    }

    #[test]
    fn commands_reply_without_touching_the_managed_file() {
        let mock = MockFeishu::start();
        mock.push_text("--status", "ou_owner");
        mock.push_text("--bogus", "ou_owner");
        let (config, _temp, target, binding, cursor) = fixture(&mock);
        let before = fs::read_to_string(&target.path).unwrap();
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let status: StatusProvider = Arc::new(|| crate::commands::Status {
            target: "cindy/acme/bots/cindy/system_prompt.md".to_string(),
            data_port: 12345,
            agents: vec![crate::commands::AgentRow {
                id: "Mac.lan".to_string(),
                last_seen_unix: now_unix(),
                peer: "127.0.0.1".to_string(),
                hash: "abc123456789".to_string(),
            }],
            online_window_secs: 120,
            now: now_unix(),
            ..Default::default()
        });

        let outcome = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &cursor,
            &status,
            target.path.parent().unwrap(),
        )
        .unwrap();

        assert_eq!(fs::read_to_string(&target.path).unwrap(), before);
        let acks = mock.acks();
        assert_eq!(acks.len(), 2, "{acks:?}");
        assert!(acks[0].contains("12345"), "{}", acks[0]);
        assert!(acks[0].contains("1 台在线"), "{}", acks[0]);
        assert!(acks[1].contains("未识别的命令：--bogus"), "{}", acks[1]);
        assert!(outcome.log_message.unwrap().contains("Feishu command"));
    }

    #[test]
    fn ignores_other_senders_and_non_text_and_duplicates() {
        let mock = MockFeishu::start();
        mock.push_text("from a stranger", "ou_someone");
        let (mut config, _temp, target, binding, cursor) = fixture(&mock);
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let outcome = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &cursor,
            &no_status(),
            target.path.parent().unwrap(),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&target.path).unwrap(), "old prompt\n");
        assert!(outcome.log_message.is_none());

        // A non-text message from the owner is acknowledged but not written.
        mock.messages.lock().unwrap().clear();
        mock.messages.lock().unwrap().push(json!({
            "message_id": "m-post",
            "create_time": (now_unix() * 1000).to_string(),
            "msg_type": "post",
            "body": { "content": "{}" },
            "sender": { "id": "ou_owner", "sender_type": "user" },
            "chat_id": "oc_p2p",
        }));
        let outcome = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &cursor,
            &no_status(),
            target.path.parent().unwrap(),
        )
        .unwrap();
        assert!(outcome.log_message.is_none());
        assert_eq!(fs::read_to_string(&target.path).unwrap(), "old prompt\n");
        assert!(mock.acks().iter().any(|ack| ack.contains("纯文本")));

        // dry-run never writes.
        config.feishu.control.dry_run = true;
        mock.messages.lock().unwrap().clear();
        mock.push_text("dry run content", "ou_owner");
        let _ = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &cursor,
            &no_status(),
            target.path.parent().unwrap(),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&target.path).unwrap(), "old prompt\n");
        assert!(mock.acks().iter().any(|ack| ack.contains("dry-run")));
    }

    #[test]
    fn same_content_is_not_written_again() {
        let mock = MockFeishu::start();
        mock.push_text("old prompt", "ou_owner");
        let (config, _temp, target, binding, cursor) = fixture(&mock);
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let before = fs::metadata(&target.path).unwrap().modified().unwrap();
        let outcome = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &cursor,
            &no_status(),
            target.path.parent().unwrap(),
        )
        .unwrap();
        assert!(outcome.log_message.is_none());
        assert_eq!(
            fs::metadata(&target.path).unwrap().modified().unwrap(),
            before
        );
        assert!(mock.acks().iter().any(|ack| ack.contains("一致")));
    }

    #[test]
    fn oversized_message_is_rejected() {
        let mock = MockFeishu::start();
        mock.push_text(&"x".repeat(4096), "ou_owner");
        let (mut config, _temp, target, binding, cursor) = fixture(&mock);
        config.feishu.control.max_message_bytes = 1024;
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let outcome = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &cursor,
            &no_status(),
            target.path.parent().unwrap(),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&target.path).unwrap(), "old prompt\n");
        assert!(outcome.log_message.unwrap().contains("rejected"));
        assert!(mock.acks().iter().any(|ack| ack.contains("超过上限")));
    }

    #[test]
    fn cursor_deduplicates_and_bounds_ids() {
        let mut cursor = Cursor {
            last_create_time_ms: 0,
            seen_ids: Vec::new(),
            failures: BTreeMap::new(),
        };
        cursor.record("a", 10);
        cursor.record("a", 10);
        assert_eq!(cursor.seen_ids.len(), 1);
        assert!(cursor.seen("a"));
        assert_eq!(cursor.last_create_time_ms, 10);
        for index in 0..300 {
            cursor.record(&format!("id{index}"), 100 + index);
        }
        assert_eq!(cursor.seen_ids.len(), SEEN_IDS_LIMIT);
    }

    #[test]
    fn a_failed_write_is_retried_then_given_up() {
        let mock = MockFeishu::start();
        mock.push_text("cannot be written", "ou_owner");
        let (config, _temp, target, binding, cursor) = fixture(&mock);
        // Point the target at a directory: the atomic replace then fails like a
        // full disk or a read-only mount.
        fs::remove_file(&target.path).unwrap();
        fs::create_dir_all(&target.path).unwrap();
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();

        let first = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &cursor,
            &no_status(),
            target.path.parent().unwrap(),
        )
        .unwrap();
        assert!(!first.cursor.seen("m-0"));
        assert_eq!(first.cursor.failures.get("m-0").copied(), Some(1));
        assert!(first.log_message.as_deref().unwrap().contains("will retry"));

        let second = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &first.cursor,
            &no_status(),
            target.path.parent().unwrap(),
        )
        .unwrap();
        assert!(!second.cursor.seen("m-0"));
        let third = poll_once(
            &config,
            &client,
            &binding,
            &target,
            &second.cursor,
            &no_status(),
            target.path.parent().unwrap(),
        )
        .unwrap();
        assert!(third.cursor.seen("m-0"));
        assert_eq!(third.cursor.failures.get("m-0"), None);

        let acks = mock.acks();
        assert!(acks[0].contains("稍后自动重试"));
        assert!(acks.last().unwrap().contains("已重试 3 次"));
        assert_eq!(acks.len(), 2);
    }

    #[test]
    fn resolves_target_inside_a_source() {
        use crate::config::{Config, SourceConfig};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owners");
        let mut config = Config::default();
        config.sync.sources = vec![SourceConfig {
            id: "cindy".to_string(),
            root: root.display().to_string(),
            globs: vec!["*/bots/*/system_prompt.md".to_string()],
        }];
        config.sync.target = "cindy/acme/bots/cindy/system_prompt.md".to_string();
        let sources = crate::prompts::resolve_sources(&config.sync);
        let target = resolve_target(&config, &sources).unwrap();
        assert_eq!(target.key, "cindy/acme/bots/cindy/system_prompt.md");
        assert_eq!(
            target.path,
            fs::canonicalize(&root)
                .unwrap()
                .join("acme/bots/cindy/system_prompt.md")
        );

        config.sync.target = "cindy/../../etc/passwd".to_string();
        assert!(resolve_target(&config, &sources).is_err());

        config.sync.target = "nope/x.md".to_string();
        assert!(resolve_target(&config, &sources).is_err());
    }

    #[test]
    fn target_candidates_put_non_empty_files_first() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owners");
        let dir = root.join("acme/bots/cindy");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("SOUL.md"), "soul content").unwrap();
        fs::write(dir.join("system_prompt.md"), "").unwrap();
        let mut config = Config::default();
        config.sync.sources = vec![crate::config::SourceConfig {
            id: "cindy".to_string(),
            root: root.display().to_string(),
            globs: vec![
                "*/bots/*/system_prompt.md".to_string(),
                "*/bots/*/SOUL.md".to_string(),
            ],
        }];
        let candidates = target_candidates(&config).unwrap();
        assert_eq!(candidates.len(), 2);
        assert!(candidates[0].key.ends_with("SOUL.md"));
        assert!(candidates[0].bytes > 0);
        assert_eq!(candidates[1].bytes, 0);
    }

    #[test]
    fn set_target_persists_and_narrows_globs() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(None, Some(temp.path())).unwrap();
        let root = temp.path().join("owners");
        let dir = root.join("acme/bots/cindy");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("SOUL.md"), "soul").unwrap();
        let text = format!(
            "[sync]\ntarget = \"\"\n[[sync.sources]]\nid = \"cindy\"\nroot = \"{}\"\nglobs = [\"*/bots/*/system_prompt.md\", \"*/bots/*/SOUL.md\"]\n",
            root.display()
        );
        fs::write(&paths.config_file, &text).unwrap();
        let mut config: Config = toml::from_str(&text).unwrap();
        let key = "cindy/acme/bots/cindy/SOUL.md";
        set_target(&mut config, &paths.config_file, key, true).unwrap();
        assert_eq!(config.sync.target, key);
        assert_eq!(
            config.sync.sources[0].globs,
            vec!["acme/bots/cindy/SOUL.md"]
        );
        let reloaded: Config =
            toml::from_str(&fs::read_to_string(&paths.config_file).unwrap()).unwrap();
        assert_eq!(reloaded.sync.target, key);
        assert_eq!(
            reloaded.sync.sources[0].globs,
            vec!["acme/bots/cindy/SOUL.md"]
        );
        assert!(set_target(&mut config, &paths.config_file, "cindy/../escape.md", true).is_err());
    }

    #[test]
    fn ensure_target_fills_the_single_candidate_without_narrowing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owners");
        let dir = root.join("acme/bots/cindy");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("SOUL.md"), "soul").unwrap();
        let config_file = temp.path().join("config.toml");
        let text = format!(
            "[sync]\ntarget = \"\"\n[[sync.sources]]\nid = \"cindy\"\nroot = \"{}\"\nglobs = [\"*/bots/*/*.md\"]\n",
            root.display()
        );
        fs::write(&config_file, &text).unwrap();
        let mut config: Config = toml::from_str(&text).unwrap();
        let logger = Logger::new(
            &temp.path().join("logs"),
            "test.log",
            crate::logx::Level::Info,
            65536,
            1,
            false,
        )
        .unwrap();

        let chosen = ensure_target(&mut config, &config_file, &logger, false)
            .unwrap()
            .expect("auto-detected target");
        assert_eq!(chosen, "cindy/acme/bots/cindy/SOUL.md");
        assert_eq!(config.sync.target, chosen);
        // Startup auto-detection must not narrow the source globs.
        assert_eq!(config.sync.sources[0].globs, vec!["*/bots/*/*.md"]);
        let reloaded: Config = toml::from_str(&fs::read_to_string(&config_file).unwrap()).unwrap();
        assert_eq!(reloaded.sync.target, chosen);

        // An existing target is left untouched.
        assert_eq!(
            ensure_target(&mut config, &config_file, &logger, false).unwrap(),
            Some(chosen)
        );
    }

    #[test]
    fn ensure_target_does_not_guess_between_multiple_candidates() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owners");
        for bot in ["one", "two"] {
            let dir = root.join(format!("acme/bots/{bot}"));
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("SOUL.md"), format!("soul {bot}")).unwrap();
        }
        let config_file = temp.path().join("config.toml");
        let text = format!(
            "[sync]\ntarget = \"\"\n[[sync.sources]]\nid = \"cindy\"\nroot = \"{}\"\nglobs = [\"*/bots/*/*.md\"]\n",
            root.display()
        );
        fs::write(&config_file, &text).unwrap();
        let mut config: Config = toml::from_str(&text).unwrap();
        let logger = Logger::new(
            &temp.path().join("logs"),
            "test.log",
            crate::logx::Level::Info,
            65536,
            1,
            false,
        )
        .unwrap();
        assert!(ensure_target(&mut config, &config_file, &logger, false)
            .unwrap()
            .is_none());
        assert!(config.sync.target.is_empty());
        let reloaded: Config = toml::from_str(&fs::read_to_string(&config_file).unwrap()).unwrap();
        assert!(reloaded.sync.target.is_empty());
    }

    #[test]
    fn bind_contact_resolves_an_email_and_binds() {
        let mock = MockFeishu::start();
        let mut config = Config::default();
        config.feishu.enabled = true;
        config.feishu.app.app_id = "cli_test".to_string();
        config.feishu.app.app_secret = "secret".to_string();
        config.feishu.app.api_base = mock.base.clone();
        config.feishu.control.bind_contact = "owner@example.com".to_string();
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let (binding, source) = bind_once(&config, &client, "hello").unwrap();
        assert_eq!(source, OwnerSource::Contact);
        assert_eq!(binding.open_id, "ou_owner");
        assert_eq!(binding.chat_id, "oc_p2p");
        assert_eq!(binding.app_id, "cli_test");
        assert!(mock.acks().iter().any(|text| text == "hello"));
    }

    #[test]
    fn bindings_without_a_chat_id_are_rejected() {
        let mut config = Config::default();
        config.feishu.app.app_id = "cli_x".to_string();
        let binding = Binding {
            chat_id: "  ".to_string(),
            open_id: "ou_x".to_string(),
            app_id: "cli_x".to_string(),
            bound_unix: 1,
        };
        let err = checked_binding(&config, binding).unwrap_err();
        assert!(err.to_string().contains("no chat_id"));

        let binding = Binding {
            chat_id: "oc_x".to_string(),
            open_id: "ou_x".to_string(),
            app_id: "cli_other".to_string(),
            bound_unix: 1,
        };
        assert!(checked_binding(&config, binding).is_err());
    }

    #[test]
    fn owner_cell_publishes_the_bound_recipient() {
        let cell = owner_cell("");
        publish_owner(&cell, "ou_new");
        assert_eq!(cell.lock().unwrap().as_deref(), Some("ou_new"));
        publish_owner(&cell, "  ");
        assert_eq!(cell.lock().unwrap().as_deref(), Some("ou_new"));
    }

    #[test]
    fn prunes_old_suffix_backups() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("system_prompt.md");
        fs::write(&file, "current").unwrap();
        for index in 0..5 {
            fs::write(
                temp.path()
                    .join(format!("system_prompt.md.2026010{index}T000000Z.bak")),
                format!("old {index}"),
            )
            .unwrap();
        }
        prune_backups(&file, 2);
        let remaining: Vec<String> = fs::read_dir(temp.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.ends_with(".bak"))
            .collect();
        assert_eq!(remaining.len(), 2);
    }
}
