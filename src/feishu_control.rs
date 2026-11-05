//! Feishu control channel: first-start binding and the ingest loop that turns
//! private-chat text messages into the one managed prompt file.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{set_source_globs, set_value, Config};
use crate::feishu::{self, message_text, FeishuClient};
use crate::globpat;
use crate::interactive::Prompter;
use crate::logx::Logger;
use crate::paths::Paths;
use crate::prompts::SourceSpec;
use crate::util::{atomic_write, now_unix, safe_relative_path};

pub const BINDING_FILE: &str = "feishu-binding.json";
pub const CURSOR_FILE: &str = "feishu-cursor.json";
const SEEN_IDS_LIMIT: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub chat_id: String,
    pub open_id: String,
    pub bound_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cursor {
    last_create_time_ms: u64,
    #[serde(default)]
    seen_ids: Vec<String>,
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
        self.last_create_time_ms = self.last_create_time_ms.max(create_time_ms);
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
        bail!("sync.target is not configured (single-file mode)");
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
    Ok(TargetFile {
        key: target.to_string(),
        path: source.root.join(relative),
    })
}

pub fn load_binding(data_dir: &Path) -> Option<Binding> {
    let path = data_dir.join(BINDING_FILE);
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

fn save_binding(data_dir: &Path, binding: &Binding) -> Result<()> {
    fs::create_dir_all(data_dir)?;
    let serialized = serde_json::to_vec_pretty(binding)?;
    atomic_write(&data_dir.join(BINDING_FILE), &serialized, true)
        .context("writing feishu-binding.json")
}

/// First-start binding.
///
/// Order of attempts:
/// 1. `owner_open_id` already configured: ping the owner, learn the chat id.
/// 2. QR/link + "send the bot a message", then discover the p2p chat.
/// 3. Fall back to a Feishu email/mobile (`feishu.control.bind_contact` or a prompt).
pub fn ensure_binding(
    config: &mut Config,
    paths: &Paths,
    prompter: &Prompter,
    logger: &Logger,
    force: bool,
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
            if !config.feishu.app.owner_open_id.trim().is_empty() {
                return Ok(Some(binding));
            }
        }
    }

    let client = FeishuClient::from_config(config)?;
    client.check().context("verifying Feishu app credentials")?;

    // 1. owner_open_id configured manually: send a message to learn the chat id.
    let configured_owner = config.feishu.app.owner_open_id.trim().to_string();
    if !configured_owner.is_empty() {
        let sent = client
            .send_text_to_owner(
                &configured_owner,
                "promptsync：绑定检查，稍后你就可以直接发 prompt 了。",
            )
            .context("sending the binding check message")?;
        let binding = Binding {
            chat_id: sent.chat_id,
            open_id: configured_owner,
            bound_unix: now_unix(),
        };
        save_binding(&data_dir, &binding)?;
        logger.info(format!(
            "Feishu bound via configured owner_open_id (chat {})",
            binding.chat_id
        ));
        return Ok(Some(binding));
    }

    let app_link = format!(
        "https://applink.feishu.cn/client/bot/open?appId={}",
        config.feishu.app.app_id.trim()
    );

    if !prompter.enabled() {
        logger.warn(format!(
            "Feishu app is not bound. Open {app_link} in Feishu, send the bot a message, then re-run `promptsync server` to finish binding."
        ));
        return Ok(None);
    }

    println!("\n=== 绑定飞书机器人 ===");
    println!("1) 用飞书扫描下面的二维码，或直接打开链接：\n   {app_link}\n");
    print_qr(&app_link);
    println!("2) 在打开的机器人私聊里发送任意一句话（例如：绑定）");
    println!(
        "3) 最多等待 {} 秒，检测到消息后会自动完成绑定\n",
        config.feishu.control.bind_timeout_secs.max(15)
    );

    let deadline =
        Instant::now() + Duration::from_secs(config.feishu.control.bind_timeout_secs.max(15));
    while Instant::now() < deadline {
        match discover_p2p_binding(&client) {
            Ok(Some(binding)) => {
                save_binding(&data_dir, &binding)?;
                set_value(
                    &paths.config_file,
                    Some("feishu.app"),
                    "owner_open_id",
                    &format!("\"{}\"", binding.open_id),
                )?;
                let _ = client.send_text_to_chat(
                    &binding.chat_id,
                    "promptsync 绑定成功。以后直接把纯文本 prompt 发给我，我会覆盖服务端的那个文件。",
                );
                logger.info(format!(
                    "Feishu bound: chat {} owner {}",
                    binding.chat_id, binding.open_id
                ));
                return Ok(Some(binding));
            }
            Ok(None) => {}
            Err(err) => logger.debug(format!("Feishu binding poll failed: {err:#}")),
        }
        std::thread::sleep(Duration::from_secs(2));
    }

    let contact = {
        let configured = config.feishu.control.bind_contact.trim().to_string();
        if configured.is_empty() {
            prompter.text(
                "未检测到私聊消息。可输入飞书账号邮箱/手机号完成绑定（留空取消）",
                "",
            )
        } else {
            configured
        }
    };
    if contact.trim().is_empty() {
        logger.warn("Feishu binding cancelled");
        return Ok(None);
    }
    let open_id = client
        .lookup_open_id(contact.trim())
        .context("resolving the Feishu account")?;
    let sent = client
        .send_text_to_owner(
            &open_id,
            "promptsync 绑定成功。以后直接把纯文本 prompt 发给我即可覆盖服务端文件。",
        )
        .context("sending the binding message")?;
    let binding = Binding {
        chat_id: sent.chat_id,
        open_id: open_id.clone(),
        bound_unix: now_unix(),
    };
    save_binding(&data_dir, &binding)?;
    set_value(
        &paths.config_file,
        Some("feishu.app"),
        "owner_open_id",
        &format!("\"{open_id}\""),
    )?;
    logger.info(format!(
        "Feishu bound via contact lookup: chat {} owner {open_id}",
        binding.chat_id
    ));
    Ok(Some(binding))
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
pub fn set_target(config: &mut Config, paths: &Paths, key: &str, narrow: bool) -> Result<()> {
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
    set_value(
        &paths.config_file,
        Some("sync"),
        "target",
        &format!("\"{key}\""),
    )?;
    if narrow {
        let (id, relative) = key
            .split_once('/')
            .context("sync.target has no source id")?;
        set_source_globs(&paths.config_file, id, &[relative.to_string()])?;
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

fn qr_art(link: &str) -> Option<String> {
    let code = qrcode::QrCode::new(link.as_bytes()).ok()?;
    Some(
        code.render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .build(),
    )
}

fn print_qr(link: &str) {
    match qr_art(link) {
        Some(art) => println!("{art}\n"),
        None => println!("（二维码生成失败，请直接使用上面的链接）\n"),
    }
}

/// Look for a private chat that already contains a message from a user.
/// Feishu may not list p2p chats at all; in that case this returns `None` and
/// the caller falls back to the contact lookup.
fn discover_p2p_binding(client: &FeishuClient) -> Result<Option<Binding>> {
    let now = now_unix();
    for chat in client.list_chats()? {
        if chat.mode != "p2p" {
            continue;
        }
        let messages = client.list_messages(&chat.chat_id, now.saturating_sub(900), now + 60)?;
        for message in messages.iter().rev() {
            if message.sender_type == "user" && !message.sender_id.is_empty() {
                return Ok(Some(Binding {
                    chat_id: chat.chat_id.clone(),
                    open_id: message.sender_id.clone(),
                    bound_unix: now,
                }));
            }
        }
    }
    Ok(None)
}

/// Ingest loop (runs on the server).
pub async fn run(
    config: Config,
    data_dir: PathBuf,
    target: TargetFile,
    binding: Binding,
    logger: Logger,
) -> Result<()> {
    let client = Arc::new(FeishuClient::from_config(&config)?);
    let poll = Duration::from_secs(config.feishu.control.poll_secs.max(2));
    let mut cursor = Cursor::load(&data_dir, (binding.bound_unix + 2) * 1000);

    loop {
        let started = Instant::now();
        let client = client.clone();
        let binding = binding.clone();
        let target = target.clone();
        let config = config.clone();
        let snapshot = cursor.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            poll_once(&config, &client, &binding, &target, &snapshot)
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
        if message.chat_id != binding.chat_id || message.sender_type != "user" {
            cursor.record(&message.id, message.create_time_ms);
            continue;
        }
        if message.sender_id != binding.open_id {
            cursor.record(&message.id, message.create_time_ms);
            continue;
        }

        let reply = match apply_message(config, client, binding, target, &message) {
            Ok(Applied::Ignored { reason }) => {
                cursor.record(&message.id, message.create_time_ms);
                reason
            }
            Ok(Applied::Written {
                bytes,
                hash,
                backup,
            }) => {
                cursor.record(&message.id, message.create_time_ms);
                log_message = Some(format!(
                    "Feishu update: {} ({} B, sha256 {}, backup {})",
                    target.key,
                    bytes,
                    &hash[..8.min(hash.len())],
                    backup
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "none".to_string())
                ));
                Some(format!(
                    "✅ 已更新 {}（{bytes} B，sha256 {}）",
                    target.key,
                    &hash[..8.min(hash.len())]
                ))
            }
            Ok(Applied::DryRun { bytes, hash }) => {
                cursor.record(&message.id, message.create_time_ms);
                Some(format!(
                    "🧪 dry-run：将更新 {}（{bytes} B，sha256 {}），未写入",
                    target.key,
                    &hash[..8.min(hash.len())]
                ))
            }
            Err(err) => {
                cursor.record(&message.id, message.create_time_ms);
                log_message = Some(format!("Feishu update rejected: {err:#}"));
                Some(format!("❌ 未更新：{err:#}"))
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
    Written {
        bytes: usize,
        hash: String,
        backup: Option<PathBuf>,
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
        bail!(
            "内容 {} B 超过上限 {} B",
            text.len(),
            config.feishu.control.max_message_bytes
        );
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
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
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
    Ok(Applied::Written {
        bytes,
        hash,
        backup,
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
        chats: Arc<Mutex<Vec<serde_json::Value>>>,
        sent: Arc<Mutex<Vec<String>>>,
    }

    impl MockFeishu {
        fn start() -> Self {
            let server = Server::http("127.0.0.1:0").expect("mock server");
            let port = server.server_addr().to_ip().expect("ip addr").port();
            let messages = Arc::new(Mutex::new(Vec::new()));
            let chats = Arc::new(Mutex::new(Vec::new()));
            let sent = Arc::new(Mutex::new(Vec::new()));
            let (m, c, s) = (messages.clone(), chats.clone(), sent.clone());
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
                        ("GET", "/open-apis/im/v1/chats") => {
                            json!({ "code": 0, "data": { "items": *c.lock().unwrap(), "has_more": false } })
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
                chats,
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
            bound_unix: now_unix(),
        };
        let cursor = Cursor {
            last_create_time_ms: now_unix() * 1000 - 5000,
            seen_ids: Vec::new(),
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
    fn discovers_the_private_chat_and_skips_groups() {
        let mock = MockFeishu::start();
        mock.chats.lock().unwrap().push(json!({
            "chat_id": "oc_group", "chat_mode": "group", "name": "team"
        }));
        mock.chats.lock().unwrap().push(json!({
            "chat_id": "oc_p2p", "chat_mode": "p2p", "name": ""
        }));
        mock.push_text("绑定", "ou_owner");
        let mut config = Config::default();
        config.feishu.app.app_id = "cli_test".to_string();
        config.feishu.app.app_secret = "secret".to_string();
        config.feishu.app.api_base = mock.base.clone();
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let binding = discover_p2p_binding(&client).unwrap().expect("binding");
        assert_eq!(binding.chat_id, "oc_p2p");
        assert_eq!(binding.open_id, "ou_owner");
    }

    #[test]
    fn applies_owner_text_and_creates_a_suffix_backup() {
        let mock = MockFeishu::start();
        mock.push_text("new prompt\nsecond line", "ou_owner");
        let (config, _temp, target, binding, cursor) = fixture(&mock);
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let outcome = poll_once(&config, &client, &binding, &target, &cursor).unwrap();

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
    fn ignores_other_senders_and_non_text_and_duplicates() {
        let mock = MockFeishu::start();
        mock.push_text("from a stranger", "ou_someone");
        let (mut config, _temp, target, binding, cursor) = fixture(&mock);
        let client = FeishuClient::new(&config.feishu.app, Duration::from_secs(5)).unwrap();
        let outcome = poll_once(&config, &client, &binding, &target, &cursor).unwrap();
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
        let outcome = poll_once(&config, &client, &binding, &target, &cursor).unwrap();
        assert!(outcome.log_message.is_none());
        assert_eq!(fs::read_to_string(&target.path).unwrap(), "old prompt\n");
        assert!(mock.acks().iter().any(|ack| ack.contains("纯文本")));

        // dry-run never writes.
        config.feishu.control.dry_run = true;
        mock.messages.lock().unwrap().clear();
        mock.push_text("dry run content", "ou_owner");
        let _ = poll_once(&config, &client, &binding, &target, &cursor).unwrap();
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
        let outcome = poll_once(&config, &client, &binding, &target, &cursor).unwrap();
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
        let outcome = poll_once(&config, &client, &binding, &target, &cursor).unwrap();
        assert_eq!(fs::read_to_string(&target.path).unwrap(), "old prompt\n");
        assert!(outcome.log_message.unwrap().contains("rejected"));
        assert!(mock.acks().iter().any(|ack| ack.contains("超过上限")));
    }

    #[test]
    fn cursor_deduplicates_and_bounds_ids() {
        let mut cursor = Cursor {
            last_create_time_ms: 0,
            seen_ids: Vec::new(),
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
        assert_eq!(target.path, root.join("acme/bots/cindy/system_prompt.md"));

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
        set_target(&mut config, &paths, key, true).unwrap();
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
        assert!(set_target(&mut config, &paths, "cindy/../escape.md", true).is_err());
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
