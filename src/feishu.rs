//! Feishu (Lark) self-built app client.
//!
//! The old bot webhook is gone: everything (control channel, acknowledgements
//! and offline alerts) uses an app with `app_id`/`app_secret`.
//!
//! Credentials live only in the local config directory and are never compiled
//! into the binary.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::{Config, FeishuAppConfig};
use crate::logx::Logger;

#[derive(Debug, Clone)]
pub struct Message {
    pub id: String,
    pub create_time_ms: u64,
    pub msg_type: String,
    pub content: String,
    pub sender_type: String,
    pub sender_id: String,
    pub chat_id: String,
}

#[derive(Debug, Clone)]
pub struct SentMessage {
    pub message_id: String,
    pub chat_id: String,
}

struct CachedToken {
    token: String,
    valid_until: Instant,
}

pub struct FeishuClient {
    app_id: String,
    app_secret: String,
    api_base: String,
    http: ureq::Agent,
    token: Mutex<Option<CachedToken>>,
}

impl FeishuClient {
    pub fn new(app: &FeishuAppConfig, timeout: Duration) -> Result<Self> {
        let app_id = app.app_id.trim().to_string();
        let app_secret = app.app_secret.trim().to_string();
        if app_id.is_empty() || app_secret.is_empty() {
            bail!("feishu.app.app_id / feishu.app.app_secret are not configured");
        }
        let api_base = app.api_base.trim().trim_end_matches('/').to_string();
        let http = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5).min(timeout))
            .timeout(timeout)
            .build();
        Ok(Self {
            app_id,
            app_secret,
            api_base,
            http,
            token: Mutex::new(None),
        })
    }

    pub fn from_config(config: &Config) -> Result<Self> {
        Self::new(
            &config.feishu.app,
            Duration::from_secs(config.feishu.timeout_secs.max(3)),
        )
    }

    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.api_base, path)
    }

    /// Tenant access token, cached until shortly before it expires.
    pub fn tenant_token(&self) -> Result<String> {
        if let Ok(cached) = self.token.lock() {
            if let Some(cached) = cached.as_ref() {
                if cached.valid_until > Instant::now() {
                    return Ok(cached.token.clone());
                }
            }
        }
        let body = json!({ "app_id": self.app_id, "app_secret": self.app_secret });
        let value = self.post_json(
            "/open-apis/auth/v3/tenant_access_token/internal",
            None,
            &body,
        )?;
        let token = value
            .get("tenant_access_token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if token.is_empty() {
            bail!("Feishu returned no tenant_access_token");
        }
        let expire = value.get("expire").and_then(Value::as_u64).unwrap_or(7200);
        let valid_until = Instant::now() + Duration::from_secs(expire.saturating_sub(120).max(60));
        if let Ok(mut cached) = self.token.lock() {
            *cached = Some(CachedToken {
                token: token.clone(),
                valid_until,
            });
        }
        Ok(token)
    }

    /// Verify credentials by fetching a token.
    pub fn check(&self) -> Result<()> {
        self.tenant_token().map(|_| ())
    }

    pub fn send_text_to(
        &self,
        receive_id_type: &str,
        receive_id: &str,
        text: &str,
    ) -> Result<SentMessage> {
        if receive_id.trim().is_empty() {
            bail!("empty Feishu receive_id");
        }
        let token = self.tenant_token()?;
        let body = json!({
            "receive_id": receive_id,
            "msg_type": "text",
            "content": json!({ "text": text }).to_string(),
        });
        let value = self.post_json(
            &format!("/open-apis/im/v1/messages?receive_id_type={receive_id_type}"),
            Some(&token),
            &body,
        )?;
        let data = value.get("data").cloned().unwrap_or(Value::Null);
        Ok(SentMessage {
            message_id: data
                .get("message_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            chat_id: data
                .get("chat_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }

    pub fn send_text_to_chat(&self, chat_id: &str, text: &str) -> Result<SentMessage> {
        self.send_text_to("chat_id", chat_id, text)
    }

    pub fn send_text_to_owner(&self, open_id: &str, text: &str) -> Result<SentMessage> {
        self.send_text_to("open_id", open_id, text)
    }

    /// Messages in one chat with `create_time` in the given (second) range.
    pub fn list_messages(
        &self,
        chat_id: &str,
        start_secs: u64,
        end_secs: u64,
    ) -> Result<Vec<Message>> {
        let token = self.tenant_token()?;
        let mut messages = Vec::new();
        let mut page_token: Option<String> = None;
        loop {
            let mut path = format!(
                "/open-apis/im/v1/messages?container_id_type=chat&container_id={chat_id}&start_time={start_secs}&end_time={end_secs}&sort_type=ByCreateTimeAsc&page_size=50"
            );
            if let Some(page) = page_token.as_deref() {
                if !page.is_empty() {
                    path.push_str("&page_token=");
                    path.push_str(page);
                }
            }
            let value = self.get_json(&path, Some(&token))?;
            let data = value.get("data").cloned().unwrap_or(Value::Null);
            if let Some(items) = data.get("items").and_then(Value::as_array) {
                for item in items {
                    let sender = item.get("sender").cloned().unwrap_or(Value::Null);
                    let body = item.get("body").cloned().unwrap_or(Value::Null);
                    messages.push(Message {
                        id: item
                            .get("message_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        create_time_ms: item
                            .get("create_time")
                            .and_then(Value::as_str)
                            .unwrap_or("0")
                            .parse()
                            .unwrap_or(0),
                        msg_type: item
                            .get("msg_type")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        content: body
                            .get("content")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        sender_type: sender
                            .get("sender_type")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        sender_id: sender
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        chat_id: item
                            .get("chat_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    });
                }
            }
            let has_more = data
                .get("has_more")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            page_token = data
                .get("page_token")
                .and_then(Value::as_str)
                .map(str::to_string);
            if !has_more || page_token.is_none() {
                break;
            }
        }
        messages.sort_by_key(|message| message.create_time_ms);
        Ok(messages)
    }

    /// Resolve a Feishu email or mobile number to an open_id.
    /// Needs the `contact:user.id:readonly` permission.
    pub fn lookup_open_id(&self, contact: &str) -> Result<String> {
        let contact = contact.trim();
        if contact.is_empty() {
            bail!("empty contact");
        }
        let token = self.tenant_token()?;
        let body = if contact.contains('@') {
            json!({ "emails": [contact] })
        } else {
            json!({ "mobiles": [contact] })
        };
        let value = self.post_json(
            "/open-apis/contact/v3/users/batch_get_id?user_id_type=open_id",
            Some(&token),
            &body,
        )?;
        let list = value
            .pointer("/data/user_list")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for entry in list {
            if let Some(id) = entry.get("user_id").and_then(Value::as_str) {
                if !id.is_empty() {
                    return Ok(id.to_string());
                }
            }
        }
        bail!("Feishu could not resolve {contact} to an open_id (check the contact permission)")
    }

    /// The account that owns this app, as an open_id in this app's namespace.
    ///
    /// Feishu exposes the app's own `owner.owner_id` (and `creator_id`) to the
    /// app itself with a tenant token, so the alert recipient can be resolved
    /// automatically: nobody has to message the bot first.
    pub fn app_owner_open_id(&self) -> Result<String> {
        let token = self.tenant_token()?;
        let path = format!(
            "/open-apis/application/v6/applications/{}?lang=zh_cn",
            self.app_id
        );
        let value = self.get_json(&path, Some(&token))?;
        let app = value.pointer("/data/app").cloned().unwrap_or(Value::Null);
        for pointer in ["/owner/owner_id", "/creator_id"] {
            if let Some(id) = app.pointer(pointer).and_then(Value::as_str) {
                if !id.is_empty() {
                    return Ok(id.to_string());
                }
            }
        }
        bail!(
            "Feishu returned no owner for app {} (needs application:application:self_manage on a published app)",
            self.app_id
        )
    }

    fn post_json(&self, path: &str, token: Option<&str>, body: &Value) -> Result<Value> {
        let mut request = self
            .http
            .post(&self.url(path))
            .set("Content-Type", "application/json; charset=utf-8");
        if let Some(token) = token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        match request.send_json(body) {
            Ok(response) => {
                let text = response.into_string().unwrap_or_default();
                parse_response(&text)
            }
            Err(ureq::Error::Status(code, response)) => {
                let text = response.into_string().unwrap_or_default();
                bail!("Feishu HTTP {code} for {path}: {text}");
            }
            Err(err) => bail!("Feishu request to {path} failed: {err}"),
        }
    }

    fn get_json(&self, path: &str, token: Option<&str>) -> Result<Value> {
        let mut request = self.http.get(&self.url(path));
        if let Some(token) = token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        match request.call() {
            Ok(response) => {
                let text = response.into_string().unwrap_or_default();
                parse_response(&text)
            }
            Err(ureq::Error::Status(code, response)) => {
                let text = response.into_string().unwrap_or_default();
                bail!("Feishu HTTP {code} for {path}: {text}");
            }
            Err(err) => bail!("Feishu request to {path} failed: {err}"),
        }
    }
}

/// Feishu's account host, used by the app-registration (device code) flow.
pub const FEISHU_ACCOUNTS_BASE: &str = "https://accounts.feishu.cn";
/// Feishu's open-platform host, used for the verification page link.
pub const FEISHU_OPEN_BASE: &str = "https://open.feishu.cn";

/// A pending "one-click app creation" session.
#[derive(Debug, Clone)]
pub struct AppRegistration {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// The app credentials produced after the user confirms in the browser.
#[derive(Debug, Clone)]
pub struct RegisteredApp {
    pub app_id: String,
    pub app_secret: String,
    pub owner_open_id: Option<String>,
    pub tenant_brand: Option<String>,
}

/// One poll result of the app-registration device flow.
#[derive(Debug, Clone)]
pub enum RegistrationPoll {
    Pending,
    SlowDown,
    Success(RegisteredApp),
    Denied(String),
    Expired(String),
}

fn post_form(agent: &ureq::Agent, url: &str, fields: &[(&str, &str)]) -> Result<Value> {
    let response = match agent.post(url).send_form(fields) {
        Ok(response) => response,
        Err(ureq::Error::Status(code, response)) => {
            let text = response.into_string().unwrap_or_default();
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                return Ok(value);
            }
            bail!("Feishu HTTP {code} for {url}: {text}");
        }
        Err(err) => bail!("Feishu request to {url} failed: {err}"),
    };
    let text = response.into_string().unwrap_or_default();
    serde_json::from_str(&text)
        .with_context(|| format!("Feishu returned invalid JSON from {url}: {text}"))
}

/// Start a one-click app registration: Feishu returns a short user code and a
/// verification URL the user opens to create/authorise a PersonalAgent app.
pub fn begin_app_registration(timeout: Duration) -> Result<AppRegistration> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5).min(timeout))
        .timeout(timeout)
        .build();
    let value = post_form(
        &agent,
        &format!("{FEISHU_ACCOUNTS_BASE}/oauth/v1/app/registration"),
        &[
            ("action", "begin"),
            ("archetype", "PersonalAgent"),
            ("auth_method", "client_secret"),
            ("request_user_info", "open_id tenant_brand"),
        ],
    )?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        let detail = value
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or("");
        bail!("Feishu app registration failed: {error} {detail}");
    }
    let device_code = value
        .get("device_code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let user_code = value
        .get("user_code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if device_code.is_empty() || user_code.is_empty() {
        bail!("Feishu app registration returned no device_code/user_code");
    }
    let verification_url =
        format!("{FEISHU_OPEN_BASE}/page/cli?user_code={user_code}&from=xdt-maker");
    Ok(AppRegistration {
        device_code,
        user_code,
        verification_url,
        expires_in: value
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(300),
        interval: value.get("interval").and_then(Value::as_u64).unwrap_or(5),
    })
}

/// Poll the registration flow once.
pub fn poll_app_registration(device_code: &str, timeout: Duration) -> Result<RegistrationPoll> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5).min(timeout))
        .timeout(timeout)
        .build();
    let value = post_form(
        &agent,
        &format!("{FEISHU_ACCOUNTS_BASE}/oauth/v1/app/registration"),
        &[("action", "poll"), ("device_code", device_code)],
    )?;
    Ok(parse_registration_poll(&value))
}

fn parse_registration_poll(value: &Value) -> RegistrationPoll {
    let user_info = value.get("user_info").cloned().unwrap_or(Value::Null);
    let owner_open_id = user_info
        .get("open_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string);
    let tenant_brand = user_info
        .get("tenant_brand")
        .and_then(Value::as_str)
        .filter(|brand| !brand.is_empty())
        .map(str::to_string);
    let error = value
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let detail = value
        .get("error_description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if error.is_empty() {
        let app_id = value
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let app_secret = value
            .get("client_secret")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if !app_id.is_empty() && !app_secret.is_empty() {
            return RegistrationPoll::Success(RegisteredApp {
                app_id,
                app_secret,
                owner_open_id,
                tenant_brand,
            });
        }
        return RegistrationPoll::Pending;
    }
    match error {
        "authorization_pending" => RegistrationPoll::Pending,
        "slow_down" => RegistrationPoll::SlowDown,
        "access_denied" => RegistrationPoll::Denied(detail.to_string()),
        "expired_token" | "invalid_grant" => RegistrationPoll::Expired(detail.to_string()),
        other => RegistrationPoll::Denied(format!("{other} {detail}").trim().to_string()),
    }
}

fn parse_response(text: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(text)
        .with_context(|| format!("Feishu returned invalid JSON: {text}"))?;
    let code = value.get("code").and_then(Value::as_i64).unwrap_or(0);
    if code != 0 {
        let msg = value.get("msg").and_then(Value::as_str).unwrap_or("");
        bail!("Feishu API error {code}: {msg}");
    }
    Ok(value)
}

/// Extract the plain text of a `text` message, stripping @mentions.
/// Returns `None` for any other message type (rich text, files, images...).
pub fn message_text(message: &Message) -> Option<String> {
    if message.msg_type != "text" {
        return None;
    }
    let content: Value = serde_json::from_str(&message.content).ok()?;
    let text = content.get("text")?.as_str()?;
    Some(normalize_text(&strip_mentions(text)))
}

pub fn normalize_text(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

fn strip_mentions(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        let rest = &text[index..];
        if let Some(tail) = rest.strip_prefix("@_user_") {
            let digits = tail.chars().take_while(|c| c.is_ascii_digit()).count();
            if digits > 0 {
                index += "@_user_".len() + digits;
                if text[index..].starts_with(' ') {
                    index += 1;
                }
                continue;
            }
        }
        if rest.starts_with("@_all") {
            index += "@_all".len();
            if text[index..].starts_with(' ') {
                index += 1;
            }
            continue;
        }
        let ch = rest.chars().next().expect("non-empty remainder");
        output.push(ch);
        index += ch.len_utf8();
    }
    output
}

/// One-line description of the Feishu configuration state, for logs/status.
pub fn describe(config: &Config) -> String {
    if !config.feishu.enabled {
        return "disabled".to_string();
    }
    if !config.feishu_app_configured() {
        return "enabled, no app credentials".to_string();
    }
    // A configured recipient is not the same as a saved private-chat binding;
    // say what is actually known here (the binding file is checked separately).
    let recipient = if config.feishu_bound() {
        "recipient set"
    } else {
        "no recipient yet"
    };
    format!("enabled ({recipient})")
}

/// Send an alert to the bound owner through the app.
pub fn notify_blocking(config: &Config, text: &str) -> Result<()> {
    if !config.feishu.enabled {
        bail!("Feishu notifications are disabled (feishu.enabled = false)");
    }
    if !config.feishu_app_configured() {
        bail!("Feishu app credentials are missing (feishu.app.app_id / app_secret)");
    }
    let owner = config.feishu.app.owner_open_id.trim();
    if owner.is_empty() {
        bail!("Feishu owner is not bound yet (bind it from the `promptsync server` wizard)");
    }
    let client = FeishuClient::from_config(config)?;
    client.send_text_to_owner(owner, text)?;
    Ok(())
}

pub fn spawn_notify(config: &Config, logger: &Logger, text: String) {
    if !config.feishu.enabled {
        logger.info(format!("Feishu disabled, notification suppressed: {text}"));
        return;
    }
    let config = config.clone();
    let logger = logger.clone();
    tokio::spawn(async move {
        let result = tokio::task::spawn_blocking(move || notify_blocking(&config, &text)).await;
        match result {
            Ok(Ok(())) => logger.info("Feishu notification sent"),
            Ok(Err(err)) => logger.error(format!("Feishu notification failed: {err:#}")),
            Err(err) => logger.error(format!("Feishu task panicked: {err}")),
        }
    });
}

pub fn offline_alert(
    role: &str,
    agent_id: &str,
    host: &str,
    peer: &str,
    offline_secs: u64,
    last_success: Option<String>,
    last_error: &str,
) -> String {
    format!(
        "【promptsync 离线告警】\n角色: {role}\n节点: {agent_id} ({host})\n对端: {peer}\n连续失联: {}秒\n最后成功: {}\n最近错误: {last_error}\n时间: {}",
        offline_secs,
        last_success.unwrap_or_else(|| "从未成功".to_string()),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%SZ"),
    )
}

pub fn format_unix(timestamp: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp as i64, 0)
        .map(|value| value.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| timestamp.to_string())
}

pub fn recovery_message(role: &str, agent_id: &str, host: &str, peer: &str) -> String {
    format!(
        "【promptsync 恢复通知】\n角色: {role}\n节点: {agent_id} ({host})\n对端: {peer}\n状态: 已恢复同步\n时间: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%SZ"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_message(content: &str) -> Message {
        Message {
            id: "m1".to_string(),
            create_time_ms: 1,
            msg_type: "text".to_string(),
            content: json!({ "text": content }).to_string(),
            sender_type: "user".to_string(),
            sender_id: "ou_x".to_string(),
            chat_id: "oc_x".to_string(),
        }
    }

    #[test]
    fn extracts_plain_text_and_strips_mentions() {
        let message = text_message("@_user_1 这是新的 prompt\n第二行");
        assert_eq!(message_text(&message).unwrap(), "这是新的 prompt\n第二行");
        let message = text_message("@_all hello");
        assert_eq!(message_text(&message).unwrap(), "hello");
    }

    #[test]
    fn rejects_non_text_messages() {
        let mut message = text_message("x");
        message.msg_type = "post".to_string();
        assert!(message_text(&message).is_none());
        message.msg_type = "file".to_string();
        assert!(message_text(&message).is_none());
    }

    #[test]
    fn normalizes_newlines() {
        assert_eq!(normalize_text("a\r\nb\rc"), "a\nb\nc");
    }

    #[test]
    fn parses_api_errors() {
        assert!(parse_response(r#"{"code":0,"msg":"ok","data":{}}"#).is_ok());
        let err = parse_response(r#"{"code":99991663,"msg":"invalid token"}"#).unwrap_err();
        assert!(err.to_string().contains("99991663"));
    }
}

#[cfg(test)]
mod registration_tests {
    use super::*;

    #[test]
    fn poll_success_carries_owner() {
        let value = serde_json::json!({
            "client_id": "cli_x",
            "client_secret": "sec",
            "user_info": {"open_id": "ou_1", "tenant_brand": "feishu"}
        });
        match parse_registration_poll(&value) {
            RegistrationPoll::Success(app) => {
                assert_eq!(app.app_id, "cli_x");
                assert_eq!(app.app_secret, "sec");
                assert_eq!(app.owner_open_id.as_deref(), Some("ou_1"));
                assert_eq!(app.tenant_brand.as_deref(), Some("feishu"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn poll_pending_and_denied() {
        assert!(matches!(
            parse_registration_poll(&serde_json::json!({"error": "authorization_pending"})),
            RegistrationPoll::Pending
        ));
        assert!(matches!(
            parse_registration_poll(&serde_json::json!({"error": "slow_down"})),
            RegistrationPoll::SlowDown
        ));
        assert!(matches!(
            parse_registration_poll(&serde_json::json!({"error": "access_denied"})),
            RegistrationPoll::Denied(_)
        ));
        assert!(matches!(
            parse_registration_poll(&serde_json::json!({"error": "expired_token"})),
            RegistrationPoll::Expired(_)
        ));
    }
}
