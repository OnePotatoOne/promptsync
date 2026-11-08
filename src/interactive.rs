//! Interactive first-run wizard.
//!
//! One linear step at a time ("下一步" style): every step shows the current or
//! detected value, Enter keeps it, and the wizard ends with a summary that has
//! to be confirmed before the server/agent starts. Feishu pairing happens
//! inside the wizard - there is no separate binding command.

use anyhow::Result;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

use crate::config::{set_value, Config};
use crate::crypto::ClusterSecret;
use crate::feishu::{self, FeishuClient};
use crate::feishu_control;
use crate::logx::Logger;
use crate::paths::Paths;
use crate::util::toml_string;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Agent,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Server => "server",
            Role::Agent => "agent",
        }
    }
}

#[derive(Clone)]
pub struct Prompter {
    enabled: bool,
}

impl Prompter {
    pub fn new(enabled: bool) -> Self {
        let enabled = enabled && io::stdin().is_terminal() && io::stdout().is_terminal();
        Self { enabled }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn ask(&self, prompt: &str) -> Option<String> {
        print!("{prompt}");
        let _ = io::stdout().flush();
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(line.trim().to_string()),
            Err(_) => None,
        }
    }

    /// Print a `[n/total] title` heading.
    pub fn step(&self, index: usize, total: usize, title: &str) {
        if !self.enabled {
            return;
        }
        println!("\n──── 第 {index}/{total} 步：{title} ────");
    }

    pub fn confirm(&self, question: &str, default: bool) -> bool {
        if !self.enabled {
            return default;
        }
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        loop {
            match self.ask(&format!("{question} {hint} ")) {
                None => return default,
                Some(answer) => {
                    if answer.is_empty() {
                        return default;
                    }
                    if let Some(value) = parse_yes_no(&answer) {
                        return value;
                    }
                    eprintln!("请输入 y 或 n。");
                }
            }
        }
    }

    pub fn select(&self, question: &str, options: &[String], default: usize) -> usize {
        if !self.enabled {
            return default;
        }
        println!("\n{question}");
        for (index, option) in options.iter().enumerate() {
            let marker = if index == default { ">" } else { " " };
            println!("  {marker} {}. {option}", index + 1);
        }
        loop {
            match self.ask(&format!("选择 [{}]: ", default + 1)) {
                None => return default,
                Some(answer) => {
                    if answer.is_empty() {
                        return default;
                    }
                    if let Some(index) = parse_choice(&answer, options.len()) {
                        return index;
                    }
                    eprintln!("请输入 1-{} 之间的序号。", options.len());
                }
            }
        }
    }

    pub fn text(&self, label: &str, current: &str) -> String {
        if !self.enabled {
            return current.to_string();
        }
        let prompt = if current.is_empty() {
            format!("{label}: ")
        } else {
            format!("{label} [{current}]: ")
        };
        match self.ask(&prompt) {
            None => current.to_string(),
            Some(answer) if answer.is_empty() => current.to_string(),
            Some(answer) => answer,
        }
    }
}

pub fn parse_yes_no(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" | "是" | "好" | "确认" => Some(true),
        "n" | "no" | "否" | "不" => Some(false),
        _ => None,
    }
}

pub fn parse_choice(value: &str, count: usize) -> Option<usize> {
    let number: usize = value.trim().parse().ok()?;
    if number >= 1 && number <= count {
        Some(number - 1)
    } else {
        None
    }
}

/// First-run state passed into [`prepare`].
#[derive(Debug, Clone, Copy)]
pub struct PrepareOptions {
    /// The config file was created from the template on this start.
    pub created: bool,
    /// `--configure`: run the wizard even when the config already exists.
    pub force_wizard: bool,
}

/// Entry point used by `server` and `agent`.
///
/// * non-interactive: print a one-line hint when the config was just created.
/// * existing config and no `--configure`: start immediately and print a short
///   summary. The common path must not cost a keypress.
/// * otherwise: run the stepped wizard once, then print the summary and start.
pub fn prepare(
    paths: &Paths,
    config: Config,
    role: Role,
    prompter: &Prompter,
    logger: &Logger,
    options: PrepareOptions,
) -> Result<Option<Config>> {
    let PrepareOptions {
        created,
        force_wizard,
    } = options;
    if !prompter.enabled() {
        if created {
            eprintln!(
                "[promptsync] 已创建 {}；集群密钥已生成，用 `promptsync secret --show` 查看。非交互环境不进入向导，要改配置就编辑该文件或加 `--configure`。",
                paths.config_file.display()
            );
        }
        return Ok(Some(config));
    }

    let mut config = config;
    if !created && !force_wizard {
        print_startup_summary(&config, paths, role);
        return Ok(Some(config));
    }
    if created {
        println!("首次启动：回车使用推荐值。");
    } else {
        println!("进入配置向导，回车保留当前值。");
    }

    // The summary at the end is not a numbered step: every step already
    // persisted its value, so there is nothing left to confirm.
    let total = match role {
        Role::Server => 4,
        Role::Agent => 3,
    };
    match role {
        Role::Server => server_wizard(&mut config, paths, prompter, logger, total, created)?,
        Role::Agent => agent_wizard(&mut config, paths, prompter, logger, total, created)?,
    }
    let (reloaded, _) = paths.load()?;
    config = reloaded;
    print_summary(&config, paths, role);
    Ok(Some(config))
}

/// One-line Feishu state for the startup summary.
fn feishu_state_text(config: &Config) -> String {
    if !config.feishu.enabled {
        return "未启用".to_string();
    }
    if !config.feishu_app_configured() {
        return "已启用，缺少 app_id / app_secret".to_string();
    }
    let owner = config.feishu.app.owner_open_id.trim();
    if owner.is_empty() {
        "已启用，接收人自动识别（应用所有者）".to_string()
    } else {
        format!("已启用，接收人 {}", mask_id(owner))
    }
}

/// Short summary shown when an existing config is used as-is.
fn print_startup_summary(config: &Config, paths: &Paths, role: Role) {
    println!("\n──── 配置已就绪 ────");
    println!("配置文件     {}", paths.config_file.display());
    match role {
        Role::Server => println!(
            "受管文件     {}",
            if config.sync.target.trim().is_empty() {
                "启动时自动识别".to_string()
            } else {
                config.sync.target.trim().to_string()
            }
        ),
        Role::Agent => println!(
            "服务端       {}:{}",
            config.agent.server,
            if config.agent.port == 0 {
                "自动端口".to_string()
            } else {
                config.agent.port.to_string()
            }
        ),
    }
    println!("飞书         {}", feishu_state_text(config));
    println!(
        "要改配置     编辑上面的文件，或重新运行 `promptsync {} --configure`",
        role.label()
    );
    println!();
}

fn server_wizard(
    config: &mut Config,
    paths: &Paths,
    prompter: &Prompter,
    logger: &Logger,
    total: usize,
    first_run: bool,
) -> Result<()> {
    prompter.step(1, total, "监听地址与数据端口");
    println!("数据端口在敲门成功后才会绑定；0 = 自动推导。");
    let bind = prompter.text("监听地址", &config.server.bind);
    let port = ask_port(prompter, "数据端口（0 = 自动推导）", config.server.port)?;
    apply(paths, Some("server"), "bind", &toml_string(bind.trim()))?;
    apply(paths, Some("server"), "port", &port.to_string())?;
    config.server.bind = bind.trim().to_string();
    config.server.port = port;

    prompter.step(2, total, "要同步的 prompt 文件");
    configure_target(config, paths, prompter)?;

    prompter.step(3, total, "集群密钥");
    configure_secret(config, paths, prompter)?;

    prompter.step(4, total, "飞书（私聊覆盖 prompt + 离线告警）");
    configure_feishu(
        config,
        paths,
        prompter,
        logger,
        first_run || config.feishu.enabled,
        Role::Server,
    )?;
    Ok(())
}

fn agent_wizard(
    config: &mut Config,
    paths: &Paths,
    prompter: &Prompter,
    logger: &Logger,
    total: usize,
    first_run: bool,
) -> Result<()> {
    prompter.step(1, total, "服务端地址");
    let server = prompter.text("服务端主机名或 IP", &config.agent.server);
    let port = ask_port(prompter, "数据端口（0 = 自动推导）", config.agent.port)?;
    apply(paths, Some("agent"), "server", &toml_string(server.trim()))?;
    apply(paths, Some("agent"), "port", &port.to_string())?;
    config.agent.server = server.trim().to_string();
    config.agent.port = port;

    prompter.step(2, total, "集群密钥");
    configure_secret(config, paths, prompter)?;

    prompter.step(3, total, "飞书（离线告警）");
    configure_feishu(
        config,
        paths,
        prompter,
        logger,
        first_run || config.feishu.enabled,
        Role::Agent,
    )?;
    Ok(())
}

fn apply(paths: &Paths, section: Option<&str>, key: &str, literal: &str) -> Result<()> {
    set_value(&paths.config_file, section, key, literal)
}

fn ask_port(prompter: &Prompter, label: &str, current: u16) -> Result<u16> {
    loop {
        let value = prompter.text(label, &current.to_string());
        match value.trim().parse::<u16>() {
            Ok(port) => return Ok(port),
            Err(_) => eprintln!("端口必须是 0-65535 的数字。"),
        }
    }
}

fn configure_target(config: &mut Config, paths: &Paths, prompter: &Prompter) -> Result<()> {
    let candidates = feishu_control::target_candidates(config)?;
    if candidates.is_empty() {
        println!("没有在同步源里找到 system_prompt.md / SOUL.md。");
        if offer_starter_target(config, paths, prompter)? {
            return Ok(());
        }
        let manual = prompter.text(
            "手动输入 sync.target（<source id>/<相对路径>，留空跳过）",
            config.sync.target.trim(),
        );
        if manual.trim().is_empty() {
            println!("已跳过：稍后可以在配置里设置 sync.target。");
        } else {
            feishu_control::set_target(config, &paths.config_file, manual.trim(), false)?;
            println!("已设置 sync.target = {}", config.sync.target);
        }
        return Ok(());
    }

    let current = config.sync.target.trim().to_string();
    let non_empty: Vec<&feishu_control::TargetCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.bytes > 0)
        .collect();
    let options: Vec<String> = candidates
        .iter()
        .map(|candidate| {
            let mark = if candidate.key == current {
                "  ← 当前"
            } else {
                ""
            };
            let empty = if candidate.bytes == 0 { "  (空)" } else { "" };
            format!("{}  ({} B){empty}{mark}", candidate.key, candidate.bytes)
        })
        .collect();
    let default = candidates
        .iter()
        .position(|candidate| candidate.key == current)
        .unwrap_or(0);
    let chosen_index = if non_empty.len() == 1 {
        let index = candidates
            .iter()
            .position(|candidate| candidate.key == non_empty[0].key)
            .unwrap_or(0);
        println!(
            "检测到唯一非空的 prompt：{}（{} B）",
            candidates[index].key, candidates[index].bytes
        );
        index
    } else if candidates.len() == 1 {
        println!("检测到唯一候选：{}", candidates[0].key);
        0
    } else {
        prompter.select(
            "检测到多个 prompt 文件，选择要维护的那一个：",
            &options,
            default,
        )
    };
    let key = candidates[chosen_index].key.clone();
    // One managed file is the product default: the control channel always
    // overwrites exactly this file. Narrowing the globs keeps the bundle small
    // and is what the old confirmation offered by default, so do it silently.
    feishu_control::set_target(config, &paths.config_file, &key, true)?;
    println!("已设置为唯一受管文件：{key}（其它文件停止管理，不删除）");
    Ok(())
}

/// When no prompt file exists yet, offer a working default instead of asking
/// the user to type a `<source id>/<path>` key. One Enter is enough to end up
/// with a usable, synced file.
fn offer_starter_target(config: &mut Config, paths: &Paths, prompter: &Prompter) -> Result<bool> {
    let Some(source) = config
        .sync
        .sources
        .iter()
        .find(|source| source.id == "shared")
        .cloned()
    else {
        return Ok(false);
    };
    let root = crate::util::expand_tilde(&source.root);
    let path = root.join("prompt.md");
    if !prompter.confirm(
        &format!("创建一个新的受管 prompt（{}）？", path.display()),
        true,
    ) {
        return Ok(false);
    }
    fs::create_dir_all(&root)?;
    if !path.exists() {
        fs::write(
            &path,
            "# 系统提示词\n\n在这里写内容；之后也可以直接给飞书机器人发纯文本覆盖这个文件。\n",
        )?;
    }
    feishu_control::set_target(config, &paths.config_file, "shared/prompt.md", true)?;
    println!("已创建受管文件：{}", path.display());
    Ok(true)
}

fn configure_secret(config: &mut Config, paths: &Paths, prompter: &Prompter) -> Result<()> {
    let secret = ClusterSecret::resolve(&config.cluster_secret)?;
    // Printed in full (not just the fingerprint) so it can be copied straight
    // to the other machine without opening config.toml.
    println!(
        "当前集群密钥（复制下面这串到其他机器）：\n\n   {}\n",
        secret.to_hex()
    );
    println!(
        "指纹 {}；已保存在 {}。",
        secret.fingerprint(),
        paths.config_file.display()
    );
    println!("输入所有机器共用的同一句口令；直接回车保留上面这把：");
    loop {
        let value = prompter.text("集群口令", "");
        if value.trim().is_empty() {
            return Ok(());
        }
        if let Some(warning) = ClusterSecret::passphrase_warning(&value) {
            eprintln!("{warning}");
        }
        match ClusterSecret::from_input(&value) {
            Ok(secret) => {
                apply(
                    paths,
                    None,
                    "cluster_secret",
                    &toml_string(&secret.to_hex()),
                )?;
                config.cluster_secret = secret.to_hex();
                println!(
                    "已更新，新密钥（复制这串到其他机器）：\n\n   {}\n\n指纹 {}；已写入 {}",
                    secret.to_hex(),
                    secret.fingerprint(),
                    paths.config_file.display()
                );
                return Ok(());
            }
            Err(err) => eprintln!("口令无效：{err}"),
        }
    }
}

fn configure_feishu(
    config: &mut Config,
    paths: &Paths,
    prompter: &Prompter,
    logger: &Logger,
    default_enabled: bool,
    role: Role,
) -> Result<()> {
    match role {
        Role::Server => println!("飞书自建应用：私聊发纯文本覆盖 prompt，同时发送离线告警。"),
        Role::Agent => println!("飞书自建应用：离线告警会发到你的私聊。"),
    }
    if !prompter.confirm("启用飞书？", default_enabled) {
        apply(paths, Some("feishu"), "enabled", "false")?;
        config.feishu.enabled = false;
        println!("已跳过飞书，稍后重新运行 {} 即可再配置。", role.label());
        return Ok(());
    }
    apply(paths, Some("feishu"), "enabled", "true")?;
    config.feishu.enabled = true;

    let has_app = !config.feishu.app.app_id.trim().is_empty()
        && !config.feishu.app.app_secret.trim().is_empty();
    if has_app {
        println!("已配置应用 {}。", mask_id(config.feishu.app.app_id.trim()));
        if prompter.confirm("继续使用这个应用？", true) {
            return finish_feishu(config, paths, logger, role);
        }
    }

    let options = [
        "一键创建（推荐）：点开链接确认，自动填好凭据".to_string(),
        "已有应用：手动粘贴 app_id / app_secret".to_string(),
        "跳过飞书".to_string(),
    ];
    let choice = prompter.select(
        "创建飞书应用（已有应用可打开 https://open.feishu.cn/app 查看列表）：",
        &options,
        0,
    );
    match choice {
        0 => {
            if let Err(err) = register_feishu_app(config, paths) {
                println!("一键创建没有完成：{err:#}");
                if prompter.confirm("改为手动粘贴 app_id / app_secret？", true) {
                    manual_feishu_credentials(config, paths, prompter, role)?;
                } else {
                    apply(paths, Some("feishu"), "enabled", "false")?;
                    config.feishu.enabled = false;
                    println!("已跳过飞书，稍后重新运行 {} 即可再配置。", role.label());
                    return Ok(());
                }
            }
        }
        1 => manual_feishu_credentials(config, paths, prompter, role)?,
        _ => {
            apply(paths, Some("feishu"), "enabled", "false")?;
            config.feishu.enabled = false;
            println!("已跳过飞书，稍后重新运行 {} 即可再配置。", role.label());
            return Ok(());
        }
    }
    finish_feishu(config, paths, logger, role)
}

/// Short safe rendering of an app id for prompts/logs.
fn mask_id(app_id: &str) -> String {
    let chars: Vec<char> = app_id.chars().collect();
    if chars.len() <= 10 {
        return app_id.to_string();
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// One-click creation: ask Feishu for a device code, show the link + QR, then
/// poll until the user confirms in the browser. On success the returned
/// credentials and the owner open_id are written straight into config.toml.
fn register_feishu_app(config: &mut Config, paths: &Paths) -> Result<()> {
    println!(
        "
正在向飞书申请一个自建应用…"
    );
    let registration = feishu::begin_app_registration(Duration::from_secs(20))?;
    println!("请打开下面的链接（或扫码），在飞书里点「确认创建」：\n");
    println!("  {}\n", registration.verification_url);
    feishu_control::print_qr(&registration.verification_url);
    println!(
        "确认后这里会自动继续，不需要复制粘贴；链接 {} 秒内有效。",
        registration.expires_in
    );
    let deadline = Instant::now() + Duration::from_secs(registration.expires_in.clamp(30, 900));
    let mut interval = registration.interval.clamp(2, 10);
    loop {
        if Instant::now() >= deadline {
            anyhow::bail!("链接已过期");
        }
        std::thread::sleep(Duration::from_secs(interval));
        match feishu::poll_app_registration(&registration.device_code, Duration::from_secs(20))? {
            feishu::RegistrationPoll::Pending => {}
            feishu::RegistrationPoll::SlowDown => interval = (interval + 5).min(15),
            feishu::RegistrationPoll::Success(app) => {
                apply(
                    paths,
                    Some("feishu.app"),
                    "app_id",
                    &toml_string(&app.app_id),
                )?;
                apply(
                    paths,
                    Some("feishu.app"),
                    "app_secret",
                    &toml_string(&app.app_secret),
                )?;
                config.feishu.app.app_id = app.app_id.clone();
                config.feishu.app.app_secret = app.app_secret.clone();
                if let Some(owner) = app.owner_open_id.as_deref() {
                    if !owner.is_empty() {
                        apply(
                            paths,
                            Some("feishu.app"),
                            "owner_open_id",
                            &toml_string(owner),
                        )?;
                        config.feishu.app.owner_open_id = owner.to_string();
                    }
                }
                println!(
                    "已创建应用 {}（owner {}）。",
                    mask_id(&app.app_id),
                    app.owner_open_id.as_deref().unwrap_or("未返回")
                );
                return Ok(());
            }
            feishu::RegistrationPoll::Denied(message) => {
                anyhow::bail!("你在飞书里取消了授权 {message}")
            }
            feishu::RegistrationPoll::Expired(message) => {
                anyhow::bail!("链接已过期 {message}")
            }
        }
    }
}

fn manual_feishu_credentials(
    config: &mut Config,
    paths: &Paths,
    prompter: &Prompter,
    role: Role,
) -> Result<()> {
    println!(
        "\n打开 https://open.feishu.cn/app ，进入应用 → 凭证与基础信息，复制 app_id / app_secret。"
    );
    match role {
        Role::Server => println!(
            "应用需要机器人能力和 im:message:readonly、im:message:send_as_bot、im:chat:readonly 权限。"
        ),
        Role::Agent => println!(
            "应用至少需要 im:message:send_as_bot（自动绑定只发一条消息，不需要读权限）。"
        ),
    }
    loop {
        let app_id = prompter.text("app_id", &config.feishu.app.app_id);
        let app_secret = prompter.text("app_secret", &config.feishu.app.app_secret);
        if app_id.trim().is_empty() || app_secret.trim().is_empty() {
            println!("app_id 和 app_secret 都必须填写。");
            if !prompter.confirm("继续填写？", true) {
                anyhow::bail!("没有填写 app_id / app_secret");
            }
            continue;
        }
        config.feishu.app.app_id = app_id.trim().to_string();
        config.feishu.app.app_secret = app_secret.trim().to_string();
        apply(
            paths,
            Some("feishu.app"),
            "app_id",
            &toml_string(app_id.trim()),
        )?;
        apply(
            paths,
            Some("feishu.app"),
            "app_secret",
            &toml_string(app_secret.trim()),
        )?;
        return Ok(());
    }
}

fn finish_feishu(config: &mut Config, paths: &Paths, logger: &Logger, role: Role) -> Result<()> {
    print!("校验凭据 … ");
    let _ = io::stdout().flush();
    match FeishuClient::from_config(config).and_then(|client| client.check()) {
        Ok(()) => println!("通过。"),
        Err(err) => {
            println!("失败：{err:#}");
            println!("应用凭据已保存；可在下次运行 {} 时重新配置。", role.label());
            return Ok(());
        }
    }

    println!();
    // Enabling the server's control channel requires a managed file. Fill it in
    // here so the wizard never produces a config that silently disables Feishu.
    if role == Role::Server && config.sync.target.trim().is_empty() {
        match feishu_control::ensure_target(config, &paths.config_file, logger, false) {
            Ok(Some(key)) => println!("已自动选定受管文件：{key}"),
            Ok(None) => println!(
                "警告：还没有受管文件（sync.target），飞书控制通道不会启动；请设置 [sync] target 或重新运行向导第 2 步。"
            ),
            Err(err) => println!("自动识别 sync.target 失败：{err:#}"),
        }
    }
    // Binding is fully automatic: the recipient is the app owner (or whatever
    // `owner_open_id` pins) and the chat id comes back from the send itself, so
    // the wizard never asks the user to send a message from Feishu.
    let purpose = match role {
        Role::Server => feishu_control::BindingPurpose::Server,
        Role::Agent => feishu_control::BindingPurpose::Agent,
    };
    match feishu_control::ensure_binding(config, paths, logger, true, purpose) {
        Ok(Some(binding)) => {
            match role {
                Role::Server => println!(
                    "飞书已自动绑定：接收人 open_id {}（确认消息已发送，之后直接在这个私聊里发纯文本即可）。",
                    binding.open_id
                ),
                Role::Agent => println!(
                    "飞书告警已自动绑定：接收人 open_id {}（确认消息已发送）。",
                    binding.open_id
                ),
            }
            println!("注意：server 与 agent 绑定的是同一个飞书应用（app_id 相同），只需要绑一次；");
            println!(
                "      私聊里发 --help 可以查状态（--status / --agents / --config），以 -- 开头的消息只查询，不会覆盖文件。"
            );
        }
        Ok(None) => {
            println!("飞书已启用，但这次没能自动绑定；启动后会继续自动重试，不会让你去发绑定码。");
            println!("要指定别人接收，可在 config.toml 的 [feishu.app] 填写 owner_open_id。");
        }
        Err(err) => println!("飞书绑定失败：{err:#}。启动后会自动重试。"),
    }
    Ok(())
}

fn print_summary(config: &Config, paths: &Paths, role: Role) {
    let secret = ClusterSecret::resolve(&config.cluster_secret).ok();
    let server_endpoints = secret
        .as_ref()
        .map(|secret| crate::knock::server_ports(&config.server, secret));
    let agent_endpoints = secret
        .as_ref()
        .map(|secret| crate::knock::agent_ports(&config.agent, secret));
    let adapters = crate::adapters::detect(&config.sync);

    println!("\n──── 配置摘要 ────");
    println!("版本         {}", crate::buildinfo::description());
    println!("角色         {}", role.label());
    println!("配置文件     {}", paths.config_file.display());
    println!("配置目录     {}", paths.config_dir.display());
    println!("状态目录     {}", paths.data_dir().display());
    println!("日志目录     {}", paths.log_dir(config).display());

    if let Some(secret) = &secret {
        // Always print the secret itself: it is the value that has to be copied
        // to the other machines, and hunting for it in config.toml is busywork.
        println!("集群密钥     {}", secret.to_hex());
        println!(
            "密钥位置     {} -> cluster_secret",
            paths.config_file.display()
        );
        println!("密钥指纹     {}", secret.fingerprint());
        println!("             复制上面这串到其他机器；不要发到公开群或提交到 git。");
    } else {
        println!("集群密钥     无法解析，请重新运行并检查 cluster_secret");
    }

    if role == Role::Server {
        if let Some(ports) = &server_endpoints {
            println!(
                "监听         {}:{}",
                config.server.bind,
                if config.server.port == 0 {
                    format!("{}（自动）", ports.main)
                } else {
                    config.server.port.to_string()
                }
            );
            println!("数据端口     {}", ports.main);
            println!(
                "敲门端口     {} 个：{:?}",
                ports.knock_pool.len(),
                ports.knock_pool
            );
            // A cloud VM or a host firewall silences the knocks, and the agent
            // can then only report "no handshake answer": the server never
            // opens its data port, so there is nothing to answer with.
            println!(
                "⚠ 防火墙      云主机/ufw 必须放行 UDP {} 和全部敲门端口，否则 agent 只会看到 no handshake answer。",
                ports.main
            );
            println!(
                "              例如：sudo ufw allow {}/udp && sudo ufw allow 20000:60000/udp（或把 [server] knock_ports 固定成几个端口，只放行它们）",
                ports.main
            );
        }
        println!(
            "受管文件     {}",
            if config.sync.target.trim().is_empty() {
                "（未设置）"
            } else {
                config.sync.target.trim()
            }
        );
        println!("同步源       {} 个", config.sync.sources.len());
    } else {
        if let Some(ports) = &agent_endpoints {
            println!(
                "服务端       {}:{}",
                config.agent.server,
                if config.agent.port == 0 {
                    format!("{}（自动）", ports.main)
                } else {
                    config.agent.port.to_string()
                }
            );
            println!(
                "轮询/离线    {}s / {}s",
                config.agent.poll_secs, config.agent.offline_threshold_secs
            );
            // A hand-typed port is the classic cause of a silent handshake
            // failure: the server derives its data port from the same secret,
            // so a pinned number only works when the server pins it too.
            if config.agent.port != 0 && config.agent.port != ports.main {
                println!(
                    "⚠ 端口填的是 {}，但用同一密钥推导出来的是 {}；除非服务端 [server] 里也写了 port = {}，否则这一步应该填 0（握手会一直超时）。",
                    config.agent.port, ports.main, config.agent.port
                );
            }
        }
        println!("节点 ID      {}", crate::agent::effective_agent_id(config));
        println!(
            "受管文件     {}",
            if config.sync.target.trim().is_empty() {
                "（由服务端下发）"
            } else {
                config.sync.target.trim()
            }
        );
        println!("同步源       {} 个", config.sync.sources.len());
    }

    if role == Role::Server {
        // Only the agent writes client files; the server just serves the bundle.
        println!("客户端适配   由 agent 决定（server 不写本机客户端文件）");
    } else {
        println!(
            "客户端适配   {}{}",
            if config.sync.adapt_clients {
                "启用"
            } else {
                "关闭"
            },
            if adapters.is_empty() {
                "（未检测到客户端）".to_string()
            } else {
                format!(
                    "，检测到 {} 个：{}",
                    adapters.len(),
                    adapters
                        .iter()
                        .map(|adapter| adapter.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        );
    }

    println!("飞书         {}", feishu_state_text(config));
    if config.feishu.enabled {
        let app_id = config.feishu.app.app_id.trim();
        println!(
            "飞书应用     {}",
            if app_id.is_empty() {
                "未配置".to_string()
            } else {
                mask_id(app_id)
            }
        );
        let owner = config.feishu.app.owner_open_id.trim();
        if role == Role::Server {
            println!(
                "告警接收人   {}",
                if owner.is_empty() {
                    "未绑定".to_string()
                } else {
                    mask_id(owner)
                }
            );
            // The control channel only exists on the server; an agent has no
            // sync.target of its own.
            println!(
                "飞书控制     target={} dry_run={}",
                if config.sync.target.trim().is_empty() {
                    "-"
                } else {
                    config.sync.target.trim()
                },
                config.feishu.control.dry_run
            );
            if config.sync.target.trim().is_empty() {
                println!("             ⚠ 未设置 sync.target：飞书控制通道不会启动");
            }
        } else {
            println!(
                "告警接收人   {}",
                if owner.is_empty() {
                    "自动识别（应用所有者）".to_string()
                } else {
                    mask_id(owner)
                }
            );
        }
    }

    println!();
    match role {
        Role::Server => {
            println!("下一步       其他机器首次启动时，在集群密钥步骤粘贴上面那串密钥；");
            println!("             或运行 promptsync secret --set \"<这串密钥>\"。");
        }
        Role::Agent => {
            println!("下一步       确认上面的密钥与服务端一致；不一致就重新运行");
            println!("             promptsync agent，在集群密钥步骤粘贴服务端那串。");
        }
    }
    println!(
        "改配置       编辑 {}，或重新运行 `promptsync {} --configure`",
        paths.config_file.display(),
        role.label()
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yes_no() {
        assert_eq!(parse_yes_no("y"), Some(true));
        assert_eq!(parse_yes_no("是"), Some(true));
        assert_eq!(parse_yes_no("n"), Some(false));
        assert_eq!(parse_yes_no("maybe"), None);
    }

    #[test]
    fn parses_menu_choice() {
        assert_eq!(parse_choice("1", 3), Some(0));
        assert_eq!(parse_choice("3", 3), Some(2));
        assert_eq!(parse_choice("4", 3), None);
    }

    #[test]
    fn prompts_are_disabled_without_a_terminal() {
        let prompter = Prompter::new(false);
        assert!(!prompter.enabled());
        assert!(prompter.confirm("q", true));
        assert!(!prompter.confirm("q", false));
        assert_eq!(prompter.text("q", "keep"), "keep");
    }
}
