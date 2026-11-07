//! Interactive first-run wizard.
//!
//! One linear step at a time ("下一步" style): every step shows the current or
//! detected value, Enter keeps it, and the wizard ends with a summary that has
//! to be confirmed before the server/agent starts. Feishu pairing happens
//! inside the wizard - there is no separate binding command.

use anyhow::Result;
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

/// Entry point used by `server` and `agent`.
///
/// * non-interactive: print a one-line hint when the config was just created.
/// * existing config: ask once whether to start with it.
/// * otherwise: run the stepped wizard, then a summary confirmation.
pub fn prepare(
    paths: &Paths,
    config: Config,
    created: bool,
    role: Role,
    prompter: &Prompter,
    logger: &Logger,
) -> Result<Option<Config>> {
    if !prompter.enabled() {
        if created {
            eprintln!(
                "[promptsync] 已从模板创建 {}。请按需修改后启动；非交互环境不会进入配置向导。",
                paths.config_file.display()
            );
        }
        return Ok(Some(config));
    }

    let mut config = config;
    if !created {
        println!("\n检测到已有配置：{}", paths.config_file.display());
        if prompter.confirm("直接使用它启动？", true) {
            return Ok(Some(config));
        }
        println!("进入配置向导，回车保留当前值。");
    } else {
        println!("首次启动：回车使用推荐值。");
    }

    let total = match role {
        Role::Server => 5,
        Role::Agent => 4,
    };
    loop {
        match role {
            Role::Server => server_wizard(&mut config, paths, prompter, logger, total, created)?,
            Role::Agent => agent_wizard(&mut config, paths, prompter, logger, total, created)?,
        }
        let (reloaded, _) = paths.load()?;
        config = reloaded;
        print_summary(&config, paths, role);
        if prompter.confirm("保存并启动？", true) {
            return Ok(Some(config));
        }
        if !prompter.confirm("重新配置一遍？", true) {
            return Ok(None);
        }
    }
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

    prompter.step(5, total, "确认");
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

    prompter.step(4, total, "确认");
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
        let manual = prompter.text(
            "手动输入 sync.target（<source id>/<相对路径>，留空跳过）",
            config.sync.target.trim(),
        );
        if manual.trim().is_empty() {
            println!("已跳过：稍后可以在配置里设置 sync.target。");
        } else {
            feishu_control::set_target(config, paths, manual.trim(), false)?;
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
    let narrow = if candidates.len() > 1 || current != key {
        prompter.confirm("以后只同步这一个文件？（其它文件停止管理，不删除）", true)
    } else {
        true
    };
    feishu_control::set_target(config, paths, &key, narrow)?;
    println!("已设置为唯一受管文件：{key}");
    Ok(())
}

fn configure_secret(config: &mut Config, paths: &Paths, prompter: &Prompter) -> Result<()> {
    let secret = ClusterSecret::resolve(&config.cluster_secret)?;
    let source = if config.cluster_secret.trim().is_empty() {
        "内置"
    } else {
        "配置"
    };
    println!("当前：{source}密钥，指纹 {}。", secret.fingerprint());
    println!("输入所有机器共用的同一句口令（回车保持不变）：");
    loop {
        let value = prompter.text("集群口令", "");
        if value.trim().is_empty() {
            return Ok(());
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
                println!("已更新，指纹 {}。", secret.fingerprint());
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
            return finish_feishu(config, paths, prompter, logger, role);
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
    finish_feishu(config, paths, prompter, logger, role)
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
            "应用至少需要 im:message:send_as_bot；扫码绑定还需要 im:message:readonly、im:chat:readonly。"
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

fn finish_feishu(
    config: &mut Config,
    paths: &Paths,
    prompter: &Prompter,
    logger: &Logger,
    role: Role,
) -> Result<()> {
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
    // An agent only needs the owner open_id to send alerts. Asking for it here
    // also supports send-only apps that cannot discover the private chat.
    if role == Role::Agent && config.feishu.app.owner_open_id.trim().is_empty() {
        let owner = prompter.text(
            "告警接收者 open_id（留空则扫码绑定；服务端 status --json 可查）",
            "",
        );
        if !owner.trim().is_empty() {
            apply(
                paths,
                Some("feishu.app"),
                "owner_open_id",
                &toml_string(owner.trim()),
            )?;
            config.feishu.app.owner_open_id = owner.trim().to_string();
        }
    }
    let purpose = match role {
        Role::Server => feishu_control::BindingPurpose::Server,
        Role::Agent => feishu_control::BindingPurpose::Agent,
    };
    match feishu_control::ensure_binding(config, paths, prompter, logger, true, purpose) {
        Ok(Some(binding)) => match role {
            Role::Server => println!(
                "飞书绑定完成：open_id {}（之后直接在这个私聊里发纯文本即可）。",
                binding.open_id
            ),
            Role::Agent => {
                println!("飞书告警已连接：open_id {}。", binding.open_id)
            }
        },
        Ok(None) => match role {
            Role::Server => {
                println!("飞书还没完成绑定；服务启动后会自动等待你发来第一条私聊消息。")
            }
            Role::Agent => {
                println!("飞书还没完成绑定；离线告警暂不会发送，重新运行 agent 可再配置。")
            }
        },
        Err(err) => match role {
            Role::Server => println!("飞书绑定失败：{err:#}。服务启动后仍会自动重试。"),
            Role::Agent => println!("飞书告警绑定失败：{err:#}。可重新运行 agent 再配置。"),
        },
    }
    Ok(())
}

fn print_summary(config: &Config, paths: &Paths, role: Role) {
    let ports = match ClusterSecret::resolve(&config.cluster_secret) {
        Ok(secret) => crate::knock::server_ports(&config.server, &secret),
        Err(_) => crate::knock::Ports {
            main: config.server.port,
            knock_pool: Vec::new(),
        },
    };
    println!("\n──── 配置摘要 ────");
    println!("配置文件   {}", paths.config_file.display());
    if role == Role::Server {
        println!(
            "监听       {}:{}",
            config.server.bind,
            if config.server.port == 0 {
                format!("{}（自动）", ports.main)
            } else {
                config.server.port.to_string()
            }
        );
        println!("敲门端口   {}", ports.knock_pool.len());
        println!(
            "受管文件   {}",
            if config.sync.target.trim().is_empty() {
                "（未设置）"
            } else {
                config.sync.target.trim()
            }
        );
    } else {
        println!(
            "服务端     {}:{}",
            config.agent.server,
            if config.agent.port == 0 {
                "自动".to_string()
            } else {
                config.agent.port.to_string()
            }
        );
    }
    println!(
        "集群密钥   {}",
        if config.cluster_secret.trim().is_empty() {
            "使用编译进二进制的密钥"
        } else {
            "配置文件中的密钥"
        }
    );
    println!("飞书       {}", crate::feishu::describe(config));
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
