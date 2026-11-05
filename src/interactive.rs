//! Interactive first-run wizard.
//!
//! One linear step at a time ("下一步" style): every step shows the current or
//! detected value, Enter keeps it, and the wizard ends with a summary that has
//! to be confirmed before the server/agent starts. Feishu pairing happens
//! inside the wizard - there is no separate binding command.

use anyhow::Result;
use std::io::{self, IsTerminal, Write};

use crate::config::{set_value, Config};
use crate::crypto::ClusterSecret;
use crate::feishu::FeishuClient;
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
        println!("进入配置向导，每一步直接回车即可保留当前值。");
    } else {
        println!("首次启动：将用几步确认配置，每一步直接回车即可使用推荐值。");
    }

    let total = match role {
        Role::Server => 5,
        Role::Agent => 4,
    };
    loop {
        match role {
            Role::Server => server_wizard(&mut config, paths, prompter, logger, total, created)?,
            Role::Agent => agent_wizard(&mut config, paths, prompter, logger, total)?,
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
    println!("数据端口只在端口敲门成功后才会绑定；填 0 表示由集群密钥自动推导。");
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

    prompter.step(3, total, "agent 端飞书告警（可选）");
    configure_agent_alerts(config, paths, prompter, logger)?;

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
        "编译进本二进制的那把随机密钥"
    } else {
        "配置文件里的密钥"
    };
    println!("当前使用：{source}（指纹 {}）。", secret.fingerprint());
    println!("如果所有机器用的是同一次编译的二进制，直接回车即可；");
    println!("如果是分别编译的，需要在这里填同一串 64 位 hex（输入内容会显示在终端）。");
    if prompter.confirm("使用当前密钥？", true) {
        return Ok(());
    }
    loop {
        let value = prompter.text("集群密钥（64 位 hex）", "");
        match ClusterSecret::from_hex(&value) {
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
            Err(err) => eprintln!("密钥无效：{err}"),
        }
    }
}

fn configure_feishu(
    config: &mut Config,
    paths: &Paths,
    prompter: &Prompter,
    logger: &Logger,
    default_enabled: bool,
) -> Result<()> {
    println!("飞书用企业自建应用接收你私聊发来的纯文本，覆盖服务端那一个 prompt 文件；");
    println!("同一个应用也用来发离线告警（不再使用群机器人 webhook）。");
    if !prompter.confirm("启用飞书？", default_enabled) {
        apply(paths, Some("feishu"), "enabled", "false")?;
        config.feishu.enabled = false;
        println!("已跳过飞书，稍后重新运行 server 即可再配置。");
        return Ok(());
    }
    apply(paths, Some("feishu"), "enabled", "true")?;
    config.feishu.enabled = true;

    println!("\n需要先在飞书开放平台创建企业自建应用：");
    println!("  1) 启用「机器人」能力；");
    println!("  2) 权限：im:message:readonly、im:message:send_as_bot、im:chat:readonly；");
    println!("  3) 创建版本并发布；");
    println!("  4) 在「凭证与基础信息」里复制 app_id / app_secret。\n");

    loop {
        let app_id = prompter.text("app_id", &config.feishu.app.app_id);
        let app_secret = prompter.text("app_secret", &config.feishu.app.app_secret);
        if app_id.trim().is_empty() || app_secret.trim().is_empty() {
            println!("app_id 和 app_secret 都必须填写。");
            if !prompter.confirm("继续填写？", true) {
                apply(paths, Some("feishu"), "enabled", "false")?;
                config.feishu.enabled = false;
                return Ok(());
            }
            continue;
        }
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
        config.feishu.app.app_id = app_id.trim().to_string();
        config.feishu.app.app_secret = app_secret.trim().to_string();

        print!("校验凭据 … ");
        let _ = io::stdout().flush();
        match FeishuClient::from_config(config).and_then(|client| client.check()) {
            Ok(()) => {
                println!("通过。");
                break;
            }
            Err(err) => {
                println!("失败：{err:#}");
                if !prompter.confirm("重新填写 app_id / app_secret？", true) {
                    return Ok(());
                }
            }
        }
    }

    println!();
    match feishu_control::ensure_binding(config, paths, prompter, logger, true) {
        Ok(Some(binding)) => println!(
            "飞书绑定完成：open_id {}（之后直接在这个私聊里发纯文本即可）。",
            binding.open_id
        ),
        Ok(None) => {
            println!("飞书还没绑定成功。服务仍会启动；下次重新运行 server 进入向导可以再绑一次。")
        }
        Err(err) => {
            println!("飞书绑定失败：{err:#}。服务仍会启动；下次重新运行 server 进入向导可以再试。")
        }
    }
    Ok(())
}

fn configure_agent_alerts(
    config: &mut Config,
    paths: &Paths,
    prompter: &Prompter,
    logger: &Logger,
) -> Result<()> {
    let _ = logger;
    println!("agent 自己发离线告警需要飞书应用凭据；不配置也不影响 prompt 同步。");
    if !prompter.confirm("配置 agent 端离线告警？", config.feishu.enabled) {
        return Ok(());
    }
    loop {
        let app_id = prompter.text("app_id", &config.feishu.app.app_id);
        let app_secret = prompter.text("app_secret", &config.feishu.app.app_secret);
        let owner = prompter.text(
            "告警接收者 open_id（服务端 status --json 可查）",
            &config.feishu.app.owner_open_id,
        );
        if app_id.trim().is_empty() || app_secret.trim().is_empty() || owner.trim().is_empty() {
            println!("app_id、app_secret、owner_open_id 都需要填写。");
            if !prompter.confirm("继续填写？", true) {
                return Ok(());
            }
            continue;
        }
        apply(paths, Some("feishu"), "enabled", "true")?;
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
        apply(
            paths,
            Some("feishu.app"),
            "owner_open_id",
            &toml_string(owner.trim()),
        )?;
        config.feishu.enabled = true;
        config.feishu.app.app_id = app_id.trim().to_string();
        config.feishu.app.app_secret = app_secret.trim().to_string();
        config.feishu.app.owner_open_id = owner.trim().to_string();

        print!("校验凭据 … ");
        let _ = io::stdout().flush();
        match FeishuClient::from_config(config).and_then(|client| client.check()) {
            Ok(()) => {
                println!("通过。");
                return Ok(());
            }
            Err(err) => {
                println!("失败：{err:#}");
                if !prompter.confirm("重新填写？", true) {
                    return Ok(());
                }
            }
        }
    }
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
