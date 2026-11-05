//! Interactive start-up prompts.
//!
//! * First start: the config was just created from the template, so the user
//!   gets a short guide and may edit it right away.
//! * Later starts: confirm that the existing config should be used (default
//!   yes); answering no opens either a small key/value wizard or $EDITOR.
//!
//! Prompts only appear when stdin/stdout are terminals and no explicit
//! overrides were given, so services, pipes and tests never block.

use anyhow::{bail, Context, Result};
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::process::Command;

use crate::config::{set_value, Config};
use crate::paths::Paths;

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

    pub fn select(&self, question: &str, options: &[&str], default: usize) -> usize {
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

/// Run the start-up guidance. Returns the config that should be used.
pub fn prepare(
    paths: &Paths,
    config: Config,
    created: bool,
    role: Role,
    prompter: &Prompter,
) -> Result<Config> {
    if !prompter.enabled() {
        if created {
            eprintln!(
                "[promptsync] 已从模板创建 {}。请按需修改（agent 必须设置 agent.server）后启动；非交互环境不会等待输入。",
                paths.config_file.display()
            );
        }
        return Ok(config);
    }

    println!();
    if created {
        println!("首次启动：config 目录为空，已按模板生成配置。");
    } else {
        println!("已检测到已有配置。");
    }
    print_guidance(paths, &config, role);

    if !created && prompter.confirm("是否使用已有配置启动？", true) {
        return Ok(config);
    }

    // On the very first agent start the server address is still the template
    // placeholder, so default to the guided edit instead of starting blindly.
    let default_choice = if created && role == Role::Agent && is_loopback(&config.agent.server) {
        1
    } else {
        0
    };
    let choice = prompter.select(
        "现在要做什么？",
        &[
            "直接使用当前配置启动",
            "交互式修改关键项后启动",
            "用编辑器打开配置文件后启动",
        ],
        default_choice,
    );
    match choice {
        0 => Ok(config),
        1 => customize(paths, config, role, prompter),
        _ => edit_in_editor(paths, config, role, prompter),
    }
}

fn is_loopback(host: &str) -> bool {
    matches!(
        host.trim().to_ascii_lowercase().as_str(),
        "" | "127.0.0.1" | "localhost" | "::1" | "[::1]"
    )
}

fn print_guidance(paths: &Paths, config: &Config, role: Role) {
    println!("  config: {}", paths.config_file.display());
    println!("  state : {}", paths.data_dir().display());
    println!("  logs  : {}", paths.log_dir(config).display());
    println!("\n请按指引确认以下配置（直接回车 = 使用默认值）：");
    match role {
        Role::Agent => {
            println!(
                "  [agent] server = \"{}\"    <- 必须改成服务端 IP / 主机名",
                config.agent.server
            );
            println!(
                "  [agent] port = {}          <- 0 = 由集群密钥自动推导（需与服务端一致）",
                config.agent.port
            );
        }
        Role::Server => {
            println!(
                "  [server] bind = \"{}\"    <- 对外监听地址",
                config.server.bind
            );
            println!(
                "  [server] port = {}          <- 0 = 由集群密钥自动推导",
                config.server.port
            );
            println!(
                "  [sync] target = \"{}\"   <- 飞书私聊覆盖的那一个文件",
                config.sync.target
            );
        }
    }
    println!(
        "  cluster_secret = {}   <- 不同次编译的二进制需填成同一个 64 位 hex",
        if config.cluster_secret.trim().is_empty() {
            "\"\"  (使用编译进二进制的密钥)"
        } else {
            "\"...\"  (已配置)"
        }
    );
    println!(
        "  [feishu] app_id = {}   <- 可选；自建应用，控制私聊 + 离线告警",
        if config.feishu.app.app_id.trim().is_empty() {
            "\"\"  (未配置)"
        } else {
            "\"cli_...\"  (已配置)"
        }
    );
    println!(
        "  [[sync.sources]] = {} 个同步源   <- 要同步的 prompt 目录",
        config.sync.sources.len()
    );
    println!();
}

fn customize(paths: &Paths, mut config: Config, role: Role, prompter: &Prompter) -> Result<Config> {
    loop {
        match role {
            Role::Agent => {
                let server = prompter.text("服务端地址 (agent.server)", &config.agent.server);
                let port = ask_port(prompter, "数据端口 (agent.port, 0=自动)", config.agent.port)?;
                set_value(
                    &paths.config_file,
                    Some("agent"),
                    "server",
                    &toml_string(&server),
                )?;
                set_value(&paths.config_file, Some("agent"), "port", &port.to_string())?;
            }
            Role::Server => {
                let bind = prompter.text("监听地址 (server.bind)", &config.server.bind);
                let port = ask_port(
                    prompter,
                    "数据端口 (server.port, 0=自动)",
                    config.server.port,
                )?;
                set_value(
                    &paths.config_file,
                    Some("server"),
                    "bind",
                    &toml_string(&bind),
                )?;
                set_value(
                    &paths.config_file,
                    Some("server"),
                    "port",
                    &port.to_string(),
                )?;
            }
        }
        println!(
            "\n已写回 {}（集群密钥对齐：promptsync secret --set <hex>）",
            paths.config_file.display()
        );
        println!(
            "飞书控制/告警：在配置的 [feishu.app] 填 app_id/app_secret（enabled = true），然后运行 `promptsync feishu-bind` 完成扫码绑定。"
        );
        match paths.load() {
            Ok((reloaded, _)) => return Ok(reloaded),
            Err(err) => {
                eprintln!("配置校验失败：{err:#}");
                if !prompter.confirm("重新修改？", true) {
                    return Err(err);
                }
                config = reload_fallback(paths).unwrap_or(config);
            }
        }
    }
}

fn reload_fallback(paths: &Paths) -> Option<Config> {
    paths.load().ok().map(|(config, _)| config)
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

fn edit_in_editor(
    paths: &Paths,
    config: Config,
    role: Role,
    prompter: &Prompter,
) -> Result<Config> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| default_editor().to_string());
    loop {
        println!(
            "\n用编辑器打开（保存后退出即可继续）:\n  {editor} {}",
            paths.config_file.display()
        );
        match run_editor(&editor, &paths.config_file) {
            Ok(()) => {}
            Err(err) => {
                eprintln!("无法启动编辑器：{err:#}");
                if prompter.confirm("改为交互式修改关键项？", true) {
                    return customize(paths, config, role, prompter);
                }
                return Err(err);
            }
        }
        match paths.load() {
            Ok((reloaded, _)) => return Ok(reloaded),
            Err(err) => {
                eprintln!("配置校验失败：{err:#}");
                if !prompter.confirm("再次编辑？", true) {
                    return Err(err);
                }
            }
        }
    }
}

fn run_editor(editor: &str, file: &Path) -> Result<()> {
    let mut parts = editor.split_whitespace();
    let program = parts.next().context("empty editor command")?;
    let mut command = Command::new(program);
    for arg in parts {
        command.arg(arg);
    }
    let status = command
        .arg(file)
        .status()
        .with_context(|| format!("running editor {editor}"))?;
    if !status.success() {
        bail!("editor exited with {status}");
    }
    Ok(())
}

fn default_editor() -> &'static str {
    if cfg!(windows) {
        "notepad"
    } else {
        "vi"
    }
}

fn toml_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yes_no() {
        assert_eq!(parse_yes_no("y"), Some(true));
        assert_eq!(parse_yes_no("YES"), Some(true));
        assert_eq!(parse_yes_no("是"), Some(true));
        assert_eq!(parse_yes_no("n"), Some(false));
        assert_eq!(parse_yes_no("否"), Some(false));
        assert_eq!(parse_yes_no("maybe"), None);
    }

    #[test]
    fn parses_menu_choice() {
        assert_eq!(parse_choice("1", 3), Some(0));
        assert_eq!(parse_choice("3", 3), Some(2));
        assert_eq!(parse_choice("4", 3), None);
        assert_eq!(parse_choice("0", 3), None);
        assert_eq!(parse_choice("x", 3), None);
    }

    #[test]
    fn prompts_are_disabled_without_a_terminal() {
        let prompter = Prompter::new(false);
        assert!(!prompter.enabled());
        assert!(prompter.confirm("q", true));
        assert!(!prompter.confirm("q", false));
        assert_eq!(prompter.select("q", &["a", "b"], 1), 1);
        assert_eq!(prompter.text("q", "keep"), "keep");
    }
}
