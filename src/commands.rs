//! Read-only commands sent from the bound Feishu private chat.
//!
//! Any message whose first non-space characters are `--` is a command, never
//! prompt content: it is answered with a status view and the managed file is
//! left untouched. An unknown verb answers with the manual instead of failing
//! silently, so a typo can never overwrite a prompt.

use chrono::{TimeZone, Utc};

/// One agent as reported by the server registry.
#[derive(Debug, Clone)]
pub struct AgentRow {
    pub id: String,
    pub last_seen_unix: u64,
    pub peer: String,
    pub hash: String,
}

/// Everything a `--command` may print.
///
/// The server rebuilds this on every request, so a reply always shows live
/// numbers (epoch, online agents, bound chat) instead of what was true at
/// startup.
#[derive(Debug, Clone, Default)]
pub struct Status {
    pub version: String,
    pub build: String,
    pub config_file: String,
    pub log_file: String,
    pub target: String,
    pub hash: String,
    pub epoch: u64,
    pub files: usize,
    pub bytes: u64,
    pub updated_unix: u64,
    pub bind_addr: String,
    pub data_port: u16,
    pub knock_pool: Vec<u16>,
    pub secret_fingerprint: String,
    pub feishu_app: String,
    pub feishu_owner: String,
    pub feishu_chat: String,
    pub feishu_bound_unix: u64,
    pub dry_run: bool,
    pub agents: Vec<AgentRow>,
    pub online_window_secs: u64,
    pub now: u64,
}

/// Shown for `--help`, for a bare `--`, and for anything unrecognised.
pub const MANUAL: &str = "\
promptsync 飞书命令（以 -- 开头的消息只查询，不会覆盖 prompt）

  --status    服务端概览：受管文件、hash/epoch、端口、在线 agent 数
  --agents    每个 agent 的在线状态、最后心跳、内容 hash
  --config    生效配置：受管文件、端口、密钥指纹、飞书绑定
  --ports     数据端口与敲门端口池
  --version   版本与构建指纹
  --whoami    当前绑定的飞书应用 / 接收人 / 私聊
  --help      这份手册

其它任何文本都会整段覆盖受管文件（= 更新 prompt）。";

/// Turn one chat message into an answer.
///
/// Returns `None` when the message is not a command, so the caller treats it as
/// prompt content. Returns `Some(text)` for a known verb and for an unknown one
/// (the manual plus the offending verb).
pub fn handle(text: &str, status: &Status) -> Option<String> {
    let trimmed = text.trim();
    // A Markdown file may legitimately open with `---` front matter; that is
    // content, not a command, so it is handed back to the caller untouched.
    if trimmed.starts_with("---\n") || trimmed.starts_with("---\r\n") {
        return None;
    }
    let rest = trimmed.strip_prefix("--")?;
    let verb = rest
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let body = match verb.as_str() {
        "" | "help" | "?" | "h" => MANUAL.to_string(),
        "status" => status_text(status),
        "agents" | "agent" => agents_text(status),
        "config" => config_text(status),
        "ports" => ports_text(status),
        "version" | "ver" => version_text(status),
        "whoami" => whoami_text(status),
        _ => format!("未识别的命令：--{}\n\n{}", verb, MANUAL),
    };
    Some(body)
}

fn status_text(status: &Status) -> String {
    let mut lines = vec![
        format!("promptsync {} build {}", status.version, status.build),
        format!("受管文件  {}", or_dash(&status.target)),
        format!(
            "内容      hash {} | epoch {} | {}",
            short_hash(&status.hash),
            status.epoch,
            ts(status.updated_unix)
        ),
        format!("数据端口  {}（敲门成功后开放）", status.data_port),
        format!(
            "agent     {} 台在线 / 共 {} 台（在线窗口 {}s）",
            online_count(status),
            status.agents.len(),
            status.online_window_secs
        ),
        format!("飞书      {}", binding_line(status)),
        format!("日志      {}", or_dash(&status.log_file)),
    ];
    if status.dry_run {
        lines.push("模式      dry-run（只回执，不写文件）".to_string());
    }
    lines.join("\n")
}

fn agents_text(status: &Status) -> String {
    if status.agents.is_empty() {
        return format!(
            "还没有 agent 连上过这台服务端。\n在线窗口 {}s；agent 首次拉取后这里会出现它的心跳。",
            status.online_window_secs
        );
    }
    let mut lines = vec![format!(
        "agent 列表（{} 台在线 / 共 {} 台，在线窗口 {}s）",
        online_count(status),
        status.agents.len(),
        status.online_window_secs
    )];
    for agent in &status.agents {
        let online = is_online(status, agent.last_seen_unix);
        // The hash is what the agent reports it holds; compare it with ours
        // so a machine that stopped applying updates stands out.
        let sync_mark = if agent.hash.trim().is_empty() {
            ""
        } else if agent.hash.trim() == status.hash.trim() {
            " ✓"
        } else {
            " 落后"
        };
        lines.push(format!(
            "{} {:<18} {:>7} 前  {:<15} {}{}",
            if online { "●" } else { "○" },
            truncate(&agent.id, 18),
            age(status.now, agent.last_seen_unix),
            truncate(&agent.peer, 15),
            short_hash(&agent.hash),
            sync_mark,
        ));
    }
    lines.push("● 在线　○ 离线　✓ 已是最新　落后 = 还没拿到当前版本".to_string());
    lines.join("\n")
}

fn config_text(status: &Status) -> String {
    [
        format!("配置文件  {}", or_dash(&status.config_file)),
        format!("集群密钥  指纹 {}", or_dash(&status.secret_fingerprint)),
        format!("监听      {}", or_dash(&status.bind_addr)),
        format!(
            "数据端口  {}　敲门端口 {} 个",
            status.data_port,
            status.knock_pool.len()
        ),
        format!("受管文件  {}", or_dash(&status.target)),
        format!(
            "飞书      app {} | 接收人 {} | dry_run={}",
            or_dash(&status.feishu_app),
            or_dash(&status.feishu_owner),
            status.dry_run
        ),
        format!("私聊      {}", or_dash(&status.feishu_chat)),
    ]
    .join("\n")
}

fn ports_text(status: &Status) -> String {
    format!(
        "数据端口  {}\n敲门端口  {:?}（每次随机 3~6 个）\n密钥指纹  {}",
        status.data_port,
        status.knock_pool,
        or_dash(&status.secret_fingerprint)
    )
}

fn version_text(status: &Status) -> String {
    format!("promptsync {} build {}", status.version, status.build)
}

fn whoami_text(status: &Status) -> String {
    format!(
        "飞书应用  {}\n接收人    {}\n私聊      {}\n绑定时间  {}",
        or_dash(&status.feishu_app),
        or_dash(&status.feishu_owner),
        or_dash(&status.feishu_chat),
        ts(status.feishu_bound_unix)
    )
}

fn binding_line(status: &Status) -> String {
    if status.feishu_chat.trim().is_empty() {
        "尚未绑定".to_string()
    } else {
        format!("已绑定 {}", mask(&status.feishu_chat))
    }
}

fn online_count(status: &Status) -> usize {
    status
        .agents
        .iter()
        .filter(|agent| is_online(status, agent.last_seen_unix))
        .count()
}

fn is_online(status: &Status, last_seen_unix: u64) -> bool {
    last_seen_unix > 0 && status.now.saturating_sub(last_seen_unix) <= status.online_window_secs
}

fn or_dash(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_string()
    }
}

fn short_hash(hash: &str) -> String {
    let trimmed = hash.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed[..12.min(trimmed.len())].to_string()
    }
}

fn truncate(value: &str, width: usize) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= width {
        return value.to_string();
    }
    let mut out: String = chars[..width.saturating_sub(1)].iter().collect();
    out.push('…');
    out
}

fn mask(value: &str) -> String {
    let chars: Vec<char> = value.trim().chars().collect();
    if chars.len() <= 8 {
        return value.trim().to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// `2026-11-08 20:31:02Z`, or `-` for 0.
fn ts(unix: u64) -> String {
    if unix == 0 {
        return "-".to_string();
    }
    Utc.timestamp_opt(unix as i64, 0)
        .single()
        .map(|time| time.format("%Y-%m-%d %H:%M:%SZ").to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// Compact age such as `8s`, `2m05s`, `1h02m`, `3d04h`.
fn age(now: u64, then: u64) -> String {
    if then == 0 {
        return "-".to_string();
    }
    let seconds = now.saturating_sub(then);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else if seconds < 86_400 {
        format!("{}h{:02}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d{:02}h", seconds / 86_400, (seconds % 86_400) / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Status {
        Status {
            version: "0.3.2".to_string(),
            build: "abcd1234".to_string(),
            config_file: "/cfg/config.toml".to_string(),
            log_file: "/cfg/logs/server.log".to_string(),
            target: "cindy-bots/acme/bots/cindy/SOUL.md".to_string(),
            hash: "9a43307bd06e4894aa".to_string(),
            epoch: 7,
            files: 1,
            bytes: 744,
            updated_unix: 1_700_000_000,
            bind_addr: "0.0.0.0".to_string(),
            data_port: 57394,
            knock_pool: vec![1, 2, 3],
            secret_fingerprint: "b43a8e4a1514".to_string(),
            feishu_app: "cli_aa7a…9bfe".to_string(),
            feishu_owner: "ou_6dbe…3b26".to_string(),
            feishu_chat: "oc_75c68738886786be6225b8f64df2b23c".to_string(),
            feishu_bound_unix: 1_700_000_100,
            dry_run: false,
            agents: vec![
                AgentRow {
                    id: "Mac.lan".to_string(),
                    last_seen_unix: 1_700_000_010,
                    peer: "100.90.145.64".to_string(),
                    hash: "9a43307bd06e".to_string(),
                },
                AgentRow {
                    id: "win-office".to_string(),
                    last_seen_unix: 1_699_999_000,
                    peer: "10.0.0.8".to_string(),
                    hash: String::new(),
                },
            ],
            online_window_secs: 120,
            now: 1_700_000_020,
        }
    }

    #[test]
    fn plain_text_is_not_a_command() {
        assert!(handle("hello", &sample()).is_none());
        assert!(handle(" - status", &sample()).is_none());
        assert!(handle("--status", &sample()).is_some());
    }

    #[test]
    fn front_matter_is_content_not_a_command() {
        assert!(handle("---\ntitle: x\n---\nbody", &sample()).is_none());
        // `--` alone still asks for help.
        assert_eq!(handle("--", &sample()).unwrap(), MANUAL);
    }

    #[test]
    fn unknown_verbs_return_the_manual() {
        let reply = handle("--nope", &sample()).unwrap();
        assert!(reply.contains("未识别的命令：--nope"));
        assert!(reply.contains("--agents"));
    }

    #[test]
    fn bare_and_help_return_the_manual() {
        for text in ["--", "--help", "  --HELP  ", "--?"] {
            let reply = handle(text, &sample()).unwrap();
            assert_eq!(reply, MANUAL, "{text}");
        }
    }

    #[test]
    fn status_counts_online_agents_and_never_leaks_the_secret() {
        let reply = handle("--status", &sample()).unwrap();
        assert!(reply.contains("1 台在线 / 共 2 台"), "{reply}");
        assert!(reply.contains("57394"));
        assert!(reply.contains("epoch 7"));
        assert!(
            !reply.contains("b43a8e4a1514"),
            "status must not print the fingerprint"
        );
    }

    #[test]
    fn agents_marks_online_and_offline_rows() {
        let reply = handle("--agents", &sample()).unwrap();
        assert!(reply.contains("● Mac.lan"), "{reply}");
        assert!(reply.contains("○ win-office"), "{reply}");
        assert!(reply.contains("9a43307bd06e"));
    }

    #[test]
    fn config_and_ports_render_the_expected_fields() {
        let config = handle("--config", &sample()).unwrap();
        assert!(config.contains("指纹 b43a8e4a1514"));
        assert!(config.contains("敲门端口 3 个"));
        let ports = handle("--ports", &sample()).unwrap();
        assert!(ports.contains("数据端口  57394"));
        assert!(ports.contains("[1, 2, 3]"));
    }

    #[test]
    fn whoami_and_version_are_short() {
        let whoami = handle("--whoami", &sample()).unwrap();
        assert!(
            whoami.contains("oc_75c68738886786be6225b8f64df2b23c"),
            "{whoami}"
        );
        assert!(whoami.contains("cli_aa7a…9bfe"), "{whoami}");
        assert_eq!(
            handle("--version", &sample()).unwrap(),
            "promptsync 0.3.2 build abcd1234"
        );
    }

    #[test]
    fn ages_stay_compact() {
        assert_eq!(age(1_700_000_020, 1_700_000_012), "8s");
        assert_eq!(age(1_700_000_020, 1_699_999_900), "2m00s");
        assert_eq!(age(1_700_000_020, 1_699_996_420), "1h00m");
        assert_eq!(age(1_700_000_020, 1_699_500_000), "5d18h");
        assert_eq!(age(1_700_000_020, 0), "-");
    }
}
