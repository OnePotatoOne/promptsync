//! Configuration file handling.
//!
//! A single TOML file describes both roles. The file is created with mode 0600
//! on first use because it may contain the cluster secret.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_POLL_SECS: u64 = 10;
pub const DEFAULT_OFFLINE_THRESHOLD_SECS: u64 = 120;
pub const DEFAULT_GATE_TTL_SECS: u64 = 90;
pub const DEFAULT_KNOCK_WINDOW_SECS: u64 = 6;
pub const DEFAULT_MAX_BUNDLE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Hex encoded 32-byte cluster secret. Empty means "use the value compiled
    /// into this build". All machines must agree, otherwise knocks and
    /// handshakes are rejected.
    pub cluster_secret: String,
    pub server: ServerConfig,
    pub agent: AgentConfig,
    pub feishu: FeishuConfig,
    pub logging: LoggingConfig,
    pub sync: SyncConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Address the data port binds to (after a successful knock).
    pub bind: String,
    /// Data port; 0 means "derive from the cluster secret".
    pub port: u16,
    /// Knock ports; empty means "derive from the cluster secret".
    pub knock_ports: Vec<u16>,
    /// How long an authorised source IP may use the data port.
    pub gate_ttl_secs: u64,
    /// Time window in which the knock sequence must be completed.
    pub knock_window_secs: u64,
    pub max_sessions: usize,
    /// Report agents that stop polling to Feishu.
    pub monitor_agents: bool,
    pub monitor_interval_secs: u64,
    /// Agent state is forgotten after this many seconds of silence.
    pub forget_agent_after_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Host name or IP of the server.
    pub server: String,
    /// Data port; 0 means "derive from the cluster secret".
    pub port: u16,
    /// Knock ports; empty means "derive from the cluster secret". Must match the
    /// server when it overrides them.
    pub knock_ports: Vec<u16>,
    pub poll_secs: u64,
    /// Consecutive unreachability after which Feishu is notified.
    pub offline_threshold_secs: u64,
    /// Free-form identifier used in logs and Feishu alerts. Empty = hostname.
    pub agent_id: String,
    pub handshake_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub knock_interval_ms: u64,
    /// Random number of knock packets per attempt: `knock_min..=knock_max`.
    pub knock_min: usize,
    pub knock_max: usize,
    /// Random +- jitter applied to every knock delay.
    pub knock_jitter_ms: u64,
    /// Number of attempts for the whole poll cycle (knock + handshake).
    pub connect_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FeishuConfig {
    pub enabled: bool,
    pub notify_on_recovery: bool,
    pub timeout_secs: u64,
    /// Repeat an unresolved offline alert after this many seconds (0 = once).
    pub repeat_alert_secs: u64,
    pub app: FeishuAppConfig,
    pub control: FeishuControlConfig,
}

/// Self-built Feishu app credentials. They live only in the local config
/// directory (mode 0600) and are never compiled into the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FeishuAppConfig {
    pub app_id: String,
    pub app_secret: String,
    /// Owner open_id. Filled in automatically by the binding flow; it is also
    /// the recipient of offline alerts.
    pub owner_open_id: String,
    /// API endpoint (tests point this at a local mock server).
    pub api_base: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FeishuControlConfig {
    /// How often the server polls the bound private chat for new messages.
    pub poll_secs: u64,
    /// Messages larger than this are rejected instead of overwriting prompts.
    pub max_message_bytes: usize,
    /// Log what would happen without writing files (for a first trial run).
    pub dry_run: bool,
    /// How long to wait for the "scan and send a message" binding step.
    pub bind_timeout_secs: u64,
    /// Optional Feishu email/phone used by the fallback binding path.
    pub bind_contact: String,
    /// How many `<file>.<stamp>.bak` backups to keep (0 = keep all).
    pub keep_backups: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Directory for log files. Empty = `<data dir>/logs`.
    pub dir: String,
    pub level: String,
    pub max_file_bytes: u64,
    pub keep_files: usize,
    pub stderr: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncConfig {
    /// The one file managed through Feishu, as `<source id>/<relative path>`.
    /// Empty disables the Feishu control channel.
    pub target: String,
    pub sources: Vec<SourceConfig>,
    /// Hard cap for a pulled bundle.
    pub max_bundle_bytes: u64,
    /// Keep this many backup generations when applying a bundle.
    pub keep_backups: usize,
    /// Follow symbolic links while scanning (off by default: links could point
    /// outside the configured root).
    pub follow_symlinks: bool,
    /// Delete files that were managed before but disappeared from the bundle.
    /// Off by default: shrinking the source set never removes user files.
    pub delete_removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceConfig {
    /// Stable identifier; appears as the first path component of a bundle entry.
    pub id: String,
    /// Root directory, `~` is expanded.
    pub root: String,
    /// Glob patterns relative to the root.
    pub globs: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".to_string(),
            port: 0,
            knock_ports: Vec::new(),
            gate_ttl_secs: DEFAULT_GATE_TTL_SECS,
            knock_window_secs: DEFAULT_KNOCK_WINDOW_SECS,
            max_sessions: 32,
            monitor_agents: true,
            monitor_interval_secs: 5,
            forget_agent_after_secs: 7 * 24 * 3600,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 0,
            knock_ports: Vec::new(),
            poll_secs: DEFAULT_POLL_SECS,
            offline_threshold_secs: DEFAULT_OFFLINE_THRESHOLD_SECS,
            agent_id: String::new(),
            handshake_timeout_secs: 4,
            request_timeout_secs: 8,
            knock_interval_ms: 55,
            knock_min: crate::knock::DEFAULT_KNOCK_MIN,
            knock_max: crate::knock::DEFAULT_KNOCK_MAX,
            knock_jitter_ms: 45,
            connect_attempts: 3,
        }
    }
}

impl Default for FeishuConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            notify_on_recovery: true,
            timeout_secs: 10,
            repeat_alert_secs: 0,
            app: FeishuAppConfig::default(),
            control: FeishuControlConfig::default(),
        }
    }
}

impl Default for FeishuAppConfig {
    fn default() -> Self {
        Self {
            app_id: String::new(),
            app_secret: String::new(),
            owner_open_id: String::new(),
            api_base: "https://open.feishu.cn".to_string(),
        }
    }
}

impl Default for FeishuControlConfig {
    fn default() -> Self {
        Self {
            poll_secs: 5,
            max_message_bytes: 32 * 1024,
            dry_run: false,
            bind_timeout_secs: 90,
            bind_contact: String::new(),
            keep_backups: 50,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            dir: String::new(),
            level: "info".to_string(),
            max_file_bytes: 5 * 1024 * 1024,
            keep_files: 3,
            stderr: true,
        }
    }
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            sources: default_sources(),
            max_bundle_bytes: DEFAULT_MAX_BUNDLE_BYTES,
            keep_backups: 10,
            follow_symlinks: false,
            delete_removed: false,
        }
    }
}

impl Default for SourceConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            root: String::new(),
            globs: vec!["**/*.md".to_string()],
        }
    }
}

/// Where Cindy keeps its bot prompts on this platform.
pub fn cindy_owners_root() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    #[cfg(target_os = "macos")]
    {
        home.join("Library/Application Support/CindyGlobal/owners")
    }
    #[cfg(target_os = "windows")]
    {
        dirs::config_dir()
            .unwrap_or_else(|| home.join("AppData/Roaming"))
            .join("CindyGlobal/owners")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        dirs::config_dir()
            .unwrap_or_else(|| home.join(".config"))
            .join("CindyGlobal/owners")
    }
}

/// Default source set used by `Config::default()` (the shipped template has the
/// same layout, with platform paths substituted at generation time).
pub fn default_sources() -> Vec<SourceConfig> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    let cindy_bots_globs = vec![
        "*/bots/*/system_prompt.md".to_string(),
        "*/bots/*/SOUL.md".to_string(),
    ];
    let mut sources = Vec::new();
    let cindy_root = cindy_owners_root();

    sources.push(SourceConfig {
        id: "cindy-bots".to_string(),
        root: cindy_root.display().to_string(),
        globs: cindy_bots_globs,
    });
    sources.push(SourceConfig {
        id: "pi-prompts".to_string(),
        root: home.join(".pi/agent/prompts").display().to_string(),
        globs: vec!["**/*.md".to_string()],
    });
    sources.push(SourceConfig {
        id: "cindy-prompts".to_string(),
        root: home.join(".cindy/prompts").display().to_string(),
        globs: vec!["**/*.md".to_string()],
    });
    sources.push(SourceConfig {
        id: "shared".to_string(),
        root: home.join(".promptsync/shared").display().to_string(),
        globs: vec!["**/*.md".to_string()],
    });
    sources
}

impl Config {
    pub fn save(&self, path: &Path) -> Result<()> {
        let body = toml::to_string_pretty(self).context("serialising config")?;
        let header = "\
# promptsync configuration
# Generated on first run. Keep this file private (mode 0600) - it may hold the
# cluster secret. \"cluster_secret\" empty means: use the secret compiled into
# this build. Set the same hex value on server and agents to pair binaries that
# were built separately.

";
        crate::util::atomic_write(path, format!("{header}{body}").as_bytes(), true)
            .with_context(|| format!("writing config {}", path.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if !self.cluster_secret.trim().is_empty() {
            let cleaned: String = self
                .cluster_secret
                .trim()
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect();
            if cleaned.len() != 64 {
                bail!(
                    "cluster_secret must be 64 hex characters (32 bytes), got {}",
                    cleaned.len()
                );
            }
        }
        if self.agent.poll_secs == 0 {
            bail!("agent.poll_secs must be greater than 0");
        }
        if self.agent.offline_threshold_secs == 0 {
            bail!("agent.offline_threshold_secs must be greater than 0");
        }
        if self.server.max_sessions == 0 {
            bail!("server.max_sessions must be greater than 0");
        }
        let app_id = self.feishu.app.app_id.trim();
        let app_secret = self.feishu.app.app_secret.trim();
        if app_id.is_empty() != app_secret.is_empty() {
            bail!("feishu.app.app_id and feishu.app.app_secret must be set together");
        }
        if !self.feishu.app.api_base.starts_with("http://")
            && !self.feishu.app.api_base.starts_with("https://")
        {
            bail!("feishu.app.api_base must start with http:// or https://");
        }
        if self.feishu.control.poll_secs == 0 {
            bail!("feishu.control.poll_secs must be greater than 0");
        }
        if self.feishu.control.max_message_bytes < 1024 {
            bail!("feishu.control.max_message_bytes must be at least 1024");
        }
        if self.fsync_target_invalid() {
            bail!("sync.target must look like \"<source id>/<relative path>\"");
        }
        if self.agent.knock_min == 0 {
            bail!("agent.knock_min must be at least 1");
        }
        if self.agent.knock_max < self.agent.knock_min {
            bail!("agent.knock_max must be >= agent.knock_min");
        }
        if self.agent.knock_max > 16 {
            bail!("agent.knock_max supports at most 16");
        }
        if self.agent.knock_jitter_ms > 2_000 {
            bail!("agent.knock_jitter_ms must be <= 2000");
        }
        for (label, ports) in [
            ("server.knock_ports", &self.server.knock_ports),
            ("agent.knock_ports", &self.agent.knock_ports),
        ] {
            if ports.len() > 16 {
                bail!("{label} supports at most 16 ports");
            }
            if ports.contains(&0) {
                bail!("{label} must not contain port 0");
            }
            let mut unique = std::collections::HashSet::new();
            for port in ports {
                if !unique.insert(*port) {
                    bail!("{label} contains duplicate port {port}");
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        for source in &self.sync.sources {
            if source.id.is_empty()
                || !source
                    .id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                bail!(
                    "invalid source id {:?}: use letters, digits, '-', '_' or '.'",
                    source.id
                );
            }
            if !seen.insert(source.id.clone()) {
                bail!("duplicate source id {:?}", source.id);
            }
            if source.root.trim().is_empty() {
                bail!("source {:?} has an empty root", source.id);
            }
            if source.globs.is_empty() {
                bail!("source {:?} has no globs", source.id);
            }
        }
        Ok(())
    }

    fn fsync_target_invalid(&self) -> bool {
        let target = self.sync.target.trim();
        if target.is_empty() {
            return false;
        }
        match target.split_once('/') {
            Some((id, rest)) => id.is_empty() || crate::util::safe_relative_path(rest).is_none(),
            None => true,
        }
    }

    pub fn feishu_app_configured(&self) -> bool {
        !self.feishu.app.app_id.trim().is_empty() && !self.feishu.app.app_secret.trim().is_empty()
    }

    pub fn feishu_bound(&self) -> bool {
        !self.feishu.app.owner_open_id.trim().is_empty()
    }
}

/// Replace a scalar value in an existing config file while keeping the
/// surrounding comments intact. Creates the section/key when it is missing.
pub fn set_value(path: &Path, section: Option<&str>, key: &str, literal: &str) -> Result<()> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut lines: Vec<String> = text.lines().map(|line| line.to_string()).collect();
    let mut current_section: Option<String> = None;
    let mut section_index: Option<usize> = None;
    let mut replaced = false;

    for (index, line) in lines.iter_mut().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.len() > 2 {
            let inner = trimmed.trim_matches(|c| c == '[' || c == ']').trim();
            current_section = Some(inner.to_string());
            if section.map(|wanted| wanted == inner).unwrap_or(false) && section_index.is_none() {
                section_index = Some(index);
            }
            continue;
        }
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let in_section = match section {
            None => current_section.is_none(),
            Some(wanted) => current_section.as_deref() == Some(wanted),
        };
        if !in_section {
            continue;
        }
        if let Some((lhs, _)) = trimmed.split_once('=') {
            if lhs.trim() == key {
                *line = format!("{key} = {literal}");
                replaced = true;
                break;
            }
        }
    }

    if !replaced {
        match section_index {
            Some(index) => lines.insert(index + 1, format!("{key} = {literal}")),
            None => match section {
                Some(section) => {
                    if lines
                        .last()
                        .map(|line| !line.trim().is_empty())
                        .unwrap_or(false)
                    {
                        lines.push(String::new());
                    }
                    lines.push(format!("[{section}]"));
                    lines.push(format!("{key} = {literal}"));
                }
                None => lines.insert(0, format!("{key} = {literal}")),
            },
        }
    }

    let mut output = lines.join("\n");
    output.push('\n');
    crate::util::atomic_write(path, output.as_bytes(), true)
        .with_context(|| format!("writing {}", path.display()))
}

/// Replace the `globs` array of one `[[sync.sources]]` block, keeping comments.
pub fn set_source_globs(path: &Path, source_id: &str, globs: &[String]) -> Result<()> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut lines: Vec<String> = text.lines().map(|line| line.to_string()).collect();
    let literal = format!(
        "[{}]",
        globs
            .iter()
            .map(|glob| format!("\"{}\"", glob.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut block_start: Option<usize> = None;
    let mut block_id: Option<String> = None;
    let mut insert_at: Option<usize> = None;
    let mut replaced = false;
    for (index, line) in lines.iter_mut().enumerate() {
        let trimmed = line.trim().to_string();
        if trimmed.starts_with('[') {
            block_start = if trimmed == "[[sync.sources]]" {
                Some(index)
            } else {
                None
            };
            block_id = None;
            insert_at = None;
            continue;
        }
        if block_start.is_none() {
            continue;
        }
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            let lhs = lhs.trim();
            if lhs == "id" {
                block_id = Some(rhs.trim().trim_matches('"').to_string());
                insert_at = Some(index + 1);
            } else if lhs == "globs" && block_id.as_deref() == Some(source_id) {
                *line = format!("globs = {literal}");
                replaced = true;
                break;
            }
        }
    }
    if !replaced {
        match insert_at {
            Some(index) if block_id.as_deref() == Some(source_id) => {
                lines.insert(index, format!("globs = {literal}"));
            }
            _ => bail!("source {source_id:?} not found in {}", path.display()),
        }
    }
    let mut output = lines.join("\n");
    output.push('\n');
    crate::util::atomic_write(path, output.as_bytes(), true)
        .with_context(|| format!("writing {}", path.display()))
}

/// Replace the `cluster_secret` line without destroying the template comments.
pub fn set_cluster_secret(path: &Path, secret_hex: &str) -> Result<()> {
    set_value(path, None, "cluster_secret", &format!("\"{secret_hex}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().expect("default config valid");
    }

    #[test]
    fn rejects_bad_secret_and_ids() {
        let config = Config {
            cluster_secret: "abc".to_string(),
            ..Config::default()
        };
        assert!(config.validate().is_err());

        let mut config = Config::default();
        let duplicate = config.sync.sources[0].clone();
        config.sync.sources.push(duplicate);
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.sync.sources[0].id = "../evil".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn cluster_secret_write_keeps_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "# header\ncluster_secret = \"\"\n\n[agent]\npoll_secs = 10\n",
        )
        .unwrap();
        let hex = "ab".repeat(32);
        set_cluster_secret(&path, &hex).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# header"));
        assert!(text.contains("[agent]"));
        assert!(text.contains(&format!("cluster_secret = \"{hex}\"")));
    }

    #[test]
    fn set_value_respects_sections_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "# top\ncluster_secret = \"\"\n\n[agent]\n# doc\nserver = \"127.0.0.1\"\nport = 0\n\n[feishu]\nenabled = false\n",
        )
        .unwrap();
        set_value(&path, Some("agent"), "server", "\"10.0.0.2\"").unwrap();
        set_value(&path, Some("agent"), "port", "41234").unwrap();
        set_value(&path, None, "cluster_secret", "\"aa\"").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# top"));
        assert!(text.contains("# doc"));
        assert!(text.contains("server = \"10.0.0.2\""));
        assert!(text.contains("port = 41234"));
        assert!(text.contains("cluster_secret = \"aa\""));
        assert!(text.contains("[feishu]"));
        // Values in other sections are untouched.
        assert!(text.contains("enabled = false"));
    }

    #[test]
    fn set_source_globs_targets_the_right_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "# top\n[[sync.sources]]\nid = \"a\"\nroot = \"/a\"\nglobs = [\"**/*.md\"]\n\n[[sync.sources]]\n# keep me\nid = \"b\"\nroot = \"/b\"\nglobs = [\"*/bots/*/SOUL.md\"]\n",
        )
        .unwrap();
        set_source_globs(&path, "b", &["*/bots/*/SOUL.md".to_string()]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# keep me"));
        assert!(text.contains("globs = [\"**/*.md\"]"));
        assert!(text.contains("globs = [\"*/bots/*/SOUL.md\"]"));
        assert!(set_source_globs(&path, "missing", &["x".to_string()]).is_err());
    }

    #[test]
    fn round_trips_through_toml() {
        let config = Config::default();
        let text = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed.sync.sources.len(), config.sync.sources.len());
        assert_eq!(parsed.agent.poll_secs, 10);
    }
}
