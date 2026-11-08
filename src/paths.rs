//! The personal configuration directory.
//!
//! There is exactly one place for per-machine configuration: a directory that
//! is empty out of the box (and ignored by git). On every start the directory
//! is created if needed; when it does not contain `config.toml` yet, a fresh
//! one is rendered from `templates/config.toml` and written there.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::{cindy_owners_root, Config};
use crate::util::{atomic_write, expand_tilde, now_unix};

pub const CONFIG_FILE_NAME: &str = "config.toml";
const CONFIG_TEMPLATE: &str = include_str!("../templates/config.toml");

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
}

impl Paths {
    /// Resolution order:
    /// 1. `--config-dir`
    /// 2. `--config <file>` (its parent becomes the config directory)
    /// 3. `PROMPTSYNC_CONFIG_DIR`
    /// 4. `./config` (relative to the current working directory); when it has
    ///    no config file yet, an existing `~/.promptsync/config.toml` is
    ///    reused instead of silently creating a second config with a new
    ///    cluster secret.
    pub fn resolve(config_file: Option<&Path>, config_dir: Option<&Path>) -> Result<Self> {
        let dir = match (config_dir, config_file) {
            (Some(dir), _) => absolute(dir)?,
            (None, Some(file)) => {
                let parent = file
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."));
                absolute(&parent)?
            }
            (None, None) => {
                let from_env = std::env::var("PROMPTSYNC_CONFIG_DIR")
                    .ok()
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty());
                match from_env {
                    Some(value) => absolute(&expand_tilde(&value))?,
                    None => {
                        let work = std::env::current_dir()
                            .context("resolving the current working directory")?;
                        let cwd = work.join("config");
                        let home = dirs::home_dir().map(|home| home.join(".promptsync"));
                        let chosen = default_dir(&work, home.as_deref());
                        if chosen == work {
                            // Started from inside the config directory itself
                            // (`cd config && promptsync ...`): `./config` would
                            // be a brand-new nested config with its own secret.
                            eprintln!(
                                "[promptsync] 当前目录就是配置目录，使用 {}（而不是新建 {}）；要改目录请传 --config-dir",
                                chosen.join(CONFIG_FILE_NAME).display(),
                                cwd.join(CONFIG_FILE_NAME).display()
                            );
                        } else if chosen != cwd {
                            eprintln!(
                                "[promptsync] 复用已有配置 {}（{} 里还没有 config.toml）；要改目录请传 --config-dir",
                                chosen.join(CONFIG_FILE_NAME).display(),
                                cwd.display()
                            );
                        }
                        chosen
                    }
                }
            }
        };
        let file = match config_file {
            Some(file) => absolute(file)?,
            None => dir.join(CONFIG_FILE_NAME),
        };
        Ok(Self {
            config_dir: dir,
            config_file: file,
        })
    }

    /// Create the directory and, when no config file exists yet, render the
    /// template into it. Returns `true` when a new file was written.
    pub fn ensure(&self) -> Result<bool> {
        fs::create_dir_all(&self.config_dir)
            .with_context(|| format!("creating config dir {}", self.config_dir.display()))?;
        if self.config_file.exists() {
            return Ok(false);
        }
        self.write_template(false)?;
        Ok(true)
    }

    /// Write the config from the template. With `force`, an existing file is
    /// backed up first.
    pub fn write_template(&self, force: bool) -> Result<Option<PathBuf>> {
        fs::create_dir_all(&self.config_dir)
            .with_context(|| format!("creating config dir {}", self.config_dir.display()))?;
        let mut backup = None;
        if self.config_file.exists() {
            if !force {
                bail!(
                    "config file already exists: {} (use the command's --force to overwrite)",
                    self.config_file.display()
                );
            }
            let path = self
                .config_file
                .with_file_name(format!("config.toml.bak.{}", now_unix()));
            fs::copy(&self.config_file, &path)
                .with_context(|| format!("backing up {}", self.config_file.display()))?;
            backup = Some(path);
        }
        let rendered = render_template(&self.config_dir)?;
        // Never write a template that cannot be parsed.
        let parsed: Config =
            toml::from_str(&rendered).context("the config template is not valid TOML")?;
        parsed
            .validate()
            .context("the config template is invalid")?;
        atomic_write(&self.config_file, rendered.as_bytes(), true)
            .with_context(|| format!("writing {}", self.config_file.display()))?;
        Ok(backup)
    }

    /// Load the config, creating it from the template when it is missing.
    /// Returns `(config, was_created)`.
    pub fn load(&self) -> Result<(Config, bool)> {
        let created = self.ensure()?;
        let text = fs::read_to_string(&self.config_file)
            .with_context(|| format!("reading {}", self.config_file.display()))?;
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("parsing {}", self.config_file.display()))?;
        config.validate()?;
        Ok((config, created))
    }

    /// Runtime state (managed files, agent/server state, backups).
    pub fn data_dir(&self) -> PathBuf {
        self.config_dir.join("state")
    }

    /// Log directory; `logging.dir` overrides the default inside the config dir.
    pub fn log_dir(&self, config: &Config) -> PathBuf {
        let configured = config.logging.dir.trim();
        if configured.is_empty() {
            self.config_dir.join("logs")
        } else {
            expand_tilde(configured)
        }
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("resolving the current working directory")?
        .join(path))
}

fn render_template(config_dir: &Path) -> Result<String> {
    let home = dirs::home_dir().context("determining the home directory")?;
    let cindy = cindy_owners_root();
    let mut text = CONFIG_TEMPLATE.to_string();
    for (placeholder, value) in [
        ("{home}", home.display().to_string()),
        ("{cindy_root}", cindy.display().to_string()),
        ("{config_dir}", config_dir.display().to_string()),
    ] {
        text = text.replace(placeholder, &toml_escape(&value));
    }
    Ok(text)
}

/// Pick the implicit config directory. A local `./config/config.toml` always
/// wins (backwards compatible); otherwise an existing per-user config is
/// reused so running from another directory does not mint a new secret.
/// Pick the default config directory when no flag or env var names one.
///
/// `work` is the current working directory (absolute), `home` the optional
/// `~/.promptsync`. Order: `<work>/config/config.toml`, then `<work>/config.toml`
/// (the user is standing inside a config directory), then an existing home
/// config, and finally `<work>/config` (which `ensure` will create).
fn default_dir(work: &Path, home: Option<&Path>) -> PathBuf {
    let cwd = work.join("config");
    if cwd.join(CONFIG_FILE_NAME).exists() {
        return cwd;
    }
    // Inside the config directory: reusing it avoids creating config/config
    // with a second, freshly generated cluster secret.
    if work.join(CONFIG_FILE_NAME).exists() {
        return work.to_path_buf();
    }
    if let Some(home) = home.filter(|home| home.join(CONFIG_FILE_NAME).exists()) {
        return home.to_path_buf();
    }
    cwd
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_config_from_template_when_missing() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(None, Some(&temp.path().join("personal"))).unwrap();
        assert!(!paths.config_file.exists());
        let (config, created) = paths.load().unwrap();
        assert!(created);
        assert!(paths.config_file.exists());
        assert!(paths.config_file.metadata().unwrap().len() > 100);
        assert!(paths.data_dir().ends_with("personal/state"));
        assert_eq!(paths.log_dir(&config), paths.config_dir.join("logs"));
        // A second start must not touch the existing file.
        let before = fs::read(&paths.config_file).unwrap();
        let (_, created_again) = paths.load().unwrap();
        assert!(!created_again);
        assert_eq!(before, fs::read(&paths.config_file).unwrap());
    }

    #[test]
    fn writes_without_leaking_placeholders() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(None, Some(temp.path())).unwrap();
        paths.ensure().unwrap();
        let text = fs::read_to_string(&paths.config_file).unwrap();
        assert!(!text.contains("{home}"));
        assert!(!text.contains("{cindy_root}"));
        assert!(!text.contains("{config_dir}"));
    }

    #[test]
    fn force_backs_up_the_previous_file() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::resolve(None, Some(temp.path())).unwrap();
        paths.ensure().unwrap();
        fs::write(&paths.config_file, "cluster_secret = \"old\"\n").unwrap();
        let backup = paths.write_template(true).unwrap();
        assert!(backup.is_some());
        let text = fs::read_to_string(&paths.config_file).unwrap();
        assert!(text.contains("promptsync"));
        assert!(!text.contains("cluster_secret = \"old\""));
    }

    #[test]
    fn default_dir_prefers_a_local_config() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("config");
        fs::create_dir_all(&cwd).unwrap();
        fs::write(cwd.join(CONFIG_FILE_NAME), "cluster_secret = \"x\"\n").unwrap();
        let home = temp.path().join("home/.promptsync");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join(CONFIG_FILE_NAME), "cluster_secret = \"x\"\n").unwrap();
        assert_eq!(default_dir(temp.path(), Some(&home)), cwd);
    }

    #[test]
    fn default_dir_reuses_the_home_config_when_the_cwd_has_none() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home/.promptsync");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join(CONFIG_FILE_NAME), "cluster_secret = \"x\"\n").unwrap();
        assert_eq!(default_dir(temp.path(), Some(&home)), home);
    }

    #[test]
    fn default_dir_stays_local_when_nothing_exists() {
        let temp = tempfile::tempdir().unwrap();
        let cwd = temp.path().join("config");
        let home = temp.path().join("home/.promptsync");
        assert_eq!(default_dir(temp.path(), Some(&home)), cwd);
    }

    /// `cd config && promptsync server` must reuse that directory instead of
    /// creating `config/config` with a new cluster secret.
    #[test]
    fn default_dir_reuses_the_cwd_when_standing_inside_a_config_dir() {
        let temp = tempfile::tempdir().unwrap();
        let inside = temp.path().join("config");
        fs::create_dir_all(&inside).unwrap();
        fs::write(inside.join(CONFIG_FILE_NAME), "cluster_secret = \"x\"\n").unwrap();
        let home = temp.path().join("home/.promptsync");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join(CONFIG_FILE_NAME), "cluster_secret = \"x\"\n").unwrap();
        assert_eq!(default_dir(&inside, Some(&home)), inside);
    }

    #[test]
    fn explicit_file_wins_over_the_default_name() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("custom.toml");
        let paths = Paths::resolve(Some(&file), None).unwrap();
        assert_eq!(paths.config_file, file);
        assert_eq!(paths.config_dir, temp.path());
    }
}
