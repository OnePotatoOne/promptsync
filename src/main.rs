//! promptsync command line interface.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

use promptsync::buildinfo;
use promptsync::config::{set_cluster_secret, Config};
use promptsync::crypto::ClusterSecret;
use promptsync::interactive::{self, Prompter, Role};
use promptsync::knock::{agent_ports, server_ports};
use promptsync::logx::{Level, Logger};
use promptsync::paths::Paths;
use promptsync::prompts::{canonical_hash, resolve_sources, scan, total_bytes, ScanOptions};
use promptsync::{agent, feishu, feishu_control, server};

#[derive(Parser)]
#[command(
    name = "promptsync",
    version,
    about = "Encrypted, port-knocked prompt synchronisation",
    long_about = "Keeps prompt files identical across machines.\n\n\
        The `server` owns the authoritative set and publishes a hash; every `agent`\n\
        polls that hash (default every 10s) and pulls the bundle when it changed.\n\
        Transport is UDP with random port knocking, X25519 + AES-256-GCM encryption\n\
        and a fragment-level reliable layer.\n\n\
        All personal configuration lives in one config directory (default ./config,\n\
        ignored by git). On start it is created and filled from templates/config.toml\n\
        when it is empty."
)]
struct Cli {
    /// Personal configuration directory (default: ./config)
    #[arg(long, global = true, value_name = "DIR")]
    config_dir: Option<PathBuf>,
    /// Explicit config file (overrides the file inside --config-dir)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Override the configured log level (debug|info|warn|error)
    #[arg(long, global = true)]
    log_level: Option<String>,
    /// Never ask questions (services, scripts, cron)
    #[arg(long, global = true)]
    non_interactive: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the authoritative server
    Server {
        /// Bind address for the data port (after a valid knock)
        #[arg(long)]
        bind: Option<String>,
        /// Data port (overrides the secret-derived port)
        #[arg(long)]
        port: Option<u16>,
    },
    /// Run the polling agent in the foreground
    Agent {
        /// Server host name or IP
        #[arg(long)]
        server: Option<String>,
        /// Data port (overrides the secret-derived port)
        #[arg(long)]
        port: Option<u16>,
        /// Poll once, print the result and exit
        #[arg(long)]
        once: bool,
    },
    /// Create the config directory and config file from the template
    Init {
        /// Overwrite an existing config (the old one is backed up first)
        #[arg(long)]
        force: bool,
    },
    /// Show local synchronisation state
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Print the derived data/knock ports and the secret fingerprint
    Ports,
    /// Show, generate or set the cluster secret
    Secret {
        /// Print the effective secret (keep it private!)
        #[arg(long)]
        show: bool,
        /// Print a fresh random secret
        #[arg(long)]
        generate: bool,
        /// Store this hex secret in the configuration file
        #[arg(long, value_name = "HEX")]
        set: Option<String>,
    },
    /// Send a test message through the Feishu app
    FeishuTest {
        #[arg(long, default_value = "")]
        text: String,
    },
    /// (Re)bind the Feishu bot: scan the QR code / open the link, then message it
    FeishuBind {
        /// Forget the current owner/chat and bind again from scratch
        #[arg(long)]
        reset: bool,
    },
    /// Print the effective configuration
    ConfigFile,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("error: cannot start async runtime: {err}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(dispatch(cli)) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(1)
        }
    }
}

async fn dispatch(cli: Cli) -> Result<u8> {
    let paths = Paths::resolve(cli.config.as_deref(), cli.config_dir.as_deref())?;
    if let Command::Init { force } = &cli.command {
        return init(&paths, *force);
    }
    let (mut config, created) = paths.load()?;

    // Interactive only for the long-running roles, and only when the caller did
    // not already pass explicit overrides (that means "scripted use").
    let explicit_override = match &cli.command {
        Command::Server { bind, port } => bind.is_some() || port.is_some(),
        Command::Agent { server, port, once } => server.is_some() || port.is_some() || *once,
        _ => true,
    };
    let prompter = Prompter::new(!cli.non_interactive && !explicit_override);
    let role = match &cli.command {
        Command::Server { .. } => Some(Role::Server),
        Command::Agent { .. } => Some(Role::Agent),
        _ => None,
    };
    if let Some(role) = role {
        config = interactive::prepare(&paths, config, created, role, &prompter)?;
    }

    match &cli.command {
        Command::Server { bind, port } => {
            if let Some(bind) = bind {
                config.server.bind = bind.clone();
            }
            if let Some(port) = port {
                config.server.port = *port;
            }
            let logger = make_logger(&config, &paths, "server", cli.log_level.as_deref())?;
            log_paths(&logger, &paths, created);
            if config.sync.target.trim().is_empty() {
                match feishu_control::auto_detect_target(&mut config, &paths, &prompter, &logger) {
                    Ok(Some(target)) => logger.info(format!("managed prompt file: {target}")),
                    Ok(None) => logger.warn("sync.target is not set; single-file mode is off"),
                    Err(err) => logger.warn(format!("detecting sync.target failed: {err:#}")),
                }
            }
            if config.feishu.enabled && config.feishu_app_configured() {
                let mut bind_config = config.clone();
                let bind_paths = paths.clone();
                let bind_logger = logger.clone();
                let bind_prompter = prompter.clone();
                let bound = tokio::task::spawn_blocking(move || {
                    feishu_control::ensure_binding(
                        &mut bind_config,
                        &bind_paths,
                        &bind_prompter,
                        &bind_logger,
                        false,
                    )
                })
                .await
                .context("Feishu binding task")??;
                match bound {
                    Some(binding) => {
                        logger.info(format!(
                            "Feishu control channel bound to chat {}",
                            binding.chat_id
                        ));
                        if let Ok((reloaded, _)) = paths.load() {
                            config = reloaded;
                        }
                    }
                    None => logger.warn(
                        "Feishu control channel is not bound; prompts can still be edited locally",
                    ),
                }
            }
            tokio::select! {
                result = server::run(config, logger.clone(), paths.data_dir()) => result?,
                _ = shutdown_signal() => logger.info("shutdown signal received"),
            }
            Ok(0)
        }
        Command::Agent {
            server: host,
            port,
            once,
        } => {
            if let Some(host) = host {
                config.agent.server = host.clone();
            }
            if let Some(port) = port {
                config.agent.port = *port;
            }
            let logger = make_logger(&config, &paths, "agent", cli.log_level.as_deref())?;
            log_paths(&logger, &paths, created);
            if *once {
                return agent::run_once(config, logger, paths.data_dir()).await;
            }
            tokio::select! {
                result = agent::run(config, logger.clone(), paths.data_dir()) => result?,
                _ = shutdown_signal() => logger.info("shutdown signal received"),
            }
            Ok(0)
        }
        Command::Status { json } => status(&config, &paths, *json),
        Command::Ports => ports(&config, &paths),
        Command::Secret {
            show,
            generate,
            set,
        } => secret(&mut config, &paths, *show, *generate, set.as_deref()),
        Command::FeishuTest { text } => feishu_test(&config, text).await,
        Command::FeishuBind { reset } => {
            if !config.feishu.enabled {
                bail!("feishu.enabled is false in {}", paths.config_file.display());
            }
            if !config.feishu_app_configured() {
                bail!(
                    "feishu.app.app_id / app_secret are empty; create a Feishu app and fill them in {}",
                    paths.config_file.display()
                );
            }
            if *reset {
                feishu_control::reset_binding(&mut config, &paths)?;
            }
            let logger = make_logger(&config, &paths, "feishu", cli.log_level.as_deref())?;
            let mut bind_config = config.clone();
            let bind_paths = paths.clone();
            let bind_prompter = prompter.clone();
            let result = tokio::task::spawn_blocking(move || {
                feishu_control::ensure_binding(
                    &mut bind_config,
                    &bind_paths,
                    &bind_prompter,
                    &logger,
                    true,
                )
            })
            .await
            .context("Feishu binding task")??;
            match result {
                Some(binding) => {
                    println!(
                        "bound: chat_id={} open_id={}",
                        binding.chat_id, binding.open_id
                    )
                }
                None => println!("Feishu binding was not completed"),
            }
            Ok(0)
        }
        Command::ConfigFile => {
            println!("# config dir:  {}", paths.config_dir.display());
            println!("# config file: {}", paths.config_file.display());
            println!("# state dir:   {}", paths.data_dir().display());
            println!(
                "# build {} (fingerprint {})",
                env!("CARGO_PKG_VERSION"),
                buildinfo::fingerprint()
            );
            println!();
            print!("{}", std::fs::read_to_string(&paths.config_file)?);
            Ok(0)
        }
        Command::Init { .. } => unreachable!(),
    }
}

fn make_logger(
    config: &Config,
    paths: &Paths,
    name: &str,
    override_level: Option<&str>,
) -> Result<Logger> {
    let level = Level::parse(override_level.unwrap_or(&config.logging.level));
    Logger::new(
        &paths.log_dir(config),
        &format!("{name}.log"),
        level,
        config.logging.max_file_bytes,
        config.logging.keep_files,
        config.logging.stderr,
    )
}

fn log_paths(logger: &Logger, paths: &Paths, created: bool) {
    if created {
        logger.info(format!(
            "config dir was empty - created {} from templates/config.toml",
            paths.config_file.display()
        ));
    }
    logger.info(format!("config: {}", paths.config_file.display()));
    logger.info(format!("state:  {}", paths.data_dir().display()));
}

fn init(paths: &Paths, force: bool) -> Result<u8> {
    let backup = paths.write_template(force)?;
    let (config, _) = paths.load()?;
    let secret = ClusterSecret::resolve(&config.cluster_secret)?;
    let ports = server_ports(&config.server, &secret);
    std::fs::create_dir_all(paths.data_dir())?;
    std::fs::create_dir_all(paths.log_dir(&config))?;
    println!("config dir:        {}", paths.config_dir.display());
    println!("config file:       {}", paths.config_file.display());
    println!("state dir:         {}", paths.data_dir().display());
    println!("log dir:           {}", paths.log_dir(&config).display());
    if let Some(backup) = backup {
        println!("old config backed up to {}", backup.display());
    }
    println!("build fingerprint: {}", buildinfo::fingerprint());
    println!(
        "derived ports:     data {}, knock pool {:?} (random subset/order per attempt)",
        ports.main, ports.knock_pool
    );
    println!(
        "secret fingerprint: {} (same secret is required on every machine)",
        secret.fingerprint()
    );
    println!("\nnote: this config directory is ignored by git and must never be committed.");
    println!("next steps:");
    println!("  1. on the server:  promptsync server");
    println!("  2. on each agent:  set agent.server in the config, then promptsync agent");
    println!(
        "  3. if you build separately per machine, run `promptsync secret --show` on the server\n     and `promptsync secret --set <hex>` on the agents so they share the secret."
    );
    Ok(0)
}

fn resolve_secret(config: &Config) -> Result<ClusterSecret> {
    ClusterSecret::resolve(&config.cluster_secret)
}

fn ports(config: &Config, paths: &Paths) -> Result<u8> {
    let secret = resolve_secret(config)?;
    let endpoints = server_ports(&config.server, &secret);
    let agent_endpoints = agent_ports(&config.agent, &secret);
    println!(
        "build:      {} ({})",
        buildinfo::fingerprint(),
        buildinfo::description()
    );
    println!("config dir: {}", paths.config_dir.display());
    println!(
        "secret:     fingerprint {} ({})",
        secret.fingerprint(),
        if config.cluster_secret.trim().is_empty() {
            "embedded build secret"
        } else {
            "configured"
        }
    );
    println!(
        "data port:  {} (server bind {}:{})",
        endpoints.main, config.server.bind, endpoints.main
    );
    println!(
        "knock pool: {:?} ({} ports, {}..={} random per attempt)",
        endpoints.knock_pool,
        endpoints.knock_pool.len(),
        config.agent.knock_min,
        config.agent.knock_max
    );
    println!("agent uses data port {}", agent_endpoints.main);
    println!(
        "agent server target: {}:{}",
        config.agent.server, agent_endpoints.main
    );
    Ok(0)
}

fn secret(
    config: &mut Config,
    paths: &Paths,
    show: bool,
    generate: bool,
    set: Option<&str>,
) -> Result<u8> {
    if generate {
        let secret = ClusterSecret::random();
        println!("{}", secret.to_hex());
        println!("# fresh secret - store it in cluster_secret on every machine");
        return Ok(0);
    }
    if let Some(value) = set {
        let secret = ClusterSecret::from_hex(value)?;
        config.cluster_secret = secret.to_hex();
        set_cluster_secret(&paths.config_file, &secret.to_hex())?;
        println!(
            "cluster secret updated in {} (fingerprint {})",
            paths.config_file.display(),
            secret.fingerprint()
        );
        println!("# copy the same value to every other machine");
        return Ok(0);
    }
    let secret = resolve_secret(config)?;
    if show || set.is_none() {
        println!("{}", secret.to_hex());
        println!(
            "# keep this private; source: {}",
            if config.cluster_secret.trim().is_empty() {
                "compiled into this build"
            } else {
                "config file"
            }
        );
    }
    Ok(0)
}

fn status(config: &Config, paths: &Paths, json: bool) -> Result<u8> {
    let secret = resolve_secret(config)?;
    let ports = server_ports(&config.server, &secret);
    let agent_endpoints = agent_ports(&config.agent, &secret);
    let sources = resolve_sources(&config.sync);
    let options = ScanOptions::from(&config.sync);
    let entries = scan(&sources, &options, None)?;
    let hash = canonical_hash(&entries);
    let bytes = total_bytes(&entries);
    let data_dir = paths.data_dir();
    let log_dir = paths.log_dir(config);
    let state = agent::AgentState::load(&data_dir);
    let managed = std::fs::read_to_string(data_dir.join("managed.json"))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| {
            value
                .get("files")
                .and_then(|files| files.as_array())
                .map(|files| files.len())
        })
        .unwrap_or(0);

    if json {
        let payload = serde_json::json!({
            "build": buildinfo::fingerprint(),
            "config_dir": paths.config_dir.display().to_string(),
            "config_file": paths.config_file.display().to_string(),
            "state_dir": data_dir.display().to_string(),
            "log_dir": log_dir.display().to_string(),
            "secret_fingerprint": secret.fingerprint(),
            "secret_source": if config.cluster_secret.trim().is_empty() { "embedded" } else { "config" },
            "ports": { "data": ports.main, "knock_pool": ports.knock_pool, "agent_data": agent_endpoints.main, "agent_knock_pool": agent_endpoints.knock_pool },
            "agent": {
                "id": agent::effective_agent_id(config),
                "server": config.agent.server,
                "poll_secs": config.agent.poll_secs,
                "offline_threshold_secs": config.agent.offline_threshold_secs,
            },
            "state": state,
            "local": { "files": entries.len(), "bytes": bytes, "hash": hash, "managed": managed },
            "sources": sources.iter().map(|source| serde_json::json!({
                "id": source.id,
                "root": source.root.display().to_string(),
                "globs": source.globs,
                "exists": source.root.is_dir(),
            })).collect::<Vec<_>>(),
            "feishu": {
                "enabled": config.feishu.enabled,
                "app_configured": config.feishu_app_configured(),
                "bound": config.feishu_bound(),
                "owner_open_id": config.feishu.app.owner_open_id,
                "target": config.sync.target,
                "dry_run": config.feishu.control.dry_run,
            },
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(0);
    }

    println!("build            {}", buildinfo::fingerprint());
    println!("config dir       {}", paths.config_dir.display());
    println!("config file      {}", paths.config_file.display());
    println!("state dir        {}", data_dir.display());
    println!("logs             {}", log_dir.display());
    println!(
        "secret           fingerprint {} ({})",
        secret.fingerprint(),
        if config.cluster_secret.trim().is_empty() {
            "embedded"
        } else {
            "config"
        }
    );
    println!(
        "server data port {} (bind {})",
        ports.main, config.server.bind
    );
    println!(
        "knock pool       {:?} ({} ports, {}..={} chosen at random per attempt)",
        ports.knock_pool,
        ports.knock_pool.len(),
        config.agent.knock_min,
        config.agent.knock_max
    );
    println!("agent knock pool {:?}", agent_endpoints.knock_pool);
    println!(
        "agent            {} -> {}:{} every {}s (offline after {}s)",
        agent::effective_agent_id(config),
        config.agent.server,
        agent_endpoints.main,
        config.agent.poll_secs,
        config.agent.offline_threshold_secs
    );
    println!(
        "local prompts    {} files, {} (hash {}, {} managed)",
        entries.len(),
        promptsync::util::human_bytes(bytes),
        &hash[..16.min(hash.len())],
        managed
    );
    println!(
        "agent state      last success {}, failures {}, last error {}",
        if state.last_success_unix == 0 {
            "never".to_string()
        } else {
            format!(
                "{} ago",
                promptsync::util::human_age(
                    promptsync::util::now_unix().saturating_sub(state.last_success_unix)
                )
            )
        },
        state.consecutive_failures,
        state.last_error.as_deref().unwrap_or("-")
    );
    println!("feishu           {}", feishu::describe(config));
    println!(
        "feishu target    {}",
        if config.sync.target.trim().is_empty() {
            "-"
        } else {
            config.sync.target.trim()
        }
    );
    println!("sources:");
    for source in &sources {
        println!(
            "  {:<16} {:<60} {}",
            source.id,
            source.root.display(),
            if source.root.is_dir() {
                "ok"
            } else {
                "missing"
            }
        );
    }
    Ok(0)
}

async fn feishu_test(config: &Config, text: &str) -> Result<u8> {
    if !config.feishu.enabled {
        bail!("feishu.enabled is false in the config file");
    }
    if !config.feishu_app_configured() {
        bail!("feishu.app.app_id / app_secret are empty; create a Feishu app first");
    }
    if !config.feishu_bound() {
        bail!("the Feishu owner is not bound yet; run `promptsync feishu-bind`");
    }
    let message = if text.trim().is_empty() {
        format!(
            "【promptsync 测试】\n节点: {}\n构建: {}\n时间: {}",
            agent::effective_agent_id(config),
            buildinfo::fingerprint(),
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%SZ"),
        )
    } else {
        text.to_string()
    };
    let config = config.clone();
    tokio::task::spawn_blocking(move || feishu::notify_blocking(&config, &message))
        .await
        .context("Feishu task")??;
    println!("Feishu app accepted the message");
    Ok(0)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut interrupt = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
