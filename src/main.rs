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
use promptsync::{agent, feishu, server};

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
        /// Store this passphrase (or legacy 64-hex secret) in the configuration file
        #[arg(long, value_name = "PASSPHRASE")]
        set: Option<String>,
    },
    /// Send a test message through the Feishu app
    FeishuTest {
        #[arg(long, default_value = "")]
        text: String,
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

    // First start (or an old config created before this feature) gets a random
    // cluster secret. Never fall back to a key compiled into the binary: that
    // would make every download of the public release share the same key.
    let secret_generated = match &cli.command {
        Command::Server { .. } | Command::Agent { .. } => {
            ensure_cluster_secret(&paths, &mut config, false)?
        }
        Command::Status { json } => ensure_cluster_secret(&paths, &mut config, *json)?,
        Command::Ports => ensure_cluster_secret(&paths, &mut config, false)?,
        // `Secret` handles generation itself so `--set` does not first create a
        // throwaway key, and `FeishuTest`/`ConfigFile` do not need one.
        _ => false,
    };

    // Interactive only for the long-running roles, and only when the caller did
    // not already pass explicit overrides (that means "scripted use").
    let explicit_override = match &cli.command {
        Command::Server { bind, port } => bind.is_some() || port.is_some(),
        Command::Agent { server, port, once } => server.is_some() || port.is_some() || *once,
        _ => true,
    };
    let prompter = Prompter::new(!cli.non_interactive && !explicit_override);

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
            match interactive::prepare(
                &paths,
                config,
                created,
                Role::Server,
                &prompter,
                &logger,
                secret_generated,
            )? {
                Some(prepared) => config = prepared,
                None => {
                    println!("已取消启动，配置保留在 {}", paths.config_file.display());
                    return Ok(0);
                }
            }
            // Explicit CLI overrides win over anything the wizard wrote.
            if let Some(bind) = bind {
                config.server.bind = bind.clone();
            }
            if let Some(port) = port {
                config.server.port = *port;
            }
            logger.info(format!("configuration: {}", paths.config_file.display()));
            tokio::select! {
                result = server::run(config, logger.clone(), paths.data_dir(), paths.config_file.clone()) => result?,
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
            match interactive::prepare(
                &paths,
                config,
                created,
                Role::Agent,
                &prompter,
                &logger,
                secret_generated,
            )? {
                Some(prepared) => config = prepared,
                None => {
                    println!("已取消启动，配置保留在 {}", paths.config_file.display());
                    return Ok(0);
                }
            }
            if let Some(host) = host {
                config.agent.server = host.clone();
            }
            if let Some(port) = port {
                config.agent.port = *port;
            }
            logger.info(format!("configuration: {}", paths.config_file.display()));
            if *once {
                return agent::run_once(config, logger, paths.data_dir()).await;
            }
            tokio::select! {
                result = agent::run(config, logger.clone(), paths.data_dir(), paths.config_file.clone()) => result?,
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

/// Generate the cluster secret when the config does not have one yet and show
/// it once. The secret is deliberately printed to stdout (not the log file):
/// it is needed to pair the other machines, and the user may not have opened
/// `config.toml` yet.
fn ensure_cluster_secret(paths: &Paths, config: &mut Config, to_stderr: bool) -> Result<bool> {
    match config.ensure_cluster_secret(&paths.config_file)? {
        Some(secret) => {
            if to_stderr {
                eprint!("{}", generated_secret_text(paths, &secret));
            } else {
                print!("{}", generated_secret_text(paths, &secret));
            }
            Ok(true)
        }
        None => Ok(false),
    }
}

fn generated_secret_text(paths: &Paths, secret: &ClusterSecret) -> String {
    format!(
        "\n已为本机生成新的集群密钥（首次启动只生成一次）：\n  {}\n  指纹: {}\n  已写入: {}\n  所有机器必须使用同一个密钥。其他机器首次启动时粘贴它，\n  或运行 `promptsync secret --set \"<上面这串>\"`。\n  以后查看: `promptsync secret --show`，或打开上面的配置文件。\n  注意：这串密钥只在本终端显示，不要发到公开群或提交到 git。\n\n",
        secret.to_hex(),
        secret.fingerprint(),
        paths.config_file.display()
    )
}

fn print_generated_secret(paths: &Paths, secret: &ClusterSecret) {
    print!("{}", generated_secret_text(paths, secret));
}

fn init(paths: &Paths, force: bool) -> Result<u8> {
    let backup = paths.write_template(force)?;
    let (mut config, _) = paths.load()?;
    let generated = config.ensure_cluster_secret(&paths.config_file)?;
    if let Some(secret) = generated.as_ref() {
        print_generated_secret(paths, secret);
    }
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
    if generated.is_none() {
        println!("cluster secret:    {}", secret.to_hex());
    }
    println!(
        "secret fingerprint: {} (same secret is required on every machine)",
        secret.fingerprint()
    );
    println!(
        "secret file:       {} -> cluster_secret",
        paths.config_file.display()
    );
    println!("\nnote: this config directory is ignored by git and must never be committed.");
    println!("next steps:");
    println!("  1. on the server:  promptsync server");
    println!("  2. on each agent:  set agent.server in the config, then promptsync agent");
    println!(
        "  3. copy the cluster secret above to every other machine (wizard step 3 / `promptsync secret --set <secret>`)."
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
        "secret:     fingerprint {} (stored in {})",
        secret.fingerprint(),
        paths.config_file.display()
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
        let secret = ClusterSecret::from_input(value)?;
        config.cluster_secret = secret.to_hex();
        set_cluster_secret(&paths.config_file, &secret.to_hex())?;
        println!(
            "cluster secret updated in {} (fingerprint {})",
            paths.config_file.display(),
            secret.fingerprint()
        );
        println!("# type the same passphrase on every other machine");
        return Ok(0);
    }

    // `--show` or no arguments: make sure a first-run config gets a key, and
    // print it once (the same wording as server/agent startup).
    if let Some(generated) = config.ensure_cluster_secret(&paths.config_file)? {
        print_generated_secret(paths, &generated);
    }
    let secret = resolve_secret(config)?;
    if show || set.is_none() {
        println!("{}", secret.to_hex());
        println!(
            "# keep this private; stored in {} (cluster_secret)",
            paths.config_file.display()
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
    let client_files = promptsync::adapters::detect(&config.sync);
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
            "secret_source": "config",
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
            "adapters": {
                "enabled": config.sync.adapt_clients,
                "targets": client_files.iter().map(|adapter| serde_json::json!({
                    "id": adapter.id,
                    "path": adapter.path.display().to_string(),
                    "exists": adapter.path.is_file(),
                })).collect::<Vec<_>>(),
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
        "secret           fingerprint {} (config)",
        secret.fingerprint()
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
    if !config.sync.adapt_clients {
        println!("client prompts   disabled");
    } else {
        println!(
            "client prompts   {}",
            if client_files.is_empty() {
                "none detected".to_string()
            } else {
                format!("{} detected", client_files.len())
            }
        );
        for adapter in &client_files {
            println!(
                "  {:<16} {}{}",
                adapter.id,
                adapter.path.display(),
                if adapter.path.is_file() {
                    ""
                } else {
                    "  (new)"
                }
            );
        }
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
        bail!(
            "the Feishu owner is not bound yet; run `promptsync server` once in a terminal to bind"
        );
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
