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
    /// Personal configuration directory (default: ./config, or an existing ~/.promptsync)
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
    /// Re-run the configuration wizard even when a config already exists
    #[arg(long, global = true)]
    configure: bool,
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
    /// List the central backups of client instruction files
    /// (`<state>/client-backups`) and old `.bak` files not migrated yet
    Backups {
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
        /// Store this passphrase (or 64-hex secret) in the configuration file;
        /// `-` reads it from stdin (keeps it out of shell history and `ps`)
        #[arg(long, value_name = "PASSPHRASE", allow_hyphen_values = true)]
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
    // Inspecting state must not create a config directory (and a fresh cluster
    // secret) in whatever directory the command happened to run from.
    let needs_existing_config = matches!(
        cli.command,
        Command::Status { .. }
            | Command::Backups { .. }
            | Command::Ports
            | Command::ConfigFile
            | Command::FeishuTest { .. }
    );
    if needs_existing_config && !paths.config_file.exists() {
        bail!(
            "no config file at {}; run `promptsync server` or `promptsync agent` first, or pass --config-dir",
            paths.config_file.display()
        );
    }
    let (mut config, created) = paths.load()?;

    // Interactive only for the long-running roles, and only when the caller did
    // not already pass explicit overrides (that means "scripted use").
    let explicit_override = match &cli.command {
        Command::Server { bind, port } => bind.is_some() || port.is_some(),
        Command::Agent { server, port, once } => server.is_some() || port.is_some() || *once,
        _ => true,
    };
    // `--configure` must still reach the wizard even when a --port/--bind
    // override would otherwise make the run look scripted.
    let prompter = Prompter::new(!cli.non_interactive && (!explicit_override || cli.configure));
    if cli.configure && !prompter.enabled() && !cli.non_interactive {
        eprintln!("[promptsync] 当前不是交互终端，--configure 被忽略；请在终端里运行。");
    }

    // An agent never benefits from a freshly generated random secret: no server
    // can share it, so every handshake would time out silently. Scripted agent
    // runs (`--server`, `--once`, services) therefore refuse to start without a
    // secret instead of generating one; the wizard asks for the server's.
    if matches!(cli.command, Command::Agent { .. })
        && !prompter.enabled()
        && config.cluster_secret.trim().is_empty()
    {
        bail!(
            "{} 里还没有集群密钥。agent 必须使用 server 的同一个密钥，自动生成的随机密钥永远连不上。\n\
             先运行 `promptsync --config-dir {} secret --set \"<server 的密钥或口令>\"`，\n\
             或在终端里直接运行 `promptsync agent`（不带 --server/--once）进入向导。",
            paths.config_file.display(),
            paths.config_dir.display()
        );
    }

    // First start (or an old config created before this feature) gets a random
    // cluster secret. Never fall back to a key compiled into the binary: that
    // would make every download of the public release share the same key.
    let fresh_secret = match &cli.command {
        Command::Server { .. } | Command::Agent { .. } => {
            ensure_cluster_secret(&paths, &mut config, false)?
        }
        Command::Status { json } => ensure_cluster_secret(&paths, &mut config, *json)?,
        Command::Ports => ensure_cluster_secret(&paths, &mut config, false)?,
        // `Secret` handles generation itself so `--set` does not first create a
        // throwaway key, and `FeishuTest`/`ConfigFile` do not need one.
        _ => false,
    };
    // A secret generated in this run has not been paired with anything yet, so
    // treat the run like a first start: the wizard's secret step must appear
    // even when config.toml itself already existed (e.g. created by an earlier
    // scripted run), otherwise the random key would be used silently forever.
    let first_start = created || fresh_secret;

    // The server's signing key is generated on its first start (and added to
    // configs created by older versions). Agents never get one.
    if matches!(cli.command, Command::Server { .. })
        && config.ensure_signing_key(&paths.config_file)?
    {
        let signer = promptsync::crypto::ServerSigner::from_hex(&config.server.signing_key)?;
        let public = signer.public_hex();
        println!(
            "\n已生成 server 签名密钥（私钥保存在 {} 的 [server] signing_key，保密）。\n  公钥: {}\n  指纹: {}\n  agent 首次连接时会自动信任这把公钥；也可以把公钥填进 agent 的 [agent] server_public_key。\n",
            paths.config_file.display(),
            public,
            promptsync::crypto::server_key_fingerprint(&public)
        );
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
            match interactive::prepare(
                &paths,
                config,
                Role::Server,
                &prompter,
                &logger,
                interactive::PrepareOptions {
                    created: first_start,
                    force_wizard: cli.configure,
                },
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
                Role::Agent,
                &prompter,
                &logger,
                interactive::PrepareOptions {
                    created: first_start,
                    force_wizard: cli.configure,
                },
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
        Command::Backups { json } => backups(&config, &paths, *json),
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
        "  3. copy the cluster secret above to every other machine (the wizard's secret step / `promptsync secret --set <secret>`)."
    );
    println!(
        "  4. change settings later: edit {} or run `promptsync <server|agent> --configure`.",
        paths.config_file.display()
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
    let derived = secret.ports();
    let port_pinned = config.server.port != 0;
    let knock_pinned = !config.server.knock_ports.is_empty();
    println!(
        "data port:  {} (server bind {}:{}; {})",
        endpoints.main,
        config.server.bind,
        endpoints.main,
        if port_pinned {
            "pinned by [server] port"
        } else {
            "derived from the secret"
        }
    );
    println!(
        "knock pool: {:?} ({} ports, {}..={} random per attempt; {})",
        endpoints.knock_pool,
        endpoints.knock_pool.len(),
        config.agent.knock_min,
        config.agent.knock_max,
        if knock_pinned {
            "pinned by [server] knock_ports"
        } else {
            "derived from the secret"
        }
    );
    if config.server.signing_key.trim().is_empty() {
        println!("server key: (not generated yet; created on the first `promptsync server` start)");
    } else {
        let public =
            promptsync::crypto::ServerSigner::from_hex(&config.server.signing_key)?.public_hex();
        println!(
            "server key: fingerprint {} public {}",
            promptsync::crypto::server_key_fingerprint(&public),
            public
        );
    }
    // What every agent of this server must use. A pinned server port is not
    // derivable from the secret, so agents left at `port = 0` would knock and
    // then talk to the derived port and time out silently.
    println!("agents of this server:");
    if port_pinned {
        println!(
            "  [agent] port = {}   (required: the server pins it; port = 0 would use {})",
            endpoints.main, derived.main
        );
    } else {
        println!("  [agent] port = 0   (or {})", endpoints.main);
    }
    if knock_pinned {
        println!(
            "  [agent] knock_ports = {:?}   (required: the server pins them)",
            endpoints.knock_pool
        );
    } else {
        println!("  [agent] knock_ports = []   (derived from the same secret)");
    }
    if !config.server.signing_key.trim().is_empty() {
        let public =
            promptsync::crypto::ServerSigner::from_hex(&config.server.signing_key)?.public_hex();
        println!(
            "  [agent] server_public_key = \"{public}\"   (optional: pins the key instead of trusting it on first contact)"
        );
    }
    // The local [agent] section only matters when this machine runs an agent;
    // say so instead of printing numbers that look authoritative.
    let agent_matches = agent_endpoints == endpoints;
    println!(
        "this machine as agent: {}:{} knock {:?}{}",
        config.agent.server,
        agent_endpoints.main,
        agent_endpoints.knock_pool,
        if agent_matches {
            " (matches the server settings above)"
        } else {
            " (differs from the server settings above; only fine if the agent talks to another server)"
        }
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
        // `--set -` reads the secret from stdin so it never lands in shell
        // history or in the process list that other local users can read.
        let owned;
        let value = if value == "-" {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .context("reading the secret from stdin")?;
            owned = line;
            owned.as_str()
        } else {
            value
        };
        if let Some(warning) = ClusterSecret::passphrase_warning(value) {
            eprintln!("{warning}");
        }
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
    // 完整适配计划：要写入的客户端文件 + 可能造成重复加载的旧副本位置。
    let client_plan = promptsync::adapters::plan(&config.sync);
    let client_files = &client_plan.adapters;
    // 旧位置上确实还有文件的，才值得在 status 里提示。
    let duplicates: Vec<_> = client_plan
        .retire
        .iter()
        .filter(|old| old.path.is_file())
        .collect();
    let hash = canonical_hash(&entries);
    let bytes = total_bytes(&entries);
    let data_dir = paths.data_dir();
    let log_dir = paths.log_dir(config);
    let binding = promptsync::feishu_control::load_binding(&data_dir)
        .filter(|binding| binding.app_id == config.feishu.app.app_id.trim());
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
                "chat_id": binding.as_ref().map(|binding| binding.chat_id.clone()).unwrap_or_default(),
                "target": config.sync.target,
                "dry_run": config.feishu.control.dry_run,
            },
            "adapters": {
                "enabled": config.sync.adapt_clients,
                "targets": client_files.iter().map(|adapter| serde_json::json!({
                    "id": adapter.id,
                    "path": adapter.path.display().to_string(),
                    "exists": adapter.path.is_file(),
                    // 非空时该文件只写一行导入语句，导入的目标文件。
                    "imports": adapter.import,
                })).collect::<Vec<_>>(),
                // 下次同步时会检查的旧副本（是同步副本就备份移走，否则保留并告警）。
                "duplicates": duplicates.iter().map(|old| serde_json::json!({
                    "id": old.id,
                    "path": old.path.display().to_string(),
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
    if let Some(binding) = binding.as_ref() {
        println!(
            "feishu chat      {} -> {}（私聊发纯文本即可覆盖）",
            binding.chat_id,
            if config.sync.target.trim().is_empty() {
                "-"
            } else {
                config.sync.target.trim()
            }
        );
    } else if config.feishu.enabled && config.feishu_app_configured() {
        println!("feishu chat      -（未绑定：启动 server 后自动用应用所有者绑定）");
    }
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
        for adapter in client_files {
            println!(
                "  {:<16} {}{}{}",
                adapter.id,
                adapter.path.display(),
                if adapter.path.is_file() {
                    ""
                } else {
                    "  (new)"
                },
                // 导入语句文件：说明它引用的是哪个文件，而不是 prompt 正文。
                adapter
                    .import
                    .as_ref()
                    .map(|target| format!("  (imports {target})"))
                    .unwrap_or_default()
            );
        }
        // 客户端文件的旧内容统一备份在这里（`promptsync backups` 查看详情）。
        println!(
            "  {:<16} {}  (`promptsync backups` lists them)",
            "backups",
            paths
                .data_dir()
                .join(promptsync::client_backups::DIR_NAME)
                .display()
        );
        // 旧位置上的文件会让同一个引擎读到两份 prompt。
        for old in &duplicates {
            println!(
                "  {:<16} {}  (duplicate: moved away on the next sync if it is a promptsync copy)",
                old.id,
                old.path.display()
            );
        }
    }
    Ok(0)
}

/// `promptsync backups`：列出集中备份库里的备份，以及客户端目录里还没迁移的旧 `.bak`。
///
/// 参数：`config` 当前配置；`paths` 配置/状态目录；`json` 为 true 时输出 JSON。
/// 只读，不改动任何文件（迁移由 agent 在下一次同步时完成）。
fn backups(config: &Config, paths: &Paths, json: bool) -> Result<u8> {
    use promptsync::client_backups::{BackupStore, Kind};
    let data_dir = paths.data_dir();
    // 集中备份库及其全部记录。
    let store = BackupStore::new(&data_dir);
    let entries = store.entries();
    // 客户端目录里还留着的旧备份（演练，不改动文件）。
    let pending = promptsync::adapters::pending_migration(&config.sync, &data_dir);
    if json {
        // 把一条记录转换成 JSON（附带内容文件路径）。
        let entry_json = |entry: &promptsync::client_backups::Entry| {
            serde_json::json!({
                "time": entry.time,
                "id": entry.id,
                "path": entry.path,
                "kind": entry.kind,
                "bytes": entry.bytes,
                "sha256": entry.sha256,
                "file": store.blob_path(entry).display().to_string(),
            })
        };
        let payload = serde_json::json!({
            "store": store.root().display().to_string(),
            "entries": entries.iter().map(entry_json).collect::<Vec<_>>(),
            "pending_migration": pending.iter().map(|(old, entry)| serde_json::json!({
                "file": old.display().to_string(),
                "kind": entry.kind,
                "path": entry.path,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(0);
    }
    println!("backup store   {}", store.root().display());
    if entries.is_empty() {
        println!("  (empty)");
    }
    // 先列原始文件（永不自动清理），再按时间从新到旧列其他备份。
    let originals: Vec<_> = entries
        .iter()
        .filter(|entry| entry.kind == Kind::Original)
        .collect();
    let others: Vec<_> = entries
        .iter()
        .rev()
        .filter(|entry| entry.kind != Kind::Original)
        .collect();
    for (title, group) in [
        (
            "原始文件（promptsync 接管前的内容，永不自动清理）",
            originals,
        ),
        (
            "其他备份（从新到旧，每个文件保留 sync.keep_backups 份）",
            others,
        ),
    ] {
        if group.is_empty() {
            continue;
        }
        println!("{title}");
        for entry in group {
            println!(
                "  {}  {:<12} {:<10} {:>6} B  {}",
                entry.time,
                entry.id,
                entry.kind.label(),
                entry.bytes,
                entry.path
            );
            println!("      -> {}", store.blob_path(entry).display());
        }
    }
    if !pending.is_empty() {
        println!(
            "待迁移的旧备份（{} 个，agent 下一次同步时移入备份库）",
            pending.len()
        );
        for (old, entry) in &pending {
            println!("  {}  [{}]", old.display(), entry.kind.label());
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
