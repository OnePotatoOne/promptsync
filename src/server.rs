//! Server role: owns the authoritative prompt set, publishes its hash and
//! serves bundles to port-knocked, authenticated agents.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::buildinfo;
use crate::commands;
use crate::config::Config;
use crate::crypto::{
    accept_hello, server_key_fingerprint, ClusterSecret, ServerSigner, SessionKeys,
    MAX_CLOCK_SKEW_SECS, TYPE_HELLO,
};
use crate::feishu;
use crate::knock::{server_ports, Gate, KnockOutcome, KnockTracker};
use crate::logx::Logger;
use crate::prompts::{canonical_hash, resolve_sources, scan, total_bytes, ScanOptions, SourceSpec};
use crate::proto::{decode_request, encode_response, Bundle, Manifest, Request, Response};
use crate::util::{atomic_write, now_unix};
use crate::wire::{handshake_kind, Channel, Header, MAX_MESSAGE};

// HELLOs are cheap to reject before authentication, so the limit only needs to
// stop brute force. It must stay above the legitimate rate: several agents
// behind one NAT, a short `agent.poll_secs`, or a restart with retries all
// share the same source IP. At 120/min a single agent can poll every second
// and twenty agents on a 10s poll still fit.
const HELLO_RATE_LIMIT: usize = 120;
const HELLO_RATE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Default)]
struct Snapshot {
    epoch: u64,
    hash: String,
    entries: Arc<BTreeMap<String, Vec<u8>>>,
    updated_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub last_seen_unix: u64,
    pub peer: String,
    pub hash: String,
    #[serde(default)]
    pub offline_reported: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AgentRegistry {
    #[serde(default)]
    agents: BTreeMap<String, AgentRecord>,
}

struct SessionEntry {
    peer: SocketAddr,
    sender: mpsc::Sender<Vec<u8>>,
    instance: u64,
    hello: Vec<u8>,
    ready: Vec<u8>,
}

struct ServerState {
    config: Config,
    secret: Arc<ClusterSecret>,
    /// Signs every manifest; agents pin `signer_public`.
    signer: ServerSigner,
    /// Hex public key matching `signer`, sent with each manifest.
    signer_public: String,
    sources: Vec<SourceSpec>,
    scan_options: ScanOptions,
    snapshot: Mutex<Snapshot>,
    gate: Arc<Gate>,
    registry: Mutex<AgentRegistry>,
    data_dir: std::path::PathBuf,
    /// Config path shown by `--status` / `--config`.
    config_file: std::path::PathBuf,
    logger: Logger,
    knocks: Arc<KnockTracker>,
    sessions: Mutex<HashMap<[u8; 8], SessionEntry>>,
    session_count: AtomicUsize,
    next_session_instance: AtomicU64,
    hello_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    max_sessions: usize,
    /// Recipient of offline alerts; updated when a binding is established at
    /// runtime, so a later restart is not required for alerts to work.
    feishu_owner: crate::feishu_control::OwnerCell,
}

pub async fn run(
    mut config: Config,
    logger: Logger,
    data_dir: std::path::PathBuf,
    config_file: std::path::PathBuf,
) -> Result<()> {
    config.validate()?;
    // The control channel manages exactly one file. When `sync.target` is empty
    // (a fresh config started from a service or with --port/--bind skips the
    // wizard), pick the single candidate instead of silently disabling Feishu.
    if config.feishu.enabled && config.feishu_app_configured() {
        if let Err(err) =
            crate::feishu_control::ensure_target(&mut config, &config_file, &logger, false)
        {
            logger.warn(format!("cannot auto-detect sync.target: {err:#}"));
        }
    }
    let secret = Arc::new(
        ClusterSecret::resolve(&config.cluster_secret).context("resolving cluster secret")?,
    );
    let ports = server_ports(&config.server, &secret);
    // The CLI generates the key on first start; a library caller (tests) must
    // provide one. Never sign with a throwaway key: agents pin the public key,
    // so a key that changes on restart would lock every agent out.
    if config.server.signing_key.trim().is_empty() {
        bail!("server.signing_key is empty; start the server through `promptsync server` once to generate it");
    }
    let signer =
        ServerSigner::from_hex(&config.server.signing_key).context("loading server.signing_key")?;
    let signer_public = signer.public_hex();
    fs::create_dir_all(&data_dir).with_context(|| format!("creating {}", data_dir.display()))?;
    let sources = resolve_sources(&config.sync);
    let scan_options = ScanOptions::from(&config.sync);
    let entries = scan(&sources, &scan_options, Some(&logger))?;
    let hash = canonical_hash(&entries);

    logger.info(buildinfo::description());
    logger.info(format!(
        "secret fingerprint {} | data port {} | knock pool {:?} (each attempt uses a random subset/order)",
        secret.fingerprint(),
        ports.main,
        ports.knock_pool
    ));
    logger.info(format!(
        "server signing key {} (public key {signer_public}; agents pin it on first contact or via [agent] server_public_key)",
        server_key_fingerprint(&signer_public)
    ));
    logger.info(format!(
        "watching {} source(s): {} files, {} hash {}",
        sources.len(),
        entries.len(),
        crate::util::human_bytes(total_bytes(&entries)),
        short_hash(&hash)
    ));
    logger.info(format!(
        "受管文件 {} | 数据端口 {}（敲门成功后开放） | 飞书 {}",
        if config.sync.target.trim().is_empty() {
            "未设置（飞书控制关闭）".to_string()
        } else {
            config.sync.target.trim().to_string()
        },
        ports.main,
        feishu::describe(&config)
    ));
    logger.info(format!(
        "要改配置：编辑 {}，或运行 `promptsync server --configure`（日志 {}）",
        config_file.display(),
        logger.path().display()
    ));

    let registry = load_registry(&data_dir);
    if !registry.agents.is_empty() {
        logger.info(format!("tracking {} known agent(s)", registry.agents.len()));
    }

    // A binding file may already carry the recipient even when config.toml has
    // no owner_open_id yet (e.g. after a restart right after binding).
    let initial_owner = {
        let configured = config.feishu.app.owner_open_id.trim();
        if !configured.is_empty() {
            configured.to_string()
        } else {
            crate::feishu_control::load_binding(&data_dir)
                .filter(|binding| binding.app_id == config.feishu.app.app_id.trim())
                .map(|binding| binding.open_id)
                .filter(|owner| !owner.trim().is_empty())
                .unwrap_or_default()
        }
    };
    let feishu_owner = crate::feishu_control::owner_cell(&initial_owner);

    let state = Arc::new(ServerState {
        gate: Arc::new(Gate::new(Duration::from_secs(config.server.gate_ttl_secs))),
        knocks: Arc::new(KnockTracker::new(
            ports.knock_pool.clone(),
            secret.knock_key(),
            Duration::from_secs(config.server.knock_window_secs),
        )),
        max_sessions: config.server.max_sessions,
        snapshot: Mutex::new(Snapshot {
            epoch: 1,
            hash,
            entries: Arc::new(entries),
            updated_unix: now_unix(),
        }),
        sessions: Mutex::new(HashMap::new()),
        session_count: AtomicUsize::new(0),
        next_session_instance: AtomicU64::new(1),
        hello_attempts: Mutex::new(HashMap::new()),
        config,
        secret,
        signer,
        signer_public,
        sources,
        scan_options,
        registry: Mutex::new(registry),
        data_dir,
        config_file,
        feishu_owner,
        logger: logger.clone(),
    });

    for port in ports.knock_pool.clone() {
        let tracker = state.knocks.clone();
        let gate = state.gate.clone();
        let logger = logger.clone();
        let host = state.config.server.bind.clone();
        tokio::spawn(async move {
            knock_listener(&host, port, tracker, gate, logger).await;
        });
    }

    {
        let state = state.clone();
        tokio::spawn(async move { watch_sources(state).await });
    }
    {
        let state = state.clone();
        tokio::spawn(async move { monitor_agents(state).await });
    }

    if state.config.feishu.enabled {
        if !state.config.feishu_app_configured() {
            logger.info("Feishu control disabled: feishu.app.app_id / app_secret are empty");
        } else {
            match crate::feishu_control::resolve_target(&state.config, &state.sources) {
                Ok(target) => {
                    let binding = crate::feishu_control::load_binding(&state.data_dir);
                    if let Some(binding) = binding.as_ref() {
                        logger.info(format!(
                            "Feishu control: private chat {} -> {} (dry_run={})",
                            binding.chat_id, target.key, state.config.feishu.control.dry_run
                        ));
                    } else {
                        logger.info(
                            "Feishu: 尚未绑定；正在自动识别接收人（应用所有者）并绑定，不需要你发消息",
                        );
                    }
                    let config = state.config.clone();
                    let data_dir = state.data_dir.clone();
                    let feishu_config_file = state.config_file.clone();
                    let owner = Arc::clone(&state.feishu_owner);
                    let logger = logger.clone();
                    // `--commands` read this live, so a reply always shows the
                    // current epoch, port and agent list.
                    let status_state = Arc::clone(&state);
                    let status: crate::feishu_control::StatusProvider =
                        Arc::new(move || command_status(&status_state));
                    tokio::spawn(async move {
                        if let Err(err) = crate::feishu_control::run(
                            config,
                            data_dir,
                            feishu_config_file,
                            target,
                            binding,
                            owner,
                            logger.clone(),
                            status,
                        )
                        .await
                        {
                            logger.error(format!("Feishu control stopped: {err:#}"));
                        }
                    });
                }
                Err(err) => logger.warn(format!(
                    "Feishu control disabled until sync.target is fixed: {err:#}"
                )),
            }
        }
    } else if !state.config.sync.target.trim().is_empty() {
        logger.info("Feishu control disabled (feishu.enabled = false)");
    }

    let bind_host = state.config.server.bind.clone();
    let bind_addr_text = format!("{bind_host}:{}", ports.main);
    loop {
        state.gate.wait_for_active().await;
        let socket = match UdpSocket::bind(&bind_addr_text).await {
            Ok(socket) => Arc::new(socket),
            Err(err) => {
                logger.error(format!("cannot bind {bind_addr_text}: {err}"));
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        logger.info(format!(
            "data port {bind_addr_text} is now open (authorised clients present)"
        ));
        serve_socket(state.clone(), socket).await;
        logger.info(format!(
            "data port {bind_addr_text} closed again (nobody authorised)"
        ));
    }
}

/// Collect the numbers printed by a `--command` reply.
///
/// Called from the Feishu ingest loop on every command, so it stays read-only
/// and cheap: three short lock acquisitions and one small file read.
fn command_status(state: &Arc<ServerState>) -> commands::Status {
    let snapshot = state
        .snapshot
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let ports = server_ports(&state.config.server, &state.secret);
    let binding = crate::feishu_control::load_binding(&state.data_dir);
    let mut agents: Vec<commands::AgentRow> = state
        .registry
        .lock()
        .map(|registry| {
            registry
                .agents
                .iter()
                .map(|(id, record)| commands::AgentRow {
                    id: id.clone(),
                    last_seen_unix: record.last_seen_unix,
                    peer: record.peer.clone(),
                    hash: record.hash.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    agents.sort_by_key(|agent| std::cmp::Reverse(agent.last_seen_unix));

    commands::Status {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build: buildinfo::fingerprint().to_string(),
        config_file: state.config_file.display().to_string(),
        log_file: state.logger.path().display().to_string(),
        target: state.config.sync.target.trim().to_string(),
        hash: snapshot.hash.clone(),
        epoch: snapshot.epoch,
        files: snapshot.entries.len(),
        bytes: total_bytes(&snapshot.entries),
        updated_unix: snapshot.updated_unix,
        bind_addr: state.config.server.bind.clone(),
        data_port: ports.main,
        knock_pool: ports.knock_pool.clone(),
        secret_fingerprint: state.secret.fingerprint(),
        feishu_app: mask_id(state.config.feishu.app.app_id.trim()),
        feishu_owner: mask_id(&binding_owner(&state.config, binding.as_ref())),
        feishu_chat: binding
            .as_ref()
            .map(|binding| binding.chat_id.clone())
            .unwrap_or_default(),
        feishu_bound_unix: binding
            .as_ref()
            .map(|binding| binding.bound_unix)
            .unwrap_or(0),
        dry_run: state.config.feishu.control.dry_run,
        agents,
        online_window_secs: state.config.agent.offline_threshold_secs.max(30),
        now: now_unix(),
    }
}

/// Recipient shown by `--whoami`: config wins, then the binding file.
fn binding_owner(config: &Config, binding: Option<&crate::feishu_control::Binding>) -> String {
    let configured = config.feishu.app.owner_open_id.trim();
    if !configured.is_empty() {
        configured.to_string()
    } else {
        binding
            .map(|binding| binding.open_id.clone())
            .unwrap_or_default()
    }
}

/// Short `cli_aa7a…9bfe` form for app ids and open ids in chat replies.
fn mask_id(value: &str) -> String {
    let chars: Vec<char> = value.trim().chars().collect();
    if chars.len() <= 10 {
        return value.trim().to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

async fn knock_listener(
    host: &str,
    port: u16,
    tracker: Arc<KnockTracker>,
    gate: Arc<Gate>,
    logger: Logger,
) {
    let socket = match UdpSocket::bind((host, port)).await {
        Ok(socket) => socket,
        Err(err) => {
            logger.error(format!("cannot bind knock port {port}: {err}"));
            return;
        }
    };
    logger.debug(format!("listening for knocks on udp/{port}"));
    let mut buffer = vec![0u8; 512];
    loop {
        let (size, peer) = match socket.recv_from(&mut buffer).await {
            Ok(value) => value,
            Err(_) => continue,
        };
        match tracker.submit(&buffer[..size], peer.ip(), port) {
            KnockOutcome::Complete => {
                logger.info(format!(
                    "knock sequence completed by {} - gate open for udp/{}",
                    peer.ip(),
                    port
                ));
                gate.open(peer.ip());
            }
            KnockOutcome::Progress { seen, total } => {
                logger.debug(format!("knock progress from {}: {seen}/{total}", peer.ip()));
            }
            KnockOutcome::Rejected => {
                logger.debug(format!("ignored invalid knock from {}", peer.ip()));
            }
        }
    }
}

async fn watch_sources(state: Arc<ServerState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let entries = match scan(&state.sources, &state.scan_options, Some(&state.logger)) {
            Ok(entries) => entries,
            Err(err) => {
                state
                    .logger
                    .error(format!("scanning prompt sources failed: {err:#}"));
                continue;
            }
        };
        let hash = canonical_hash(&entries);
        let mut snapshot = match state.snapshot.lock() {
            Ok(snapshot) => snapshot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if snapshot.hash == hash {
            continue;
        }
        let changes = diff_summary(&snapshot.entries, &entries);
        snapshot.epoch += 1;
        snapshot.hash = hash.clone();
        snapshot.updated_unix = now_unix();
        snapshot.entries = Arc::new(entries.clone());
        state.logger.info(format!(
            "prompt set changed (epoch {}, hash {}, {} files, {}): {changes}",
            snapshot.epoch,
            short_hash(&hash),
            entries.len(),
            crate::util::human_bytes(total_bytes(&entries))
        ));
    }
}

fn diff_summary(old: &BTreeMap<String, Vec<u8>>, new: &BTreeMap<String, Vec<u8>>) -> String {
    let added: Vec<&String> = new.keys().filter(|key| !old.contains_key(*key)).collect();
    let removed: Vec<&String> = old.keys().filter(|key| !new.contains_key(*key)).collect();
    let modified: Vec<&String> = new
        .iter()
        .filter(|(key, content)| old.get(*key).map(|old| old != *content).unwrap_or(false))
        .map(|(key, _)| key)
        .collect();
    let mut parts = Vec::new();
    if !added.is_empty() {
        parts.push(format!("added {added:?}"));
    }
    if !removed.is_empty() {
        parts.push(format!("removed {removed:?}"));
    }
    if !modified.is_empty() {
        parts.push(format!("modified {modified:?}"));
    }
    parts.join(", ")
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(16).collect()
}

async fn serve_socket(state: Arc<ServerState>, socket: Arc<UdpSocket>) {
    let mut buffer = vec![0u8; 2048];
    loop {
        tokio::select! {
            result = socket.recv_from(&mut buffer) => {
                match result {
                    Ok((size, peer)) => {
                        handle_datagram(&state, &socket, &buffer[..size], peer).await;
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(400)) => {}
        }
        state.gate.prune();
        state.knocks.prune();
        if state.session_count.load(Ordering::SeqCst) == 0 && !state.gate.any_active() {
            return;
        }
    }
}

async fn handle_datagram(
    state: &Arc<ServerState>,
    socket: &Arc<UdpSocket>,
    packet: &[u8],
    peer: SocketAddr,
) {
    if !state.gate.allows(peer.ip()) {
        state
            .logger
            .debug(format!("dropped datagram from unauthorised {}", peer.ip()));
        return;
    }
    state.gate.touch(peer.ip());

    if handshake_kind(packet) == Some(TYPE_HELLO) {
        let session_id: [u8; 8] = packet[4..12].try_into().expect("validated HELLO header");
        let existing = {
            let sessions = match state.sessions.lock() {
                Ok(sessions) => sessions,
                Err(poisoned) => poisoned.into_inner(),
            };
            cached_hello(&sessions, &session_id, peer, packet)
        };
        if let Some((is_retransmit, ready)) = existing {
            // Replaying an authenticated HELLO must be idempotent: creating a
            // new ephemeral key here would desynchronise the first READY that
            // the client accepted from the session retained by the server.
            if is_retransmit {
                let _ = socket.send_to(&ready, peer).await;
            }
            return;
        }
        if !allow_hello(state, peer.ip()) {
            state
                .logger
                .warn(format!("HELLO rate limit hit for {}", peer.ip()));
            return;
        }
        if state.session_count.load(Ordering::SeqCst) >= state.max_sessions {
            state.logger.warn("session limit reached, dropping HELLO");
            return;
        }
        match accept_hello(
            packet,
            &state.secret.auth_key(),
            now_unix(),
            MAX_CLOCK_SKEW_SECS,
        ) {
            Ok(handshake) => {
                let (tx, rx) = mpsc::channel(2048);
                let instance = state.next_session_instance.fetch_add(1, Ordering::Relaxed);
                {
                    let mut sessions = match state.sessions.lock() {
                        Ok(sessions) => sessions,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    // Another identical HELLO may have been handled between the
                    // lookup and authentication. Never replace a live session.
                    if sessions.contains_key(&handshake.session) {
                        return;
                    }
                    sessions.insert(
                        handshake.session,
                        SessionEntry {
                            peer,
                            sender: tx,
                            instance,
                            hello: packet.to_vec(),
                            ready: handshake.packet.clone(),
                        },
                    );
                }
                if socket.send_to(&handshake.packet, peer).await.is_err() {
                    state
                        .logger
                        .warn(format!("failed to answer HELLO from {peer}"));
                    remove_session_if_current(state, &handshake.session, instance);
                    return;
                }
                state.logger.debug(format!(
                    "session {} opened for {peer}",
                    hex::encode(handshake.session)
                ));
                tokio::spawn(session_task(
                    state.clone(),
                    socket.clone(),
                    peer,
                    handshake.session,
                    instance,
                    handshake.keys,
                    rx,
                    Instant::now(),
                ));
            }
            Err(err) => {
                state
                    .logger
                    .debug(format!("rejected HELLO from {peer}: {err}"));
            }
        }
        return;
    }

    let header = match Header::parse(packet) {
        Ok(header) => header,
        Err(_) => return,
    };
    let sender = {
        let sessions = match state.sessions.lock() {
            Ok(sessions) => sessions,
            Err(poisoned) => poisoned.into_inner(),
        };
        sessions
            .get(&header.session)
            .filter(|entry| entry.peer == peer)
            .map(|entry| entry.sender.clone())
    };
    if let Some(sender) = sender {
        if sender.try_send(packet.to_vec()).is_err() {
            state.logger.debug("session queue full, dropping datagram");
        }
    }
}

fn allow_hello(state: &ServerState, ip: IpAddr) -> bool {
    let mut attempts = match state.hello_attempts.lock() {
        Ok(attempts) => attempts,
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = Instant::now();
    attempts.retain(|_, list| {
        list.retain(|instant| now.duration_since(*instant) < HELLO_RATE_WINDOW);
        !list.is_empty()
    });
    let list = attempts.entry(crate::util::norm_ip(ip)).or_default();
    if list.len() >= HELLO_RATE_LIMIT {
        return false;
    }
    list.push(now);
    true
}

/// One authenticated session: answers STATUS / BUNDLE / BYE until the agent
/// leaves or stays silent for 30 s. `ready_sent` is when READY went out and
/// seeds the channel RTT from the first request.
#[allow(clippy::too_many_arguments)]
async fn session_task(
    state: Arc<ServerState>,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    session_id: [u8; 8],
    instance: u64,
    keys: SessionKeys,
    rx: mpsc::Receiver<Vec<u8>>,
    ready_sent: Instant,
) {
    state.session_count.fetch_add(1, Ordering::SeqCst);
    let mut channel = Channel::new(socket, peer, session_id, &keys, false, rx, None);
    let mut agent_id = String::from("unknown");
    let mut first_request = true;
    loop {
        let payload = match channel.recv_message(Duration::from_secs(30)).await {
            Ok(payload) => payload,
            Err(_) => break,
        };
        if first_request {
            // The agent sends STATUS right after READY, so this is one RTT and
            // seeds the timeout for our (possibly large) replies.
            channel.set_rtt_hint(ready_sent.elapsed());
            first_request = false;
        }
        state.gate.touch(peer.ip());
        let request = match decode_request(&payload) {
            Ok(request) => request,
            Err(err) => {
                state.logger.warn(format!("bad request from {peer}: {err}"));
                let _ = reply(
                    &mut channel,
                    &state.config,
                    &Response::Error {
                        code: "bad_request".to_string(),
                        message: err.to_string(),
                    },
                )
                .await;
                break;
            }
        };
        match request {
            Request::Status {
                agent_id: id,
                applied_hash,
            } => {
                agent_id = sanitize_agent_id(&id);
                let snapshot = current_snapshot(&state);
                // Record what the agent reports it holds, not our own hash:
                // `--agents` must reveal a machine that is behind.
                state.record_agent(&agent_id, peer, &sanitize_hash(&applied_hash));
                state.logger.debug(format!(
                    "status for {agent_id} from {peer}: epoch {} hash {}",
                    snapshot.epoch,
                    short_hash(&snapshot.hash)
                ));
                let (feishu_app_id, feishu_owner_open_id) = if state.config.feishu.enabled {
                    let app_id = state.config.feishu.app.app_id.trim().to_string();
                    let binding_owner = crate::feishu_control::load_binding(&state.data_dir)
                        .filter(|binding| binding.app_id == app_id)
                        .map(|binding| binding.open_id)
                        .filter(|owner| !owner.trim().is_empty());
                    let configured_owner = state.config.feishu.app.owner_open_id.trim();
                    let owner = binding_owner.unwrap_or_else(|| configured_owner.to_string());
                    (app_id, owner)
                } else {
                    (String::new(), String::new())
                };
                let mut manifest = Manifest {
                    epoch: snapshot.epoch,
                    hash: snapshot.hash.clone(),
                    files: snapshot.entries.len(),
                    bytes: total_bytes(&snapshot.entries),
                    updated_unix: snapshot.updated_unix,
                    target: state.config.sync.target.clone(),
                    feishu_app_id,
                    feishu_owner_open_id,
                    server_key: state.signer_public.clone(),
                    signature: String::new(),
                };
                manifest.signature = state.signer.sign_hex(&manifest.signing_bytes());
                if reply(&mut channel, &state.config, &Response::Status(manifest))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Request::Bundle { agent_id: id } => {
                agent_id = sanitize_agent_id(&id);
                let snapshot = current_snapshot(&state);
                let bundle =
                    Bundle::from_entries(&snapshot.entries, snapshot.epoch, snapshot.hash.clone());
                let encoded = match encode_response(&Response::Bundle(bundle.clone())) {
                    Ok(encoded) => encoded,
                    Err(err) => {
                        state.logger.error(format!("cannot encode bundle: {err}"));
                        break;
                    }
                };
                if encoded.len() > MAX_MESSAGE {
                    state.logger.error(format!(
                        "bundle too large for one transfer ({} bytes)",
                        encoded.len()
                    ));
                    let _ = reply(
                        &mut channel,
                        &state.config,
                        &Response::Error {
                            code: "bundle_too_large".to_string(),
                            message: "reduce sync.max_bundle_bytes".to_string(),
                        },
                    )
                    .await;
                    break;
                }
                state.logger.info(format!(
                    "serving bundle epoch {} ({} files, {}) to {agent_id} at {peer}",
                    snapshot.epoch,
                    snapshot.entries.len(),
                    crate::util::human_bytes(encoded.len() as u64)
                ));
                if reply(&mut channel, &state.config, &Response::Bundle(bundle))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Request::Bye {
                agent_id: id,
                applied_hash,
            } => {
                // After a pull the agent reports the bundle it just applied.
                let applied = sanitize_hash(&applied_hash);
                if !applied.is_empty() {
                    agent_id = sanitize_agent_id(&id);
                    state.record_agent(&agent_id, peer, &applied);
                }
                break;
            }
        }
    }

    remove_session_if_current(&state, &session_id, instance);
    state.session_count.fetch_sub(1, Ordering::SeqCst);
    state.logger.debug(format!(
        "session {} closed for {peer} (agent {agent_id})",
        hex::encode(session_id)
    ));
}

fn cached_hello(
    sessions: &HashMap<[u8; 8], SessionEntry>,
    session_id: &[u8; 8],
    peer: SocketAddr,
    packet: &[u8],
) -> Option<(bool, Vec<u8>)> {
    sessions.get(session_id).map(|entry| {
        (
            entry.peer == peer && entry.hello == packet,
            entry.ready.clone(),
        )
    })
}

fn remove_session_if_current(state: &ServerState, session_id: &[u8; 8], instance: u64) {
    let mut sessions = match state.sessions.lock() {
        Ok(sessions) => sessions,
        Err(poisoned) => poisoned.into_inner(),
    };
    remove_session_from_map_if_current(&mut sessions, session_id, instance);
}

fn remove_session_from_map_if_current(
    sessions: &mut HashMap<[u8; 8], SessionEntry>,
    session_id: &[u8; 8],
    instance: u64,
) {
    if sessions
        .get(session_id)
        .map(|entry| entry.instance == instance)
        .unwrap_or(false)
    {
        sessions.remove(session_id);
    }
}

async fn reply(channel: &mut Channel, config: &Config, response: &Response) -> Result<()> {
    let payload = encode_response(response)?;
    let timeout = Duration::from_secs(config.agent.request_timeout_secs.max(2) * 3);
    channel.send_message(&payload, timeout).await
}

fn current_snapshot(state: &ServerState) -> Snapshot {
    match state.snapshot.lock() {
        Ok(snapshot) => snapshot.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Keep only a plausible hex hash reported by an agent (max 64 chars).
///
/// `hash` is untrusted input from an authenticated peer; anything that is not
/// hex is dropped so the registry and Feishu replies stay clean.
fn sanitize_hash(hash: &str) -> String {
    let trimmed = hash.trim();
    if trimmed.len() <= 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        trimmed.to_ascii_lowercase()
    } else {
        String::new()
    }
}

fn sanitize_agent_id(id: &str) -> String {
    let cleaned: String = id
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-_.:@".contains(*c))
        .take(128)
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

impl ServerState {
    fn record_agent(&self, agent_id: &str, peer: SocketAddr, hash: &str) {
        let now = now_unix();
        let mut registry = match self.registry.lock() {
            Ok(registry) => registry,
            Err(poisoned) => poisoned.into_inner(),
        };
        let recovered = {
            let record = registry
                .agents
                .entry(agent_id.to_string())
                .or_insert_with(|| AgentRecord {
                    last_seen_unix: now,
                    peer: peer.to_string(),
                    hash: hash.to_string(),
                    offline_reported: false,
                });
            let recovered = record.offline_reported;
            record.last_seen_unix = now;
            record.peer = peer.to_string();
            // Older agents report no hash; keep the last known value then.
            if !hash.is_empty() {
                record.hash = hash.to_string();
            }
            record.offline_reported = false;
            recovered
        };
        let serialized = serde_json::to_vec_pretty(&*registry).ok();
        drop(registry);
        if let Some(serialized) = serialized {
            if let Err(err) = atomic_write(&self.data_dir.join("agents.json"), &serialized, true) {
                self.logger
                    .warn(format!("cannot persist agents.json: {err}"));
            }
        }
        if recovered {
            self.logger.info(format!("agent {agent_id} is back online"));
            if self.config.feishu.notify_on_recovery {
                self.spawn_feishu(feishu::recovery_message(
                    "server",
                    agent_id,
                    "server",
                    &peer.to_string(),
                ));
            }
        }
    }

    /// Send an alert through the Feishu app, using the recipient that may have
    /// been learned after startup.
    fn spawn_feishu(&self, text: String) {
        let mut config = self.config.clone();
        if let Some(owner) = self
            .feishu_owner
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
        {
            config.feishu.app.owner_open_id = owner;
        }
        feishu::spawn_notify(&config, &self.logger, text);
    }
}

async fn monitor_agents(state: Arc<ServerState>) {
    if !state.config.server.monitor_agents {
        state
            .logger
            .info("agent monitoring disabled (server.monitor_agents = false)");
        return;
    }
    let interval = Duration::from_secs(state.config.server.monitor_interval_secs.max(1));
    let threshold = state.config.agent.offline_threshold_secs;
    let forget = state.config.server.forget_agent_after_secs;
    loop {
        tokio::time::sleep(interval).await;
        let now = now_unix();
        let mut alerts: Vec<(String, AgentRecord)> = Vec::new();
        {
            let mut registry = match state.registry.lock() {
                Ok(registry) => registry,
                Err(poisoned) => poisoned.into_inner(),
            };
            for (agent_id, record) in registry.agents.iter_mut() {
                let silent = now.saturating_sub(record.last_seen_unix);
                if silent > threshold && !record.offline_reported {
                    record.offline_reported = true;
                    alerts.push((agent_id.clone(), record.clone()));
                }
            }
            if forget > 0 {
                registry
                    .agents
                    .retain(|_, record| now.saturating_sub(record.last_seen_unix) < forget);
            }
            if let Ok(serialized) = serde_json::to_vec_pretty(&*registry) {
                let _ = atomic_write(&state.data_dir.join("agents.json"), &serialized, true);
            }
        }
        for (agent_id, record) in alerts {
            let silent = now.saturating_sub(record.last_seen_unix);
            state.logger.warn(format!(
                "agent {agent_id} unreachable for {}s (last peer {})",
                silent, record.peer
            ));
            state.spawn_feishu(feishu::offline_alert(
                "server-monitor",
                &agent_id,
                &agent_id,
                &record.peer,
                silent,
                Some(feishu::format_unix(record.last_seen_unix)),
                "agent stopped polling the server",
            ));
        }
    }
}

fn load_registry(data_dir: &std::path::Path) -> AgentRegistry {
    let path = data_dir.join("agents.json");
    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => AgentRegistry::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_ids_are_sanitised() {
        assert_eq!(sanitize_agent_id("mac-1"), "mac-1");
        assert_eq!(sanitize_agent_id("  mac\n1  "), "mac1");
        assert_eq!(sanitize_agent_id(""), "unknown");
        assert_eq!(sanitize_agent_id(&"x".repeat(200)).len(), 128);
    }

    fn session_entry(peer: SocketAddr, instance: u64) -> SessionEntry {
        let (sender, _) = mpsc::channel(1);
        SessionEntry {
            peer,
            sender,
            instance,
            hello: b"authenticated hello".to_vec(),
            ready: b"original ready".to_vec(),
        }
    }

    #[test]
    fn repeated_hello_reuses_the_original_ready() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let other_peer: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        let session = [7u8; 8];
        let sessions = HashMap::from([(session, session_entry(peer, 1))]);
        let cached = cached_hello(&sessions, &session, peer, b"authenticated hello").unwrap();
        assert!(cached.0);
        assert_eq!(cached.1, b"original ready");
        assert!(
            !cached_hello(&sessions, &session, peer, b"different hello")
                .unwrap()
                .0
        );
        assert!(
            !cached_hello(&sessions, &session, other_peer, b"authenticated hello")
                .unwrap()
                .0
        );
    }

    #[test]
    fn an_old_session_cannot_remove_a_newer_session() {
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let session = [9u8; 8];
        let mut sessions = HashMap::from([(session, session_entry(peer, 2))]);
        remove_session_from_map_if_current(&mut sessions, &session, 1);
        assert!(sessions.contains_key(&session));
        remove_session_from_map_if_current(&mut sessions, &session, 2);
        assert!(!sessions.contains_key(&session));
    }

    #[test]
    fn diff_reports_changes() {
        let mut old = BTreeMap::new();
        old.insert("a".to_string(), b"1".to_vec());
        let mut new = BTreeMap::new();
        new.insert("a".to_string(), b"2".to_vec());
        new.insert("b".to_string(), b"3".to_vec());
        let summary = diff_summary(&old, &new);
        assert!(summary.contains("added"));
        assert!(summary.contains("modified"));
    }
}
