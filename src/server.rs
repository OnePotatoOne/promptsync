//! Server role: owns the authoritative prompt set, publishes its hash and
//! serves bundles to port-knocked, authenticated agents.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::buildinfo;
use crate::config::Config;
use crate::crypto::{accept_hello, ClusterSecret, SessionKeys, MAX_CLOCK_SKEW_SECS, TYPE_HELLO};
use crate::feishu;
use crate::knock::{server_ports, Gate, KnockOutcome, KnockTracker};
use crate::logx::Logger;
use crate::prompts::{canonical_hash, resolve_sources, scan, total_bytes, ScanOptions, SourceSpec};
use crate::proto::{decode_request, encode_response, Bundle, Manifest, Request, Response};
use crate::util::{atomic_write, now_unix};
use crate::wire::{handshake_kind, Channel, Header, MAX_MESSAGE};

const HELLO_RATE_LIMIT: usize = 20;
const HELLO_RATE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
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

struct ServerState {
    config: Config,
    secret: Arc<ClusterSecret>,
    sources: Vec<SourceSpec>,
    scan_options: ScanOptions,
    snapshot: Mutex<Snapshot>,
    gate: Arc<Gate>,
    registry: Mutex<AgentRegistry>,
    data_dir: std::path::PathBuf,
    logger: Logger,
    knocks: Arc<KnockTracker>,
    sessions: Mutex<HashMap<[u8; 8], mpsc::Sender<Vec<u8>>>>,
    session_count: AtomicUsize,
    hello_attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    max_sessions: usize,
}

pub async fn run(
    config: Config,
    logger: Logger,
    data_dir: std::path::PathBuf,
    config_file: std::path::PathBuf,
) -> Result<()> {
    config.validate()?;
    let secret = Arc::new(
        ClusterSecret::resolve(&config.cluster_secret).context("resolving cluster secret")?,
    );
    let ports = server_ports(&config.server, &secret);
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
        "watching {} source(s): {} files, {} hash {}",
        sources.len(),
        entries.len(),
        crate::util::human_bytes(total_bytes(&entries)),
        short_hash(&hash)
    ));

    let registry = load_registry(&data_dir);
    if !registry.agents.is_empty() {
        logger.info(format!("tracking {} known agent(s)", registry.agents.len()));
    }

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
        hello_attempts: Mutex::new(HashMap::new()),
        config,
        secret,
        sources,
        scan_options,
        registry: Mutex::new(registry),
        data_dir,
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
                            "Feishu: 尚未绑定；在飞书私聊里给机器人发一条消息即可自动完成绑定",
                        );
                    }
                    let config = state.config.clone();
                    let data_dir = state.data_dir.clone();
                    let logger = logger.clone();
                    tokio::spawn(async move {
                        if let Err(err) = crate::feishu_control::run(
                            config,
                            data_dir,
                            config_file,
                            target,
                            binding,
                            logger.clone(),
                        )
                        .await
                        {
                            logger.error(format!("Feishu control stopped: {err:#}"));
                        }
                    });
                }
                Err(err) => logger.error(format!("Feishu control disabled: {err:#}")),
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
                {
                    let mut sessions = match state.sessions.lock() {
                        Ok(sessions) => sessions,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    sessions.insert(handshake.session, tx);
                }
                if socket.send_to(&handshake.packet, peer).await.is_err() {
                    state
                        .logger
                        .warn(format!("failed to answer HELLO from {peer}"));
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
                    handshake.keys,
                    rx,
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
        sessions.get(&header.session).cloned()
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

async fn session_task(
    state: Arc<ServerState>,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    session_id: [u8; 8],
    keys: SessionKeys,
    rx: mpsc::Receiver<Vec<u8>>,
) {
    state.session_count.fetch_add(1, Ordering::SeqCst);
    let mut channel = Channel::new(socket, peer, session_id, &keys, false, rx, None);
    let mut agent_id = String::from("unknown");
    loop {
        let payload = match channel.recv_message(Duration::from_secs(30)).await {
            Ok(payload) => payload,
            Err(_) => break,
        };
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
            Request::Status { agent_id: id } => {
                agent_id = sanitize_agent_id(&id);
                let snapshot = current_snapshot(&state);
                state.record_agent(&agent_id, peer, &snapshot.hash);
                state.logger.debug(format!(
                    "status for {agent_id} from {peer}: epoch {} hash {}",
                    snapshot.epoch,
                    short_hash(&snapshot.hash)
                ));
                let manifest = Manifest {
                    epoch: snapshot.epoch,
                    hash: snapshot.hash.clone(),
                    files: snapshot.entries.len(),
                    bytes: total_bytes(&snapshot.entries),
                    updated_unix: snapshot.updated_unix,
                    target: state.config.sync.target.clone(),
                };
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
                state.record_agent(&agent_id, peer, &snapshot.hash);
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
            Request::Bye { .. } => break,
        }
    }

    {
        let mut sessions = match state.sessions.lock() {
            Ok(sessions) => sessions,
            Err(poisoned) => poisoned.into_inner(),
        };
        sessions.remove(&session_id);
    }
    state.session_count.fetch_sub(1, Ordering::SeqCst);
    state.logger.debug(format!(
        "session {} closed for {peer} (agent {agent_id})",
        hex::encode(session_id)
    ));
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
            record.hash = hash.to_string();
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
                spawn_feishu(
                    &self.config,
                    &self.logger,
                    feishu::recovery_message("server", agent_id, "server", &peer.to_string()),
                );
            }
        }
    }
}

fn spawn_feishu(config: &Config, logger: &Logger, text: String) {
    feishu::spawn_notify(config, logger, text);
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
            spawn_feishu(
                &state.config,
                &state.logger,
                feishu::offline_alert(
                    "server-monitor",
                    &agent_id,
                    &agent_id,
                    &record.peer,
                    silent,
                    Some(feishu::format_unix(record.last_seen_unix)),
                    "agent stopped polling the server",
                ),
            );
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
