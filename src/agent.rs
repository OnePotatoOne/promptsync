//! Agent role: poll the server hash every `poll_secs`, pull the bundle when it
//! changed, apply it locally and log every step. Reports outages to Feishu.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::buildinfo;
use crate::config::Config;
use crate::crypto::{ClientHello, ClusterSecret, KnockSequence, MAX_CLOCK_SKEW_SECS, TYPE_READY};
use crate::feishu;
use crate::knock::{agent_ports, random_count, random_plan, Ports};
use crate::logx::Logger;
use crate::prompts::{
    apply, canonical_hash, resolve_sources, scan, total_bytes, ApplyReport, ScanOptions, SourceSpec,
};
use crate::proto::{decode_response, encode_request, Request, Response};
use crate::util::{atomic_write, now_unix};
use crate::wire::{handshake_kind, spawn_pump, Channel};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    #[serde(default)]
    pub last_success_unix: u64,
    #[serde(default)]
    pub last_cycle_unix: u64,
    #[serde(default)]
    pub server_hash: Option<String>,
    #[serde(default)]
    pub local_hash: Option<String>,
    #[serde(default)]
    pub files: usize,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub consecutive_failures: u64,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub agent_id: String,
}

impl AgentState {
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("agent-state.json");
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let serialized = serde_json::to_vec_pretty(self)?;
        atomic_write(&data_dir.join("agent-state.json"), &serialized, true)
            .context("writing agent-state.json")
    }
}

#[derive(Debug)]
pub enum SyncOutcome {
    UpToDate {
        hash: String,
    },
    Updated {
        hash: String,
        local_hash: String,
        report: ApplyReport,
        bytes: u64,
        skipped: usize,
    },
}

impl SyncOutcome {
    pub fn hash(&self) -> &str {
        match self {
            SyncOutcome::UpToDate { hash } => hash,
            SyncOutcome::Updated { hash, .. } => hash,
        }
    }

    pub fn local_hash(&self) -> &str {
        match self {
            SyncOutcome::UpToDate { hash } => hash,
            SyncOutcome::Updated { local_hash, .. } => local_hash,
        }
    }

    pub fn is_update(&self) -> bool {
        matches!(self, SyncOutcome::Updated { .. })
    }
}

pub fn effective_agent_id(config: &Config) -> String {
    let configured = config.agent.agent_id.trim();
    if !configured.is_empty() {
        return configured.to_string();
    }
    hostname::get()
        .ok()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "agent".to_string())
}

pub async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    let host = host.trim();
    if host.is_empty() {
        bail!("agent.server is empty");
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let address = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("no address found for {host}"))?;
    Ok(address)
}

fn local_bind(peer: SocketAddr) -> &'static str {
    if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
}

async fn knock(
    socket: &UdpSocket,
    peer: SocketAddr,
    pool: &[u16],
    key: &[u8; 32],
    config: &Config,
    logger: &Logger,
) -> Result<()> {
    if pool.is_empty() {
        return Ok(());
    }
    let count = random_count(
        config.agent.knock_min.max(1),
        config.agent.knock_max.max(config.agent.knock_min.max(1)),
        pool.len(),
    );
    let base = Duration::from_millis(config.agent.knock_interval_ms.clamp(10, 2_000));
    let jitter = Duration::from_millis(config.agent.knock_jitter_ms.min(2_000));
    let plan = random_plan(pool, count, base, jitter);
    let sequence = KnockSequence::generate(plan.steps.len() as u8);
    let mut sent = 0usize;
    for step in &plan.steps {
        tokio::time::sleep(step.delay).await;
        let packet = sequence.packet(step.slot, key, now_unix());
        socket
            .send_to(&packet, SocketAddr::new(peer.ip(), step.port))
            .await
            .with_context(|| format!("sending knock to udp/{}", step.port))?;
        sent += 1;
    }
    logger.debug(format!(
        "sent randomised {sent}-of-{} knock to {} (base {}ms, jitter {}ms)",
        pool.len(),
        peer.ip(),
        config.agent.knock_interval_ms.clamp(10, 2_000),
        config.agent.knock_jitter_ms.min(2_000)
    ));
    Ok(())
}

async fn open_session(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    secret: &ClusterSecret,
    config: &Config,
    ports: &Ports,
    logger: &Logger,
) -> Result<Channel> {
    let auth = secret.auth_key();
    let attempts = config.agent.connect_attempts.max(1);
    let timeout = Duration::from_secs(config.agent.handshake_timeout_secs.max(1));
    let mut last_error: anyhow::Error = anyhow!("handshake failed");

    for attempt in 1..=attempts {
        let hello = ClientHello::new(now_unix());
        let session = hello.session();
        let packet = hello.packet(&auth);
        let deadline = Instant::now() + timeout;
        let mut last_send = Instant::now();
        let mut ready: Option<Vec<u8>> = None;
        socket
            .send_to(&packet, peer)
            .await
            .with_context(|| format!("sending HELLO to {peer}"))?;
        let mut buffer = vec![0u8; 2048];
        while Instant::now() < deadline {
            if last_send.elapsed() > Duration::from_millis(400) {
                socket.send_to(&packet, peer).await.ok();
                last_send = Instant::now();
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait = remaining.min(Duration::from_millis(400));
            match tokio::time::timeout(wait, socket.recv_from(&mut buffer)).await {
                Ok(Ok((size, from))) => {
                    if from.ip() != peer.ip() {
                        continue;
                    }
                    let response = &buffer[..size];
                    if handshake_kind(response) == Some(TYPE_READY) && response[4..12] == session {
                        ready = Some(response.to_vec());
                        break;
                    }
                }
                Ok(Err(_)) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(_) => {}
            }
        }
        match ready {
            Some(ready) => match hello.finish(&ready, &auth, now_unix(), MAX_CLOCK_SKEW_SECS) {
                Ok(keys) => {
                    let (tx, rx) = mpsc::channel(2048);
                    let pump = spawn_pump(socket.clone(), session, tx);
                    logger.debug(format!(
                        "session {} established with {peer}",
                        hex::encode(session)
                    ));
                    return Ok(Channel::new(
                        socket,
                        peer,
                        session,
                        &keys,
                        true,
                        rx,
                        Some(pump),
                    ));
                }
                Err(err) => last_error = err.context("verifying the server handshake"),
            },
            None => {
                last_error = anyhow!("no handshake answer from {peer} (attempt {attempt})");
            }
        }
        if attempt < attempts {
            // The server may have closed the gate again; redo the whole dance.
            knock(
                &socket,
                peer,
                &ports.knock_pool,
                &secret.knock_key(),
                config,
                logger,
            )
            .await
            .ok();
        }
    }
    Err(last_error)
}

async fn request(channel: &mut Channel, request: &Request, timeout: Duration) -> Result<Response> {
    let payload = encode_request(request)?;
    channel.send_message(&payload, timeout).await?;
    let response = channel.recv_message(timeout).await?;
    decode_response(&response)
}

async fn send_bye(channel: &mut Channel, agent_id: &str) {
    let bye = Request::Bye {
        agent_id: agent_id.to_string(),
    };
    if let Ok(payload) = encode_request(&bye) {
        let _ = channel.send_message(&payload, Duration::from_secs(2)).await;
    }
}

/// One complete poll cycle. `previous` is used to recognise a server bundle
/// that could only be applied partially (unknown local source).
#[allow(clippy::too_many_arguments)]
pub async fn sync_once(
    config: &Config,
    secret: &ClusterSecret,
    ports: &Ports,
    sources: &[SourceSpec],
    agent_id: &str,
    data_dir: &Path,
    previous: Option<&AgentState>,
    logger: &Logger,
) -> Result<SyncOutcome> {
    let scan_options = ScanOptions::from(&config.sync);
    let local_entries = scan(sources, &scan_options, Some(logger))?;
    let local_hash = canonical_hash(&local_entries);

    let peer = resolve_server(&config.agent.server, ports.main).await?;
    let socket = Arc::new(
        UdpSocket::bind(local_bind(peer))
            .await
            .context("binding local UDP socket")?,
    );
    knock(
        &socket,
        peer,
        &ports.knock_pool,
        &secret.knock_key(),
        config,
        logger,
    )
    .await?;
    let mut channel = open_session(socket, peer, secret, config, ports, logger).await?;

    let request_timeout = Duration::from_secs(config.agent.request_timeout_secs.max(2));
    let bundle_timeout = request_timeout * 3;
    let status = request(
        &mut channel,
        &Request::Status {
            agent_id: agent_id.to_string(),
        },
        request_timeout,
    )
    .await?;
    let manifest = match status {
        Response::Status(manifest) => manifest,
        Response::Error { code, message } => {
            send_bye(&mut channel, agent_id).await;
            bail!("server error {code}: {message}");
        }
        other => {
            send_bye(&mut channel, agent_id).await;
            bail!("unexpected server response: {other:?}");
        }
    };

    if manifest.hash == local_hash
        || previous
            .map(|state| {
                state.server_hash.as_deref() == Some(manifest.hash.as_str())
                    && state.local_hash.as_deref() == Some(local_hash.as_str())
            })
            .unwrap_or(false)
    {
        send_bye(&mut channel, agent_id).await;
        return Ok(SyncOutcome::UpToDate {
            hash: manifest.hash,
        });
    }

    logger.info(format!(
        "server hash {} differs from local {} - pulling bundle ({} files, {})",
        &manifest.hash[..manifest.hash.len().min(16)],
        &local_hash[..local_hash.len().min(16)],
        manifest.files,
        crate::util::human_bytes(manifest.bytes)
    ));
    let response = request(
        &mut channel,
        &Request::Bundle {
            agent_id: agent_id.to_string(),
        },
        bundle_timeout,
    )
    .await?;
    let bundle = match response {
        Response::Bundle(bundle) => bundle,
        Response::Error { code, message } => {
            send_bye(&mut channel, agent_id).await;
            bail!("server refused the bundle ({code}): {message}");
        }
        other => {
            send_bye(&mut channel, agent_id).await;
            bail!("unexpected server response to bundle request: {other:?}");
        }
    };
    send_bye(&mut channel, agent_id).await;

    if bundle.hash != manifest.hash {
        bail!(
            "server changed the prompt set during the transfer ({} -> {})",
            &manifest.hash[..16.min(manifest.hash.len())],
            &bundle.hash[..16.min(bundle.hash.len())]
        );
    }
    let bundle_hash = bundle.hash.clone();
    let entries = bundle.into_entries()?;
    let computed = canonical_hash(&entries);
    if computed != bundle_hash {
        bail!("bundle integrity check failed (hash mismatch)");
    }
    let bytes = total_bytes(&entries);
    if bytes > config.sync.max_bundle_bytes {
        bail!(
            "bundle is {bytes} bytes, above sync.max_bundle_bytes ({})",
            config.sync.max_bundle_bytes
        );
    }

    // Only apply entries whose source is configured on this machine.
    let known: BTreeSet<&str> = sources.iter().map(|source| source.id.as_str()).collect();
    let mut applicable: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut skipped = 0usize;
    for (key, content) in entries {
        match key.split_once('/') {
            Some((id, _)) if known.contains(id) => {
                applicable.insert(key, content);
            }
            _ => {
                skipped += 1;
                logger.debug(format!("skipping {key} (source not configured here)"));
            }
        }
    }
    if skipped > 0 {
        logger.warn(format!(
            "{skipped} bundle entr{} ignored: their sources are not configured on this machine",
            if skipped == 1 { "y was" } else { "ies were" }
        ));
    }
    let report = apply(
        &applicable,
        sources,
        data_dir,
        config.sync.keep_backups,
        config.sync.delete_removed,
        logger,
    )?;
    let local_hash = canonical_hash(&applicable);
    logger.info(format!(
        "applied bundle {}: {}",
        &bundle_hash[..bundle_hash.len().min(16)],
        report.summary()
    ));
    Ok(SyncOutcome::Updated {
        hash: bundle_hash,
        local_hash,
        report,
        bytes,
        skipped,
    })
}

/// Tracks success/failure and decides when Feishu must be called.
pub struct OfflineTracker {
    threshold: Duration,
    repeat: Duration,
    last_success: Option<Instant>,
    started: Instant,
    reported: bool,
    last_alert: Option<Instant>,
}

impl OfflineTracker {
    pub fn new(threshold_secs: u64, repeat_secs: u64) -> Self {
        Self {
            threshold: Duration::from_secs(threshold_secs.max(1)),
            repeat: Duration::from_secs(repeat_secs),
            last_success: None,
            started: Instant::now(),
            reported: false,
            last_alert: None,
        }
    }

    pub fn on_success(&mut self) -> bool {
        let recovered = self.reported;
        self.reported = false;
        self.last_alert = None;
        self.last_success = Some(Instant::now());
        recovered
    }

    pub fn on_failure(&mut self) -> bool {
        let offline_for = self.offline_for();
        if offline_for < self.threshold {
            return false;
        }
        if !self.reported {
            self.reported = true;
            self.last_alert = Some(Instant::now());
            return true;
        }
        if self.repeat > Duration::ZERO {
            if let Some(last) = self.last_alert {
                if last.elapsed() >= self.repeat {
                    self.last_alert = Some(Instant::now());
                    return true;
                }
            }
        }
        false
    }

    pub fn offline_for(&self) -> Duration {
        match self.last_success {
            Some(instant) => instant.elapsed(),
            None => self.started.elapsed(),
        }
    }

    pub fn last_success(&self) -> Option<Instant> {
        self.last_success
    }

    pub fn is_reported(&self) -> bool {
        self.reported
    }
}

fn spawn_feishu(config: &Config, logger: &Logger, text: String) {
    feishu::spawn_notify(config, logger, text);
}

pub async fn run(config: Config, logger: Logger, data_dir: PathBuf) -> Result<()> {
    config.validate()?;
    let secret = Arc::new(
        ClusterSecret::resolve(&config.cluster_secret).context("resolving cluster secret")?,
    );
    let ports = agent_ports(&config.agent, &secret);
    let sources = resolve_sources(&config.sync);
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating {}", data_dir.display()))?;
    let agent_id = effective_agent_id(&config);
    let mut state = AgentState::load(&data_dir);
    state.agent_id = agent_id.clone();
    let mut tracker = OfflineTracker::new(
        config.agent.offline_threshold_secs,
        config.feishu.repeat_alert_secs,
    );
    if state.last_success_unix > 0 {
        logger.info(format!(
            "resuming: last success {} ago, last hash {:?}",
            crate::util::human_age(now_unix().saturating_sub(state.last_success_unix)),
            state.server_hash
        ));
    }

    logger.info(buildinfo::description());
    logger.info(format!(
        "agent {agent_id} | server {}:{} | knock pool {:?} (random {}-{} per attempt) | poll {}s | offline threshold {}s | secret {}",
        config.agent.server,
        ports.main,
        ports.knock_pool,
        config.agent.knock_min,
        config.agent.knock_max,
        config.agent.poll_secs,
        config.agent.offline_threshold_secs,
        secret.fingerprint()
    ));
    logger.info(format!(
        "syncing {} source(s) into {}",
        sources.len(),
        data_dir.display()
    ));

    loop {
        let cycle_start = Instant::now();
        let result = sync_once(
            &config,
            &secret,
            &ports,
            &sources,
            &agent_id,
            &data_dir,
            Some(&state),
            &logger,
        )
        .await;
        match result {
            Ok(outcome) => {
                let recovered = tracker.on_success();
                state.last_success_unix = now_unix();
                state.last_cycle_unix = now_unix();
                state.server_hash = Some(outcome.hash().to_string());
                state.local_hash = Some(outcome.local_hash().to_string());
                state.consecutive_failures = 0;
                state.last_error = None;
                if outcome.is_update() {
                    if let SyncOutcome::Updated {
                        report,
                        bytes,
                        skipped,
                        ..
                    } = &outcome
                    {
                        state.files = report.written.len() + report.unchanged;
                        state.bytes = *bytes;
                        logger.info(format!(
                            "sync complete: {} ({} from server, {} skipped)",
                            report.summary(),
                            crate::util::human_bytes(*bytes),
                            skipped
                        ));
                    }
                } else {
                    logger.debug(format!(
                        "up to date at {}",
                        &outcome.hash()[..outcome.hash().len().min(16)]
                    ));
                }
                if let Err(err) = state.save(&data_dir) {
                    logger.warn(format!("cannot persist agent state: {err:#}"));
                }
                if recovered {
                    logger.info("connection restored");
                    if config.feishu.notify_on_recovery {
                        spawn_feishu(
                            &config,
                            &logger,
                            feishu::recovery_message(
                                "agent",
                                &agent_id,
                                &agent_id,
                                &format!("{}:{}", config.agent.server, ports.main),
                            ),
                        );
                    }
                }
            }
            Err(err) => {
                let alert = tracker.on_failure();
                state.last_cycle_unix = now_unix();
                state.consecutive_failures += 1;
                state.last_error = Some(format!("{err:#}"));
                if let Err(save_err) = state.save(&data_dir) {
                    logger.warn(format!("cannot persist agent state: {save_err:#}"));
                }
                if state.consecutive_failures <= 3 {
                    logger.warn(format!(
                        "sync failed (attempt {}): {err:#}",
                        state.consecutive_failures
                    ));
                } else {
                    logger.debug(format!(
                        "sync still failing after {} attempts: {err:#}",
                        state.consecutive_failures
                    ));
                }
                if alert {
                    let offline = tracker.offline_for().as_secs();
                    logger.warn(format!("offline for {offline}s - sending Feishu alert"));
                    spawn_feishu(
                        &config,
                        &logger,
                        feishu::offline_alert(
                            "agent",
                            &agent_id,
                            &agent_id,
                            &format!("{}:{}", config.agent.server, ports.main),
                            offline,
                            tracker
                                .last_success()
                                .map(|_| format!("{}s ago", tracker.offline_for().as_secs())),
                            &format!("{err:#}"),
                        ),
                    );
                }
            }
        }

        let elapsed = cycle_start.elapsed();
        let interval = Duration::from_secs(config.agent.poll_secs.max(1));
        if elapsed < interval {
            tokio::time::sleep(interval - elapsed).await;
        }
    }
}

/// `promptsync agent --once`
pub async fn run_once(config: Config, logger: Logger, data_dir: PathBuf) -> Result<u8> {
    config.validate()?;
    let secret = ClusterSecret::resolve(&config.cluster_secret)?;
    let ports = agent_ports(&config.agent, &secret);
    let sources = resolve_sources(&config.sync);
    std::fs::create_dir_all(&data_dir)?;
    let agent_id = effective_agent_id(&config);
    let mut state = AgentState::load(&data_dir);
    let outcome = sync_once(
        &config,
        &secret,
        &ports,
        &sources,
        &agent_id,
        &data_dir,
        Some(&state),
        &logger,
    )
    .await?;
    state.agent_id = agent_id;
    state.last_success_unix = now_unix();
    state.last_cycle_unix = now_unix();
    state.server_hash = Some(outcome.hash().to_string());
    state.local_hash = Some(outcome.local_hash().to_string());
    state.consecutive_failures = 0;
    state.last_error = None;
    if let SyncOutcome::Updated { report, bytes, .. } = &outcome {
        state.files = report.written.len() + report.unchanged;
        state.bytes = *bytes;
    }
    state.save(&data_dir)?;
    match &outcome {
        SyncOutcome::UpToDate { hash } => println!(
            "up to date (hash {}, {} local file(s))",
            &hash[..hash.len().min(16)],
            scan(&sources, &ScanOptions::from(&config.sync), None)?.len()
        ),
        SyncOutcome::Updated { report, .. } => println!("updated: {}", report.summary()),
    }
    Ok(0u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_tracker_alerts_once_after_threshold() {
        let mut tracker = OfflineTracker::new(1, 0);
        assert!(!tracker.on_failure());
        std::thread::sleep(Duration::from_millis(1100));
        assert!(tracker.on_failure());
        assert!(!tracker.on_failure());
        assert!(tracker.is_reported());
        assert!(tracker.on_success());
        assert!(!tracker.on_success());
    }

    #[test]
    fn offline_tracker_repeats_when_configured() {
        let mut tracker = OfflineTracker::new(1, 1);
        std::thread::sleep(Duration::from_millis(1100));
        assert!(tracker.on_failure());
        assert!(!tracker.on_failure());
        std::thread::sleep(Duration::from_millis(1100));
        assert!(tracker.on_failure());
    }

    #[test]
    fn agent_state_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let state = AgentState {
            last_success_unix: 42,
            server_hash: Some("abc".into()),
            ..Default::default()
        };
        state.save(dir.path()).unwrap();
        let loaded = AgentState::load(dir.path());
        assert_eq!(loaded.last_success_unix, 42);
        assert_eq!(loaded.server_hash.as_deref(), Some("abc"));
    }
}
