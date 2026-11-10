//! Agent role: poll the server hash every `poll_secs`, pull the bundle when it
//! changed, apply it locally and log every step. Reports outages to Feishu.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::buildinfo;
use crate::config::Config;
use crate::crypto::{ClientHello, ClusterSecret, KnockSequence, MAX_CLOCK_SKEW_SECS, TYPE_READY};
use crate::feishu;
use crate::feishu_control;
use crate::knock::{agent_ports, random_count, random_plan, Ports};
use crate::logx::Logger;
use crate::prompts::{
    apply, canonical_hash, resolve_sources, scan, total_bytes, ApplyReport, ScanOptions, SourceSpec,
};
use crate::proto::{decode_response, encode_request, Manifest, Request, Response};
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
    /// Server public key trusted on first contact (hex). Manifests signed by
    /// any other key are refused until this is cleared deliberately.
    #[serde(default)]
    pub server_key: Option<String>,
    /// `updated_unix` of the newest signed manifest accepted so far; older
    /// signed manifests are refused (rollback protection).
    #[serde(default)]
    pub signed_unix: u64,
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

/// Result of one poll cycle.
///
/// `local_hash` is always the canonical hash of a fresh scan of *all* local
/// sources, never the server hash: the agent may keep files the server does
/// not publish (other bots, `delete_removed = false`), so the two differ by
/// design and the next cycle compares against the scan, not the bundle.
#[derive(Debug)]
pub enum SyncOutcome {
    UpToDate {
        /// Server hash reported in the STATUS reply.
        hash: String,
        /// Hash of the local sources scanned in this cycle.
        local_hash: String,
        /// Verified server key and manifest time (see `Trust`).
        trust: Trust,
    },
    Updated {
        /// Server hash of the applied bundle.
        hash: String,
        /// Hash of the local sources re-scanned after the bundle and the
        /// client adapters were written.
        local_hash: String,
        /// Verified server key and manifest time (see `Trust`).
        trust: Trust,
        report: ApplyReport,
        bytes: u64,
        skipped: usize,
    },
}

impl SyncOutcome {
    pub fn hash(&self) -> &str {
        match self {
            SyncOutcome::UpToDate { hash, .. } => hash,
            SyncOutcome::Updated { hash, .. } => hash,
        }
    }

    /// Hash of the local sources at the end of the cycle; persisted as
    /// `AgentState::local_hash` so the next cycle can tell "nothing changed
    /// since the last pull" apart from "a local file drifted".
    pub fn local_hash(&self) -> &str {
        match self {
            SyncOutcome::UpToDate { local_hash, .. } => local_hash,
            SyncOutcome::Updated { local_hash, .. } => local_hash,
        }
    }

    pub fn is_update(&self) -> bool {
        matches!(self, SyncOutcome::Updated { .. })
    }

    /// Server key / manifest time to persist in `AgentState` after the cycle.
    pub fn trust(&self) -> &Trust {
        match self {
            SyncOutcome::UpToDate { trust, .. } => trust,
            SyncOutcome::Updated { trust, .. } => trust,
        }
    }
}

/// What the agent learned about the server's identity in one cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Trust {
    /// Hex public key that signed the manifest; `None` for an unsigned
    /// manifest from an older server that was accepted because nothing was
    /// pinned yet.
    pub server_key: Option<String>,
    /// `updated_unix` of the accepted signed manifest (0 when unsigned).
    pub signed_unix: u64,
    /// `true` when this cycle pinned the key for the first time.
    pub first_use: bool,
}

impl AgentState {
    /// Merge the trust result of a successful cycle into the persisted state.
    ///
    /// `trust` comes from `SyncOutcome::trust`. A pinned key is never dropped
    /// here (an unsigned manifest is refused once a key is pinned), and the
    /// rollback watermark only moves forward.
    pub fn remember_trust(&mut self, trust: &Trust) {
        if let Some(key) = trust.server_key.as_ref() {
            self.server_key = Some(key.clone());
            self.signed_unix = self.signed_unix.max(trust.signed_unix);
        }
    }
}

/// Decide whether a manifest may be acted on.
///
/// `configured` is `[agent] server_public_key` (may be empty), `pinned` the key
/// remembered from first contact and `last_signed` the newest accepted
/// `updated_unix`. The configured key wins over the pinned one. Returns the
/// trust to persist, or an error explaining why the manifest is refused.
pub fn check_manifest_trust(
    manifest: &Manifest,
    configured: &str,
    pinned: Option<&str>,
    last_signed: u64,
) -> Result<Trust> {
    let configured = configured.trim();
    let expected = if configured.is_empty() {
        pinned.map(str::trim).filter(|key| !key.is_empty())
    } else {
        Some(configured)
    };
    let key = manifest.server_key.trim();
    if key.is_empty() || manifest.signature.trim().is_empty() {
        if let Some(expected) = expected {
            bail!(
                "server 没有签名这次回复，但本机已信任 server 公钥 {}（指纹 {}）：可能是旧版本 server，也可能是冒充者，拒绝同步。请把 server 升级到同一版本",
                expected,
                crate::crypto::server_key_fingerprint(expected)
            );
        }
        // Older server and nothing pinned yet: keep working, but unsigned.
        return Ok(Trust::default());
    }
    if let Some(expected) = expected {
        if !expected.eq_ignore_ascii_case(key) {
            bail!(
                "server 公钥变了：本机信任 {}（指纹 {}），这次收到 {}（指纹 {}）。拒绝同步——持有集群密钥的其他机器可以冒充 server。\n\
                 如果确实是你重装/更换了 server：在 server 上运行 `promptsync ports` 拿到新公钥，填进 agent 的 [agent] server_public_key；\
                 或删除 agent 的 state/agent-state.json 里的 server_key 重新信任",
                expected,
                crate::crypto::server_key_fingerprint(expected),
                key,
                crate::crypto::server_key_fingerprint(key)
            );
        }
    }
    crate::crypto::verify_server_signature(key, &manifest.signing_bytes(), &manifest.signature)
        .context("server 回复的签名无效，拒绝同步")?;
    if expected.is_some() && manifest.updated_unix < last_signed {
        bail!(
            "server 回复的版本时间 {} 早于本机已接受的 {}：疑似回滚到旧版本，拒绝同步（server 时钟被调回过去也会这样）",
            manifest.updated_unix,
            last_signed
        );
    }
    Ok(Trust {
        server_key: Some(key.to_ascii_lowercase()),
        signed_unix: manifest.updated_unix,
        first_use: expected.is_none(),
    })
}

/// The server stayed silent for every HELLO of one session attempt.
///
/// The server never answers invalid traffic, so a wrong secret, a wrong port,
/// a stopped server, a firewall and clock skew all look identical from here.
/// A dedicated type lets callers recognise this case (through `anyhow`
/// context layers) and print `handshake_hint` instead of a bare timeout.
#[derive(Debug)]
pub struct NoHandshakeAnswer {
    /// Address the HELLO packets were sent to.
    pub peer: SocketAddr,
    /// Number of knock + HELLO rounds that were tried.
    pub attempts: u32,
}

impl std::fmt::Display for NoHandshakeAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no handshake answer from {} (attempt {})",
            self.peer, self.attempts
        )
    }
}

impl std::error::Error for NoHandshakeAnswer {}

/// `true` when `err` (or any context layer below it) is `NoHandshakeAnswer`.
pub fn is_no_handshake(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| cause.is::<NoHandshakeAnswer>())
}

/// Multi-line checklist printed on the first silent handshake.
///
/// `secret` / `ports` are what this agent actually uses and `config` supplies
/// the server host. Every number here can be compared with `promptsync ports`
/// on the server, which is the fastest way to tell the causes apart.
pub fn handshake_hint(secret: &ClusterSecret, ports: &Ports, config: &Config) -> String {
    let host = config.agent.server.trim();
    let loopback = host
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(host.eq_ignore_ascii_case("localhost"));
    let mut text = format!(
        "server {host}:{} 没有任何握手应答。server 对无效包一律不回，下面几种原因在 agent 这边看起来完全一样：\n\
         1. 集群密钥不同：本机指纹 {}，在 server 上运行 `promptsync ports` 对比 fingerprint（密钥不同时敲门端口也不同，server 日志里不会出现任何 knock）；\n\
         2. 端口不同：本机数据端口 {}、敲门端口 {:?}；server 若在 [server] 里固定了 port / knock_ports，agent 必须写同样的值；\n\
         3. server 没在运行，或 agent.server 地址不对；\n\
         4. 防火墙 / 安全组拦截了 UDP（数据端口和全部敲门端口都要放行）；\n\
         5. 两端时钟相差超过 60 秒（敲门包会被丢弃，先做 NTP 校时）。\n\
         定位：server 用 `--log-level debug` 启动后再看日志——完全没有 knock 记录 → 1/3/4；`ignored invalid knock` → 1/5；\
         `knock sequence completed` 却没有 session → 密钥不同。",
        ports.main,
        secret.fingerprint(),
        ports.main,
        ports.knock_pool,
    );
    if loopback {
        text.push_str(&format!(
            "\n注意：agent.server 是本机回环地址 {host}，只有 server 跑在同一台机器上才可能连通。"
        ));
    }
    text
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
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}:{port}"))?;
    pick_address(addresses).ok_or_else(|| anyhow!("no address found for {host}"))
}

/// Choose the address to knock and talk to from a DNS answer.
///
/// `addresses` is the resolver output in its own order. IPv4 wins: the server
/// binds `0.0.0.0` by default, which accepts no IPv6 at all, and resolvers
/// often list AAAA first (Tailscale MagicDNS, dual-stack DDNS). IPv6 is used
/// only when the name has no A record; to force IPv6, put the literal address
/// into `agent.server` and bind the server to `::`.
fn pick_address(addresses: impl IntoIterator<Item = SocketAddr>) -> Option<SocketAddr> {
    let mut first_v6 = None;
    for address in addresses {
        if address.is_ipv4() {
            return Some(address);
        }
        first_v6.get_or_insert(address);
    }
    first_v6
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
        let first_send = Instant::now();
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
                    // Handshake time seeds the retransmission timeout. With
                    // resent HELLOs it over-estimates, which only delays loss
                    // recovery instead of causing spurious retransmissions.
                    let handshake_rtt = first_send.elapsed();
                    let (tx, rx) = mpsc::channel(2048);
                    let pump = spawn_pump(socket.clone(), session, tx);
                    logger.debug(format!(
                        "session {} established with {peer}",
                        hex::encode(session)
                    ));
                    let mut channel =
                        Channel::new(socket, peer, session, &keys, true, rx, Some(pump));
                    channel.set_rtt_hint(handshake_rtt);
                    return Ok(channel);
                }
                Err(err) => last_error = err.context("verifying the server handshake"),
            },
            None => {
                last_error = anyhow::Error::new(NoHandshakeAnswer {
                    peer,
                    attempts: attempt,
                });
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

fn log_adapted(report: &crate::adapters::AdaptReport, logger: &Logger) {
    for (client, path, err) in &report.failed {
        logger.warn(format!(
            "client prompt for {client} ({}): {err}",
            path.display()
        ));
    }
    // 旧位置是用户自己的文件，没有移走：提醒对应引擎可能会加载两份指令。
    for (client, path) in &report.kept {
        logger.warn(format!(
            "client prompt for {client}: {} is not a promptsync copy, left untouched; {client} may load two instruction files (remove it by hand if that is not intended)",
            path.display()
        ));
    }
    // 迁入集中备份库的旧 .bak 文件：逐个说明去向。
    for (old, entry) in &report.migrated {
        logger.info(format!(
            "client backup: moved {} into the backup store ({}, {} B, {:?})",
            old.display(),
            entry.id,
            entry.bytes,
            entry.kind
        ));
    }
    // 被移走的旧副本：告诉用户备份在哪里。
    for (client, path, backup) in &report.retired {
        logger.info(format!(
            "client prompt for {client}: moved duplicate {} to {}",
            path.display(),
            backup.display()
        ));
    }
    if report.has_changes() {
        logger.info(format!("client prompts: {}", report.summary()));
    } else if !report.is_empty() {
        logger.debug(format!("client prompts: {}", report.summary()));
    }
}

/// Close the session. `applied_hash` is the server hash this agent holds
/// after the cycle (empty when unknown); the server shows it in `--agents`.
async fn send_bye(channel: &mut Channel, agent_id: &str, applied_hash: &str) {
    let bye = Request::Bye {
        agent_id: agent_id.to_string(),
        applied_hash: applied_hash.to_string(),
    };
    if let Ok(payload) = encode_request(&bye) {
        let _ = channel.send_message(&payload, Duration::from_secs(2)).await;
    }
}

/// Copy the server's Feishu recipient when both sides use the same app.
///
/// Feishu open_ids are app-scoped, so this is only valid when the app id
/// matches. The agent still falls back to its own automatic binding loop (app
/// owner) when the app differs or the server has no recipient yet.
fn adopt_feishu_owner(
    config: &Config,
    manifest: &crate::proto::Manifest,
    owner: &Arc<Mutex<Option<String>>>,
    config_file: Option<&Path>,
    logger: &Logger,
) {
    if !config.feishu.enabled {
        return;
    }
    let app_id = config.feishu.app.app_id.trim();
    if app_id.is_empty() || manifest.feishu_app_id.trim() != app_id {
        return;
    }
    let incoming = manifest.feishu_owner_open_id.trim();
    if incoming.is_empty() {
        return;
    }
    let mut guard = match owner.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    if guard.is_some() {
        return;
    }
    *guard = Some(incoming.to_string());
    drop(guard);
    if let Some(path) = config_file {
        let literal = serde_json::to_string(incoming).unwrap_or_else(|_| format!("\"{incoming}\""));
        if let Err(err) =
            crate::config::set_value(path, Some("feishu.app"), "owner_open_id", &literal)
        {
            logger.warn(format!(
                "adopted Feishu owner from server but could not persist it: {err:#}"
            ));
        }
    }
    logger.info(format!(
        "adopted Feishu owner {} from server (same app {})",
        incoming, app_id
    ));
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
    feishu_owner: Option<&Arc<Mutex<Option<String>>>>,
    config_file: Option<&Path>,
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
    // The hash this agent applied last; reported so `--agents` shows lag.
    let held_hash = previous
        .and_then(|state| state.server_hash.clone())
        .unwrap_or_default();
    let status = request(
        &mut channel,
        &Request::Status {
            agent_id: agent_id.to_string(),
            applied_hash: held_hash.clone(),
        },
        request_timeout,
    )
    .await?;
    let manifest = match status {
        Response::Status(manifest) => manifest,
        Response::Error { code, message } => {
            send_bye(&mut channel, agent_id, &held_hash).await;
            bail!("server error {code}: {message}");
        }
        other => {
            send_bye(&mut channel, agent_id, &held_hash).await;
            bail!("unexpected server response: {other:?}");
        }
    };
    // Verify the server's signature before acting on anything in the manifest
    // (hash, adapter target, Feishu recipient).
    let trust = match check_manifest_trust(
        &manifest,
        &config.agent.server_public_key,
        previous.and_then(|state| state.server_key.as_deref()),
        previous.map(|state| state.signed_unix).unwrap_or(0),
    ) {
        Ok(trust) => trust,
        Err(err) => {
            send_bye(&mut channel, agent_id, &held_hash).await;
            return Err(err);
        }
    };
    match trust.server_key.as_deref() {
        Some(key) if trust.first_use => logger.warn(format!(
            "首次信任 server 公钥 {key}（指纹 {}）。请在 server 上运行 `promptsync ports` 核对；之后公钥变化会被拒绝",
            crate::crypto::server_key_fingerprint(key)
        )),
        None => logger.warn(
            "server 没有签名（旧版本 server）：本机无法确认对方确实是 server。请把 server 升级到同一版本",
        ),
        _ => {}
    }
    if let Some(owner) = feishu_owner {
        adopt_feishu_owner(config, &manifest, owner, config_file, logger);
    }

    if manifest.hash == local_hash
        || previous
            .map(|state| {
                state.server_hash.as_deref() == Some(manifest.hash.as_str())
                    && state.local_hash.as_deref() == Some(local_hash.as_str())
            })
            .unwrap_or(false)
    {
        // Keep client configs current even when the prompt itself did not
        // change (e.g. a new client was installed after the last pull).
        let adapted =
            crate::adapters::apply_bundle(&config.sync, &local_entries, &manifest.target, data_dir);
        log_adapted(&adapted, logger);
        send_bye(&mut channel, agent_id, &manifest.hash).await;
        return Ok(SyncOutcome::UpToDate {
            hash: manifest.hash,
            local_hash,
            trust,
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
            send_bye(&mut channel, agent_id, &held_hash).await;
            bail!("server refused the bundle ({code}): {message}");
        }
        other => {
            send_bye(&mut channel, agent_id, &held_hash).await;
            bail!("unexpected server response to bundle request: {other:?}");
        }
    };
    // Report the bundle as held; if applying it fails below, the next STATUS
    // reports the previous hash again and the registry corrects itself.
    let bye_hash = if bundle.hash == manifest.hash {
        manifest.hash.clone()
    } else {
        held_hash.clone()
    };
    send_bye(&mut channel, agent_id, &bye_hash).await;

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

    // Only apply entries this machine would sync itself: the source must be
    // configured here and the path must match that source's globs. A root such
    // as CindyGlobal/owners also holds skills and memories; without the glob
    // check the server could write any file below it.
    let by_id: BTreeMap<&str, &SourceSpec> = sources
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect();
    let mut applicable: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut skipped = 0usize;
    for (key, content) in entries {
        let accepted = key
            .split_once('/')
            .and_then(|(id, rest)| by_id.get(id).map(|source| (source, rest)))
            .map(|(source, rest)| crate::prompts::source_accepts(source, rest));
        match accepted {
            Some(true) => {
                applicable.insert(key, content);
            }
            Some(false) => {
                skipped += 1;
                logger.warn(format!(
                    "skipping {key}: outside the globs of its source on this machine"
                ));
            }
            None => {
                skipped += 1;
                logger.debug(format!("skipping {key} (source not configured here)"));
            }
        }
    }
    if skipped > 0 {
        logger.warn(format!(
            "{skipped} bundle entr{} ignored: not synced by this machine's sources/globs",
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
    let adapted =
        crate::adapters::apply_bundle(&config.sync, &applicable, &manifest.target, data_dir);
    log_adapted(&adapted, logger);
    // Re-scan instead of hashing `applicable`: local sources may hold files the
    // server does not publish, and an adapter may have rewritten a file inside
    // a source (e.g. Cindy's SOUL.md). Recording the bundle hash here made the
    // next cycle see a "local change" and pull the same bundle every poll.
    let local_hash = canonical_hash(&scan(sources, &scan_options, Some(logger))?);
    logger.info(format!(
        "applied bundle {}: {}",
        &bundle_hash[..bundle_hash.len().min(16)],
        report.summary()
    ));
    Ok(SyncOutcome::Updated {
        hash: bundle_hash,
        local_hash,
        trust,
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

fn spawn_feishu(
    config: &Config,
    logger: &Logger,
    owner: &Arc<Mutex<Option<String>>>,
    text: String,
) {
    let mut config = config.clone();
    if let Some(owner) = owner.lock().ok().and_then(|guard| guard.clone()) {
        config.feishu.app.owner_open_id = owner;
    }
    feishu::spawn_notify(&config, logger, text);
}

/// Start the background binding loop when the agent has no recipient yet.
/// Binding is automatic (the app owner is resolved and messaged once), so this
/// only retries transient failures and updates the shared owner cell.
fn spawn_feishu_binding(
    config: &Config,
    logger: &Logger,
    data_dir: &Path,
    config_file: &Path,
    owner: &Arc<Mutex<Option<String>>>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.feishu.enabled || !config.feishu_app_configured() {
        return None;
    }
    if owner.lock().ok().and_then(|guard| guard.clone()).is_some() {
        return None;
    }
    let config = config.clone();
    let logger = logger.clone();
    let data_dir = data_dir.to_path_buf();
    let config_file = config_file.to_path_buf();
    let owner = Arc::clone(owner);
    Some(tokio::spawn(async move {
        match feishu_control::bind_agent(&config, &data_dir, &config_file, &logger).await {
            Ok(binding) => {
                if let Ok(mut guard) = owner.lock() {
                    *guard = Some(binding.open_id.clone());
                }
                logger.info(format!(
                    "Feishu alert binding ready: open_id {}",
                    binding.open_id
                ));
            }
            Err(err) => logger.warn(format!(
                "Feishu alert binding stopped; offline alerts will not send: {err:#}"
            )),
        }
    }))
}

pub async fn run(
    config: Config,
    logger: Logger,
    data_dir: PathBuf,
    config_file: PathBuf,
) -> Result<()> {
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
    logger.info(format!(
        "要改配置：编辑 {}，或运行 `promptsync agent --configure`（日志 {}）",
        config_file.display(),
        logger.path().display()
    ));

    // A recipient may already be configured, or a previous binding may still
    // be valid even if config.toml has no owner_open_id. Reuse it before
    // starting another binding loop.
    let mut initial_owner = config.feishu.app.owner_open_id.trim().to_string();
    if initial_owner.is_empty() {
        if let Some(binding) = feishu_control::load_binding(&data_dir) {
            if binding.app_id == config.feishu.app.app_id.trim()
                && !binding.open_id.trim().is_empty()
            {
                initial_owner = binding.open_id;
            }
        }
    }
    let feishu_owner = Arc::new(Mutex::new(if initial_owner.is_empty() {
        None
    } else {
        Some(initial_owner)
    }));
    // Start the code-binding task only after the first sync. The first
    // manifest may already carry the server's owner; in that case there is
    // nothing to bind and the user never sees a code.
    let mut binding_task: Option<tokio::task::JoinHandle<()>> = None;
    // The handshake checklist is long; show it once per failure streak and
    // again only after the connection worked in between.
    let mut handshake_hint_shown = false;

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
            Some(&feishu_owner),
            Some(&config_file),
        )
        .await;
        match result {
            Ok(outcome) => {
                let recovered = tracker.on_success();
                handshake_hint_shown = false;
                state.last_success_unix = now_unix();
                state.last_cycle_unix = now_unix();
                state.server_hash = Some(outcome.hash().to_string());
                state.local_hash = Some(outcome.local_hash().to_string());
                state.remember_trust(outcome.trust());
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
                            &feishu_owner,
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
                // A secret mismatch is indistinguishable from a firewall on the
                // wire (the server stays silent), so print the full checklist
                // once per failure streak, right on the first silent attempt.
                if !handshake_hint_shown && is_no_handshake(&err) {
                    logger.warn(handshake_hint(&secret, &ports, &config));
                    handshake_hint_shown = true;
                }
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
                        &feishu_owner,
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

        if binding_task
            .as_ref()
            .map(|handle| handle.is_finished())
            .unwrap_or(true)
        {
            binding_task = None;
        }
        if feishu_owner
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
        {
            if let Some(handle) = binding_task.take() {
                handle.abort();
            }
        } else if binding_task.is_none() {
            binding_task =
                spawn_feishu_binding(&config, &logger, &data_dir, &config_file, &feishu_owner);
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
    let outcome = match sync_once(
        &config,
        &secret,
        &ports,
        &sources,
        &agent_id,
        &data_dir,
        Some(&state),
        &logger,
        None,
        None,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            // `--once` is the documented first test; it must explain a silent
            // server just like the long-running loop does.
            if is_no_handshake(&err) {
                logger.warn(handshake_hint(&secret, &ports, &config));
            }
            return Err(err);
        }
    };
    state.agent_id = agent_id;
    state.last_success_unix = now_unix();
    state.last_cycle_unix = now_unix();
    state.server_hash = Some(outcome.hash().to_string());
    state.local_hash = Some(outcome.local_hash().to_string());
    state.remember_trust(outcome.trust());
    state.consecutive_failures = 0;
    state.last_error = None;
    if let SyncOutcome::Updated { report, bytes, .. } = &outcome {
        state.files = report.written.len() + report.unchanged;
        state.bytes = *bytes;
    }
    state.save(&data_dir)?;
    match &outcome {
        SyncOutcome::UpToDate { hash, .. } => println!(
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
    fn adopts_the_server_feishu_owner_only_for_the_same_app() {
        let dir = tempfile::tempdir().unwrap();
        let config_file = dir.path().join("config.toml");
        std::fs::write(
            &config_file,
            "[feishu.app]\napp_id = \"cli_test\"\napp_secret = \"secret\"\nowner_open_id = \"\"\n",
        )
        .unwrap();
        let logger = crate::logx::Logger::new(
            &dir.path().join("logs"),
            "test.log",
            crate::logx::Level::Info,
            1024,
            1,
            false,
        )
        .unwrap();
        let mut config = Config::default();
        config.feishu.enabled = true;
        config.feishu.app.app_id = "cli_test".to_string();
        config.feishu.app.app_secret = "secret".to_string();
        let owner = Arc::new(Mutex::new(None));
        let manifest = crate::proto::Manifest {
            epoch: 1,
            hash: "hash".to_string(),
            files: 0,
            bytes: 0,
            updated_unix: 0,
            target: String::new(),
            feishu_app_id: "cli_test".to_string(),
            feishu_owner_open_id: "ou_owner".to_string(),
            server_key: String::new(),
            signature: String::new(),
        };

        adopt_feishu_owner(&config, &manifest, &owner, Some(&config_file), &logger);
        assert_eq!(owner.lock().unwrap().as_deref(), Some("ou_owner"));
        assert!(std::fs::read_to_string(&config_file)
            .unwrap()
            .contains("owner_open_id = \"ou_owner\""));

        let other_owner = Arc::new(Mutex::new(None));
        let other_app = crate::proto::Manifest {
            feishu_app_id: "cli_other".to_string(),
            ..manifest
        };
        adopt_feishu_owner(&config, &other_app, &other_owner, None, &logger);
        assert!(other_owner.lock().unwrap().is_none());
    }

    /// Signed manifest for the trust tests. `signer` signs it; `updated` is the
    /// manifest time used for rollback checks.
    fn signed_manifest(signer: &crate::crypto::ServerSigner, updated: u64) -> Manifest {
        let mut manifest = Manifest {
            epoch: 3,
            hash: "ab".repeat(32),
            files: 1,
            bytes: 10,
            updated_unix: updated,
            target: "shared/prompt.md".to_string(),
            feishu_app_id: "cli_x".to_string(),
            feishu_owner_open_id: "ou_x".to_string(),
            server_key: signer.public_hex(),
            signature: String::new(),
        };
        manifest.signature = signer.sign_hex(&manifest.signing_bytes());
        manifest
    }

    fn new_signer() -> crate::crypto::ServerSigner {
        crate::crypto::ServerSigner::from_hex(&crate::crypto::ServerSigner::generate_hex()).unwrap()
    }

    #[test]
    fn first_contact_pins_and_the_same_key_keeps_working() {
        let signer = new_signer();
        let first = check_manifest_trust(&signed_manifest(&signer, 100), "", None, 0).unwrap();
        assert!(first.first_use);
        assert_eq!(
            first.server_key.as_deref(),
            Some(signer.public_hex().as_str())
        );
        let mut state = AgentState::default();
        state.remember_trust(&first);
        let again = check_manifest_trust(
            &signed_manifest(&signer, 100),
            "",
            state.server_key.as_deref(),
            state.signed_unix,
        )
        .unwrap();
        assert!(!again.first_use);
    }

    #[test]
    fn another_server_key_is_refused() {
        let pinned = new_signer();
        let impostor = new_signer();
        let err = check_manifest_trust(
            &signed_manifest(&impostor, 100),
            "",
            Some(&pinned.public_hex()),
            0,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("公钥变了"), "{err:#}");
        // A configured key wins over (and is checked like) a pinned one.
        assert!(check_manifest_trust(
            &signed_manifest(&impostor, 100),
            &pinned.public_hex(),
            Some(&impostor.public_hex()),
            0
        )
        .is_err());
    }

    #[test]
    fn unsigned_manifests_only_pass_before_a_key_is_pinned() {
        let signer = new_signer();
        let mut unsigned = signed_manifest(&signer, 100);
        unsigned.server_key.clear();
        unsigned.signature.clear();
        assert_eq!(
            check_manifest_trust(&unsigned, "", None, 0).unwrap(),
            Trust::default()
        );
        assert!(check_manifest_trust(&unsigned, "", Some(&signer.public_hex()), 0).is_err());
    }

    #[test]
    fn tampered_or_rolled_back_manifests_are_refused() {
        let signer = new_signer();
        let mut tampered = signed_manifest(&signer, 100);
        tampered.target = "cindy-bots/evil/SOUL.md".to_string();
        assert!(check_manifest_trust(&tampered, "", None, 0).is_err());
        let mut redirected = signed_manifest(&signer, 100);
        redirected.feishu_owner_open_id = "ou_attacker".to_string();
        assert!(check_manifest_trust(&redirected, "", None, 0).is_err());

        let old = signed_manifest(&signer, 50);
        let err = check_manifest_trust(&old, "", Some(&signer.public_hex()), 100).unwrap_err();
        assert!(format!("{err:#}").contains("回滚"), "{err:#}");
    }

    #[test]
    fn dns_answers_prefer_ipv4() {
        let v6: SocketAddr = "[fd7a:115c:a1e0::1]:12345".parse().unwrap();
        let v4: SocketAddr = "100.90.160.50:12345".parse().unwrap();
        assert_eq!(pick_address([v6, v4]), Some(v4));
        assert_eq!(pick_address([v6]), Some(v6));
        assert_eq!(pick_address(Vec::<SocketAddr>::new()), None);
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
