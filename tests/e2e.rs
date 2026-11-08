//! End-to-end tests: real UDP sockets, port knocking, handshake and sync.

use std::fs;
use std::net::UdpSocket as StdUdpSocket;
use std::path::{Path, PathBuf};
use std::time::Duration;

use promptsync::agent::{sync_once, AgentState, SyncOutcome};
use promptsync::config::{Config, SourceConfig};
use promptsync::crypto::{ClientHello, ClusterSecret, KnockSequence, TYPE_READY};
use promptsync::knock::{agent_ports, random_plan};
use promptsync::logx::{Level, Logger};
use promptsync::prompts::resolve_sources;
use promptsync::server;
use promptsync::util::now_unix;
use promptsync::wire::handshake_kind;

fn free_udp_port() -> u16 {
    let socket = StdUdpSocket::bind("127.0.0.1:0").expect("bind ephemeral port");
    socket.local_addr().expect("local addr").port()
}

fn sources(id: &str, root: &Path) -> Vec<SourceConfig> {
    vec![SourceConfig {
        id: id.to_string(),
        root: root.display().to_string(),
        globs: vec![
            "*/bots/*/SOUL.md".to_string(),
            "*/bots/*/system_prompt.md".to_string(),
        ],
    }]
}

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
    fs::write(path, content).expect("write prompt");
}

struct Cluster {
    temp: tempfile::TempDir,
    server_root: PathBuf,
    agent_root: PathBuf,
    server_config: Config,
    agent_config: Config,
    secret: ClusterSecret,
    server_logger: Logger,
    agent_logger: Logger,
}

fn cluster() -> Cluster {
    let temp = tempfile::tempdir().expect("tempdir");
    let server_root = temp.path().join("server-prompts");
    let agent_root = temp.path().join("agent-prompts");
    fs::create_dir_all(server_root.join("owner/bots/cindy")).expect("server root");
    write(&server_root.join("owner/bots/cindy/SOUL.md"), "soul v1");
    write(
        &server_root.join("owner/bots/cindy/system_prompt.md"),
        "system v1",
    );

    let main_port = free_udp_port();
    let knock_ports: Vec<u16> = (0..5).map(|_| free_udp_port()).collect();
    let secret_hex = "5a".repeat(32);

    let mut agent_config = Config {
        cluster_secret: secret_hex.clone(),
        ..Config::default()
    };
    agent_config.server.bind = "127.0.0.1".to_string();
    agent_config.server.port = main_port;
    agent_config.server.knock_ports = knock_ports.clone();
    agent_config.agent.server = "127.0.0.1".to_string();
    agent_config.agent.port = main_port;
    agent_config.agent.knock_ports = knock_ports;
    agent_config.agent.poll_secs = 1;
    agent_config.agent.offline_threshold_secs = 2;
    agent_config.feishu.enabled = false;
    agent_config.sync.sources = sources("cindy-bots", &agent_root);
    agent_config.sync.delete_removed = true;
    // Tests must never touch the real ~/.codex, ~/.claude, ... files.
    agent_config.sync.adapt_clients = false;

    let mut server_config = agent_config.clone();
    server_config.sync.sources = sources("cindy-bots", &server_root);
    // Fixed test key: agents verify every manifest against it.
    server_config.server.signing_key = "7e".repeat(32);

    let server_logger = Logger::new(
        &temp.path().join("logs"),
        "server.log",
        Level::Debug,
        1_000_000,
        2,
        false,
    )
    .expect("server logger");
    let agent_logger = Logger::new(
        &temp.path().join("logs"),
        "agent.log",
        Level::Debug,
        1_000_000,
        2,
        false,
    )
    .expect("agent logger");

    Cluster {
        secret: ClusterSecret::resolve(&secret_hex).expect("secret"),
        temp,
        server_root,
        agent_root,
        server_config,
        agent_config,
        server_logger,
        agent_logger,
    }
}

async fn start_server(cluster: &Cluster) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let config = cluster.server_config.clone();
    let logger = cluster.server_logger.clone();
    let data_dir = cluster.temp.path().join("server-state");
    let config_file = cluster.temp.path().join("server-config.toml");
    let handle =
        tokio::spawn(async move { server::run(config, logger, data_dir, config_file).await });
    tokio::time::sleep(Duration::from_millis(500)).await;
    handle
}

/// One poll without remembered state (every call looks like a fresh start).
///
/// `cluster` is the test cluster from `cluster()`, `agent_id` the id reported
/// to the server.
async fn poll(cluster: &Cluster, agent_id: &str) -> anyhow::Result<SyncOutcome> {
    poll_with(cluster, agent_id, None).await
}

/// One poll that passes `previous` the way `agent::run` does between cycles.
///
/// `previous` is the state built by `remember` from the last outcome; `None`
/// behaves like a freshly started agent.
async fn poll_with(
    cluster: &Cluster,
    agent_id: &str,
    previous: Option<&AgentState>,
) -> anyhow::Result<SyncOutcome> {
    let ports = agent_ports(&cluster.agent_config.agent, &cluster.secret);
    let sources = resolve_sources(&cluster.agent_config.sync);
    let data_dir = cluster.temp.path().join("agent-state");
    sync_once(
        &cluster.agent_config,
        &cluster.secret,
        &ports,
        &sources,
        agent_id,
        &data_dir,
        previous,
        &cluster.agent_logger,
        None,
        None,
    )
    .await
}

/// Copy the hashes of `outcome` into `state`, mirroring the bookkeeping in
/// `agent::run` after a successful cycle.
fn remember(state: &mut AgentState, outcome: &SyncOutcome) {
    state.server_hash = Some(outcome.hash().to_string());
    state.local_hash = Some(outcome.local_hash().to_string());
    state.remember_trust(outcome.trust());
}

/// Public key matching the fixed test signing key in `cluster()`.
fn test_server_public_key(cluster: &Cluster) -> String {
    promptsync::crypto::ServerSigner::from_hex(&cluster.server_config.server.signing_key)
        .unwrap()
        .public_hex()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end_sync_over_udp() {
    let cluster = cluster();
    let handle = start_server(&cluster).await;

    let outcome = poll(&cluster, "e2e-agent").await.expect("first sync");
    assert!(outcome.is_update(), "first pull must update the agent");
    assert_eq!(
        fs::read_to_string(cluster.agent_root.join("owner/bots/cindy/SOUL.md")).unwrap(),
        "soul v1"
    );
    assert_eq!(
        fs::read_to_string(cluster.agent_root.join("owner/bots/cindy/system_prompt.md")).unwrap(),
        "system v1"
    );

    // Nothing changed: the next poll is a hash match and must not pull.
    let outcome = poll(&cluster, "e2e-agent").await.expect("second sync");
    assert!(matches!(outcome, SyncOutcome::UpToDate { .. }));

    // Server-side edit is picked up after the watcher noticed it.
    write(
        &cluster.server_root.join("owner/bots/cindy/SOUL.md"),
        "soul v2",
    );
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let outcome = poll(&cluster, "e2e-agent").await.expect("third sync");
    assert!(outcome.is_update());
    assert_eq!(
        fs::read_to_string(cluster.agent_root.join("owner/bots/cindy/SOUL.md")).unwrap(),
        "soul v2"
    );

    // Local drift is repaired by the next pull.
    write(
        &cluster.agent_root.join("owner/bots/cindy/SOUL.md"),
        "local edit",
    );
    let outcome = poll(&cluster, "e2e-agent").await.expect("drift sync");
    assert!(outcome.is_update());
    assert_eq!(
        fs::read_to_string(cluster.agent_root.join("owner/bots/cindy/SOUL.md")).unwrap(),
        "soul v2"
    );

    // Deleting a managed file on the server deletes it on the agent too.
    fs::remove_file(
        cluster
            .server_root
            .join("owner/bots/cindy/system_prompt.md"),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let outcome = poll(&cluster, "e2e-agent").await.expect("delete sync");
    assert!(outcome.is_update());
    assert!(!cluster
        .agent_root
        .join("owner/bots/cindy/system_prompt.md")
        .exists());

    handle.abort();
}

/// Regression: an agent that keeps files the server does not publish (another
/// bot, `delete_removed = false`) must settle to "up to date" after one pull.
/// It used to record the bundle hash as its local hash, so every poll saw a
/// "local change" and pulled the same bundle again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extra_local_files_do_not_cause_repeated_pulls() {
    let mut cluster = cluster();
    cluster.agent_config.sync.delete_removed = false;
    write(
        &cluster.agent_root.join("owner/bots/other/SOUL.md"),
        "agent only",
    );
    let handle = start_server(&cluster).await;

    let mut state = AgentState::default();
    let first = poll_with(&cluster, "extra-agent", Some(&state))
        .await
        .expect("first sync");
    assert!(first.is_update(), "first pull must update the agent");
    assert_ne!(
        first.local_hash(),
        first.hash(),
        "local hash must cover the agent-only file, not mirror the bundle"
    );
    remember(&mut state, &first);

    // Two rounds: the second one catches an UpToDate cycle that overwrites the
    // remembered local hash with the server hash.
    for round in 1..=2 {
        let outcome = poll_with(&cluster, "extra-agent", Some(&state))
            .await
            .expect("steady sync");
        assert!(
            matches!(outcome, SyncOutcome::UpToDate { .. }),
            "round {round} pulled the unchanged bundle again"
        );
        remember(&mut state, &outcome);
    }
    assert_eq!(
        fs::read_to_string(cluster.agent_root.join("owner/bots/other/SOUL.md")).unwrap(),
        "agent only"
    );

    // Drift in a managed file is still detected and repaired.
    write(
        &cluster.agent_root.join("owner/bots/cindy/SOUL.md"),
        "local edit",
    );
    let outcome = poll_with(&cluster, "extra-agent", Some(&state))
        .await
        .expect("drift sync");
    assert!(outcome.is_update(), "local drift must trigger a pull");
    assert_eq!(
        fs::read_to_string(cluster.agent_root.join("owner/bots/cindy/SOUL.md")).unwrap(),
        "soul v1"
    );

    handle.abort();
}

/// The manifest signature survives the real UDP path; a pinned key from a
/// different server makes the agent refuse to sync anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_verifies_the_server_signature() {
    let mut cluster = cluster();
    let handle = start_server(&cluster).await;

    let mut state = AgentState::default();
    let outcome = poll_with(&cluster, "signed-agent", Some(&state))
        .await
        .expect("signed sync");
    assert!(outcome.trust().first_use, "first contact pins the key");
    assert_eq!(
        outcome.trust().server_key.as_deref(),
        Some(test_server_public_key(&cluster).as_str())
    );
    remember(&mut state, &outcome);

    // Pinning the correct key explicitly keeps working.
    cluster.agent_config.agent.server_public_key = test_server_public_key(&cluster);
    poll_with(&cluster, "signed-agent", Some(&state))
        .await
        .expect("configured key matches");

    // A key from another server: refused, and nothing is written.
    fs::remove_file(cluster.agent_root.join("owner/bots/cindy/SOUL.md")).unwrap();
    cluster.agent_config.agent.server_public_key =
        promptsync::crypto::ServerSigner::from_hex(&"11".repeat(32))
            .unwrap()
            .public_hex();
    let err = poll_with(&cluster, "signed-agent", Some(&state))
        .await
        .expect_err("a different server key must be refused");
    assert!(format!("{err:#}").contains("公钥变了"), "{err:#}");
    assert!(!cluster.agent_root.join("owner/bots/cindy/SOUL.md").exists());

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retransmitted_hello_returns_the_same_ready() {
    let cluster = cluster();
    let handle = start_server(&cluster).await;
    let peer: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socket = tokio::net::UdpSocket::bind(peer).await.unwrap();
    let server = cluster.server_config.server.clone();
    let ports = promptsync::knock::server_ports(&server, &cluster.secret);
    let plan = random_plan(&ports.knock_pool, 3, Duration::ZERO, Duration::ZERO);
    let sequence = KnockSequence::generate(plan.steps.len() as u8);
    for step in &plan.steps {
        let packet = sequence.packet(step.slot, &cluster.secret.knock_key(), now_unix());
        socket
            .send_to(&packet, ("127.0.0.1", step.port))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let hello = ClientHello::new(now_unix());
    let packet = hello.packet(&cluster.secret.auth_key());
    let server_addr = ("127.0.0.1", ports.main);
    socket.send_to(&packet, server_addr).await.unwrap();
    let mut first = vec![0u8; 256];
    let (first_len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut first))
        .await
        .expect("first READY")
        .unwrap();
    first.truncate(first_len);
    assert_eq!(handshake_kind(&first), Some(TYPE_READY));

    socket.send_to(&packet, server_addr).await.unwrap();
    let mut second = vec![0u8; 256];
    let (second_len, _) =
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut second))
            .await
            .expect("retransmitted READY")
            .unwrap();
    second.truncate(second_len);
    assert_eq!(
        second, first,
        "retransmission must reuse the same server key"
    );

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_port_requires_a_valid_knock() {
    let mut cluster = cluster();
    let handle = start_server(&cluster).await;

    // Agent knocks on the wrong ports, so the gate never opens.
    cluster.agent_config.agent.knock_ports = (0..5).map(|_| free_udp_port()).collect();
    cluster.agent_config.agent.connect_attempts = 1;
    cluster.agent_config.agent.handshake_timeout_secs = 1;
    let result = poll(&cluster, "blocked-agent").await;
    assert!(result.is_err(), "sync must fail without the right knock");
    assert!(!cluster.agent_root.join("owner/bots/cindy/SOUL.md").exists());

    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_cluster_secret_is_rejected() {
    let mut cluster = cluster();
    let handle = start_server(&cluster).await;

    // The right ports (taken from the server config) but the wrong secret: the
    // gate opens, yet every HELLO fails authentication and is dropped silently.
    cluster.secret = ClusterSecret::resolve(&"11".repeat(32)).unwrap();
    cluster.agent_config.agent.connect_attempts = 1;
    cluster.agent_config.agent.handshake_timeout_secs = 1;
    cluster.agent_config.agent.knock_ports = cluster.server_config.server.knock_ports.clone();
    let result = poll(&cluster, "wrong-secret-agent").await;
    let err = result.expect_err("a mismatched cluster secret must not sync");
    // The silent server must be recognisable so the agent can print the
    // diagnostic checklist instead of a bare timeout.
    assert!(
        promptsync::agent::is_no_handshake(&err),
        "unexpected error: {err:#}"
    );
    assert!(!cluster.agent_root.join("owner/bots/cindy/SOUL.md").exists());

    handle.abort();
}
