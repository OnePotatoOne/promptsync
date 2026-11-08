//! Command-line behaviour that only shows up in the real binary: first-start
//! secret handling, the `ports` report and config-directory resolution.
//!
//! Each test runs the compiled `promptsync` with its own temporary config
//! directory and `HOME`, so no real configuration is ever read or written.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

/// Run the compiled binary.
///
/// `cwd` is the working directory, `home` the fake `HOME` (keeps
/// `~/.promptsync` out of the test), `args` the command line after the binary.
fn run(cwd: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_promptsync"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env_remove("PROMPTSYNC_CONFIG_DIR")
        .output()
        .expect("run promptsync")
}

/// Read `cluster_secret` from the config file at `path` (empty when unset).
fn stored_secret(path: &Path) -> String {
    let text = fs::read_to_string(path).expect("read config");
    text.lines()
        .find_map(|line| line.trim().strip_prefix("cluster_secret = "))
        .map(|value| value.trim_matches('"').to_string())
        .unwrap_or_default()
}

/// A scripted first agent start (`--once`) must not invent a random secret
/// that no server can share; it has to stop and say how to set the real one.
#[test]
fn scripted_agent_refuses_to_generate_a_secret() {
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join("cfg");
    let config_dir_text = config_dir.display().to_string();
    let output = run(
        temp.path(),
        temp.path(),
        &[
            "--config-dir",
            &config_dir_text,
            "agent",
            "--server",
            "127.0.0.1",
            "--once",
        ],
    );
    assert!(!output.status.success(), "agent must refuse to start");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("secret --set"), "stderr: {stderr}");
    assert_eq!(
        stored_secret(&config_dir.join("config.toml")),
        "",
        "no secret may be generated for a scripted agent"
    );
}

/// The server role keeps generating its secret on first start.
#[test]
fn server_init_still_generates_a_secret() {
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join("cfg");
    let config_dir_text = config_dir.display().to_string();
    let output = run(
        temp.path(),
        temp.path(),
        &["--config-dir", &config_dir_text, "init"],
    );
    assert!(output.status.success());
    assert_eq!(stored_secret(&config_dir.join("config.toml")).len(), 64);
}

/// With `[server] port` pinned, `ports` must tell agents to pin the same port
/// instead of printing the secret-derived one as if it applied.
#[test]
fn ports_tells_agents_to_copy_a_pinned_server_port() {
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join("cfg");
    let config_dir_text = config_dir.display().to_string();
    assert!(run(
        temp.path(),
        temp.path(),
        &["--config-dir", &config_dir_text, "init"]
    )
    .status
    .success());
    let file = config_dir.join("config.toml");
    let text = fs::read_to_string(&file).unwrap();
    let pinned = text.replacen("[server]\n", "[server]\nport = 12345\n", 1);
    // Drop the template's own `port = 0` inside [server] so the key is unique.
    let mut in_server = false;
    let mut seen_port = false;
    let rewritten: Vec<&str> = pinned
        .lines()
        .filter(|line| {
            if line.starts_with('[') {
                in_server = line.trim() == "[server]";
            }
            if in_server && line.trim_start().starts_with("port =") {
                if seen_port {
                    return false;
                }
                seen_port = true;
            }
            true
        })
        .collect();
    fs::write(&file, rewritten.join("\n")).unwrap();

    let output = run(
        temp.path(),
        temp.path(),
        &["--config-dir", &config_dir_text, "ports"],
    );
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[agent] port = 12345   (required"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("pinned by [server] port"),
        "stdout: {stdout}"
    );
}

/// `cd config && promptsync ports` must use that directory rather than look
/// for (or later create) `config/config/config.toml`.
#[test]
fn running_inside_the_config_dir_reuses_it() {
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join("config");
    let config_dir_text = config_dir.display().to_string();
    assert!(run(
        temp.path(),
        temp.path(),
        &["--config-dir", &config_dir_text, "init"]
    )
    .status
    .success());
    let output = run(&config_dir, temp.path(), &["ports"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The binary sees the canonical cwd (macOS: /var -> /private/var).
    let canonical = config_dir.canonicalize().unwrap();
    assert!(
        stdout.contains(&format!("config dir: {}", canonical.display())),
        "stdout: {stdout}"
    );
    assert!(!config_dir.join("config").exists());
}
