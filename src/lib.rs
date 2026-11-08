//! promptsync - encrypted, port-knocked prompt synchronisation.
//!
//! * `server` owns the authoritative prompt set and publishes a SHA-256 hash.
//! * `agent` polls that hash every 10 seconds and pulls the bundle when it moved.
//! * Transport is UDP, PSK-authenticated X25519 + AES-256-GCM, with a
//!   fragment-level reliable layer on top.
//! * The data port is only bound while a valid port-knock sequence opened a gate.

pub mod adapters;
pub mod agent;
pub mod buildinfo;
pub mod commands;
pub mod config;
pub mod crypto;
pub mod feishu;
pub mod feishu_control;
pub mod globpat;
pub mod interactive;
pub mod knock;
pub mod logx;
pub mod paths;
pub mod prompts;
pub mod proto;
pub mod server;
pub mod util;
pub mod wire;

pub use config::Config;

/// Exit codes used by the CLI.
pub mod exit {
    pub const OK: i32 = 0;
    pub const FAILURE: i32 = 1;
    pub const CONFIG: i32 = 2;
    pub const NETWORK: i32 = 3;
}
