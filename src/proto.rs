//! Application messages exchanged inside the encrypted channel.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Ask for the current manifest. `applied_hash` is the server hash this
    /// agent applied last (empty on first contact / older agents); the server
    /// shows it in `--agents` so a lagging machine is visible.
    Status {
        agent_id: String,
        #[serde(default)]
        applied_hash: String,
    },
    Bundle {
        agent_id: String,
    },
    /// End of session. `applied_hash` reports the server hash the agent holds
    /// after this cycle (after a pull it is the freshly applied bundle).
    Bye {
        agent_id: String,
        #[serde(default)]
        applied_hash: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Response {
    Status(Manifest),
    Bundle(Bundle),
    Error { code: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub epoch: u64,
    pub hash: String,
    pub files: usize,
    pub bytes: u64,
    pub updated_unix: u64,
    /// The server's `sync.target`, so agents can prefer the same prompt when
    /// adapting it to local client configs. Empty on older servers.
    #[serde(default)]
    pub target: String,
    /// Feishu app id and bound owner. Agents that use the same app can inherit
    /// the recipient automatically instead of asking the user to paste an
    /// open_id. Both are empty when the server has no Feishu binding.
    #[serde(default)]
    pub feishu_app_id: String,
    #[serde(default)]
    pub feishu_owner_open_id: String,
    /// Hex Ed25519 public key of the server (empty on older servers).
    #[serde(default)]
    pub server_key: String,
    /// Hex Ed25519 signature over `signing_bytes()` (empty on older servers).
    #[serde(default)]
    pub signature: String,
}

impl Manifest {
    /// Canonical bytes covered by the server signature.
    ///
    /// Every field an agent acts on is included: the content hash (the bundle
    /// is checked against it), the adapter target, the Feishu recipient it may
    /// adopt, and `updated_unix`, which agents use to refuse rollbacks to an
    /// older signed manifest. Each field is length-prefixed so no two
    /// different manifests serialise to the same bytes. `server_key` and
    /// `signature` themselves are not covered.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(b"promptsync-manifest-sig-v1");
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&(self.files as u64).to_be_bytes());
        out.extend_from_slice(&self.bytes.to_be_bytes());
        out.extend_from_slice(&self.updated_unix.to_be_bytes());
        for field in [
            &self.hash,
            &self.target,
            &self.feishu_app_id,
            &self.feishu_owner_open_id,
        ] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub epoch: u64,
    pub hash: String,
    pub files: Vec<PromptFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptFile {
    pub path: String,
    /// Base64 keeps JSON small-ish while staying human-inspectable in logs.
    pub content_b64: String,
}

impl Bundle {
    pub fn from_entries(entries: &BTreeMap<String, Vec<u8>>, epoch: u64, hash: String) -> Self {
        let files = entries
            .iter()
            .map(|(path, content)| PromptFile {
                path: path.clone(),
                content_b64: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    content,
                ),
            })
            .collect();
        Self { epoch, hash, files }
    }

    pub fn into_entries(self) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut entries = BTreeMap::new();
        for file in self.files {
            let content = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                file.content_b64.as_bytes(),
            )
            .map_err(|e| anyhow::anyhow!("invalid base64 for {}: {e}", file.path))?;
            if entries.insert(file.path.clone(), content).is_some() {
                bail!("duplicate path in bundle: {}", file.path);
            }
        }
        Ok(entries)
    }
}

pub fn encode_request(request: &Request) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(request)?)
}

pub fn encode_response(response: &Response) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(response)?)
}

pub fn decode_request(payload: &[u8]) -> Result<Request> {
    Ok(serde_json::from_slice(payload)?)
}

pub fn decode_response(payload: &[u8]) -> Result<Response> {
    Ok(serde_json::from_slice(payload)?)
}
