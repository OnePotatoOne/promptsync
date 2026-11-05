//! Application messages exchanged inside the encrypted channel.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status { agent_id: String },
    Bundle { agent_id: String },
    Bye { agent_id: String },
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
