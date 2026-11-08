//! Cryptographic primitives: cluster secret, port knocking tags, PSK
//! authenticated X25519 handshake and AES-256-GCM record protection.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashSet;
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey};

type HmacSha256 = Hmac<Sha256>;

pub const MAGIC: [u8; 2] = *b"PS";
pub const VERSION: u8 = 1;

pub const TYPE_HELLO: u8 = 0x01;
pub const TYPE_READY: u8 = 0x02;
pub const TYPE_DATA: u8 = 0x03;
pub const TYPE_ACK: u8 = 0x04;
pub const TYPE_KNOCK: u8 = 0x10;

pub const HAND_SHAKE_LEN: usize = 100;
pub const KNOCK_LEN: usize = 46;
/// Clock skew tolerated in handshakes and knocks.
pub const MAX_CLOCK_SKEW_SECS: u64 = 600;

fn hmac_tag(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

fn mac_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.ct_eq(right).unwrap_u8() == 1
}

/// Domain-separation salt for turning a human passphrase into the cluster
/// secret. It must stay constant so that separately compiled binaries derive
/// the same key from the same passphrase.
const SECRET_KDF_SALT: &[u8] = b"promptsync cluster secret v1";
/// PBKDF2 work factor. Costs roughly 0.2 s once per explicit passphrase
/// entry; the derived key (hex) is what gets stored in config.toml.
const SECRET_KDF_ROUNDS: u32 = 300_000;

/// Passphrases shorter than this (in characters) trigger a warning; they are
/// still accepted so existing setups keep working.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// PBKDF2-HMAC-SHA256 with a single 32-byte output block.
///
/// `password` is the UTF-8 passphrase, `salt` the domain separator and
/// `rounds` the iteration count. Returns the 32-byte derived key.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(password).expect("HMAC accepts keys of any length");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut block = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&block);
    for _ in 1..rounds.max(1) {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(password).expect("HMAC accepts keys of any length");
        mac.update(&block);
        block = mac.finalize().into_bytes();
        for (slot, byte) in out.iter_mut().zip(block.iter()) {
            *slot ^= byte;
        }
    }
    out
}

/// A 32-byte cluster secret. Either compiled into the build (random per build)
/// or configured by the operator. It authenticates knocks and handshakes.
#[derive(Clone)]
pub struct ClusterSecret([u8; 32]);

impl std::fmt::Debug for ClusterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClusterSecret({}...)", &self.to_hex()[..12])
    }
}

impl ClusterSecret {
    pub fn from_hex(value: &str) -> Result<Self> {
        let cleaned: String = value
            .trim()
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect();
        if cleaned.len() != 64 {
            bail!(
                "cluster secret must be 64 hex characters, got {}",
                cleaned.len()
            );
        }
        let bytes = hex::decode(cleaned).context("decoding cluster secret")?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    /// Accept either a legacy 64-hex secret or a human passphrase.
    ///
    /// A passphrase is stretched with PBKDF2-HMAC-SHA256 (300k rounds) using a
    /// fixed domain salt, so every machine that types the same phrase derives
    /// the same key. Hex input is passed through for backwards compatibility.
    pub fn from_input(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("集群口令不能为空");
        }
        let is_hex = trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit());
        if is_hex {
            return Self::from_hex(trimmed);
        }
        Ok(Self(pbkdf2_sha256(
            trimmed.as_bytes(),
            SECRET_KDF_SALT,
            SECRET_KDF_ROUNDS,
        )))
    }

    /// Warning for a passphrase that is easy to brute-force offline, or `None`.
    ///
    /// `input` is what the user typed. The PBKDF2 salt is a fixed constant (all
    /// machines must derive the same key), so one captured knock or HELLO lets
    /// an eavesdropper test guesses offline at ~300k HMAC rounds each. Random
    /// 64-hex secrets are not affected; short phrases are.
    pub fn passphrase_warning(input: &str) -> Option<String> {
        let trimmed = input.trim();
        let is_hex = trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit());
        let chars = trimmed.chars().count();
        if is_hex || chars >= MIN_PASSPHRASE_CHARS {
            return None;
        }
        Some(format!(
            "⚠ 口令只有 {chars} 个字符：抓到一个敲门包就能离线暴力猜测。建议至少 {MIN_PASSPHRASE_CHARS} 个字符，或直接复制 server 生成的 64 位 hex 密钥。"
        ))
    }

    pub fn random() -> Self {
        let mut out = [0u8; 32];
        OsRng.fill_bytes(&mut out);
        Self(out)
    }

    /// Resolve a configured secret.
    ///
    /// There is deliberately no fallback to a value compiled into the binary:
    /// first start generates a random secret and writes it to `config.toml`.
    /// An empty value here means the caller forgot to run
    /// `Config::ensure_cluster_secret` and must fail instead of silently
    /// joining a public key that every release user shares.
    pub fn resolve(configured: &str) -> Result<Self> {
        if configured.trim().is_empty() {
            bail!(
                "cluster_secret is empty; start the server or agent once \
                 (it will generate one) or run `promptsync secret --set <passphrase>`"
            );
        }
        Self::from_hex(configured)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    fn subkey(&self, label: &[u8]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"promptsync subkeys v1"), &self.0);
        let mut out = [0u8; 32];
        hk.expand(label, &mut out)
            .expect("HKDF expand of 32 bytes cannot fail");
        out
    }

    pub fn auth_key(&self) -> [u8; 32] {
        self.subkey(b"handshake-auth-key")
    }

    pub fn knock_key(&self) -> [u8; 32] {
        self.subkey(b"knock-tag-key")
    }

    /// Short, non-reversible fingerprint for logs.
    pub fn fingerprint(&self) -> String {
        hex::encode(&self.subkey(b"fingerprint")[..6])
    }
}

/// The server's Ed25519 identity.
///
/// The cluster secret is shared by every machine, so it cannot tell the server
/// apart from an agent: any agent holding it could answer a handshake. Only
/// the server holds this signing key; agents pin its public key and refuse
/// manifests that are not signed by it.
pub struct ServerSigner(ed25519_dalek::SigningKey);

impl ServerSigner {
    /// Fresh random key, returned as the 64-hex seed stored in config.toml.
    pub fn generate_hex() -> String {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        hex::encode(seed)
    }

    /// Load the signer from the 64-hex seed in `[server] signing_key`.
    pub fn from_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value.trim()).context("server.signing_key is not hex")?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("server.signing_key must be 64 hex characters"))?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    /// Hex public key that agents pin (`[agent] server_public_key`).
    pub fn public_hex(&self) -> String {
        hex::encode(self.0.verifying_key().to_bytes())
    }

    /// Hex signature over `message`.
    pub fn sign_hex(&self, message: &[u8]) -> String {
        use ed25519_dalek::Signer;
        hex::encode(self.0.sign(message).to_bytes())
    }
}

/// Short fingerprint of a hex public key for logs and `ports`.
///
/// `public_hex` is the 64-hex key; returns the first 12 hex characters of its
/// SHA-256, or `"invalid"` when the input is not hex.
pub fn server_key_fingerprint(public_hex: &str) -> String {
    use sha2::Digest;
    match hex::decode(public_hex.trim()) {
        Ok(bytes) => hex::encode(&Sha256::digest(bytes)[..6]),
        Err(_) => "invalid".to_string(),
    }
}

/// Verify `signature_hex` over `message` with the pinned `public_hex` key.
///
/// Uses strict verification (rejects malleable / small-order encodings).
pub fn verify_server_signature(
    public_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<()> {
    let key_bytes: [u8; 32] = hex::decode(public_hex.trim())
        .context("server public key is not hex")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("server public key must be 64 hex characters"))?;
    let signature_bytes: [u8; 64] = hex::decode(signature_hex.trim())
        .context("server signature is not hex")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("server signature must be 128 hex characters"))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| anyhow!("server public key is not a valid Ed25519 key"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    key.verify_strict(message, &signature)
        .map_err(|_| anyhow!("server signature does not verify"))
}

/// Ports are derived from the cluster secret so that every machine sharing the
/// secret agrees without hard-coded numbers in a public repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedPorts {
    pub main: u16,
    pub knock: Vec<u16>,
}

/// Size of the knock-port pool. The agent picks a random subset on every
/// attempt, in a random order, so the observable knock pattern never repeats.
pub const KNOCK_POOL_SIZE: usize = 12;
/// Knocks carry a timestamp; unlike handshakes they must be fresh.
pub const MAX_KNOCK_SKEW_SECS: u64 = 60;

impl ClusterSecret {
    pub fn ports(&self) -> DerivedPorts {
        let key = self.subkey(b"port-map-v1");
        let mut used: HashSet<u16> = HashSet::new();
        let mut next = |counter: u32| -> u16 {
            loop {
                let tag = hmac_tag(&key, &counter.to_be_bytes());
                let value = u64::from_be_bytes(tag[..8].try_into().expect("8 bytes"));
                let port = 20_000 + (value % 40_000) as u16;
                if used.insert(port) {
                    return port;
                }
            }
        };
        let main = next(0);
        let mut knock = Vec::with_capacity(KNOCK_POOL_SIZE);
        for index in 1..=KNOCK_POOL_SIZE as u32 {
            knock.push(next(index));
        }
        DerivedPorts { main, knock }
    }
}

/// One knock sequence: `total` packets tagged with the same random flow id.
///
/// `slot` is the index of the chosen port inside the derived pool. The tag
/// covers the slot and the port is what the server receives on, so a packet
/// cannot be redirected to a different port, and the subset/order of ports is
/// not predictable from one attempt to the next.
#[derive(Debug, Clone)]
pub struct KnockSequence {
    pub total: u8,
    pub rand: [u8; 16],
}

impl KnockSequence {
    pub fn generate(total: u8) -> Self {
        let mut rand = [0u8; 16];
        OsRng.fill_bytes(&mut rand);
        Self { total, rand }
    }

    pub fn packet(&self, slot: u8, key: &[u8; 32], now: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(KNOCK_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(TYPE_KNOCK);
        out.push(self.total);
        out.push(slot);
        out.extend_from_slice(&self.rand);
        out.extend_from_slice(&now.to_be_bytes());
        let mut mac_input = Vec::with_capacity(64);
        mac_input.extend_from_slice(b"promptsync-knock-v2");
        mac_input.push(self.total);
        mac_input.push(slot);
        mac_input.extend_from_slice(&self.rand);
        mac_input.extend_from_slice(&now.to_be_bytes());
        let tag = hmac_tag(key, &mac_input);
        out.extend_from_slice(&tag[..16]);
        debug_assert_eq!(out.len(), KNOCK_LEN);
        out
    }
}

pub struct ParsedKnock {
    pub slot: u8,
    pub total: u8,
    pub rand: [u8; 16],
}

pub fn parse_knock(packet: &[u8], key: &[u8; 32], now: u64, skew: u64) -> Result<ParsedKnock> {
    if packet.len() != KNOCK_LEN {
        bail!("bad knock length");
    }
    if packet[0..2] != MAGIC || packet[2] != VERSION || packet[3] != TYPE_KNOCK {
        bail!("bad knock header");
    }
    let total = packet[4];
    let slot = packet[5];
    if total == 0 || total > 16 || slot >= 16 {
        bail!("bad knock geometry");
    }
    let mut rand = [0u8; 16];
    rand.copy_from_slice(&packet[6..22]);
    let ts = u64::from_be_bytes(packet[22..30].try_into().expect("8 bytes"));
    if now.abs_diff(ts) > skew {
        bail!("stale knock");
    }
    let mut mac_input = Vec::with_capacity(64);
    mac_input.extend_from_slice(b"promptsync-knock-v2");
    mac_input.push(total);
    mac_input.push(slot);
    mac_input.extend_from_slice(&rand);
    mac_input.extend_from_slice(&ts.to_be_bytes());
    let expected = hmac_tag(key, &mac_input);
    if !mac_eq(&expected[..16], &packet[30..46]) {
        bail!("bad knock tag");
    }
    Ok(ParsedKnock { slot, total, rand })
}

/// Keys for one session, one per direction.
#[derive(Clone)]
pub struct SessionKeys {
    pub c2s: [u8; 32],
    pub s2c: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys(<redacted>)")
    }
}

fn derive_session_keys(
    shared: &[u8; 32],
    auth: &[u8; 32],
    session: &[u8; 8],
    nonce_c: &[u8; 16],
    nonce_s: &[u8; 16],
) -> Result<SessionKeys> {
    let mut salt_input = Vec::with_capacity(64);
    salt_input.extend_from_slice(b"promptsync-hs-salt-v1");
    salt_input.extend_from_slice(session);
    salt_input.extend_from_slice(nonce_c);
    salt_input.extend_from_slice(nonce_s);
    let salt = hmac_tag(auth, &salt_input);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hk.expand(b"promptsync c2s v1", &mut c2s)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    hk.expand(b"promptsync s2c v1", &mut s2c)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(SessionKeys { c2s, s2c })
}

fn hello_mac(
    auth: &[u8; 32],
    session: &[u8; 8],
    ts: u64,
    client_pub: &[u8; 32],
    nonce_c: &[u8; 16],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(96);
    input.extend_from_slice(b"promptsync-hello-v1");
    input.extend_from_slice(session);
    input.extend_from_slice(&ts.to_be_bytes());
    input.extend_from_slice(client_pub);
    input.extend_from_slice(nonce_c);
    hmac_tag(auth, &input)
}

#[allow(clippy::too_many_arguments)]
fn ready_mac(
    auth: &[u8; 32],
    session: &[u8; 8],
    ts: u64,
    client_pub: &[u8; 32],
    server_pub: &[u8; 32],
    nonce_c: &[u8; 16],
    nonce_s: &[u8; 16],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(b"promptsync-ready-v1");
    input.extend_from_slice(session);
    input.extend_from_slice(&ts.to_be_bytes());
    input.extend_from_slice(client_pub);
    input.extend_from_slice(server_pub);
    input.extend_from_slice(nonce_c);
    input.extend_from_slice(nonce_s);
    hmac_tag(auth, &input)
}

pub struct ClientHello {
    eph: EphemeralSecret,
    public: [u8; 32],
    nonce: [u8; 16],
    session: [u8; 8],
    ts: u64,
}

impl ClientHello {
    pub fn new(now: u64) -> Self {
        let eph = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&eph).to_bytes();
        let mut nonce = [0u8; 16];
        let mut session = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        OsRng.fill_bytes(&mut session);
        Self {
            eph,
            public,
            nonce,
            session,
            ts: now,
        }
    }

    pub fn session(&self) -> [u8; 8] {
        self.session
    }

    pub fn packet(&self, auth: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HAND_SHAKE_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(TYPE_HELLO);
        out.extend_from_slice(&self.session);
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&self.nonce);
        let mac = hello_mac(auth, &self.session, self.ts, &self.public, &self.nonce);
        out.extend_from_slice(&mac);
        debug_assert_eq!(out.len(), HAND_SHAKE_LEN);
        out
    }

    pub fn finish(self, ready: &[u8], auth: &[u8; 32], now: u64, skew: u64) -> Result<SessionKeys> {
        if ready.len() != HAND_SHAKE_LEN {
            bail!("bad READY length: {}", ready.len());
        }
        if ready[0..2] != MAGIC || ready[2] != VERSION || ready[3] != TYPE_READY {
            bail!("bad READY header");
        }
        if ready[4..12] != self.session {
            bail!("READY carried a different session id");
        }
        let ts = u64::from_be_bytes(ready[12..20].try_into().expect("8 bytes"));
        if now.abs_diff(ts) > skew {
            bail!("stale READY");
        }
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&ready[20..52]);
        let mut nonce_s = [0u8; 16];
        nonce_s.copy_from_slice(&ready[52..68]);
        let expected = ready_mac(
            auth,
            &self.session,
            ts,
            &self.public,
            &server_pub,
            &self.nonce,
            &nonce_s,
        );
        if !mac_eq(&expected, &ready[68..100]) {
            bail!("READY failed authentication (cluster secret mismatch?)");
        }
        let peer = PublicKey::from(server_pub);
        let shared = self.eph.diffie_hellman(&peer);
        derive_session_keys(
            shared.as_bytes(),
            auth,
            &self.session,
            &self.nonce,
            &nonce_s,
        )
    }
}

pub struct ServerHandshake {
    pub packet: Vec<u8>,
    pub session: [u8; 8],
    pub keys: SessionKeys,
}

pub fn accept_hello(hello: &[u8], auth: &[u8; 32], now: u64, skew: u64) -> Result<ServerHandshake> {
    if hello.len() != HAND_SHAKE_LEN {
        bail!("bad HELLO length: {}", hello.len());
    }
    if hello[0..2] != MAGIC || hello[2] != VERSION || hello[3] != TYPE_HELLO {
        bail!("bad HELLO header");
    }
    let mut session = [0u8; 8];
    session.copy_from_slice(&hello[4..12]);
    let ts = u64::from_be_bytes(hello[12..20].try_into().expect("8 bytes"));
    if now.abs_diff(ts) > skew {
        bail!("stale HELLO");
    }
    let mut client_pub = [0u8; 32];
    client_pub.copy_from_slice(&hello[20..52]);
    let mut nonce_c = [0u8; 16];
    nonce_c.copy_from_slice(&hello[52..68]);
    let expected = hello_mac(auth, &session, ts, &client_pub, &nonce_c);
    if !mac_eq(&expected, &hello[68..100]) {
        bail!("HELLO failed authentication (cluster secret mismatch?)");
    }

    let eph = EphemeralSecret::random_from_rng(OsRng);
    let server_pub = PublicKey::from(&eph).to_bytes();
    let mut nonce_s = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_s);
    let ready_ts = now;
    let mac = ready_mac(
        auth,
        &session,
        ready_ts,
        &client_pub,
        &server_pub,
        &nonce_c,
        &nonce_s,
    );
    let mut packet = Vec::with_capacity(HAND_SHAKE_LEN);
    packet.extend_from_slice(&MAGIC);
    packet.push(VERSION);
    packet.push(TYPE_READY);
    packet.extend_from_slice(&session);
    packet.extend_from_slice(&ready_ts.to_be_bytes());
    packet.extend_from_slice(&server_pub);
    packet.extend_from_slice(&nonce_s);
    packet.extend_from_slice(&mac);
    debug_assert_eq!(packet.len(), HAND_SHAKE_LEN);

    let shared = eph.diffie_hellman(&PublicKey::from(client_pub));
    let keys = derive_session_keys(shared.as_bytes(), auth, &session, &nonce_c, &nonce_s)?;
    Ok(ServerHandshake {
        packet,
        session,
        keys,
    })
}

const WINDOW_BITS: u64 = 1024;

/// Sliding replay window for record counters (IPsec style).
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: [u64; (WINDOW_BITS / 64) as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0u64; (WINDOW_BITS / 64) as usize],
        }
    }

    pub fn would_accept(&self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if counter > self.highest {
            return true;
        }
        if self.highest - counter >= WINDOW_BITS {
            return false;
        }
        let index = (counter % WINDOW_BITS) as usize;
        self.bitmap[index / 64] & (1u64 << (index % 64)) == 0
    }

    pub fn commit(&mut self, counter: u64) {
        if counter > self.highest {
            let gap = counter - self.highest;
            if gap >= WINDOW_BITS {
                self.bitmap = [0u64; (WINDOW_BITS / 64) as usize];
            } else {
                for value in (self.highest + 1)..=counter {
                    let index = (value % WINDOW_BITS) as usize;
                    self.bitmap[index / 64] &= !(1u64 << (index % 64));
                }
            }
            self.highest = counter;
        }
        let index = (counter % WINDOW_BITS) as usize;
        self.bitmap[index / 64] |= 1u64 << (index % 64);
    }
}

fn nonce_for(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// One direction of a session: outgoing counter + incoming replay window.
pub struct DirCipher {
    cipher: Aes256Gcm,
    pub counter: u64,
    window: ReplayWindow,
}

impl DirCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key).expect("AES-256 key is 32 bytes"),
            counter: 0,
            window: ReplayWindow::new(),
        }
    }

    /// Reserve the next nonce counter for an outgoing record.
    pub fn reserve_counter(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    /// Seal a record with a previously reserved counter; returns ciphertext+tag.
    pub fn seal_with(&mut self, counter: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        debug_assert!(counter <= self.counter);
        let nonce = nonce_for(counter);
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("record encryption failed"))
    }

    /// Seal a record; returns `(counter, ciphertext_with_tag)`.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<(u64, Vec<u8>)> {
        let counter = self.reserve_counter();
        let ciphertext = self.seal_with(counter, aad, plaintext)?;
        Ok((counter, ciphertext))
    }

    pub fn open(&mut self, counter: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.window.would_accept(counter) {
            bail!("replayed or stale record");
        }
        let nonce = nonce_for(counter);
        let plaintext = self
            .cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("record failed authentication"))?;
        self.window.commit(counter);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> ClusterSecret {
        ClusterSecret::from_hex(&"11".repeat(32)).unwrap()
    }

    #[test]
    fn empty_secret_is_not_replaced_by_a_build_default() {
        assert!(ClusterSecret::resolve("").is_err());
        assert!(ClusterSecret::resolve("   ").is_err());
        assert!(ClusterSecret::resolve(&"11".repeat(32)).is_ok());
    }

    #[test]
    fn ports_are_stable_and_unique() {
        let secret = secret();
        let first = secret.ports();
        let second = secret.ports();
        assert_eq!(first, second);
        assert_eq!(first.knock.len(), KNOCK_POOL_SIZE);
        assert!(!first.knock.contains(&first.main));
        let mut all = first.knock.clone();
        all.push(first.main);
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), KNOCK_POOL_SIZE + 1);
        assert!(first.main >= 20_000);
    }

    #[test]
    fn knock_tags_are_verified() {
        let secret = secret();
        let key = secret.knock_key();
        let sequence = KnockSequence::generate(5);
        let now = 1_700_000_000;
        let packet = sequence.packet(7, &key, now);
        let parsed = parse_knock(&packet, &key, now, MAX_KNOCK_SKEW_SECS).unwrap();
        assert_eq!(parsed.slot, 7);
        assert_eq!(parsed.total, 5);
        assert_eq!(parsed.rand, sequence.rand);

        let wrong_key = ClusterSecret::random().knock_key();
        assert!(parse_knock(&packet, &wrong_key, now, MAX_KNOCK_SKEW_SECS).is_err());
        assert!(parse_knock(&packet, &key, now + 100_000, MAX_KNOCK_SKEW_SECS).is_err());
        // The slot is authenticated: flipping it must invalidate the tag.
        let mut other_slot = packet.clone();
        other_slot[5] = 8;
        assert!(parse_knock(&other_slot, &key, now, MAX_KNOCK_SKEW_SECS).is_err());

        let mut tampered = packet.clone();
        tampered[30] ^= 0xff;
        assert!(parse_knock(&tampered, &key, now, MAX_KNOCK_SKEW_SECS).is_err());
    }

    #[test]
    fn handshake_derives_matching_keys() {
        let secret = secret();
        let auth = secret.auth_key();
        let now = 1_700_000_000;
        let client = ClientHello::new(now);
        let hello = client.packet(&auth);
        let server = accept_hello(&hello, &auth, now, MAX_CLOCK_SKEW_SECS).unwrap();
        let client_keys = client
            .finish(&server.packet, &auth, now, MAX_CLOCK_SKEW_SECS)
            .unwrap();
        assert_eq!(client_keys.c2s, server.keys.c2s);
        assert_eq!(client_keys.s2c, server.keys.s2c);
        assert_ne!(client_keys.c2s, client_keys.s2c);
    }

    #[test]
    fn handshake_rejects_wrong_secret_and_tampering() {
        let auth = secret().auth_key();
        let wrong = ClusterSecret::random().auth_key();
        let now = 1_700_000_000;
        let client = ClientHello::new(now);
        let hello = client.packet(&auth);
        assert!(accept_hello(&hello, &wrong, now, MAX_CLOCK_SKEW_SECS).is_err());

        let mut tampered = hello.clone();
        tampered[40] ^= 0x01;
        assert!(accept_hello(&tampered, &auth, now, MAX_CLOCK_SKEW_SECS).is_err());

        let client = ClientHello::new(now);
        let hello = client.packet(&auth);
        let server = accept_hello(&hello, &auth, now, MAX_CLOCK_SKEW_SECS).unwrap();
        let mut ready = server.packet.clone();
        ready[90] ^= 0xff;
        assert!(client
            .finish(&ready, &auth, now, MAX_CLOCK_SKEW_SECS)
            .is_err());
    }

    #[test]
    fn records_round_trip_and_replay_is_rejected() {
        let key = ClusterSecret::random().auth_key();
        let mut sender = DirCipher::new(&key);
        let mut receiver = DirCipher::new(&key);
        let aad = b"header";

        let (counter, ciphertext) = sender.seal(aad, b"hello world").unwrap();
        assert_eq!(
            receiver.open(counter, aad, &ciphertext).unwrap(),
            b"hello world"
        );
        assert!(receiver.open(counter, aad, &ciphertext).is_err());

        let (counter2, ciphertext2) = sender.seal(aad, b"second").unwrap();
        assert!(receiver
            .open(counter2, b"other-header", &ciphertext2)
            .is_err());
        assert!(receiver.open(counter2, aad, &ciphertext2).is_ok());
    }

    #[test]
    fn replay_window_handles_reordering() {
        let mut window = ReplayWindow::new();
        assert!(window.would_accept(5));
        window.commit(5);
        assert!(window.would_accept(3));
        window.commit(3);
        assert!(!window.would_accept(3));
        assert!(!window.would_accept(5));
        assert!(window.would_accept(6));
        window.commit(6);
        assert!(!window.would_accept(0));
        // A far-ahead counter is fine (fresh), but jumping >1024 ahead expires
        // everything inside the window.
        assert!(window.would_accept(2_000));
        window.commit(2_000);
        assert!(!window.would_accept(1));
        assert!(!window.would_accept(2_000));
        assert!(window.would_accept(1_999));
    }

    #[test]
    fn server_signatures_verify_and_reject_tampering() {
        let signer = ServerSigner::from_hex(&ServerSigner::generate_hex()).unwrap();
        let public = signer.public_hex();
        let signature = signer.sign_hex(b"manifest");
        assert!(verify_server_signature(&public, b"manifest", &signature).is_ok());
        assert!(verify_server_signature(&public, b"manifesT", &signature).is_err());
        let other = ServerSigner::from_hex(&ServerSigner::generate_hex()).unwrap();
        assert!(verify_server_signature(&other.public_hex(), b"manifest", &signature).is_err());
        assert!(verify_server_signature(&public, b"manifest", "00").is_err());
        assert_eq!(server_key_fingerprint(&public).len(), 12);
        assert!(ServerSigner::from_hex("abcd").is_err());
    }

    #[test]
    fn pbkdf2_matches_rfc_vector() {
        let out = pbkdf2_sha256(b"password", b"salt", 1);
        assert_eq!(
            hex::encode(out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn passphrase_derivation_is_deterministic() {
        let a = ClusterSecret::from_input("我们家的同步口令").unwrap();
        let b = ClusterSecret::from_input("  我们家的同步口令  ").unwrap();
        assert_eq!(a.to_hex(), b.to_hex());
    }

    #[test]
    fn different_passphrases_differ() {
        let a = ClusterSecret::from_input("alpha").unwrap();
        let b = ClusterSecret::from_input("beta").unwrap();
        assert_ne!(a.to_hex(), b.to_hex());
    }

    #[test]
    fn hex_input_is_used_verbatim() {
        let hex = "aa".repeat(32);
        let secret = ClusterSecret::from_input(&hex).unwrap();
        assert_eq!(secret.to_hex(), hex);
    }

    #[test]
    fn empty_passphrase_is_rejected() {
        assert!(ClusterSecret::from_input("   ").is_err());
        assert!(ClusterSecret::passphrase_warning("alpha").is_some());
        assert!(ClusterSecret::passphrase_warning("correct horse battery").is_none());
        assert!(ClusterSecret::passphrase_warning(&"ab".repeat(32)).is_none());
    }
}
