//! UDP record format plus a small reliable layer (fragmentation, ACK bitmap,
//! retransmission) on top of AES-256-GCM records.

use anyhow::{bail, Context, Result};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::crypto::{
    self, DirCipher, SessionKeys, MAGIC, TYPE_ACK, TYPE_DATA, TYPE_HELLO, TYPE_READY, VERSION,
};

pub const HEADER_LEN: usize = 28;
pub const MAX_DATAGRAM: usize = 1200;
pub const FRAG_PAYLOAD: usize = 1080;
pub const MAX_FRAGMENTS: usize = 4096;
pub const MAX_MESSAGE: usize = FRAG_PAYLOAD * MAX_FRAGMENTS;
const ACK_WORDS: usize = MAX_FRAGMENTS / 64;
const ACK_PAYLOAD_LEN: usize = 8 + ACK_WORDS * 8;

pub type PacketReceiver = mpsc::Receiver<Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    pub session: [u8; 8],
    pub msg_id: u32,
    pub frag_index: u16,
    pub frag_count: u16,
    pub counter: u64,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..2].copy_from_slice(&MAGIC);
        out[2] = VERSION;
        out[3] = self.kind;
        out[4..12].copy_from_slice(&self.session);
        out[12..16].copy_from_slice(&self.msg_id.to_be_bytes());
        out[16..18].copy_from_slice(&self.frag_index.to_be_bytes());
        out[18..20].copy_from_slice(&self.frag_count.to_be_bytes());
        out[20..28].copy_from_slice(&self.counter.to_be_bytes());
        out
    }

    pub fn parse(packet: &[u8]) -> Result<Self> {
        if packet.len() < HEADER_LEN {
            bail!("short datagram");
        }
        if packet[0..2] != MAGIC || packet[2] != VERSION {
            bail!("bad datagram magic/version");
        }
        let mut session = [0u8; 8];
        session.copy_from_slice(&packet[4..12]);
        Ok(Self {
            kind: packet[3],
            session,
            msg_id: u32::from_be_bytes(packet[12..16].try_into().expect("4 bytes")),
            frag_index: u16::from_be_bytes(packet[16..18].try_into().expect("2 bytes")),
            frag_count: u16::from_be_bytes(packet[18..20].try_into().expect("2 bytes")),
            counter: u64::from_be_bytes(packet[20..28].try_into().expect("8 bytes")),
        })
    }
}

/// Returns the handshake kind (`TYPE_HELLO` / `TYPE_READY`) for datagrams that
/// are not encrypted records.
pub fn handshake_kind(packet: &[u8]) -> Option<u8> {
    if packet.len() == crypto::HAND_SHAKE_LEN
        && packet[0..2] == MAGIC
        && packet[2] == VERSION
        && (packet[3] == TYPE_HELLO || packet[3] == TYPE_READY)
    {
        Some(packet[3])
    } else {
        None
    }
}

#[derive(Default, Debug, Clone)]
pub struct ChannelStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub fragments_retransmitted: u64,
    pub invalid_packets: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

struct Outgoing {
    frag_count: u16,
    acked: Vec<bool>,
}

struct Reassembly {
    fragments: Vec<Option<Vec<u8>>>,
    received: usize,
    created: Instant,
}

/// Encrypted, reliable-over-UDP message channel for one session.
pub struct Channel {
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    session: [u8; 8],
    send: DirCipher,
    recv: DirCipher,
    next_msg_id: u32,
    rx: PacketReceiver,
    pending_out: HashMap<u32, Outgoing>,
    reassembly: HashMap<u32, Reassembly>,
    completed: VecDeque<Vec<u8>>,
    stats: ChannelStats,
    pump: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for Channel {
    fn drop(&mut self) {
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
    }
}

impl Channel {
    pub fn new(
        sock: Arc<UdpSocket>,
        peer: SocketAddr,
        session: [u8; 8],
        keys: &SessionKeys,
        is_client: bool,
        rx: PacketReceiver,
        pump: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        let (send_key, recv_key) = if is_client {
            (keys.c2s, keys.s2c)
        } else {
            (keys.s2c, keys.c2s)
        };
        Self {
            sock,
            peer,
            session,
            send: DirCipher::new(&send_key),
            recv: DirCipher::new(&recv_key),
            next_msg_id: 1,
            rx,
            pending_out: HashMap::new(),
            reassembly: HashMap::new(),
            completed: VecDeque::new(),
            stats: ChannelStats::default(),
            pump,
        }
    }

    pub fn stats(&self) -> &ChannelStats {
        &self.stats
    }

    fn alloc_msg_id(&mut self) -> u32 {
        let id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        if self.next_msg_id == 0 {
            self.next_msg_id = 1;
        }
        id
    }

    /// Send a whole message, retransmitting missing fragments until the peer
    /// acknowledged all of them or `timeout` elapsed.
    pub async fn send_message(&mut self, payload: &[u8], timeout: Duration) -> Result<()> {
        if payload.len() > MAX_MESSAGE {
            bail!(
                "message too large ({} bytes, limit {})",
                payload.len(),
                MAX_MESSAGE
            );
        }
        let frag_count = payload.len().div_ceil(FRAG_PAYLOAD).max(1);
        if frag_count > MAX_FRAGMENTS {
            bail!("message needs too many fragments");
        }
        let msg_id = self.alloc_msg_id();
        let fragments: Vec<&[u8]> = (0..frag_count)
            .map(|index| {
                let start = index * FRAG_PAYLOAD;
                let end = (start + FRAG_PAYLOAD).min(payload.len());
                &payload[start..end]
            })
            .collect();
        let outgoing = Outgoing {
            frag_count: frag_count as u16,
            acked: vec![false; frag_count],
        };
        self.pending_out.insert(msg_id, outgoing);
        let deadline = Instant::now() + timeout;
        let mut rto = Duration::from_millis(250);

        loop {
            let missing: Vec<usize> = {
                let out = self.pending_out.get(&msg_id).context("outgoing state")?;
                out.acked
                    .iter()
                    .enumerate()
                    .filter(|(_, acked)| !**acked)
                    .map(|(index, _)| index)
                    .collect()
            };
            if missing.is_empty() {
                self.pending_out.remove(&msg_id);
                self.stats.messages_sent += 1;
                return Ok(());
            }
            for index in missing {
                if index > 0 {
                    self.stats.fragments_retransmitted += 1;
                }
                self.transmit(msg_id, index as u16, frag_count as u16, fragments[index])
                    .await?;
            }
            let until = (Instant::now() + rto).min(deadline);
            loop {
                let remaining = until.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                if !self.pump(remaining).await? {
                    break;
                }
                let all_acked = self
                    .pending_out
                    .get(&msg_id)
                    .map(|out| out.acked.iter().all(|a| *a))
                    .unwrap_or(true);
                if all_acked {
                    break;
                }
            }
            if Instant::now() >= deadline {
                let unacknowledged = self
                    .pending_out
                    .get(&msg_id)
                    .map(|o| o.acked.iter().filter(|a| !**a).count())
                    .unwrap_or(0);
                self.pending_out.remove(&msg_id);
                bail!(
                    "timed out sending message {msg_id} ({frag_count} fragments, {unacknowledged} unacknowledged)"
                );
            }
            rto = (rto * 3 / 2).min(Duration::from_millis(1500));
        }
    }

    async fn transmit(
        &mut self,
        msg_id: u32,
        index: u16,
        count: u16,
        payload: &[u8],
    ) -> Result<()> {
        let counter = self.send.reserve_counter();
        let header = Header {
            kind: TYPE_DATA,
            session: self.session,
            msg_id,
            frag_index: index,
            frag_count: count,
            counter,
        };
        let aad = header.encode();
        let ciphertext = self.send.seal_with(counter, &aad, payload)?;
        let mut datagram = aad.to_vec();
        datagram.extend_from_slice(&ciphertext);
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += datagram.len() as u64;
        self.send_datagram(&datagram).await
    }

    async fn send_datagram(&self, datagram: &[u8]) -> Result<()> {
        for _ in 0..64 {
            match self.sock.send_to(datagram, self.peer).await {
                Ok(_) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                }
                Err(err) => return Err(err).context("sending datagram"),
            }
        }
        bail!("local UDP send buffer stayed full");
    }

    async fn send_ack(&mut self, msg_id: u32, frag_count: u16, acked: &[bool]) -> Result<()> {
        let mut payload = vec![0u8; ACK_PAYLOAD_LEN];
        payload[0..4].copy_from_slice(&msg_id.to_be_bytes());
        payload[4..6].copy_from_slice(&frag_count.to_be_bytes());
        let mut words = [0u64; ACK_WORDS];
        for (index, present) in acked.iter().enumerate() {
            if *present && index < MAX_FRAGMENTS {
                words[index / 64] |= 1u64 << (index % 64);
            }
        }
        for (position, word) in words.iter().enumerate() {
            let start = 8 + position * 8;
            payload[start..start + 8].copy_from_slice(&word.to_be_bytes());
        }
        let counter = self.send.reserve_counter();
        let header = Header {
            kind: TYPE_ACK,
            session: self.session,
            msg_id,
            frag_index: 0,
            frag_count: 0,
            counter,
        };
        let aad = header.encode();
        let ciphertext = self.send.seal_with(counter, &aad, &payload)?;
        let mut datagram = aad.to_vec();
        datagram.extend_from_slice(&ciphertext);
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += datagram.len() as u64;
        self.send_datagram(&datagram).await
    }

    /// Receive one complete message, waiting at most `timeout`.
    pub async fn recv_message(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        if let Some(message) = self.completed.pop_front() {
            return Ok(message);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("timed out waiting for a message");
            }
            self.pump(remaining).await?;
            if let Some(message) = self.completed.pop_front() {
                return Ok(message);
            }
        }
    }

    /// Process at most one datagram. Returns `false` when the wait expired.
    async fn pump(&mut self, timeout: Duration) -> Result<bool> {
        let packet = match tokio::time::timeout(timeout, self.rx.recv()).await {
            Ok(Some(packet)) => packet,
            Ok(None) => bail!("session receiver closed"),
            Err(_) => return Ok(false),
        };
        self.stats.packets_received += 1;
        self.stats.bytes_received += packet.len() as u64;
        let header = match Header::parse(&packet) {
            Ok(header) => header,
            Err(_) => {
                self.stats.invalid_packets += 1;
                return Ok(true);
            }
        };
        if header.session != self.session {
            self.stats.invalid_packets += 1;
            return Ok(true);
        }
        let (aad, ciphertext) = packet.split_at(HEADER_LEN);
        match header.kind {
            TYPE_ACK => {
                let plaintext = match self.recv.open(header.counter, aad, ciphertext) {
                    Ok(plaintext) => plaintext,
                    Err(_) => {
                        self.stats.invalid_packets += 1;
                        return Ok(true);
                    }
                };
                self.handle_ack(&plaintext);
            }
            TYPE_DATA => {
                let plaintext = match self.recv.open(header.counter, aad, ciphertext) {
                    Ok(plaintext) => plaintext,
                    Err(_) => {
                        self.stats.invalid_packets += 1;
                        return Ok(true);
                    }
                };
                self.handle_fragment(header, plaintext).await?;
            }
            _ => {
                self.stats.invalid_packets += 1;
            }
        }
        Ok(true)
    }

    fn handle_ack(&mut self, payload: &[u8]) {
        if payload.len() < ACK_PAYLOAD_LEN {
            self.stats.invalid_packets += 1;
            return;
        }
        let msg_id = u32::from_be_bytes(payload[0..4].try_into().expect("4 bytes"));
        let frag_count = u16::from_be_bytes(payload[4..6].try_into().expect("2 bytes")) as usize;
        if let Some(outgoing) = self.pending_out.get_mut(&msg_id) {
            if frag_count as u16 != outgoing.frag_count {
                return;
            }
            for index in 0..frag_count.min(MAX_FRAGMENTS) {
                let word = u64::from_be_bytes(
                    payload[8 + (index / 64) * 8..8 + (index / 64) * 8 + 8]
                        .try_into()
                        .expect("8 bytes"),
                );
                if word & (1u64 << (index % 64)) != 0 {
                    outgoing.acked[index] = true;
                }
            }
        }
    }

    async fn handle_fragment(&mut self, header: Header, plaintext: Vec<u8>) -> Result<()> {
        let count = header.frag_count as usize;
        let index = header.frag_index as usize;
        if count == 0 || count > MAX_FRAGMENTS || index >= count {
            self.stats.invalid_packets += 1;
            return Ok(());
        }
        self.reassembly
            .retain(|_, entry| entry.created.elapsed() < Duration::from_secs(30));

        let entry = self
            .reassembly
            .entry(header.msg_id)
            .or_insert_with(|| Reassembly {
                fragments: vec![None; count],
                received: 0,
                created: Instant::now(),
            });
        if entry.fragments.len() != count {
            self.stats.invalid_packets += 1;
            return Ok(());
        }
        if entry.fragments[index].is_none() {
            entry.fragments[index] = Some(plaintext);
            entry.received += 1;
        }
        if entry.received == count {
            let entry = self.reassembly.remove(&header.msg_id).expect("present");
            let mut message = Vec::new();
            let acked: Vec<bool> = entry.fragments.iter().map(|f| f.is_some()).collect();
            for fragment in entry.fragments.into_iter().flatten() {
                message.extend_from_slice(&fragment);
            }
            self.send_ack(header.msg_id, header.frag_count, &acked)
                .await?;
            self.stats.messages_received += 1;
            self.completed.push_back(message);
        } else if let Some(entry) = self.reassembly.get(&header.msg_id) {
            // Partial progress: acknowledge what we have so the sender only
            // retransmits the gaps.
            let acked: Vec<bool> = entry.fragments.iter().map(|f| f.is_some()).collect();
            self.send_ack(header.msg_id, header.frag_count, &acked)
                .await?;
        }
        Ok(())
    }
}

/// Reads datagrams from a socket and forwards the ones belonging to `session`.
pub fn spawn_pump(
    sock: Arc<UdpSocket>,
    session: [u8; 8],
    tx: mpsc::Sender<Vec<u8>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        loop {
            match sock.recv(&mut buffer).await {
                Ok(size) => {
                    let packet = &buffer[..size];
                    if handshake_kind(packet).is_some() {
                        continue;
                    }
                    if let Ok(header) = Header::parse(packet) {
                        if header.session != session {
                            continue;
                        }
                    } else {
                        continue;
                    }
                    if let Err(err) = tx.try_send(packet.to_vec()) {
                        match err {
                            mpsc::error::TrySendError::Closed(_) => break,
                            // Receiver busy: dropping is safe, the peer retransmits.
                            mpsc::error::TrySendError::Full(_) => {}
                        }
                    }
                }
                Err(_) => {
                    // ICMP port unreachable surfaces as an error; keep listening.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{accept_hello, ClientHello, ClusterSecret, MAX_CLOCK_SKEW_SECS};
    use crate::util::now_unix;
    use tokio::sync::mpsc;

    fn keys() -> ([u8; 8], SessionKeys) {
        let secret = ClusterSecret::from_hex(&"22".repeat(32)).unwrap();
        let auth = secret.auth_key();
        let now = now_unix();
        let client = ClientHello::new(now);
        let hello = client.packet(&auth);
        let server = accept_hello(&hello, &auth, now, MAX_CLOCK_SKEW_SECS).unwrap();
        let client_keys = client
            .finish(&server.packet, &auth, now, MAX_CLOCK_SKEW_SECS)
            .unwrap();
        (server.session, client_keys)
    }

    async fn pair() -> (Channel, Channel) {
        let (session, keys) = keys();
        let server_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (server_tx, server_rx) = mpsc::channel(256);
        let (client_tx, client_rx) = mpsc::channel(256);
        let server_pump = spawn_pump(server_sock.clone(), session, server_tx);
        let client_pump = spawn_pump(client_sock.clone(), session, client_tx);
        let client = Channel::new(
            client_sock.clone(),
            server_sock.local_addr().unwrap(),
            session,
            &keys,
            true,
            client_rx,
            Some(client_pump),
        );
        let server = Channel::new(
            server_sock,
            client_sock.local_addr().unwrap(),
            session,
            &keys,
            false,
            server_rx,
            Some(server_pump),
        );
        (client, server)
    }

    #[test]
    fn header_round_trip() {
        let header = Header {
            kind: TYPE_DATA,
            session: [7; 8],
            msg_id: 42,
            frag_index: 3,
            frag_count: 9,
            counter: 1234,
        };
        let encoded = header.encode();
        assert_eq!(Header::parse(&encoded).unwrap(), header);
        assert!(Header::parse(&encoded[..10]).is_err());
    }

    #[tokio::test]
    async fn sends_small_and_large_messages() {
        let (mut client, mut server) = pair().await;
        let (send_result, recv_result) = tokio::join!(
            client.send_message(b"hello", Duration::from_secs(3)),
            server.recv_message(Duration::from_secs(3))
        );
        send_result.unwrap();
        assert_eq!(recv_result.unwrap(), b"hello");

        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (send_result, recv_result) = tokio::join!(
            client.send_message(&payload, Duration::from_secs(10)),
            server.recv_message(Duration::from_secs(10))
        );
        send_result.unwrap();
        let received = recv_result.unwrap();
        assert_eq!(received.len(), payload.len());
        assert_eq!(received, payload);

        let (send_result, recv_result) = tokio::join!(
            client.send_message(b"bye", Duration::from_secs(3)),
            server.recv_message(Duration::from_secs(3))
        );
        send_result.unwrap();
        assert_eq!(recv_result.unwrap(), b"bye");
    }

    #[tokio::test]
    async fn replayed_record_is_dropped() {
        let (session, keys) = keys();
        let mut sender = DirCipher::new(&keys.c2s);
        let header = Header {
            kind: TYPE_DATA,
            session,
            msg_id: 1,
            frag_index: 0,
            frag_count: 1,
            counter: 0,
        };
        let aad = header.encode();
        let (counter, ciphertext) = sender.seal(&aad, b"payload").unwrap();
        let mut receiver = DirCipher::new(&keys.c2s);
        assert!(receiver.open(counter, &aad, &ciphertext).is_ok());
        assert!(receiver.open(counter, &aad, &ciphertext).is_err());
    }
}
