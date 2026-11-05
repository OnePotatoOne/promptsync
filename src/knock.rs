//! Port knocking with a randomised plan, per-source-IP gate and the effective
//! port map (derived from the cluster secret).
//!
//! The server derives a pool of knock ports from the cluster secret. On every
//! attempt the agent picks a random subset of that pool, visits it in a random
//! order and spreads the packets with random delays, so passive observers never
//! see the same pattern twice. Authentication rests on the per-packet HMAC tag
//! (which covers the pool slot, flow id and a fresh timestamp), not on secrecy
//! of the sequence.

use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use crate::config::{AgentConfig, ServerConfig};
use crate::crypto::{parse_knock, ClusterSecret, DerivedPorts, MAX_KNOCK_SKEW_SECS};
use crate::util::{norm_ip, now_unix};

pub const DEFAULT_KNOCK_MIN: usize = 3;
pub const DEFAULT_KNOCK_MAX: usize = 6;
const USED_FLOW_TTL: Duration = Duration::from_secs(900);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ports {
    pub main: u16,
    /// Pool of knock ports; a random subset is used per attempt.
    pub knock_pool: Vec<u16>,
}

impl From<DerivedPorts> for Ports {
    fn from(derived: DerivedPorts) -> Self {
        Self {
            main: derived.main,
            knock_pool: derived.knock,
        }
    }
}

/// Ports actually used: explicit configuration wins, otherwise they are derived
/// from the cluster secret so every machine in the cluster agrees.
pub fn server_ports(config: &ServerConfig, secret: &ClusterSecret) -> Ports {
    let derived = secret.ports();
    let main = if config.port == 0 {
        derived.main
    } else {
        config.port
    };
    let knock_pool = if config.knock_ports.is_empty() {
        derived.knock
    } else {
        config.knock_ports.clone()
    };
    Ports { main, knock_pool }
}

pub fn agent_ports(config: &AgentConfig, secret: &ClusterSecret) -> Ports {
    let derived = secret.ports();
    let main = if config.port == 0 {
        derived.main
    } else {
        config.port
    };
    let knock_pool = if config.knock_ports.is_empty() {
        derived.knock
    } else {
        config.knock_ports.clone()
    };
    Ports { main, knock_pool }
}

#[derive(Debug, Clone)]
pub struct KnockStep {
    /// Index of the port inside the derived pool (authenticated in the tag).
    pub slot: u8,
    pub port: u16,
    /// Delay before sending this packet.
    pub delay: Duration,
}

#[derive(Debug, Clone)]
pub struct KnockPlan {
    pub steps: Vec<KnockStep>,
}

impl KnockPlan {
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Build a random knock plan: random distinct slots, random order, random
/// delays with jitter (the first packet is not sent immediately either).
pub fn random_plan(pool: &[u16], count: usize, base: Duration, jitter: Duration) -> KnockPlan {
    if pool.is_empty() {
        return KnockPlan { steps: Vec::new() };
    }
    let count = count.clamp(1, pool.len().min(16));
    let mut rng = rand::thread_rng();
    let mut slots: Vec<usize> = (0..pool.len()).collect();
    slots.shuffle(&mut rng);
    slots.truncate(count);

    let base_ms = base.as_millis() as u64;
    let jitter_ms = jitter.as_millis().min(2_000) as u64;
    let random_delay = |rng: &mut rand::rngs::ThreadRng, low: u64| -> Duration {
        let span = jitter_ms.saturating_mul(2);
        let value = if span == 0 {
            low
        } else {
            low + rng.gen_range(0..=span)
        };
        Duration::from_millis(value.clamp(5, 5_000))
    };

    let mut steps = Vec::with_capacity(count);
    for (position, slot) in slots.into_iter().enumerate() {
        let delay = if position == 0 {
            // Random initial offset so attempts cannot be fingerprinted by the
            // time between the knock and the handshake.
            random_delay(&mut rng, 0)
        } else {
            random_delay(&mut rng, base_ms.saturating_sub(jitter_ms))
        };
        steps.push(KnockStep {
            slot: slot as u8,
            port: pool[slot],
            delay,
        });
    }
    KnockPlan { steps }
}

/// Random number of knock packets for one attempt, bounded by the pool size.
pub fn random_count(min: usize, max: usize, pool_len: usize) -> usize {
    let upper = max.max(min).min(pool_len).min(16);
    let lower = min.clamp(1, upper.max(1));
    if upper <= lower {
        return upper.max(1).min(pool_len.max(1));
    }
    rand::thread_rng().gen_range(lower..=upper)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnockOutcome {
    /// Invalid tag, stale timestamp, unknown port or malformed packet.
    Rejected,
    /// A valid knock that did not complete the sequence yet.
    Progress { seen: u32, total: u32 },
    /// The sequence completed; the gate is now open for this source IP.
    Complete,
}

struct KnockState {
    total: u8,
    seen: u64,
    first: Instant,
}

/// Tracks knock sequences per (source IP, random flow id).
pub struct KnockTracker {
    key: [u8; 32],
    pool: Vec<u16>,
    window: Duration,
    state: Mutex<HashMap<(IpAddr, [u8; 16]), KnockState>>,
    used_flows: Mutex<HashMap<[u8; 16], Instant>>,
    max_entries: usize,
}

impl KnockTracker {
    pub fn new(pool: Vec<u16>, key: [u8; 32], window: Duration) -> Self {
        Self {
            key,
            pool,
            window: window.max(Duration::from_secs(1)),
            state: Mutex::new(HashMap::new()),
            used_flows: Mutex::new(HashMap::new()),
            max_entries: 4096,
        }
    }

    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }

    pub fn submit(&self, packet: &[u8], source_ip: IpAddr, local_port: u16) -> KnockOutcome {
        let slot = match self.pool.iter().position(|port| *port == local_port) {
            Some(slot) => slot as u8,
            None => return KnockOutcome::Rejected,
        };
        let ip = norm_ip(source_ip);
        let parsed = match parse_knock(packet, &self.key, now_unix(), MAX_KNOCK_SKEW_SECS) {
            Ok(parsed) => parsed,
            Err(_) => return KnockOutcome::Rejected,
        };
        // The tag authenticates the slot; a packet cannot be replayed to another
        // port of the pool.
        if parsed.slot != slot {
            return KnockOutcome::Rejected;
        }
        if parsed.total as usize > self.pool.len() || parsed.total == 0 {
            return KnockOutcome::Rejected;
        }
        if self.is_used(&parsed.rand) {
            return KnockOutcome::Rejected;
        }

        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        state.retain(|_, entry| now.duration_since(entry.first) < self.window);
        if state.len() >= self.max_entries && !state.contains_key(&(ip, parsed.rand)) {
            return KnockOutcome::Rejected;
        }
        let complete = {
            let entry = state
                .entry((ip, parsed.rand))
                .or_insert_with(|| KnockState {
                    total: parsed.total,
                    seen: 0,
                    first: now,
                });
            if entry.total != parsed.total {
                return KnockOutcome::Rejected;
            }
            entry.seen |= 1u64 << slot;
            entry.seen.count_ones() == parsed.total as u32
        };
        if complete {
            state.remove(&(ip, parsed.rand));
            drop(state);
            self.mark_used(parsed.rand);
            KnockOutcome::Complete
        } else {
            let seen = state
                .get(&(ip, parsed.rand))
                .map(|entry| entry.seen.count_ones())
                .unwrap_or(0);
            KnockOutcome::Progress {
                seen,
                total: parsed.total as u32,
            }
        }
    }

    /// A completed flow id is burned for a while: replaying a sniffed sequence
    /// does not open the gate a second time.
    fn is_used(&self, flow: &[u8; 16]) -> bool {
        let now = Instant::now();
        let mut used = match self.used_flows.lock() {
            Ok(used) => used,
            Err(poisoned) => poisoned.into_inner(),
        };
        used.retain(|_, seen| now.duration_since(*seen) < USED_FLOW_TTL);
        used.contains_key(flow)
    }

    fn mark_used(&self, flow: [u8; 16]) {
        let now = Instant::now();
        let mut used = match self.used_flows.lock() {
            Ok(used) => used,
            Err(poisoned) => poisoned.into_inner(),
        };
        used.retain(|_, seen| now.duration_since(*seen) < USED_FLOW_TTL);
        if used.len() < 8192 {
            used.insert(flow, now);
        }
    }

    pub fn prune(&self) {
        if let Ok(mut state) = self.state.lock() {
            let now = Instant::now();
            state.retain(|_, entry| now.duration_since(entry.first) < self.window);
        }
        if let Ok(mut used) = self.used_flows.lock() {
            let now = Instant::now();
            used.retain(|_, seen| now.duration_since(*seen) < USED_FLOW_TTL);
        }
    }
}

/// Userspace allow-list: an IP that completed a knock may talk to the data port
/// for `ttl`. The data port is only bound while at least one entry is alive.
pub struct Gate {
    ttl: Duration,
    inner: Mutex<HashMap<IpAddr, Instant>>,
    notify: Notify,
}

impl Gate {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
            notify: Notify::new(),
        }
    }

    pub fn open(&self, ip: IpAddr) {
        let ip = norm_ip(ip);
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.insert(ip, Instant::now() + self.ttl);
        drop(inner);
        self.notify.notify_waiters();
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = norm_ip(ip);
        let now = Instant::now();
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.retain(|_, until| *until > now);
        inner.contains_key(&ip)
    }

    /// Extend the TTL while an authorised client is actively talking.
    pub fn touch(&self, ip: IpAddr) {
        let ip = norm_ip(ip);
        let now = Instant::now();
        if let Ok(mut inner) = self.inner.lock() {
            inner.retain(|_, until| *until > now);
            if let Some(until) = inner.get_mut(&ip) {
                *until = now + self.ttl;
            }
        }
    }

    pub fn any_active(&self) -> bool {
        let now = Instant::now();
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.retain(|_, until| *until > now);
        !inner.is_empty()
    }

    pub fn prune(&self) {
        let _ = self.any_active();
    }

    pub async fn wait_for_active(&self) {
        loop {
            if self.any_active() {
                return;
            }
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ClusterSecret, KnockSequence};

    fn pool() -> Vec<u16> {
        vec![41001, 41002, 41003, 41004, 41005, 41006]
    }

    #[test]
    fn random_plans_vary() {
        let pool = (0..12).map(|i| 40_000 + i).collect::<Vec<u16>>();
        let mut fingerprints = std::collections::HashSet::new();
        for _ in 0..50 {
            let count = random_count(3, 6, pool.len());
            assert!((3..=6).contains(&count));
            let plan = random_plan(
                &pool,
                count,
                Duration::from_millis(50),
                Duration::from_millis(30),
            );
            assert_eq!(plan.steps.len(), count);
            let slots: Vec<u8> = plan.steps.iter().map(|step| step.slot).collect();
            let unique: std::collections::HashSet<_> = slots.iter().collect();
            assert_eq!(unique.len(), slots.len(), "slots must be distinct");
            for step in &plan.steps {
                assert_eq!(pool[step.slot as usize], step.port);
                assert!(step.delay >= Duration::from_millis(5));
            }
            fingerprints.insert(format!(
                "{}:{:?}",
                count,
                plan.steps.iter().map(|s| s.slot).collect::<Vec<_>>()
            ));
        }
        assert!(fingerprints.len() > 10, "plans should not repeat much");
    }

    #[test]
    fn randomised_subset_completes_the_knock() {
        let secret = ClusterSecret::from_hex(&"33".repeat(32)).unwrap();
        let key = secret.knock_key();
        let pool = pool();
        let tracker = KnockTracker::new(pool.clone(), key, Duration::from_secs(6));
        let plan = random_plan(
            &pool,
            4,
            Duration::from_millis(10),
            Duration::from_millis(10),
        );
        let sequence = KnockSequence::generate(plan.steps.len() as u8);
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let now = now_unix();

        let mut last = KnockOutcome::Rejected;
        for (index, step) in plan.steps.iter().enumerate() {
            let packet = sequence.packet(step.slot, &key, now);
            last = tracker.submit(&packet, ip, step.port);
            if index + 1 < plan.steps.len() {
                assert!(matches!(last, KnockOutcome::Progress { .. }));
            }
        }
        assert_eq!(last, KnockOutcome::Complete);

        // Replaying the same flow never opens the gate twice.
        let replay = sequence.packet(plan.steps[0].slot, &key, now);
        assert_eq!(
            tracker.submit(&replay, ip, plan.steps[0].port),
            KnockOutcome::Rejected
        );
    }

    #[test]
    fn packet_on_the_wrong_port_is_rejected() {
        let secret = ClusterSecret::from_hex(&"33".repeat(32)).unwrap();
        let key = secret.knock_key();
        let pool = pool();
        let tracker = KnockTracker::new(pool.clone(), key, Duration::from_secs(6));
        let sequence = KnockSequence::generate(3);
        let packet = sequence.packet(0, &key, now_unix());
        // Valid tag for slot 0, but delivered on slot 1's port.
        assert_eq!(
            tracker.submit(&packet, "10.0.0.1".parse().unwrap(), pool[1]),
            KnockOutcome::Rejected
        );
        assert_eq!(
            tracker.submit(&packet, "10.0.0.1".parse().unwrap(), 9999),
            KnockOutcome::Rejected
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = ClusterSecret::random().knock_key();
        let other = ClusterSecret::random().knock_key();
        let pool = pool();
        let tracker = KnockTracker::new(pool.clone(), key, Duration::from_secs(6));
        let sequence = KnockSequence::generate(3);
        let packet = sequence.packet(0, &other, now_unix());
        assert_eq!(
            tracker.submit(&packet, "10.0.0.9".parse().unwrap(), pool[0]),
            KnockOutcome::Rejected
        );
        assert!(parse_knock(&packet, &key, now_unix(), MAX_KNOCK_SKEW_SECS).is_err());
    }

    #[test]
    fn gate_tracks_sources_and_expiry() {
        let gate = Gate::new(Duration::from_millis(150));
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        assert!(!gate.allows(ip));
        gate.open(ip);
        assert!(gate.allows(ip));
        assert!(gate.any_active());
        std::thread::sleep(Duration::from_millis(200));
        assert!(!gate.allows(ip));
        assert!(!gate.any_active());
    }

    #[test]
    fn ports_follow_the_secret_unless_overridden() {
        let secret = ClusterSecret::from_hex(&"44".repeat(32)).unwrap();
        let mut server = ServerConfig::default();
        let derived = secret.ports();
        let ports = server_ports(&server, &secret);
        assert_eq!(ports.main, derived.main);
        assert_eq!(ports.knock_pool, derived.knock);

        server.port = 12345;
        server.knock_ports = vec![1, 2, 3];
        let ports = server_ports(&server, &secret);
        assert_eq!(ports.main, 12345);
        assert_eq!(ports.knock_pool, vec![1, 2, 3]);
    }
}
