use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::Result;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::{OsRng, RngCore as _};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::probe::{ProbeError, ProbeOutcome, Transport};
use crate::ranges::CidrPool;

pub const BUNDLED_POOLS: &str = include_str!("../data/warp-pools.txt");

pub const SERVER_PUBLIC_KEY_B64: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

const DUMMY_STATIC_PRIVATE: [u8; 32] = [0u8; 32];

pub fn server_public_key() -> anyhow::Result<PublicKey> {
    fn bundled() -> anyhow::Result<PublicKey> {
        let bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            SERVER_PUBLIC_KEY_B64,
        )
        .map_err(|e| anyhow::anyhow!("bundled WARP server key must decode: {e}"))?;
        let arr = <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("bundled WARP server key must be 32 bytes"))?;
        Ok(PublicKey::from(arr))
    }
    let Some(b64) = crate::warpgen::persisted_server_public_key() else {
        return bundled();
    };
    let decoded = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                "failed to decode persisted WARP server public key: {e}; falling back to bundled key"
            );
            return bundled();
        }
    };
    match <[u8; 32]>::try_from(decoded.as_slice()) {
        Ok(arr) => Ok(PublicKey::from(arr)),
        Err(_) => {
            tracing::warn!(
                "persisted WARP server public key is not 32 bytes; falling back to bundled key"
            );
            bundled()
        }
    }
}

pub fn bundled_pool() -> CidrPool {
    CidrPool::parse(BUNDLED_POOLS).expect("bundled WARP pools must parse")
}

/// Primary WARP UDP ports the opt-in port gate probes first
/// (warpscout `primaryWarpPorts`, also BPB's most-hit ports).
pub const PRIMARY_WARP_PORTS: &[u16] = &[2408, 500, 1701, 4500];

/// Extended escalation list: BPB-Warp-Scanner's full 54-port set minus the
/// four primaries above (the same pool warpscout sweeps as
/// `extendedWarpPorts`). Probed only when no primary answers at all.
pub const EXTENDED_WARP_PORTS: &[u16] = &[
    854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
    987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581,
    3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
];

/// Gate sample size: sampled pool addresses probed per port tier.
pub const PORT_GATE_SAMPLE: usize = 12;

/// DPI-noise profile for WARP discovery (AmneziaWG Jc/Jmin/Jmax semantics).
///
/// Junk is plain UDP datagrams sent AROUND the handshake Init — half before,
/// half after — never inside it and never mutating it, so the plain-WG CF
/// edge (which drops unknown packets) still answers the Init. Junk sends go
/// through `send_bounded` so the per-call timeout rule holds, and they are
/// not probes: loss accounting never sees them (Working stays open + zero
/// loss per glossary).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JunkConfig {
    /// Junk datagrams per handshake probe. 0 = off (default).
    pub count: u8,
    /// Min junk datagram size in bytes.
    pub min: u16,
    /// Max junk datagram size in bytes.
    pub max: u16,
}

impl JunkConfig {
    pub const OFF: Self = Self {
        count: 0,
        min: 0,
        max: 0,
    };

    pub fn is_off(self) -> bool {
        self.count == 0 || self.max == 0
    }

    /// Future engine wiring: WarpConfig knobs travel to the transport
    /// constructor, leaving per-worker channels and cancel races untouched.
    pub fn from_warp_config(warp: &crate::api::types::WarpConfig) -> Self {
        Self {
            count: warp.junk_count,
            min: warp.junk_min,
            max: warp.junk_max,
        }
    }
}

pub struct WarpTransport {
    server_public: PublicKey,
    sockets: std::sync::Arc<SocketCache>,
    junk: JunkConfig,
}

impl WarpTransport {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            server_public: server_public_key()?,
            sockets: std::sync::Arc::new(SocketCache::default()),
            junk: JunkConfig::OFF,
        })
    }

    pub async fn with_cache(cache: std::sync::Arc<SocketCache>) -> anyhow::Result<Self> {
        cache.clear().await;
        Ok(Self {
            server_public: server_public_key()?,
            sockets: cache,
            junk: JunkConfig::OFF,
        })
    }

    pub fn with_junk(junk: JunkConfig) -> anyhow::Result<Self> {
        Ok(Self {
            server_public: server_public_key()?,
            sockets: std::sync::Arc::new(SocketCache::default()),
            junk,
        })
    }

    pub async fn with_cache_and_junk(
        cache: std::sync::Arc<SocketCache>,
        junk: JunkConfig,
    ) -> anyhow::Result<Self> {
        cache.clear().await;
        Ok(Self {
            server_public: server_public_key()?,
            sockets: cache,
            junk,
        })
    }

    pub(crate) fn from_cache(cache: std::sync::Arc<SocketCache>) -> anyhow::Result<Self> {
        Ok(Self {
            server_public: server_public_key()?,
            sockets: cache,
            junk: JunkConfig::OFF,
        })
    }
}

impl Default for WarpTransport {
    fn default() -> Self {
        Self::new().expect("WARP server key must decode")
    }
}

const MAX_SOCKETS: usize = 1024;

#[derive(Default)]
pub struct SocketCache {
    sockets: tokio::sync::Mutex<HashMap<(Ipv4Addr, u16), Arc<UdpSocket>>>,
}

impl SocketCache {
    pub(crate) async fn clear(&self) {
        self.sockets.lock().await.clear();
    }

    async fn get_or_bind(&self, ip: Ipv4Addr, port: u16) -> Result<Arc<UdpSocket>, ProbeError> {
        {
            let map = self.sockets.lock().await;
            if let Some(socket) = map.get(&(ip, port)) {
                return Ok(socket.clone());
            }
        }
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|_| ProbeError::Refused("udp bind failed"))?;
        socket
            .connect((ip, port))
            .await
            .map_err(|_| ProbeError::Refused("udp connect failed"))?;
        let socket = Arc::new(socket);
        let mut map = self.sockets.lock().await;
        if let Some(existing) = map.get(&(ip, port)) {
            return Ok(existing.clone());
        }
        if map.len() >= MAX_SOCKETS
            && let Some(victim) = map.keys().next().copied()
        {
            map.remove(&victim);
        }
        map.insert((ip, port), socket.clone());
        Ok(socket)
    }
}

pub struct WgVerifyTransport {
    static_secret: StaticSecret,
    peer_public: PublicKey,
    sockets: Arc<SocketCache>,
    amnezia: crate::wgconf::AmneziaParams,
}

impl WgVerifyTransport {
    pub fn from_config(wg: &crate::wgconf::WgConfig) -> Result<Self> {
        Ok(Self {
            static_secret: StaticSecret::from(crate::wgconf::decode_key(&wg.private_key)?),
            peer_public: PublicKey::from(crate::wgconf::decode_key(&wg.peer.public_key)?),
            sockets: Arc::new(SocketCache::default()),
            amnezia: wg.amnezia.clone(),
        })
    }

    pub async fn with_cache(cache: Arc<SocketCache>, wg: &crate::wgconf::WgConfig) -> Result<Self> {
        cache.clear().await;
        Ok(Self {
            static_secret: StaticSecret::from(crate::wgconf::decode_key(&wg.private_key)?),
            peer_public: PublicKey::from(crate::wgconf::decode_key(&wg.peer.public_key)?),
            sockets: cache,
            amnezia: wg.amnezia.clone(),
        })
    }
}

impl Transport for WgVerifyTransport {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_ms: u64,
        _idle_hold_ms: u64,
    ) -> crate::probe::ProbeFuture<'_> {
        let IpAddr::V4(ip) = ip else {
            return Box::pin(
                async move { Err(ProbeError::Refused("WARP endpoints are IPv4-only")) },
            );
        };
        let static_secret = StaticSecret::from(self.static_secret.to_bytes());
        let peer_public = self.peer_public;
        let amnezia = self.amnezia.clone();
        Box::pin(async move {
            probe_once(
                &self.sockets,
                static_secret,
                peer_public,
                ip,
                port,
                timeout_ms,
                ProbeDepth::FullSession,
                JunkConfig::OFF,
                Some(&amnezia),
            )
            .await
            .map(ProbeOutcome::plain)
        })
    }
}

impl Transport for WarpTransport {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_ms: u64,
        _idle_hold_ms: u64,
    ) -> crate::probe::ProbeFuture<'_> {
        let IpAddr::V4(ip) = ip else {
            return Box::pin(
                async move { Err(ProbeError::Refused("WARP endpoints are IPv4-only")) },
            );
        };
        let server_public = self.server_public;
        let sockets = self.sockets.clone();
        let junk = self.junk;
        Box::pin(async move {
            probe_once(
                &sockets,
                StaticSecret::from(DUMMY_STATIC_PRIVATE),
                server_public,
                ip,
                port,
                timeout_ms,
                ProbeDepth::ShapeOnly,
                junk,
                None,
            )
            .await
            .map(ProbeOutcome::plain)
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeDepth {
    ShapeOnly,
    FullSession,
}

async fn send_bounded(socket: &UdpSocket, pkt: &[u8], timeout_ms: u64) -> Result<(), ProbeError> {
    timeout(Duration::from_millis(timeout_ms), socket.send(pkt))
        .await
        .map_err(|_| ProbeError::Timeout { timeout_ms })?
        .map_err(|_| ProbeError::Refused("udp send failed"))?;
    Ok(())
}

async fn send_junk(
    socket: &UdpSocket,
    junk: JunkConfig,
    count: usize,
    timeout_ms: u64,
) -> Result<(), ProbeError> {
    if junk.is_off() || count == 0 {
        return Ok(());
    }
    let (mut lo, mut hi) = (junk.min as usize, junk.max as usize);
    if lo > hi {
        std::mem::swap(&mut lo, &mut hi);
    }
    if hi == 0 {
        return Ok(());
    }
    let lo = lo.max(1);
    for _ in 0..count {
        let span = hi - lo;
        let len = if span == 0 {
            lo
        } else {
            lo + (OsRng.next_u32() as usize % (span + 1))
        };
        let mut buf = vec![0u8; len];
        OsRng.fill_bytes(&mut buf);
        send_bounded(socket, &buf, timeout_ms).await?;
    }
    Ok(())
}

const WG_INIT_TYPE: u32 = 1;
const WG_RESPONSE_TYPE: u32 = 2;
const WG_COOKIE_TYPE: u32 = 3;
const WG_DATA_TYPE: u32 = 4;
const WG_RESPONSE_SZ: usize = 92;
const WG_COOKIE_SZ: usize = 64;

fn magic_of(h: Option<u8>, vanilla: u32) -> u32 {
    h.map_or(vanilla, u32::from)
}

/// WHY: identity params (all None, or H equal to the vanilla message type
/// with zero S padding) take the vanilla fast path, keeping the defaults-off
/// wire bytes identical to today.
fn hs_is_vanilla(p: &crate::wgconf::AmneziaParams) -> bool {
    matches!(p.h1, None | Some(1))
        && matches!(p.h2, None | Some(2))
        && matches!(p.h3, None | Some(3))
        && matches!(p.h4, None | Some(4))
        && matches!(p.s1, None | Some(0))
        && matches!(p.s2, None | Some(0))
}

/// WHY: an AWG gateway replaces the Initiation message type with the H1
/// magic and expects S1 random padding after it. boringtun generates the
/// vanilla first packet; the transport translates at the datagram layer.
fn obfuscate_init(init: &[u8], p: &crate::wgconf::AmneziaParams) -> Vec<u8> {
    let mut out = init.to_vec();
    if out.len() >= 4 {
        out[0..4].copy_from_slice(&magic_of(p.h1, WG_INIT_TYPE).to_le_bytes());
    }
    let pad = p.s1.unwrap_or(0) as usize;
    if pad > 0 {
        let mut extra = vec![0u8; pad];
        OsRng.fill_bytes(&mut extra);
        out.extend_from_slice(&extra);
    }
    out
}

fn deobfuscate_response(packet: &[u8], p: &crate::wgconf::AmneziaParams) -> Option<Vec<u8>> {
    if packet.len() != WG_RESPONSE_SZ + p.s2.unwrap_or(0) as usize {
        return None;
    }
    if u32::from_le_bytes(packet[0..4].try_into().ok()?) != magic_of(p.h2, WG_RESPONSE_TYPE) {
        return None;
    }
    let mut out = packet[..WG_RESPONSE_SZ].to_vec();
    out[0..4].copy_from_slice(&WG_RESPONSE_TYPE.to_le_bytes());
    Some(out)
}

fn deobfuscate_cookie(packet: &[u8], p: &crate::wgconf::AmneziaParams) -> Option<Vec<u8>> {
    if packet.len() != WG_COOKIE_SZ {
        return None;
    }
    if u32::from_le_bytes(packet[0..4].try_into().ok()?) != magic_of(p.h3, WG_COOKIE_TYPE) {
        return None;
    }
    let mut out = packet.to_vec();
    out[0..4].copy_from_slice(&WG_COOKIE_TYPE.to_le_bytes());
    Some(out)
}

/// WHY: AWG transport-data packets carry the H4 magic instead of type 4;
/// there is no data padding in our param set, so this is a header swap only.
fn obfuscate_data_out(pkt: &[u8], p: &crate::wgconf::AmneziaParams) -> Vec<u8> {
    let mut out = pkt.to_vec();
    if let Some(h) = p.h4
        && out.len() >= 4
    {
        out[0..4].copy_from_slice(&u32::from(h).to_le_bytes());
    }
    out
}

fn deobfuscate_data(packet: &[u8], p: &crate::wgconf::AmneziaParams) -> Option<Vec<u8>> {
    if packet.len() < 4 {
        return None;
    }
    if u32::from_le_bytes(packet[0..4].try_into().ok()?) != magic_of(p.h4, WG_DATA_TYPE) {
        return None;
    }
    let mut out = packet.to_vec();
    out[0..4].copy_from_slice(&WG_DATA_TYPE.to_le_bytes());
    Some(out)
}

async fn send_obfuscated(
    socket: &UdpSocket,
    pkt: &[u8],
    timeout_ms: u64,
    amnezia: Option<&crate::wgconf::AmneziaParams>,
) -> Result<(), ProbeError> {
    match amnezia {
        Some(p) => {
            let owned = obfuscate_data_out(pkt, p);
            send_bounded(socket, &owned, timeout_ms).await
        }
        None => send_bounded(socket, pkt, timeout_ms).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn probe_once(
    sockets: &SocketCache,
    static_secret: StaticSecret,
    peer_public: PublicKey,
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
    depth: ProbeDepth,
    junk: JunkConfig,
    amnezia: Option<&crate::wgconf::AmneziaParams>,
) -> Result<u32, ProbeError> {
    let jitter_ms = 10 + OsRng.next_u32() % 31;
    tokio::time::sleep(Duration::from_millis(jitter_ms as u64)).await;

    let index = {
        let v = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
        if v == 0 {
            NEXT_INDEX.fetch_add(1, Ordering::Relaxed)
        } else {
            v
        }
    };
    let mut tunn = Tunn::new(static_secret, peer_public, None, None, index, None);
    let mut packet = [0u8; 148];
    let init = match tunn.format_handshake_initiation(&mut packet, true) {
        TunnResult::WriteToNetwork(init) => init.to_vec(),
        TunnResult::Err(_) => return Err(ProbeError::Refused("handshake init failed")),
        _ => return Err(ProbeError::Refused("unexpected handshake result")),
    };
    let socket = sockets.get_or_bind(ip, port).await?;
    let started = std::time::Instant::now();
    let before = junk.count as usize / 2;
    let after = junk.count as usize - before;
    send_junk(&socket, junk, before, timeout_ms).await?;
    match amnezia {
        Some(p) if !hs_is_vanilla(p) => {
            let owned = obfuscate_init(&init, p);
            send_bounded(&socket, &owned, timeout_ms).await?;
        }
        _ => send_bounded(&socket, &init, timeout_ms).await?,
    }
    send_junk(&socket, junk, after, timeout_ms).await?;

    let mut reply = [0u8; 2048];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut reply)).await {
        Ok(Ok(n)) => {
            let raw = &reply[..n];
            match amnezia {
                Some(p) if !hs_is_vanilla(p) => {
                    let Some(open) =
                        deobfuscate_response(raw, p).or_else(|| deobfuscate_cookie(raw, p))
                    else {
                        tracing::debug!(len = n, "non-handshake WARP reply under AWG params");
                        return Err(ProbeError::Refused("reply is not a WARP handshake"));
                    };
                    if depth == ProbeDepth::ShapeOnly {
                        return Ok((started.elapsed().as_millis().min(u32::MAX as u128)) as u32);
                    }
                    finish_full_session(&mut tunn, &socket, &open, started, timeout_ms, Some(p))
                        .await
                }
                _ => {
                    if !classify(raw) {
                        let head = &raw[..n.min(8)];
                        tracing::debug!(
                            len = n,
                            wg_type = head
                                .first_chunk::<4>()
                                .map(|b| u32::from_le_bytes(*b))
                                .unwrap_or(0),
                            recv_index = head
                                .get(4..8)
                                .map(|b| u32::from_le_bytes(b.try_into().unwrap())),
                            "non-handshake WARP reply"
                        );
                        return Err(ProbeError::Refused("reply is not a WARP handshake"));
                    }
                    if depth == ProbeDepth::ShapeOnly {
                        return Ok((started.elapsed().as_millis().min(u32::MAX as u128)) as u32);
                    }
                    finish_full_session(&mut tunn, &socket, raw, started, timeout_ms, None).await
                }
            }
        }
        Ok(Err(_)) => Err(ProbeError::Refused("udp receive failed")),
        Err(_) => Err(ProbeError::Timeout { timeout_ms }),
    }
}

async fn finish_full_session(
    tunn: &mut Tunn,
    socket: &UdpSocket,
    response: &[u8],
    started: std::time::Instant,
    timeout_ms: u64,
    amnezia: Option<&crate::wgconf::AmneziaParams>,
) -> Result<u32, ProbeError> {
    let mut out = [0u8; 2048];
    match tunn.decapsulate(None, response, &mut out) {
        TunnResult::Done => {}
        TunnResult::WriteToNetwork(keepalive) => {
            send_obfuscated(socket, keepalive, timeout_ms, amnezia).await?;
        }
        TunnResult::Err(_) => {
            return Err(ProbeError::Refused("handshake rejected under this keypair"));
        }
        _ => return Err(ProbeError::Refused("unexpected handshake result")),
    }

    let query = build_dns_probe_packet();
    let mut wire = [0u8; 2048];
    let data = match tunn.encapsulate(&query, &mut wire) {
        TunnResult::WriteToNetwork(pkt) => pkt,
        TunnResult::Err(_) => return Err(ProbeError::Refused("session not ready for data")),
        _ => return Err(ProbeError::Refused("unexpected encapsulate result")),
    };
    send_obfuscated(socket, data, timeout_ms, amnezia).await?;

    let mut reply = [0u8; 2048];
    let elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let rem = timeout_ms.saturating_sub(elapsed_ms).max(1);
    let received = timeout(Duration::from_millis(rem), socket.recv(&mut reply)).await;
    match received {
        Ok(Ok(n)) => {
            let owned;
            // WHY the torn_down tag: this is the wgconf full-session stage of the
            // same mid-stream-death concept the probe stage stores as
            // fail_reason="torn_down" (decision 02/Q4 — one grep-able token for
            // "handshake OK, data path dead" across probe/phase-2/wgconf stages;
            // wording only, no state change here).
            let inbound: &[u8] = match amnezia {
                Some(p) => match deobfuscate_data(&reply[..n], p) {
                    Some(v) => {
                        owned = v;
                        &owned
                    }
                    None => {
                        return Err(ProbeError::Refused("torn_down: tunnel rejected data reply"));
                    }
                },
                None => &reply[..n],
            };
            match tunn.decapsulate(None, inbound, &mut out) {
                TunnResult::WriteToTunnelV4(inner, _) | TunnResult::WriteToTunnelV6(inner, _) => {
                    if inner.is_empty() {
                        Err(ProbeError::Refused(
                            "torn_down: empty data reply through tunnel",
                        ))
                    } else {
                        Ok((started.elapsed().as_millis().min(u32::MAX as u128)) as u32)
                    }
                }
                TunnResult::WriteToNetwork(_) => {
                    Err(ProbeError::Refused("no data reply through tunnel"))
                }
                TunnResult::Done | TunnResult::Err(_) => {
                    Err(ProbeError::Refused("torn_down: tunnel rejected data reply"))
                }
            }
        }
        Ok(Err(_)) => Err(ProbeError::Refused("udp receive failed")),
        Err(_) => Err(ProbeError::Timeout { timeout_ms }),
    }
}

fn build_dns_probe_packet() -> Vec<u8> {
    const SRC: [u8; 4] = [172, 16, 0, 2];
    const DST: [u8; 4] = [1, 1, 1, 1];

    let mut dns = Vec::with_capacity(32);
    dns.extend_from_slice(&[0x1a, 0x2b]);
    dns.extend_from_slice(&[0x01, 0x00]);
    dns.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    dns.extend_from_slice(&[10]);
    dns.extend_from_slice(b"cloudflare");
    dns.extend_from_slice(&[3]);
    dns.extend_from_slice(b"com");
    dns.push(0);
    dns.extend_from_slice(&[0, 1, 0, 1]);

    let mut udp = Vec::with_capacity(8 + dns.len());
    udp.extend_from_slice(&[0x9d, 0x34]);
    udp.extend_from_slice(&[0, 53]);
    udp.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&dns);

    let total = 20 + udp.len();
    let mut ip = Vec::with_capacity(total);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0x40, 0x00]);
    ip.extend_from_slice(&[64, 17]);
    ip.extend_from_slice(&[0, 0]);
    ip.extend_from_slice(&SRC);
    ip.extend_from_slice(&DST);
    let sum = ones_complement_sum16(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip.extend_from_slice(&udp);
    ip
}

fn ones_complement_sum16(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let word = match pair {
            [hi, lo] => u16::from_be_bytes([*hi, *lo]),
            [hi] => u16::from_be_bytes([*hi, 0]),
            _ => unreachable!("chunks(2) yields 1 or 2 bytes"),
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

static NEXT_INDEX: AtomicU32 = AtomicU32::new(1);

fn classify(packet: &[u8]) -> bool {
    matches!(
        Tunn::parse_incoming_packet(packet),
        Ok(boringtun::noise::Packet::HandshakeResponse(_))
            | Ok(boringtun::noise::Packet::PacketCookieReply(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_public_key_is_32_bytes() {
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            SERVER_PUBLIC_KEY_B64,
        )
        .unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn persisted_server_key_overrides_the_bundled_constant() {
        let _guard = crate::warpgen::tests::IDENTITY_LOCK.lock().unwrap();
        // WHY: this test writes CF_SCANNER_DATA_DIR; every data-dir writer must
        // hold DATA_DIR_LOCK or concurrent seam assertions (verify/paths) flake.
        let _data_dir_lock = crate::paths::test_env::DATA_DIR_LOCK.blocking_lock();
        let dir = std::env::temp_dir().join("cf-scanner-warp-key-test");
        unsafe { std::env::set_var("CF_SCANNER_DATA_DIR", &dir) };
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 32]);
        let identity = format!(
            r#"{{"id":"t","token":"t","private_key":"{}","client_id":"c","account_type":"free","license":null,"created_at":0,"peer_public_key":"{key_b64}"}}"#,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1u8; 32])
        );
        std::fs::write(dir.join("identity.json"), identity).unwrap();
        assert_eq!(server_public_key().unwrap().to_bytes(), [7u8; 32]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_persisted_server_key_falls_back_to_bundled() {
        let _guard = crate::warpgen::tests::IDENTITY_LOCK.lock().unwrap();
        // WHY: this test writes CF_SCANNER_DATA_DIR; every data-dir writer must
        // hold DATA_DIR_LOCK or concurrent seam assertions (verify/paths) flake.
        let _data_dir_lock = crate::paths::test_env::DATA_DIR_LOCK.blocking_lock();
        let dir = std::env::temp_dir().join("cf-scanner-warp-key-corrupt-test");
        unsafe { std::env::set_var("CF_SCANNER_DATA_DIR", &dir) };
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let identity = format!(
            r#"{{"id":"t","token":"t","private_key":"{}","client_id":"c","account_type":"free","license":null,"created_at":0,"peer_public_key":"not base64 at all"}}"#,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1u8; 32])
        );
        std::fs::write(dir.join("identity.json"), identity).unwrap();
        let bundled = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            SERVER_PUBLIC_KEY_B64,
        )
        .unwrap();
        assert_eq!(
            server_public_key().unwrap().to_bytes(),
            <[u8; 32]>::try_from(bundled.as_slice()).unwrap(),
            "a corrupt persisted key must fall back to the bundled constant, not error"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gate_port_lists_cover_primary_plus_fifty() {
        use super::{EXTENDED_WARP_PORTS, PRIMARY_WARP_PORTS};
        assert_eq!(PRIMARY_WARP_PORTS, &[2408, 500, 1701, 4500]);
        assert_eq!(EXTENDED_WARP_PORTS.len(), 50);
        let mut all = PRIMARY_WARP_PORTS.to_vec();
        all.extend_from_slice(EXTENDED_WARP_PORTS);
        assert!(
            all.iter().all(|&p| p > 0),
            "port lists must hold valid ports"
        );
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 54, "primary + extended must be disjoint");
    }

    #[test]
    fn bundled_pools_cover_the_known_endpoint_space() {
        let pool = bundled_pool();
        assert_eq!(pool.host_count(), 15 * 256);
    }

    #[test]
    fn classify_accepts_response_and_cookie() {
        let mut resp = vec![0u8; 92];
        resp[0..4].copy_from_slice(&2u32.to_le_bytes());
        resp[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert!(classify(&resp));

        let mut cookie = vec![0u8; 64];
        cookie[0..4].copy_from_slice(&3u32.to_le_bytes());
        cookie[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert!(classify(&cookie));
    }

    #[test]
    fn classify_accepts_any_receiver_index_like_real_warp() {
        let mut resp = vec![0u8; 92];
        resp[0..4].copy_from_slice(&2u32.to_le_bytes());
        resp[4..8].copy_from_slice(&9_582_336u32.to_le_bytes());
        assert!(classify(&resp));
    }

    #[test]
    fn classify_rejects_garbage_and_other_types() {
        let mut init = vec![0u8; 148];
        init[0..4].copy_from_slice(&1u32.to_le_bytes());
        init[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert!(!classify(&init), "an Init from the peer is not open");

        assert!(!classify(&[0u8; 4]), "too short");
        assert!(!classify(&[0xff; 92]), "unknown type");
    }

    #[tokio::test]
    async fn handshake_init_is_a_148_byte_type_1_message() {
        let mut tunn = Tunn::new(
            StaticSecret::from(DUMMY_STATIC_PRIVATE),
            server_public_key().unwrap(),
            None,
            None,
            1,
            None,
        );
        let mut packet = [0u8; 148];
        match tunn.format_handshake_initiation(&mut packet, true) {
            TunnResult::WriteToNetwork(init) => {
                assert_eq!(init.len(), 148);
                assert_eq!(u32::from_le_bytes(init[0..4].try_into().unwrap()), 1);
            }
            other => panic!("expected a ready init, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn probe_opens_when_a_response_comes_back() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 148, "server must receive a full Init");
            let mut resp = [0u8; 92];
            resp[0..4].copy_from_slice(&2u32.to_le_bytes());
            resp[4..8].copy_from_slice(&buf[4..8]);
            server.send_to(&resp, peer).await.unwrap();
        });
        let lat = WarpTransport::new()
            .unwrap()
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000, 0)
            .await
            .unwrap()
            .latency_ms;
        assert!(lat < 2000);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn probe_times_out_on_a_silent_endpoint() {
        let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = silent.local_addr().unwrap();
        let err = WarpTransport::new()
            .unwrap()
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 200, 0)
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::Timeout { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn wg_verify_transport_completes_a_real_handshake_with_a_peer() {
        use rand_core::OsRng;

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        let wg = crate::wgconf::WgConfig {
            private_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                client_secret.to_bytes(),
            ),
            address: "172.16.0.2/32".to_owned(),
            dns: None,
            mtu: None,
            amnezia: Default::default(),
            reserved: None,
            peer: crate::wgconf::WgPeer {
                public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    server_public.as_bytes(),
                ),
                preshared_key: None,
                allowed_ips: vec![],
                endpoint: None,
                persistent_keepalive: None,
            },
        };
        let transport = WgVerifyTransport::from_config(&wg).unwrap();

        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server_socket.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut tunn = Tunn::new(server_secret, client_public, None, None, 99, None);
            let mut buf = [0u8; 2048];
            let mut out = [0u8; 2048];
            loop {
                let (n, peer) = server_socket.recv_from(&mut buf).await.unwrap();
                match Tunn::parse_incoming_packet(&buf[..n]) {
                    Ok(boringtun::noise::Packet::HandshakeInit(_)) => {
                        match tunn.decapsulate(None, &buf[..n], &mut out) {
                            TunnResult::WriteToNetwork(resp) => {
                                server_socket.send_to(resp, peer).await.unwrap();
                            }
                            other => panic!("responder could not answer an Init: {other:?}"),
                        }
                    }
                    Ok(_) => match tunn.decapsulate(None, &buf[..n], &mut out) {
                        TunnResult::WriteToTunnelV4(inner, _) => {
                            let mut wire = [0u8; 2048];
                            match tunn.encapsulate(inner, &mut wire) {
                                TunnResult::WriteToNetwork(reply) => {
                                    server_socket.send_to(reply, peer).await.unwrap();
                                }
                                other => {
                                    panic!("responder could not encapsulate data: {other:?}")
                                }
                            }
                        }
                        TunnResult::Done | TunnResult::WriteToNetwork(_) => continue,
                        other => panic!("responder rejected a data packet: {other:?}"),
                    },
                    Err(e) => panic!("responder rejected the packet: {e:?}"),
                }
            }
        });

        let lat = transport
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000, 0)
            .await
            .unwrap()
            .latency_ms;
        assert!(lat < 2000);
        responder.abort();
    }

    #[tokio::test]
    async fn full_session_probe_fails_when_data_is_dropped() {
        use rand_core::OsRng;

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        let wg = crate::wgconf::WgConfig {
            private_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                client_secret.to_bytes(),
            ),
            address: "172.16.0.2/32".to_owned(),
            dns: None,
            mtu: None,
            amnezia: Default::default(),
            reserved: None,
            peer: crate::wgconf::WgPeer {
                public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    server_public.as_bytes(),
                ),
                preshared_key: None,
                allowed_ips: vec![],
                endpoint: None,
                persistent_keepalive: None,
            },
        };
        let transport = WgVerifyTransport::from_config(&wg).unwrap();

        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server_socket.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut tunn = Tunn::new(server_secret, client_public, None, None, 99, None);
            let mut buf = [0u8; 2048];
            let mut out = [0u8; 2048];
            loop {
                let (n, peer) = server_socket.recv_from(&mut buf).await.unwrap();
                if matches!(
                    Tunn::parse_incoming_packet(&buf[..n]),
                    Ok(boringtun::noise::Packet::HandshakeInit(_))
                ) && let TunnResult::WriteToNetwork(resp) =
                    tunn.decapsulate(None, &buf[..n], &mut out)
                {
                    server_socket.send_to(resp, peer).await.unwrap();
                }
            }
        });

        let err = transport
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 400, 0)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProbeError::Timeout { .. } | ProbeError::Refused(_)),
            "dropped data must fail verification, got {err:?}"
        );
        responder.abort();
    }

    #[tokio::test]
    async fn socket_cache_reuses_and_evicts() {
        let cache = SocketCache::default();
        let s1 = cache.get_or_bind(Ipv4Addr::LOCALHOST, 12000).await.unwrap();
        let s2 = cache.get_or_bind(Ipv4Addr::LOCALHOST, 12000).await.unwrap();
        assert!(
            Arc::ptr_eq(&s1, &s2),
            "same endpoint must reuse the cached socket"
        );
        for i in 0..(MAX_SOCKETS + 5) {
            let ip = Ipv4Addr::from(0x0a000001u32.wrapping_add(i as u32));
            let port = 20000 + (i as u16 % 500);
            let _ = cache.get_or_bind(ip, port).await.unwrap();
        }
        let len = cache.sockets.lock().await.len();
        assert!(len <= MAX_SOCKETS, "cache must stay bounded, got {len}");
        let s = cache
            .get_or_bind(Ipv4Addr::new(8, 8, 8, 8), 5353)
            .await
            .unwrap();
        assert!(s.local_addr().is_ok());
        let s3 = cache.get_or_bind(Ipv4Addr::LOCALHOST, 12000).await.unwrap();
        assert!(s3.local_addr().is_ok());
    }

    #[test]
    fn junk_config_defaults_to_off() {
        assert_eq!(JunkConfig::OFF, JunkConfig::default());
        assert!(JunkConfig::OFF.is_off());
        let warp = crate::api::types::WarpConfig::default();
        assert_eq!((warp.junk_count, warp.junk_min, warp.junk_max), (0, 0, 0));
        assert_eq!(JunkConfig::from_warp_config(&warp), JunkConfig::OFF);
    }

    #[test]
    fn junk_config_carries_warp_config_knobs_to_the_transport() {
        let warp = crate::api::types::WarpConfig {
            junk_count: 32,
            junk_min: 10,
            junk_max: 50,
            ..Default::default()
        };
        let junk = JunkConfig::from_warp_config(&warp);
        assert_eq!((junk.count, junk.min, junk.max), (32, 10, 50));
        assert!(!junk.is_off(), "run_warp must build a live junk profile");
    }

    #[test]
    fn hs_transforms_round_trip_and_reject_mismatches() {
        use crate::wgconf::AmneziaParams;

        let params = AmneziaParams {
            s1: Some(16),
            s2: Some(24),
            h1: Some(5),
            h2: Some(6),
            h3: Some(7),
            h4: Some(8),
            ..Default::default()
        };
        assert!(!hs_is_vanilla(&params));
        assert!(hs_is_vanilla(&AmneziaParams::default()));
        let identity = AmneziaParams {
            s1: Some(0),
            s2: Some(0),
            h1: Some(1),
            h2: Some(2),
            h3: Some(3),
            h4: Some(4),
            ..Default::default()
        };
        assert!(
            hs_is_vanilla(&identity),
            "H1..H4 = 1..4 with zero padding is the vanilla-compatible shape"
        );

        let mut tunn = Tunn::new(
            StaticSecret::from(DUMMY_STATIC_PRIVATE),
            server_public_key().unwrap(),
            None,
            None,
            1,
            None,
        );
        let mut packet = [0u8; 148];
        let init = match tunn.format_handshake_initiation(&mut packet, true) {
            TunnResult::WriteToNetwork(init) => init.to_vec(),
            other => panic!("expected a ready init, got {other:?}"),
        };
        let wire = obfuscate_init(&init, &params);
        assert_eq!(wire.len(), 148 + 16, "S1 padding must follow the Init");
        assert_eq!(
            u32::from_le_bytes(wire[0..4].try_into().unwrap()),
            5,
            "H1 magic must replace the Init message type"
        );
        assert_eq!(
            &wire[4..148],
            &init[4..],
            "the Init itself is never mutated"
        );
        assert!(
            Tunn::parse_incoming_packet(&wire).is_err(),
            "an obfuscated Init must not parse as vanilla"
        );

        let mut resp = vec![0u8; 92 + 24];
        resp[0..4].copy_from_slice(&6u32.to_le_bytes());
        let back = deobfuscate_response(&resp, &params).unwrap();
        assert_eq!(back.len(), 92);
        assert_eq!(u32::from_le_bytes(back[0..4].try_into().unwrap()), 2);
        assert!(Tunn::parse_incoming_packet(&back).is_ok());
        assert!(
            deobfuscate_response(&resp[..92], &params).is_none(),
            "a response missing the S2 pad must fail"
        );
        let mut vanilla_resp = vec![0u8; 92];
        vanilla_resp[0..4].copy_from_slice(&2u32.to_le_bytes());
        assert!(
            deobfuscate_response(&vanilla_resp, &params).is_none(),
            "a vanilla response must fail under H2 magic"
        );

        let mut cookie = vec![0u8; 64];
        cookie[0..4].copy_from_slice(&7u32.to_le_bytes());
        let back = deobfuscate_cookie(&cookie, &params).unwrap();
        assert_eq!(u32::from_le_bytes(back[0..4].try_into().unwrap()), 3);
        assert!(deobfuscate_cookie(&[0u8; 65], &params).is_none());

        let data = vec![4u8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let wire = obfuscate_data_out(&data, &params);
        assert_eq!(
            u32::from_le_bytes(wire[0..4].try_into().unwrap()),
            8,
            "H4 magic must replace the data message type"
        );
        assert_eq!(&wire[4..], &data[4..]);
        assert_eq!(deobfuscate_data(&wire, &params).unwrap(), data);
        assert!(
            deobfuscate_data(&data, &params).is_none(),
            "a vanilla data packet must fail under H4 magic"
        );
    }

    async fn record_datagrams(
        server: &UdpSocket,
        max: usize,
        idle_ms: u64,
    ) -> Vec<(Vec<u8>, std::net::SocketAddr)> {
        let mut out = Vec::new();
        loop {
            let mut buf = [0u8; 2048];
            match timeout(Duration::from_millis(idle_ms), server.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => {
                    out.push((buf[..n].to_vec(), peer));
                    if out.len() >= max {
                        break;
                    }
                }
                _ => break,
            }
        }
        out
    }

    fn is_vanilla_init(datagram: &[u8]) -> bool {
        datagram.len() == 148
            && u32::from_le_bytes(datagram[0..4].try_into().unwrap()) == 1
            && matches!(
                Tunn::parse_incoming_packet(datagram),
                Ok(boringtun::noise::Packet::HandshakeInit(_))
            )
    }

    async fn answer_init(server: &UdpSocket, init: &[u8], peer: std::net::SocketAddr) {
        let mut resp = [0u8; 92];
        resp[0..4].copy_from_slice(&2u32.to_le_bytes());
        resp[4..8].copy_from_slice(&init[4..8]);
        server.send_to(&resp, peer).await.unwrap();
    }

    #[tokio::test]
    async fn junk_off_sends_exactly_one_vanilla_init() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let got = record_datagrams(&server, 8, 300).await;
            assert_eq!(got.len(), 1, "defaults-off path must send only the Init");
            assert!(
                is_vanilla_init(&got[0].0),
                "the lone datagram must be the exact boringtun Init"
            );
            answer_init(&server, &got[0].0, got[0].1).await;
        });
        let outcome = WarpTransport::new()
            .unwrap()
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000, 0)
            .await
            .unwrap();
        assert_eq!(
            (outcome.sent, outcome.received),
            (1, 1),
            "junk must never count as probes"
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn junk_datagrams_surround_without_mutating_the_init() {
        let junk = JunkConfig {
            count: 4,
            min: 32,
            max: 64,
        };
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let got = record_datagrams(&server, 8, 300).await;
            assert_eq!(got.len(), 5, "4 junk datagrams plus the Init");
            let inits: Vec<usize> = got
                .iter()
                .enumerate()
                .filter(|(_, (b, _))| is_vanilla_init(b))
                .map(|(i, _)| i)
                .collect();
            assert_eq!(inits, vec![2], "the Init sits between the junk halves");
            for (i, (b, _)) in got.iter().enumerate() {
                if i == 2 {
                    continue;
                }
                assert!(
                    (32..=64).contains(&b.len()),
                    "junk datagram {i} must honor the size bounds, got {}",
                    b.len()
                );
            }
            answer_init(&server, &got[2].0, got[2].1).await;
        });
        let outcome = WarpTransport::with_junk(junk)
            .unwrap()
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000, 0)
            .await
            .unwrap();
        assert_eq!(
            (outcome.sent, outcome.received),
            (1, 1),
            "junk sends are not probes: loss accounting is untouched"
        );
        server_task.await.unwrap();
    }

    fn awg_test_params() -> crate::wgconf::AmneziaParams {
        crate::wgconf::AmneziaParams {
            s1: Some(16),
            s2: Some(24),
            h1: Some(5),
            h2: Some(6),
            h3: Some(7),
            h4: Some(8),
            ..Default::default()
        }
    }

    fn awg_test_wg(
        client_secret: &StaticSecret,
        server_public: &PublicKey,
        amnezia: crate::wgconf::AmneziaParams,
    ) -> crate::wgconf::WgConfig {
        crate::wgconf::WgConfig {
            private_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                client_secret.to_bytes(),
            ),
            address: "172.16.0.2/32".to_owned(),
            dns: None,
            mtu: None,
            amnezia,
            reserved: None,
            peer: crate::wgconf::WgPeer {
                public_key: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    server_public.as_bytes(),
                ),
                preshared_key: None,
                allowed_ips: vec![],
                endpoint: None,
                persistent_keepalive: None,
            },
        }
    }

    async fn awg_responder(
        socket: UdpSocket,
        server_secret: StaticSecret,
        client_public: PublicKey,
        p: crate::wgconf::AmneziaParams,
    ) {
        let mut tunn = Tunn::new(server_secret, client_public, None, None, 99, None);
        let mut buf = [0u8; 2048];
        let mut out = [0u8; 2048];
        let expect_init = 148 + p.s1.unwrap_or(0) as usize;
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let pkt = &buf[..n];
            if pkt.len() >= 4
                && pkt.len() == expect_init
                && u32::from_le_bytes(pkt[0..4].try_into().unwrap()) == u32::from(p.h1.unwrap_or(1))
            {
                let mut init = pkt[..148].to_vec();
                init[0..4].copy_from_slice(&1u32.to_le_bytes());
                match tunn.decapsulate(None, &init, &mut out) {
                    TunnResult::WriteToNetwork(resp) => {
                        let mut wire = resp.to_vec();
                        wire[0..4].copy_from_slice(&u32::from(p.h2.unwrap_or(2)).to_le_bytes());
                        let mut pad = vec![0u8; p.s2.unwrap_or(0) as usize];
                        rand_core::OsRng.fill_bytes(&mut pad);
                        wire.extend_from_slice(&pad);
                        socket.send_to(&wire, peer).await.unwrap();
                    }
                    other => panic!("AWG mock could not answer an Init: {other:?}"),
                }
            } else if pkt.len() >= 4
                && u32::from_le_bytes(pkt[0..4].try_into().unwrap()) == u32::from(p.h4.unwrap_or(4))
            {
                let mut data = pkt.to_vec();
                data[0..4].copy_from_slice(&4u32.to_le_bytes());
                match tunn.decapsulate(None, &data, &mut out) {
                    TunnResult::WriteToTunnelV4(inner, _) => {
                        let mut wire = [0u8; 2048];
                        match tunn.encapsulate(inner, &mut wire) {
                            TunnResult::WriteToNetwork(reply) => {
                                let mut wire = reply.to_vec();
                                wire[0..4]
                                    .copy_from_slice(&u32::from(p.h4.unwrap_or(4)).to_le_bytes());
                                socket.send_to(&wire, peer).await.unwrap();
                            }
                            other => panic!("AWG mock could not encapsulate data: {other:?}"),
                        }
                    }
                    TunnResult::Done | TunnResult::WriteToNetwork(_) => continue,
                    other => panic!("AWG mock rejected a data packet: {other:?}"),
                }
            }
            // Anything else (junk, unknown magic) is dropped silently, like a
            // real AWG edge drops packets it cannot attribute.
        }
    }

    async fn vanilla_responder(
        socket: UdpSocket,
        server_secret: StaticSecret,
        client_public: PublicKey,
    ) {
        let mut tunn = Tunn::new(server_secret, client_public, None, None, 99, None);
        let mut buf = [0u8; 2048];
        let mut out = [0u8; 2048];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            match Tunn::parse_incoming_packet(&buf[..n]) {
                Ok(boringtun::noise::Packet::HandshakeInit(_)) => {
                    match tunn.decapsulate(None, &buf[..n], &mut out) {
                        TunnResult::WriteToNetwork(resp) => {
                            socket.send_to(resp, peer).await.unwrap();
                        }
                        other => panic!("vanilla mock could not answer an Init: {other:?}"),
                    }
                }
                Ok(_) => match tunn.decapsulate(None, &buf[..n], &mut out) {
                    TunnResult::WriteToTunnelV4(inner, _) => {
                        let mut wire = [0u8; 2048];
                        match tunn.encapsulate(inner, &mut wire) {
                            TunnResult::WriteToNetwork(reply) => {
                                socket.send_to(reply, peer).await.unwrap();
                            }
                            other => panic!("vanilla mock could not encapsulate: {other:?}"),
                        }
                    }
                    TunnResult::Done | TunnResult::WriteToNetwork(_) => continue,
                    other => panic!("vanilla mock rejected a data packet: {other:?}"),
                },
                Err(_) => continue,
            }
        }
    }

    #[tokio::test]
    async fn verify_honors_nonzero_h_s_params() {
        use rand_core::OsRng;

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);
        let params = awg_test_params();
        let wg = awg_test_wg(&client_secret, &server_public, params.clone());
        let transport = WgVerifyTransport::from_config(&wg).unwrap();

        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server_socket.local_addr().unwrap();
        let responder = tokio::spawn(awg_responder(
            server_socket,
            server_secret,
            client_public,
            params,
        ));

        let outcome = transport
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000, 0)
            .await
            .unwrap();
        assert_eq!(
            (outcome.sent, outcome.received),
            (1, 1),
            "loss/Working semantics unchanged"
        );
        responder.abort();
    }

    #[tokio::test]
    async fn verify_without_matching_params_fails_against_an_awg_gateway() {
        use rand_core::OsRng;

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);
        let wg = awg_test_wg(
            &client_secret,
            &server_public,
            crate::wgconf::AmneziaParams::default(),
        );
        let transport = WgVerifyTransport::from_config(&wg).unwrap();

        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server_socket.local_addr().unwrap();
        let responder = tokio::spawn(awg_responder(
            server_socket,
            server_secret,
            client_public,
            awg_test_params(),
        ));

        let err = transport
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 400, 0)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProbeError::Timeout { .. } | ProbeError::Refused(_)),
            "a vanilla Init against an AWG gateway must fail, got {err:?}"
        );
        responder.abort();
    }

    #[tokio::test]
    async fn identity_h_s_params_verify_against_a_vanilla_peer() {
        use rand_core::OsRng;

        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);
        let wg = awg_test_wg(
            &client_secret,
            &server_public,
            crate::wgconf::AmneziaParams {
                s1: Some(0),
                s2: Some(0),
                h1: Some(1),
                h2: Some(2),
                h3: Some(3),
                h4: Some(4),
                ..Default::default()
            },
        );
        let transport = WgVerifyTransport::from_config(&wg).unwrap();

        let server_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = server_socket.local_addr().unwrap();
        let responder = tokio::spawn(vanilla_responder(
            server_socket,
            server_secret,
            client_public,
        ));

        let outcome = transport
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000, 0)
            .await
            .unwrap();
        assert_eq!((outcome.sent, outcome.received), (1, 1));
        responder.abort();
    }
}
