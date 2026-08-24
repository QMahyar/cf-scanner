//! WARP mode: bundled endpoint pools and the WireGuard handshake probe.
//! boringtun builds a valid Init (MAC1 mandatory; MAC2 zeros are accepted by
//! WARP); open = a structurally valid HandshakeResponse (92B, type 2) or
//! CookieReply (64B, type 3) from the probed endpoint. Note: the intent doc's
//! "receiver-index match" does not hold against real WARP — Cloudflare answers
//! dummy-key probes with its own session index (verified live 2026-08-13,
//! wgcf-ecosystem scanners classify on packet shape alone). The socket is
//! connected to the probed endpoint, so shape is a sound signal.
//! Dummy-key probes work because Cloudflare answers handshakes for arbitrary
//! client keys — which is why discovery stays shape-only, while verify mode
//! (user keypair) runs a FULL session: complete the cryptographic handshake,
//! then push an encrypted DNS query through the tunnel and require a data
//! reply. Shape alone cannot tell a dummy-key handshake from a real one.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::Result;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::RngCore;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::probe::{ProbeError, Transport};
use crate::ranges::CidrPool;

pub const BUNDLED_POOLS: &str = include_str!("../data/warp-pools.txt");

/// WARP server public key (same for every account), base64. Source: official
/// Project X WARP guide + wgcf; refresh candidate from the registration API
/// (Task 14) when reachable.
pub const SERVER_PUBLIC_KEY_B64: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

/// Dummy static private key: WARP does not care which client key signs the
/// handshake, only that the Init is well-formed.
const DUMMY_STATIC_PRIVATE: [u8; 32] = [0u8; 32];

fn server_public_key() -> PublicKey {
    // A registration refresh wins over the bundled constant; the identity
    // file is only ever written by us (0o600, atomic), so a corrupt entry
    // falls back silently.
    let b64 = crate::warpgen::persisted_server_public_key()
        .unwrap_or_else(|| SERVER_PUBLIC_KEY_B64.to_owned());
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
        .expect("WARP server key must decode");
    PublicKey::from(
        <[u8; 32]>::try_from(bytes.as_slice()).expect("WARP server key must be 32 bytes"),
    )
}

/// Bundled WARP pools (embedded; no refresh path — the pools are stable).
pub fn bundled_pool() -> CidrPool {
    CidrPool::parse(BUNDLED_POOLS).expect("bundled WARP pools must parse")
}

/// A real UDP WireGuard handshake probe: Init in, Response/Cookie out.
/// Unit struct on purpose: the engine constructs it as a bare path
/// (`Arc::new(warp::WarpTransport)`), so the socket reuse cache lives in a
/// process-wide static instead of on the transport.
pub struct WarpTransport;

impl WarpTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WarpTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// Bound on sockets held by the per-endpoint reuse cache: a full pool would
/// otherwise pin ~14K open fds (one per endpoint x port) for the whole scan.
/// In-flight probes hold their own `Arc`, so evicting an entry never breaks
/// them; the next probe for that endpoint binds a fresh socket.
const MAX_SOCKETS: usize = 1024;

/// Per-endpoint connected UDP sockets, reused across `probes_per_endpoint`
/// attempts of the same endpoint. The engine probes each (ip, port) group
/// back to back, so a fresh bind per attempt (43K on the full pool) is pure
/// overhead; at most `MAX_SOCKETS` fds stay open at once.
#[derive(Default)]
struct SocketCache {
    sockets: tokio::sync::Mutex<HashMap<(Ipv4Addr, u16), Arc<UdpSocket>>>,
}

impl SocketCache {
    async fn get_or_bind(&self, ip: Ipv4Addr, port: u16) -> Result<Arc<UdpSocket>, ProbeError> {
        let mut map = self.sockets.lock().await;
        if let Some(socket) = map.get(&(ip, port)) {
            return Ok(socket.clone());
        }
        if map.len() >= MAX_SOCKETS {
            let victim = map.keys().next().copied().expect("cache is non-empty here");
            map.remove(&victim);
        }
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .map_err(|_| ProbeError::Refused("udp bind failed"))?;
        socket
            .connect((ip, port))
            .await
            .map_err(|_| ProbeError::Refused("udp connect failed"))?;
        let socket = Arc::new(socket);
        map.insert((ip, port), socket.clone());
        Ok(socket)
    }
}

/// Shared across every dummy-key `WarpTransport` (the engine builds one per
/// controller; `Arc<dyn Transport>` keeps it for the controller's lifetime).
static WARP_SOCKETS: std::sync::LazyLock<SocketCache> =
    std::sync::LazyLock::new(SocketCache::default);

/// The same probe driven by a user's wgconf keypair instead of the dummy key
/// (Task 13): a real handshake under the user's identity proves the endpoint
/// works with THEIR config. Endpoint swap = probe the candidate (ip, port);
/// the config's peer public key stays.
pub struct WgVerifyTransport {
    static_secret: StaticSecret,
    peer_public: PublicKey,
    sockets: SocketCache,
}

impl WgVerifyTransport {
    pub fn from_config(wg: &crate::wgconf::WgConfig) -> Result<Self> {
        Ok(Self {
            static_secret: StaticSecret::from(crate::wgconf::decode_key(&wg.private_key)?),
            peer_public: PublicKey::from(crate::wgconf::decode_key(&wg.peer.public_key)?),
            sockets: SocketCache::default(),
        })
    }
}

impl Transport for WgVerifyTransport {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_ms: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u32, ProbeError>> + Send + '_>>
    {
        let IpAddr::V4(ip) = ip else {
            return Box::pin(
                async move { Err(ProbeError::Refused("WARP endpoints are IPv4-only")) },
            );
        };
        let static_secret = StaticSecret::from(self.static_secret.to_bytes());
        let peer_public = self.peer_public;
        Box::pin(probe_once(
            &self.sockets,
            static_secret,
            peer_public,
            ip,
            port,
            timeout_ms,
            ProbeDepth::FullSession,
        ))
    }
}

impl Transport for WarpTransport {
    fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout_ms: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u32, ProbeError>> + Send + '_>>
    {
        let IpAddr::V4(ip) = ip else {
            return Box::pin(
                async move { Err(ProbeError::Refused("WARP endpoints are IPv4-only")) },
            );
        };
        Box::pin(probe_once(
            &WARP_SOCKETS,
            StaticSecret::from(DUMMY_STATIC_PRIVATE),
            server_public_key(),
            ip,
            port,
            timeout_ms,
            ProbeDepth::ShapeOnly,
        ))
    }
}

/// One WG handshake attempt shared by both transports: reuses the endpoint's
/// How deeply a probe validates an endpoint.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeDepth {
    /// Shape-only: a valid Response/Cookie proves liveness (discovery).
    ShapeOnly,
    /// Full session: cryptographically complete the handshake under the
    /// caller's keypair, then push an encrypted DNS query through the tunnel
    /// and require a data reply (verify mode). A shape-only reply cannot
    /// distinguish a dummy-key handshake from a real one; a data round-trip
    /// can.
    FullSession,
}

/// Bound socket, Init in, structurally valid Response/Cookie out — and, at
/// `ProbeDepth::FullSession`, a completed handshake plus a data round-trip.
async fn probe_once(
    sockets: &SocketCache,
    static_secret: StaticSecret,
    peer_public: PublicKey,
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
    depth: ProbeDepth,
) -> Result<u32, ProbeError> {
    // Randomized 10-40ms pacing between handshakes: synchronized Init bursts
    // trip WARP's per-IP rate shaping and read as false negatives. Bounded,
    // so a full pool stays fast even at 200 concurrency.
    let jitter_ms = 10 + RngCore::next_u64(&mut rand_core::OsRng) % 31;
    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

    // Fresh index per probe so concurrent sockets can never confuse
    // each other's receiver-index check.
    let index = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
    let mut tunn = Tunn::new(static_secret, peer_public, None, None, index, None);
    let mut packet = [0u8; 148];
    let init = match tunn.format_handshake_initiation(&mut packet, true) {
        TunnResult::WriteToNetwork(init) => init.to_vec(),
        TunnResult::Err(_) => return Err(ProbeError::Refused("handshake init failed")),
        _ => return Err(ProbeError::Refused("unexpected handshake result")),
    };
    let socket = sockets.get_or_bind(ip, port).await?;
    let started = std::time::Instant::now();
    socket
        .send(&init)
        .await
        .map_err(|_| ProbeError::Refused("udp send failed"))?;

    // Note the receiver index WARP put in its reply only for debugging.
    let mut reply = [0u8; 2048];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut reply)).await {
        Ok(Ok(n)) => {
            if !classify(&reply[..n]) {
                tracing::debug!(
                    len = n,
                    wg_type = u32::from_le_bytes(reply[..n.min(4)].try_into().unwrap_or([0; 4])),
                    recv_index = reply
                        .get(4..8)
                        .map(|b| u32::from_le_bytes(b.try_into().unwrap())),
                    "non-handshake WARP reply"
                );
                return Err(ProbeError::Refused("reply is not a WARP handshake"));
            }
            if depth == ProbeDepth::ShapeOnly {
                return Ok(started.elapsed().as_millis() as u32);
            }
            finish_full_session(&mut tunn, &socket, &reply[..n], started, timeout_ms).await
        }
        Ok(Err(_)) => Err(ProbeError::Refused("udp receive failed")),
        Err(_) => Err(ProbeError::Timeout { timeout_ms }),
    }
}

/// Handshake half of the full-session probe: validate the Response under our
/// keypair (boringtun rejects responses not bound to our Init), then prove
/// the session carries data with an encrypted DNS query to 1.1.1.1.
async fn finish_full_session(
    tunn: &mut Tunn,
    socket: &UdpSocket,
    response: &[u8],
    started: std::time::Instant,
    timeout_ms: u64,
) -> Result<u32, ProbeError> {
    let mut out = [0u8; 2048];
    match tunn.decapsulate(None, response, &mut out) {
        // Done: handshake complete and authenticated (a response not bound to
        // our Init fails decryption here). Some stacks also queue a keepalive
        // frame — send it when present.
        TunnResult::Done => {}
        TunnResult::WriteToNetwork(keepalive) => {
            socket
                .send(keepalive)
                .await
                .map_err(|_| ProbeError::Refused("keepalive send failed"))?;
        }
        TunnResult::Err(_) => {
            return Err(ProbeError::Refused("handshake rejected under this keypair"));
        }
        _ => return Err(ProbeError::Refused("unexpected handshake result")),
    }

    // Encrypted DNS query (cloudflare.com A) wrapped in IP/UDP for the tunnel.
    let query = build_dns_probe_packet();
    let mut wire = [0u8; 2048];
    let data = match tunn.encapsulate(&query, &mut wire) {
        TunnResult::WriteToNetwork(pkt) => pkt,
        TunnResult::Err(_) => return Err(ProbeError::Refused("session not ready for data")),
        _ => return Err(ProbeError::Refused("unexpected encapsulate result")),
    };
    socket
        .send(data)
        .await
        .map_err(|_| ProbeError::Refused("data send failed"))?;

    let mut reply = [0u8; 2048];
    let received = timeout(Duration::from_millis(timeout_ms), socket.recv(&mut reply)).await;
    match received {
        Ok(Ok(n)) => match tunn.decapsulate(None, &reply[..n], &mut out) {
            // WriteToTunnelV4/V6: the reply decrypted into a valid inner IP
            // packet under our session keys — data genuinely flowed.
            TunnResult::WriteToTunnelV4(inner, _) | TunnResult::WriteToTunnelV6(inner, _) => {
                if inner.is_empty() {
                    Err(ProbeError::Refused("empty data reply through tunnel"))
                } else {
                    Ok(started.elapsed().as_millis() as u32)
                }
            }
            TunnResult::WriteToNetwork(_) => {
                // Keepalive/cookie instead of our data reply: session works
                // but the endpoint did not answer the query — not verified.
                Err(ProbeError::Refused("no data reply through tunnel"))
            }
            TunnResult::Done | TunnResult::Err(_) => {
                Err(ProbeError::Refused("tunnel rejected data reply"))
            }
        },
        Ok(Err(_)) => Err(ProbeError::Refused("udp receive failed")),
        Err(_) => Err(ProbeError::Timeout { timeout_ms }),
    }
}

/// Minimal inner IPv4/UDP packet carrying a DNS A query for cloudflare.com,
/// addressed 172.16.0.2 → 1.1.1.1 (the wgconf Address convention).
fn build_dns_probe_packet() -> Vec<u8> {
    const SRC: [u8; 4] = [172, 16, 0, 2];
    const DST: [u8; 4] = [1, 1, 1, 1];

    let mut dns = Vec::with_capacity(32);
    dns.extend_from_slice(&[0x1a, 0x2b]); // id
    dns.extend_from_slice(&[0x01, 0x00]); // flags: RD
    dns.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // qd=1
    dns.extend_from_slice(&[10]); // cloudflare
    dns.extend_from_slice(b"cloudflare");
    dns.extend_from_slice(&[3]);
    dns.extend_from_slice(b"com");
    dns.push(0);
    dns.extend_from_slice(&[0, 1, 0, 1]); // A, IN

    let mut udp = Vec::with_capacity(8 + dns.len());
    udp.extend_from_slice(&[0x9d, 0x34]); // sport 40212
    udp.extend_from_slice(&[0, 53]); // dport 53
    udp.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum 0 (optional over IPv4)
    udp.extend_from_slice(&dns);

    let total = 20 + udp.len();
    let mut ip = Vec::with_capacity(total);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 1, 0x40, 0x00]); // id, DF
    ip.extend_from_slice(&[64, 17]); // ttl, proto UDP
    ip.extend_from_slice(&[0, 0]); // checksum placeholder
    ip.extend_from_slice(&SRC);
    ip.extend_from_slice(&DST);
    let sum = ones_complement_sum16(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip.extend_from_slice(&udp);
    ip
}

/// RFC 1071 ones-complement checksum over the header (checksum field zeroed
/// by the caller before summing).
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

/// Open = HandshakeResponse (type 2, 92B) or CookieReply (type 3, 64B),
/// structurally valid per boringtun's parser. No receiver-index check: real
/// WARP answers dummy-key probes under its own session index (see module doc).
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
        // Serialize against warpgen's identity tests: both mutate the
        // process-global CF_SCANNER_DATA_DIR override.
        let _guard = crate::warpgen::tests::IDENTITY_LOCK.lock().unwrap();
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
        assert_eq!(server_public_key().to_bytes(), [7u8; 32]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bundled_pools_cover_the_known_endpoint_space() {
        let pool = bundled_pool();
        assert_eq!(pool.host_count(), 8 * 256);
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
        // Live WARP (2026-08-13) replies under its own session index, so a
        // receiver-index mismatch must not close a structurally valid reply.
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
            server_public_key(),
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
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000)
            .await
            .unwrap();
        assert!(lat < 2000);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn probe_times_out_on_a_silent_endpoint() {
        // A bound-but-dumb UDP socket never replies to an Init.
        let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = silent.local_addr().unwrap();
        let err = WarpTransport::new()
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 200)
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::Timeout { .. }), "{err:?}");
    }

    /// Full WireGuard session over loopback: `WgVerifyTransport` (built from
    /// a parsed wgconf) initiates, a boringtun responder completes the
    /// handshake AND echoes a data packet back through its own tunnel — the
    /// exact bar FullSession verification sets (handshake + data reply).
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
                    Ok(_) => {
                        // Post-handshake traffic: decrypt under the session;
                        // echo the inner packet back through our own tunnel,
                        // which only works if the handshake truly completed.
                        match tunn.decapsulate(None, &buf[..n], &mut out) {
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
                        }
                    }
                    Err(e) => panic!("responder rejected the packet: {e:?}"),
                }
            }
        });

        let lat = transport
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000)
            .await
            .unwrap();
        assert!(lat < 2000);
        responder.abort();
    }

    /// A responder that answers the handshake but drops data must NOT pass
    /// FullSession verification — this is the discrimination the old
    /// shape-only check could not make.
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
                ) {
                    if let TunnResult::WriteToNetwork(resp) =
                        tunn.decapsulate(None, &buf[..n], &mut out)
                    {
                        server_socket.send_to(resp, peer).await.unwrap();
                    }
                }
                // Data packets: silently dropped, like an unregistered peer.
            }
        });

        let err = transport
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 400)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ProbeError::Timeout { .. } | ProbeError::Refused(_)),
            "dropped data must fail verification, got {err:?}"
        );
        responder.abort();
    }
}
