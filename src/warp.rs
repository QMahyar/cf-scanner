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

use crate::probe::{ProbeError, Transport};
use crate::ranges::CidrPool;

pub const BUNDLED_POOLS: &str = include_str!("../data/warp-pools.txt");

pub const SERVER_PUBLIC_KEY_B64: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

const DUMMY_STATIC_PRIVATE: [u8; 32] = [0u8; 32];

pub fn server_public_key() -> anyhow::Result<PublicKey> {
    let b64 = crate::warpgen::persisted_server_public_key()
        .unwrap_or_else(|| SERVER_PUBLIC_KEY_B64.to_owned());
    let bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                "failed to decode WARP server public key: {e}; falling back to bundled key"
            );
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                SERVER_PUBLIC_KEY_B64,
            )
            .map_err(|e| anyhow::anyhow!("bundled WARP server key must decode: {e}"))?
        }
    };
    let arr = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("WARP server public key is not 32 bytes"))?;
    Ok(PublicKey::from(arr))
}

pub fn bundled_pool() -> CidrPool {
    CidrPool::parse(BUNDLED_POOLS).expect("bundled WARP pools must parse")
}

pub struct WarpTransport {
    server_public: PublicKey,
    sockets: std::sync::Arc<SocketCache>,
}

impl WarpTransport {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            server_public: server_public_key()?,
            sockets: std::sync::Arc::new(SocketCache::default()),
        })
    }

    pub async fn with_cache(cache: std::sync::Arc<SocketCache>) -> anyhow::Result<Self> {
        cache.clear().await;
        Ok(Self {
            server_public: server_public_key()?,
            sockets: cache,
        })
    }

    pub(crate) fn from_cache(cache: std::sync::Arc<SocketCache>) -> anyhow::Result<Self> {
        Ok(Self {
            server_public: server_public_key()?,
            sockets: cache,
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
        if map.len() >= MAX_SOCKETS {
            let victim = map.keys().next().copied().expect("cache is non-empty here");
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
}

impl WgVerifyTransport {
    pub fn from_config(wg: &crate::wgconf::WgConfig) -> Result<Self> {
        Ok(Self {
            static_secret: StaticSecret::from(crate::wgconf::decode_key(&wg.private_key)?),
            peer_public: PublicKey::from(crate::wgconf::decode_key(&wg.peer.public_key)?),
            sockets: Arc::new(SocketCache::default()),
        })
    }

    pub async fn with_cache(cache: Arc<SocketCache>, wg: &crate::wgconf::WgConfig) -> Result<Self> {
        cache.clear().await;
        Ok(Self {
            static_secret: StaticSecret::from(crate::wgconf::decode_key(&wg.private_key)?),
            peer_public: PublicKey::from(crate::wgconf::decode_key(&wg.peer.public_key)?),
            sockets: cache,
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
        let server_public = self.server_public;
        let sockets = self.sockets.clone();
        Box::pin(async move {
            probe_once(
                &sockets,
                StaticSecret::from(DUMMY_STATIC_PRIVATE),
                server_public,
                ip,
                port,
                timeout_ms,
                ProbeDepth::ShapeOnly,
            )
            .await
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeDepth {
    ShapeOnly,
    FullSession,
}

async fn probe_once(
    sockets: &SocketCache,
    static_secret: StaticSecret,
    peer_public: PublicKey,
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
    depth: ProbeDepth,
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
    socket
        .send(&init)
        .await
        .map_err(|_| ProbeError::Refused("udp send failed"))?;

    let mut reply = [0u8; 2048];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut reply)).await {
        Ok(Ok(n)) => {
            if !classify(&reply[..n]) {
                let head = &reply[..n.min(8)];
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
            finish_full_session(&mut tunn, &socket, &reply[..n], started, timeout_ms).await
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
) -> Result<u32, ProbeError> {
    let mut out = [0u8; 2048];
    match tunn.decapsulate(None, response, &mut out) {
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
    let elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let rem = timeout_ms.saturating_sub(elapsed_ms).max(1);
    let received = timeout(Duration::from_millis(rem), socket.recv(&mut reply)).await;
    match received {
        Ok(Ok(n)) => match tunn.decapsulate(None, &reply[..n], &mut out) {
            TunnResult::WriteToTunnelV4(inner, _) | TunnResult::WriteToTunnelV6(inner, _) => {
                if inner.is_empty() {
                    Err(ProbeError::Refused("empty data reply through tunnel"))
                } else {
                    Ok((started.elapsed().as_millis().min(u32::MAX as u128)) as u32)
                }
            }
            TunnResult::WriteToNetwork(_) => {
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
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000)
            .await
            .unwrap();
        assert!(lat < 2000);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn probe_times_out_on_a_silent_endpoint() {
        let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = silent.local_addr().unwrap();
        let err = WarpTransport::new()
            .unwrap()
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 200)
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
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 2000)
            .await
            .unwrap();
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
            .probe(Ipv4Addr::LOCALHOST.into(), addr.port(), 400)
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
}
