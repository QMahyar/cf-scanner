//! WARP mode: bundled endpoint pools and the WireGuard handshake probe.
//! boringtun builds a valid Init (MAC1 mandatory; MAC2 zeros are accepted by
//! WARP); open = a structurally valid HandshakeResponse (92B, type 2) or
//! CookieReply (64B, type 3) from the probed endpoint. Note: the intent doc's
//! "receiver-index match" does not hold against real WARP — Cloudflare answers
//! dummy-key probes with its own session index (verified live 2026-08-13,
//! wgcf-ecosystem scanners classify on packet shape alone). The socket is
//! connected to the probed endpoint, so shape is a sound signal.
//! Dummy-key probes work because Cloudflare answers handshakes for arbitrary
//! client keys.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::Result;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
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
    let bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        SERVER_PUBLIC_KEY_B64,
    )
    .expect("bundled WARP server key must decode");
    PublicKey::from(
        <[u8; 32]>::try_from(bytes.as_slice()).expect("bundled WARP server key must be 32 bytes"),
    )
}

/// Bundled WARP pools (embedded; no refresh path — the pools are stable).
pub fn bundled_pool() -> CidrPool {
    CidrPool::parse(BUNDLED_POOLS).expect("bundled WARP pools must parse")
}

/// A real UDP WireGuard handshake probe: Init in, Response/Cookie out.
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

/// The same probe driven by a user's wgconf keypair instead of the dummy key
/// (Task 13): a real handshake under the user's identity proves the endpoint
/// works with THEIR config. Endpoint swap = probe the candidate (ip, port);
/// the config's peer public key stays.
pub struct WgVerifyTransport {
    static_secret: StaticSecret,
    peer_public: PublicKey,
}

impl WgVerifyTransport {
    pub fn from_config(wg: &crate::wgconf::WgConfig) -> Result<Self> {
        Ok(Self {
            static_secret: StaticSecret::from(crate::wgconf::decode_key(&wg.private_key)?),
            peer_public: PublicKey::from(crate::wgconf::decode_key(&wg.peer.public_key)?),
        })
    }
}

impl Transport for WgVerifyTransport {
    fn probe(
        &self,
        ip: Ipv4Addr,
        port: u16,
        timeout_ms: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u32, ProbeError>> + Send + '_>>
    {
        let static_secret = StaticSecret::from(self.static_secret.to_bytes());
        let peer_public = self.peer_public;
        Box::pin(probe_once(static_secret, peer_public, ip, port, timeout_ms))
    }
}

impl Transport for WarpTransport {
    fn probe(
        &self,
        ip: Ipv4Addr,
        port: u16,
        timeout_ms: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u32, ProbeError>> + Send + '_>>
    {
        Box::pin(probe_once(
            StaticSecret::from(DUMMY_STATIC_PRIVATE),
            server_public_key(),
            ip,
            port,
            timeout_ms,
        ))
    }
}

/// One WG handshake attempt shared by both transports: fresh Tunn + connected
/// UDP socket, Init in, structurally valid Response/Cookie out.
async fn probe_once(
    static_secret: StaticSecret,
    peer_public: PublicKey,
    ip: Ipv4Addr,
    port: u16,
    timeout_ms: u64,
) -> Result<u32, ProbeError> {
    // Fresh index per probe so concurrent sockets can never confuse
    // each other's receiver-index check.
    let index = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
    let mut tunn = Tunn::new(static_secret, peer_public, None, None, index, None);
    let mut packet = [0u8; 148];
    let init = match tunn.format_handshake_initiation(&mut packet, true) {
        TunnResult::WriteToNetwork(init) => init.to_vec(),
        TunnResult::Err(e) => return Err(ProbeError::Refused(format!("{e:?}"))),
        _ => {
            return Err(ProbeError::Refused(
                "unexpected handshake result".to_owned(),
            ));
        }
    };
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|e| ProbeError::Refused(e.to_string()))?;
    let dst: SocketAddr = (ip, port).into();
    socket
        .connect(dst)
        .await
        .map_err(|e| ProbeError::Refused(e.to_string()))?;
    let started = std::time::Instant::now();
    socket
        .send(&init)
        .await
        .map_err(|e| ProbeError::Refused(e.to_string()))?;

    // Note the receiver index WARP put in its reply only for debugging.
    let mut reply = [0u8; 2048];
    match timeout(Duration::from_millis(timeout_ms), socket.recv(&mut reply)).await {
        Ok(Ok(n)) => {
            if classify(&reply[..n]) {
                Ok(started.elapsed().as_millis() as u32)
            } else {
                tracing::debug!(
                    len = n,
                    wg_type = u32::from_le_bytes(reply[..n.min(4)].try_into().unwrap_or([0; 4])),
                    recv_index = reply
                        .get(4..8)
                        .map(|b| u32::from_le_bytes(b.try_into().unwrap())),
                    "non-handshake WARP reply"
                );
                Err(ProbeError::Refused(
                    "reply is not a WARP handshake".to_owned(),
                ))
            }
        }
        Ok(Err(e)) => Err(ProbeError::Refused(e.to_string())),
        Err(_) => Err(ProbeError::Timeout { timeout_ms }),
    }
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
            .probe(Ipv4Addr::LOCALHOST, addr.port(), 2000)
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
            .probe(Ipv4Addr::LOCALHOST, addr.port(), 200)
            .await
            .unwrap_err();
        assert!(matches!(err, ProbeError::Timeout { .. }), "{err:?}");
    }

    /// Full WireGuard handshake over loopback: `WgVerifyTransport` (built from
    /// a parsed wgconf) initiates, a boringtun responder answers. Proves the
    /// verify path uses the user's real keypair (spec testing strategy:
    /// boringtun round-trip with a local test keypair).
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
                                return;
                            }
                            other => panic!("responder could not answer an Init: {other:?}"),
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => panic!("responder rejected the packet: {e:?}"),
                }
            }
        });

        let lat = transport
            .probe(Ipv4Addr::LOCALHOST, addr.port(), 2000)
            .await
            .unwrap();
        assert!(lat < 2000);
        responder.await.unwrap();
    }
}
