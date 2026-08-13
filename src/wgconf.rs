//! WireGuard/AmneziaWG config parsing (Task 13). Accepts both the standard
//! wg-quick INI text (as exported by the official WARP client / wgcf) and the
//! AmneziaWG URI form (`wg://` / `wireguard://`). Input is UNTRUSTED user
//! paste, so parsing never panics; handshake keys are validated (32B base64)
//! so a verify run fails fast instead of on the first probe.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use url::Url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgConfig {
    /// Base64 client private key (Interface/PrivateKey or `private_key=`).
    pub private_key: String,
    /// Comma-separated `addr/prefix` list; "amneziawarp" style.
    pub address: String,
    pub dns: Option<String>,
    pub mtu: Option<u16>,
    /// AmneziaWG obfuscation params (all optional; irrelevant for the probe,
    /// kept so a rendered config round-trips).
    pub amnezia: AmneziaParams,
    pub peer: WgPeer,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AmneziaParams {
    pub jc: Option<u16>,
    pub jmin: Option<u16>,
    pub jmax: Option<u16>,
    pub s1: Option<u8>,
    pub s2: Option<u8>,
    pub h1: Option<u8>,
    pub h2: Option<u8>,
    pub h3: Option<u8>,
    pub h4: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgPeer {
    /// Base64 server public key.
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    /// `host:port` or `ip:port`; optional for probe-only configs.
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

/// Parses either form: AmneziaWG URIs (`wg://` / `wireguard://`) vs INI text.
pub fn parse_wg_entry(entry: &str) -> Result<WgConfig> {
    let text = entry.trim();
    for scheme in ["wg://", "wireguard://"] {
        if text.starts_with(scheme) {
            return parse_awg_uri(text);
        }
    }
    parse_wgconf(text)
}

/// Parses wg-quick INI text: `[Interface]` + `[Peer]` sections, `Key = Value`
/// lines, `#`/`;` full-line comments, case-insensitive keys.
pub fn parse_wgconf(text: &str) -> Result<WgConfig> {
    let mut section: Option<String> = None;
    let mut iface = BTreeMap::new();
    let mut peer_map = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = Some(line[1..line.len() - 1].trim().to_ascii_lowercase());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue; // tolerate stray non-key lines without failing the batch
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        match section.as_deref() {
            Some("interface") => {
                iface.insert(key, value);
            }
            Some("peer") => {
                peer_map.insert(key, value);
            }
            _ => continue,
        }
    }
    build_wg_config(&iface, &peer_map)
}

/// Parses `scheme://host:port?key=value&...` (AmneziaWG / "warp-uri"
/// generators). `local_address` joins multiple `addr/prefix` parts with `-`,
/// as awg configs emit.
fn parse_awg_uri(entry: &str) -> Result<WgConfig> {
    let url = Url::parse(entry).map_err(|e| anyhow!("bad wg URI: {e}"))?;
    match url.scheme() {
        "wg" | "wireguard" => {}
        s => bail!("unsupported scheme '{s}'"),
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("wg URI has no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url.port().ok_or_else(|| anyhow!("wg URI has no port"))?;
    // Raw query split, NOT `query_pairs`: form-urlencoded decoding would turn
    // the `+` inside base64 keys into a space (real-world AmneziaWG URIs ship
    // raw `+`; awg clients only percent-decode).
    let q: BTreeMap<String, String> = url
        .query()
        .map(|raw| {
            raw.split('&')
                .filter_map(|pair| {
                    let (k, v) = pair.split_once('=')?;
                    Some((
                        wg_percent_decode(k).to_ascii_lowercase(),
                        wg_percent_decode(v),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let address = q
        .get("local_address")
        .map(|a| a.split('-').collect::<Vec<_>>().join(", "))
        .unwrap_or_default();
    let amnezia = AmneziaParams {
        jc: parse_opt(&q, "jc")?,
        jmin: parse_opt(&q, "jmin")?,
        jmax: parse_opt(&q, "jmax")?,
        s1: parse_opt(&q, "s1")?,
        s2: parse_opt(&q, "s2")?,
        h1: parse_opt(&q, "h1")?,
        h2: parse_opt(&q, "h2")?,
        h3: parse_opt(&q, "h3")?,
        h4: parse_opt(&q, "h4")?,
    };
    let peer = WgPeer {
        public_key: required(&q, "public_key")?,
        preshared_key: q.get("preshared_key").cloned(),
        allowed_ips: vec![],
        endpoint: Some(format!("{host}:{port}")),
        persistent_keepalive: parse_opt(&q, "persistent_keepalive")?,
    };
    build_wg_config(
        &[
            ("privatekey".to_owned(), required(&q, "private_key")?),
            ("address".to_owned(), address),
            ("mtu".to_owned(), q.get("mtu").cloned().unwrap_or_default()),
        ]
        .into_iter()
        .collect(),
        &[
            ("publickey".to_owned(), peer.public_key.clone()),
            (
                "presharedkey".to_owned(),
                peer.preshared_key.clone().unwrap_or_default(),
            ),
            (
                "endpoint".to_owned(),
                peer.endpoint.clone().unwrap_or_default(),
            ),
        ]
        .into_iter()
        .collect(),
    )
    .map(|wg| WgConfig {
        amnezia,
        peer: WgPeer {
            persistent_keepalive: peer.persistent_keepalive,
            ..wg.peer
        },
        ..wg
    })
}

fn required(q: &BTreeMap<String, String>, key: &str) -> Result<String> {
    q.get(key)
        .filter(|v| !v.is_empty())
        .cloned()
        .ok_or_else(|| anyhow!("wg URI missing {key}"))
}

fn wg_percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

fn parse_opt<T: std::str::FromStr>(q: &BTreeMap<String, String>, key: &str) -> Result<Option<T>> {
    match q.get(key).filter(|v| !v.is_empty()) {
        Some(v) => v
            .parse()
            .ok()
            .map(Some)
            .ok_or_else(|| anyhow!("wg URI {key} is not a number: '{v}'")),
        None => Ok(None),
    }
}

fn build_wg_config(
    iface: &BTreeMap<String, String>,
    peer_map: &BTreeMap<String, String>,
) -> Result<WgConfig> {
    use anyhow::Context as _;
    let private_key = required_key(iface, "privatekey")?;
    let peer_public = required_key(peer_map, "publickey")?;
    decode_key(&private_key).context("invalid private_key")?;
    decode_key(&peer_public).context("invalid public_key")?;

    let mtu = optional_u16(iface, "mtu")?;
    let keepalive = optional_u16(peer_map, "persistentkeepalive")?;
    let amnezia = AmneziaParams {
        jc: optional_u16(iface, "jc")?,
        jmin: optional_u16(iface, "jmin")?,
        jmax: optional_u16(iface, "jmax")?,
        s1: optional_u8(iface, "s1")?,
        s2: optional_u8(iface, "s2")?,
        h1: optional_u8(iface, "h1")?,
        h2: optional_u8(iface, "h2")?,
        h3: optional_u8(iface, "h3")?,
        h4: optional_u8(iface, "h4")?,
    };

    Ok(WgConfig {
        private_key,
        address: iface.get("address").cloned().unwrap_or_default(),
        dns: iface.get("dns").cloned().filter(|v| !v.is_empty()),
        mtu,
        amnezia,
        peer: WgPeer {
            public_key: peer_public,
            preshared_key: peer_map
                .get("presharedkey")
                .cloned()
                .filter(|v| !v.is_empty()),
            allowed_ips: peer_map
                .get("allowedips")
                .map(|s| s.split(',').map(|p| p.trim().to_owned()).collect())
                .unwrap_or_default(),
            endpoint: peer_map.get("endpoint").cloned().filter(|v| !v.is_empty()),
            persistent_keepalive: keepalive,
        },
    })
}

/// Renders a canonical wg-quick text (export + display; Task 14 reuses it).
pub fn render_wgconf(wg: &WgConfig) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", wg.private_key));
    if !wg.address.is_empty() {
        out.push_str(&format!("Address = {}\n", wg.address));
    }
    if let Some(dns) = &wg.dns {
        out.push_str(&format!("DNS = {dns}\n"));
    }
    if let Some(mtu) = wg.mtu {
        out.push_str(&format!("MTU = {mtu}\n"));
    }
    for (key, value) in [
        ("Jc", wg.amnezia.jc),
        ("Jmin", wg.amnezia.jmin),
        ("Jmax", wg.amnezia.jmax),
    ] {
        if let Some(v) = value {
            out.push_str(&format!("{key} = {v}\n"));
        }
    }
    for (key, value) in [
        ("S1", wg.amnezia.s1),
        ("S2", wg.amnezia.s2),
        ("H1", wg.amnezia.h1),
        ("H2", wg.amnezia.h2),
        ("H3", wg.amnezia.h3),
        ("H4", wg.amnezia.h4),
    ] {
        if let Some(v) = value {
            out.push_str(&format!("{key} = {v}\n"));
        }
    }
    out.push('\n');
    out.push_str("[Peer]\n");
    out.push_str(&format!("PublicKey = {}\n", wg.peer.public_key));
    if let Some(pk) = &wg.peer.preshared_key {
        out.push_str(&format!("PresharedKey = {pk}\n"));
    }
    if !wg.peer.allowed_ips.is_empty() {
        out.push_str(&format!(
            "AllowedIPs = {}\n",
            wg.peer.allowed_ips.join(", ")
        ));
    }
    if let Some(ep) = &wg.peer.endpoint {
        out.push_str(&format!("Endpoint = {ep}\n"));
    }
    if let Some(ka) = wg.peer.persistent_keepalive {
        out.push_str(&format!("PersistentKeepalive = {ka}\n"));
    }
    out
}

/// Decodes a WireGuard base64 key; shared validation for parse + probe.
pub fn decode_key(b64: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| anyhow!("key is not valid base64"))?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| anyhow!("key must decode to exactly 32 bytes"))
}

fn required_key(map: &BTreeMap<String, String>, key: &str) -> Result<String> {
    map.get(key)
        .filter(|v| !v.is_empty())
        .cloned()
        .ok_or_else(|| anyhow!("missing {key}"))
}

fn optional_u16(map: &BTreeMap<String, String>, key: &str) -> Result<Option<u16>> {
    match map.get(key).filter(|v| !v.is_empty()) {
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| anyhow!("{key} is not a number: '{v}'")),
        None => Ok(None),
    }
}

fn optional_u8(map: &BTreeMap<String, String>, key: &str) -> Result<Option<u8>> {
    match map.get(key).filter(|v| !v.is_empty()) {
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| anyhow!("{key} is not a number: '{v}'")),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INI_FIXTURE: &str = include_str!("../tests/fixtures/warp-wgconf.txt");
    const URI_FIXTURE: &str = include_str!("../tests/fixtures/warp-uri.txt");

    #[test]
    fn parses_wgquick_ini_fixture() {
        let wg = parse_wgconf(INI_FIXTURE).unwrap();
        assert_eq!(
            wg.private_key,
            "39l0houfixtSIA4O3MQRDMX5fBNUQw72H+RivqX2EbI="
        );
        assert_eq!(
            wg.address,
            "172.16.0.2/32, 2606:4700:110:8d4a:ca6:b507:215:d04f/128"
        );
        assert_eq!(wg.dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(wg.mtu, Some(1280));
        assert_eq!(
            wg.amnezia,
            AmneziaParams {
                jc: Some(5),
                jmin: Some(50),
                jmax: Some(100),
                s1: Some(0),
                s2: Some(0),
                h1: Some(1),
                h2: Some(2),
                h3: Some(3),
                h4: Some(4),
            }
        );
        assert_eq!(
            wg.peer.public_key,
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        );
        assert_eq!(wg.peer.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(wg.peer.endpoint.as_deref(), Some("8.6.112.31:4198"));
        assert_eq!(wg.peer.persistent_keepalive, Some(25));
    }

    #[test]
    fn parses_amneziawg_uri_both_schemes() {
        for line in URI_FIXTURE.lines().filter(|l| !l.is_empty()) {
            let wg = parse_wg_entry(line).unwrap();
            assert_eq!(
                wg.private_key,
                "39l0houfixtSIA4O3MQRDMX5fBNUQw72H+RivqX2EbI="
            );
            assert_eq!(
                wg.address,
                "172.16.0.2/32, 2606:4700:110:8d4a:ca6:b507:215:d04f/128"
            );
            assert_eq!(wg.mtu, Some(1280));
            assert_eq!(
                wg.amnezia,
                AmneziaParams {
                    jc: Some(5),
                    jmin: Some(30),
                    jmax: Some(1000),
                    ..Default::default()
                }
            );
            assert_eq!(
                wg.peer.public_key,
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
            );
            assert_eq!(wg.peer.endpoint.as_deref(), Some("8.47.69.246:7103"));
        }
    }

    #[test]
    fn render_round_trips_the_ini_fixture() {
        let wg = parse_wgconf(INI_FIXTURE).unwrap();
        let reparsed = parse_wgconf(&render_wgconf(&wg)).unwrap();
        assert_eq!(wg, reparsed);
    }

    #[test]
    fn parser_is_case_insensitive_and_comment_tolerant() {
        let text = "[interface]\nprivatekey = 39l0houfixtSIA4O3MQRDMX5fBNUQw72H+RivqX2EbI=\n# comment\n; also a comment\n[Peer]\nPUBLICKEY = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n";
        let wg = parse_wgconf(text).unwrap();
        assert!(wg.peer.endpoint.is_none());
    }

    #[test]
    fn rejects_missing_or_garbage_keys() {
        let non_canonical_padding = INI_FIXTURE.replace("RivqX2EbI=", "RivqX2EbI");
        for bad in [
            "",
            "[Interface]\nAddress = 172.16.0.2/32\n",
            "[Interface]\nPrivateKey = ZG9uZ28=\n",
            "[Peer]\nPublicKey = 39l0houfixtSIA4O3MQRDMX5fBNUQw72H+RivqX2EbI=\n",
            non_canonical_padding.as_str(),
        ] {
            assert!(
                parse_wgconf(bad).is_err(),
                "expected rejection for: {bad:?}"
            );
        }
        assert!(parse_wg_entry("wg://1.2.3.4?private_key=abc").is_err());
        assert!(parse_wg_entry("ftp://x").is_err());
    }

    #[test]
    fn rejects_invalid_amnezia_numbers_in_ini() {
        let text = INI_FIXTURE.replace("Jc = 5", "Jc = not-a-number");
        assert!(parse_wgconf(&text).is_err());
    }

    #[test]
    fn decode_key_accepts_only_32_bytes() {
        assert_eq!(
            decode_key("39l0houfixtSIA4O3MQRDMX5fBNUQw72H+RivqX2EbI=")
                .unwrap()
                .len(),
            32
        );
        assert!(decode_key("too-short").is_err());
    }

    #[test]
    fn missing_optional_fields_stay_optional() {
        let wg = parse_wgconf("[Interface]\nPrivateKey = 39l0houfixtSIA4O3MQRDMX5fBNUQw72H+RivqX2EbI=\n[Peer]\nPublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\n")
            .unwrap();
        assert_eq!(wg.mtu, None);
        assert_eq!(wg.peer.endpoint, None);
        assert!(wg.peer.allowed_ips.is_empty());
        assert_eq!(wg.address, "");
        assert_eq!(wg.dns, None);
    }
}
