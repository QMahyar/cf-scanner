use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::redirect::Policy;
use std::sync::LazyLock;

pub const OFFICIAL_IPS_URL: &str = "https://api.cloudflare.com/client/v4/ips";
pub const OFFICIAL_IPS_V6_URL: &str = "https://www.cloudflare.com/ips-v6/";
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.error("too many redirects");
            }
            if let Err(err) = validate_fetch_url(attempt.url().as_str()) {
                return attempt.error(err.to_string());
            }
            attempt.follow()
        }))
        .build()
        .expect("HTTP client must build")
});

pub fn validate_fetch_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url).context("bad URL")?;
    if parsed.scheme() != "https" {
        bail!("only https:// URLs supported (got {}://)", parsed.scheme());
    }
    if let Some(host) = parsed.host() {
        let unroutable = match host {
            url::Host::Ipv4(v4) => {
                let [a, b, _, _] = v4.octets();
                v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    || v4.is_broadcast()
                    || (a == 169 && b == 254)
                    || a == 0
            }
            url::Host::Ipv6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                    let [a, b, _, _] = v4.octets();
                    v4.is_loopback()
                        || v4.is_unspecified()
                        || v4.is_multicast()
                        || v4.is_broadcast()
                        || (a == 169 && b == 254)
                        || a == 0
                } else {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || v6.is_multicast()
                        || v6.segments()[0] & 0xffc0 == 0xfe80
                }
            }
            url::Host::Domain(domain) => {
                let decoded = crate::util::percent_decode(domain);
                let lower = decoded.to_ascii_lowercase();
                lower == "localhost"
                    || lower.ends_with(".localhost")
                    || (!decoded.is_empty()
                        && decoded.chars().all(
                            |c| matches!(c, '0'..='9' | 'a'..='f' | 'A'..='F' | 'x' | 'X' | '.'),
                        )
                        && decoded.chars().any(|c| c.is_ascii_digit()))
            }
        };
        if unroutable {
            bail!("refusing fetch from non-routable host {host}");
        }
    }
    Ok(())
}

fn sanitize_url_for_error(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            if !parsed.username().is_empty() || parsed.password().is_some() {
                let _ = parsed.set_username("***");
                let _ = parsed.set_password(Some("***"));
            }
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string()
        }
        Err(_) => url.to_owned(),
    }
}

pub async fn fetch_tls_with_headers(url: &str, extra_headers: &str) -> Result<String> {
    let body = fetch_tls_inner(url, extra_headers).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

pub async fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    fetch_tls_inner(url, "Accept: */*").await
}

async fn fetch_tls(url: &str) -> Result<String> {
    let body = fetch_tls_inner(url, "Accept: application/json").await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn fetch_tls_inner(url: &str, extra_headers: &str) -> Result<Vec<u8>> {
    validate_fetch_url(url)?;
    let mut request = HTTP_CLIENT
        .get(url)
        .timeout(FETCH_TIMEOUT)
        .header(reqwest::header::USER_AGENT, "cf-scanner/0.1.0");
    for line in extra_headers.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() || value.is_empty() {
            continue;
        }
        if reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            || reqwest::header::HeaderValue::from_bytes(value.as_bytes()).is_err()
        {
            continue;
        }
        request = request.header(name, value);
    }
    let mut response = request
        .send()
        .await
        .with_context(|| format!("fetch failed for {}", sanitize_url_for_error(url)))?;
    const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
    if let Some(len) = response.content_length()
        && len > MAX_BODY_BYTES as u64
    {
        bail!("response body exceeds the {MAX_BODY_BYTES} byte cap (Content-Length {len})");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.with_context(|| {
        format!(
            "failed to read response body of {}",
            sanitize_url_for_error(url)
        )
    })? {
        if bytes.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            bail!("response body exceeded the {MAX_BODY_BYTES} byte cap");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub type HttpFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<String>> + Send + 'a>>;

pub trait HttpGet {
    fn get<'a>(&'a self, url: &'a str) -> HttpFuture<'a>;
}

pub struct RealHttp;

impl HttpGet for RealHttp {
    fn get<'a>(&'a self, url: &'a str) -> HttpFuture<'a> {
        Box::pin(async move { fetch_tls(url).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_url_guard_rejects_non_https_and_local_hosts() {
        assert!(validate_fetch_url("https://example.com/sub").is_ok());
        assert!(validate_fetch_url("https://8.8.8.8/sub").is_ok());
        assert!(validate_fetch_url("https://10.0.0.5:8443/sub").is_ok());
        assert!(validate_fetch_url("https://example.com:8443/sub").is_ok());
        assert!(validate_fetch_url("http://example.com/sub").is_err());
        assert!(validate_fetch_url("ftp://example.com/x").is_err());
        assert!(validate_fetch_url("file:///etc/passwd").is_err());
        assert!(validate_fetch_url("https://127.0.0.1:8765/x").is_err());
        assert!(validate_fetch_url("https://[::1]/x").is_err());
        assert!(validate_fetch_url("https://[::ffff:127.0.0.1]/x").is_err());
        assert!(validate_fetch_url("https://[::ffff:169.254.0.1]/x").is_err());
        assert!(validate_fetch_url("https://[2001:db8::1]/x").is_ok());
        assert!(validate_fetch_url("https://169.254.0.1/x").is_err());
        assert!(validate_fetch_url("https://0.0.0.0/x").is_err());
        assert!(validate_fetch_url("not a url").is_err());
    }

    #[test]
    fn fetch_url_guard_extended_ssrf_cases() {
        assert!(validate_fetch_url("https://[::127.0.0.1]/x").is_err());
        assert!(validate_fetch_url("https://[::ffff:127.0.0.1]/x").is_err());
        assert!(validate_fetch_url("https://0.1.2.3/x").is_err());
        assert!(validate_fetch_url("https://224.0.0.1/x").is_err());
        assert!(validate_fetch_url("https://255.255.255.255/x").is_err());
        assert!(validate_fetch_url("https://[ff02::1]/x").is_err());
        assert!(validate_fetch_url("https://localhost/x").is_err());
        assert!(validate_fetch_url("https://0x7f.0.0.1/x").is_err());
        assert!(validate_fetch_url("https://2130706433/x").is_err());
        assert!(validate_fetch_url("https://10.0.0.1/x").is_ok());
        assert!(validate_fetch_url("https://example.com/x").is_ok());
        assert!(validate_fetch_url("https://www.cloudflare.com/ips-v4/").is_ok());
    }
}
