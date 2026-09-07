use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::ranges;

use super::{
    MAX_CONFIG_ENTRY_BYTES, MAX_SUB_BLOB_BYTES, OutboundSpec, SUB_UA, base64_any, parse_uri,
    sanitize_error_text,
};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SubscriptionParse {
    pub specs: Vec<OutboundSpec>,
    pub ignored: usize,
    pub errors: Vec<String>,
}

pub trait SubFetch: Send + Sync {
    fn fetch(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<String>> + Send + '_>>;
}

pub struct RealSubFetch;

impl SubFetch for RealSubFetch {
    fn fetch(&self, url: &str) -> Pin<Box<dyn Future<Output = Result<String>> + Send + '_>> {
        let url = url.to_owned();
        Box::pin(async move {
            ranges::fetch_tls_with_headers(&url, &format!("User-Agent: {SUB_UA}\r\nAccept: */*"))
                .await
        })
    }
}

pub async fn fetch_subscription(fetch: &impl SubFetch, url: &str) -> Result<SubscriptionParse> {
    let body = fetch.fetch(url).await?;
    Ok(parse_subscription(&body))
}

pub fn parse_subscription(body: &str) -> SubscriptionParse {
    let text = decode_subscription_body(body);
    let mut out = SubscriptionParse::default();
    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.len() > MAX_CONFIG_ENTRY_BYTES {
            out.errors.push(format!(
                "line {}: entry exceeds {MAX_CONFIG_ENTRY_BYTES} bytes",
                idx + 1
            ));
            out.ignored += 1;
            continue;
        }
        match parse_uri(line) {
            Ok(spec) => out.specs.push(spec),
            Err(err) => {
                let reason = sanitize_error_text(&format!("{err:#}"));
                out.errors.push(format!("line {}: {reason}", idx + 1));
                out.ignored += 1;
            }
        }
    }
    out
}

fn decode_subscription_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.lines().count() != 1 {
        return body.to_owned();
    }
    if trimmed.len() > MAX_SUB_BLOB_BYTES {
        return body.to_owned();
    }
    let line = trimmed;
    let looks_like_uri = line
        .split_once("://")
        .map(|(s, _)| {
            matches!(
                s.to_ascii_lowercase().as_str(),
                "vless" | "trojan" | "vmess" | "ss"
            )
        })
        .unwrap_or(false);
    if looks_like_uri {
        return body.to_owned();
    }
    let Ok(decoded) = base64_any(line) else {
        return body.to_owned();
    };
    let Ok(text) = String::from_utf8(decoded) else {
        return body.to_owned();
    };
    if text.lines().any(|l| {
        let l = l.trim();
        l.starts_with("vless://")
            || l.starts_with("trojan://")
            || l.starts_with("vmess://")
            || l.starts_with("ss://")
    }) {
        text
    } else {
        body.to_owned()
    }
}
