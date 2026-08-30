//! CF-Scanner: find working Cloudflare IPs/endpoints on ISP-restricted
//! networks. Library target so integration tests and the binary can import
//! engine modules; the real entry point is the binary (`src/main.rs`).
//!
//! Public surface = the modules the binary and the integration tests
//! consume. `geo`, `socks`, and `inline_verify` are internal plumbing and
//! stay crate-private; reach them through their owners (engine/verify).

pub mod api;
pub mod cli_wizard;
pub mod configs;
pub mod dgst;
pub mod engine;
pub mod paths;
pub mod probe;
pub mod ranges;
pub mod server;
pub mod tray;
pub mod verify;
pub mod warp;
pub mod warpgen;
pub mod wgconf;
pub mod xray;

mod geo;
mod inline_verify;
mod socks;
pub(crate) mod util;
