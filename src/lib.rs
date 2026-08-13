//! CF-Scanner: find working Cloudflare IPs/endpoints on ISP-restricted
//! networks. Library target so integration tests can import engine modules;
//! the real entry point is the binary (`src/main.rs`).

pub mod api;
pub mod cli_wizard;
pub mod configs;
pub mod engine;
pub mod geo;
pub mod paths;
pub mod probe;
pub mod ranges;
pub mod server;
pub mod verify;
pub mod warp;
pub mod warpgen;
pub mod wgconf;
pub mod xray;
