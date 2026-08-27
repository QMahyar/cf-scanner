//! Candidate ranges for CDN mode: bundled official Cloudflare space, custom
//! CIDRs, dirty-range exclusions, and the official-ranges HTTP fetch. Pure
//! logic here; the network fetch for `ranges refresh` is injected so tests
//! never touch the wire. (Scan planning over these pools lives in
//! `crate::engine::plan`.)

mod http;
mod official;
mod pool;

pub use http::*;
pub use official::*;
pub use pool::*;
