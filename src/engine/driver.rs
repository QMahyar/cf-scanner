//! Mechanical plumbing shared by the CDN and WARP probe loops (F-27.3).
//!
//! Deliberately policy-free: the two loops keep their own producers (CDN
//! dispatches non-blocking `try_send` with inflight accounting plus a
//! neighbor side-channel; WARP uses backpressured `send().await`) and their
//! own probe bodies. Only the parts that were byte-for-byte duplicated live
//! here; a fuller "generic driver" would multiply mode-specific parameters
//! and leak policy (see T-29 abort rationale).

use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Result, anyhow};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::store::merge_sorted;
use super::{BATCH_FLUSH, ProbeContext};
use crate::api::types::{ScanEvent, Verdict};

/// Creates the per-worker bounded channel set (i % concurrency dispatch).
pub(crate) fn worker_channels<T>(
    concurrency: usize,
    per_worker_cap: usize,
) -> (Vec<mpsc::Sender<T>>, Vec<mpsc::Receiver<T>>) {
    let mut txs = Vec::with_capacity(concurrency);
    let mut rxs = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let (tx, rx) = mpsc::channel::<T>(per_worker_cap);
        txs.push(tx);
        rxs.push(rx);
    }
    (txs, rxs)
}

/// Drains the worker JoinSet, aborting the producer and cancelling the scan
/// on a worker panic. `panic_label` distinguishes the CDN/WARP messages.
pub(crate) async fn drain_workers<T: Send + 'static>(
    mut workers: JoinSet<T>,
    producer: tokio::task::JoinHandle<()>,
    cancel: impl Fn(),
    panic_label: &str,
) -> Result<()> {
    while let Some(res) = workers.join_next().await {
        if let Err(join_err) = res {
            producer.abort();
            cancel();
            return Err(anyhow!("{panic_label} worker panicked: {join_err}"));
        }
    }
    producer
        .await
        .map_err(|e| anyhow!("{panic_label} producer panicked: {e}"))
}

/// Increments the found counter (when the verdict measured latency), emits
/// the Result event, and flushes the batch at BATCH_FLUSH. Shared tail of
/// both loops' per-verdict handling.
pub(crate) fn record_and_batch(
    ctx: &Arc<ProbeContext>,
    batch: &mut Vec<Verdict>,
    verdict: Verdict,
) {
    if verdict.latency_ms.is_some() {
        ctx.found.fetch_add(1, Ordering::Release);
        let _ = ctx
            .events
            .send(ScanEvent::Result(Box::new(verdict.clone())));
    }
    batch.push(verdict);
    if batch.len() >= BATCH_FLUSH {
        merge_sorted(&ctx.store, &ctx.dirty, std::mem::take(batch));
    }
}
